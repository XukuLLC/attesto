defmodule Attesto.CIBA do
  @moduledoc """
  OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core 1.0) -
  the conn-free core.

  CIBA is the device grant's sibling: an asynchronous grant where the client
  never redirects the user's browser. The client POSTs a backchannel
  authentication request naming the end-user through a hint, the OP
  authenticates the user out-of-band on their *authentication device*, and
  the client obtains tokens from the token endpoint with the
  `#{inspect("urn:openid:params:grant-type:ciba")}` grant - by polling (poll
  mode) or after an OP → client notification (ping mode).

  Like `Attesto.DeviceCode`, every decision here is data-only: this module
  reads no `Plug.Conn`, no clock except the passed `:now`, and drives all
  state through an `Attesto.CIBAStore`. The endpoint flow decomposes as:

  1. **Validate** - `Attesto.CIBA.Request.validate/3` checks the wire
     parameters (or the signed authentication request JWT) against the
     client's registered CIBA metadata.
  2. **Resolve** - the *host* resolves the request's hint to an end-user
     (`unknown_user_id` / `expired_login_hint_token` on failure) and verifies
     any `user_code` (`missing_user_code` / `invalid_user_code`).
  3. **Issue** - `issue/4` mints the `auth_req_id` (256-bit CSPRNG, above the
     §7.3 recommended 160 bits; only its hash is stored) and creates the
     `pending` record. The host then starts the out-of-band authentication.
  4. **Decide** - `approve/4` / `deny/3` record the user's decision, returning
     the data a ping-mode host needs to deliver the §10.2 notification (which
     fires on approval AND denial).
  5. **Redeem** - `redeem/4` runs the token-endpoint state machine with the
     exact §11 error vocabulary (`authorization_pending` / `slow_down` /
     `expired_token` / `access_denied` / `invalid_grant`), consuming the
     request single-use and yielding an `Attesto.CIBA.Grant` for the host's
     usual token-minting path.

  ## Delivery modes

  Poll and ping records both enforce the §7.3 minimum token-request interval
  frozen into the record at issue time (§10.2: a ping client that polls "must
  be treated as if it had been registered to use the Poll mode"). Push mode is
  accepted at validation for completeness - the token response would be
  delivered by the host over its own transport - but **FAPI-CIBA §5.2.1
  forbids push mode**; a FAPI deployment simply never registers a push client.
  """

  alias Attesto.CIBA.Grant
  alias Attesto.CIBA.Request
  alias Attesto.{NumericDate, Scope, Secret, Thumbprint}

  @grant_type "urn:openid:params:grant-type:ciba"

  # CIBA Core §7.3: >=128 bits of entropy, 160 recommended (FAPI-CIBA requires
  # the recommendation). 32 bytes = 256 bits, matching Attesto.Secret's
  # default; base64url output stays inside the §7.3 A-Za-z0-9 . - _ charset.
  @auth_req_id_bytes 32

  # §7.3: auth_req_id values are limited to A-Z a-z 0-9 . - _ . Presented
  # values are charset/length-validated fail-closed BEFORE any store lookup,
  # the same discipline as Attesto.DeviceCode.normalize_user_code/2.
  @auth_req_id_pattern ~r/\A[A-Za-z0-9._-]{16,1024}\z/

  # FAPI-CIBA guidance favours a short authentication-request lifetime; 120s
  # accommodates a human approving on a second device without leaving a long
  # replay window.
  @default_expires_in 120
  @max_expires_in 600

  # §7.3: the default minimum token-request interval.
  @default_interval 5
  # Approval and redemption may land on nodes whose whole-second clocks differ
  # by one second. Keep the tolerance narrow; larger future timestamps indicate
  # impossible persisted state or a badly skewed deployment and fail closed.
  @decision_clock_skew_seconds 1
  @notification_token_pattern ~r/\A[A-Za-z0-9\-._~+\/]+=*\z/
  @notification_token_max_length 1024
  @statuses [:pending, :approved, :denied, :consumed]
  @decision_errors [:not_found, :already_decided, :expired]
  @consume_bound_fields [
    :auth_req_id_hash,
    :data,
    :subject,
    :acr,
    :auth_time,
    :granted_scope,
    :granted_claims,
    :interval,
    :expires_at
  ]
  @poll_bound_fields [:auth_req_id_hash, :data, :interval, :expires_at]

  @typedoc "What `issue/4` hands back: the §7.3 authentication request acknowledgement."
  @type issued :: %{
          auth_req_id: String.t(),
          expires_in: pos_integer(),
          interval: pos_integer() | nil
        }

  @type issue_attrs :: %{
          required(:subject) => String.t(),
          optional(:resource) => [String.t()],
          optional(:dpop_jkt) => String.t() | nil
        }

  @typedoc """
  The full CIBA error taxonomy. Backchannel authentication endpoint errors
  (§13) come from `Attesto.CIBA.Request.validate/3`, from the host's hint /
  user-code resolution, or from client authentication; token endpoint errors
  (§11) come from `redeem/4`.
  """
  @type error ::
          :invalid_request
          | :invalid_scope
          | :expired_login_hint_token
          | :unknown_user_id
          | :unauthorized_client
          | :missing_user_code
          | :invalid_user_code
          | :invalid_binding_message
          | :invalid_client
          | :access_denied
          | :expired_token
          | :authorization_pending
          | :slow_down
          | :invalid_grant

  @type redeem_error ::
          :authorization_pending
          | :slow_down
          | :expired_token
          | :access_denied
          | :unauthorized_client
          | :invalid_grant

  @typedoc """
  What `approve/4` / `deny/3` return: the data the host needs to deliver the
  ping-mode notification (CIBA Core §10.2) - an HTTP POST to the client's
  registered `backchannel_client_notification_endpoint` carrying
  `Authorization: Bearer <client_notification_token>` and the JSON body
  `{"auth_req_id": ...}`. `client_notification_token` is nil for poll mode
  (no notification is sent).
  """
  @type decision :: %{
          client_id: String.t(),
          delivery_mode: Request.delivery_mode(),
          client_notification_token: String.t() | nil
        }

  @doc """
  The CIBA grant type URN (CIBA Core §4 / §10.1), for token-endpoint dispatch
  and `grant_types_supported` metadata.
  """
  @spec grant_type() :: String.t()
  def grant_type, do: @grant_type

  @doc """
  Validate a backchannel authentication request's wire parameters against the
  authenticated client's registered CIBA metadata. See
  `Attesto.CIBA.Request.validate/3` for the parameter/option contract.
  """
  @spec validate_request(Request.client(), map(), keyword()) :: {:ok, Request.t()} | {:error, Request.error()}
  defdelegate validate_request(client, params, opts \\ []), to: Request, as: :validate

  @doc """
  Issue an `auth_req_id` for a validated authentication request whose hint the
  host has resolved to an end-user (CIBA Core §7.3).

  `attrs` carries what only the host knows: `:subject` (required - §7.1
  requires the user to be identified BEFORE the acknowledgement is returned;
  a hint that resolves to no user is the host's `unknown_user_id`), and the
  optional `:resource` (RFC 8707) / `:dpop_jkt` (RFC 9449 §10 pre-binding).

  Options: `:expires_in` (seconds, default #{@default_expires_in} per
  FAPI-CIBA's short-lifetime guidance), `:max_expires_in` (cap applied to the
  client's `requested_expiry`, default #{@max_expires_in}), `:interval` (the
  §7.3 minimum token-request interval, default #{@default_interval}), and
  `:now`.

  Returns `{:ok, %{auth_req_id: ..., expires_in: ..., interval: ...}}` - the
  §7.3 acknowledgement fields. `interval` is nil for a push-mode request
  (there is no token-endpoint polling to pace); the caller omits it from the
  JSON response.
  """
  @spec issue(module(), Request.t(), issue_attrs(), keyword()) ::
          {:ok, issued()}
          | {:error, :invalid_subject | :invalid_request | :invalid_resource | :invalid_dpop_jkt}
  def issue(store, %Request{} = request, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    validate_issue_options!(opts)
    now = NumericDate.non_negative_now!(opts, default: :system)

    with :ok <- require_subject(attrs),
         :ok <- validate_request_for_issue(request, now),
         :ok <- validate_issue_attrs(attrs) do
      expires_in = effective_expires_in(request, opts)
      interval = if request.delivery_mode != :push, do: Keyword.get(opts, :interval, @default_interval)
      auth_req_id = Secret.generate(@auth_req_id_bytes)

      record = %{
        auth_req_id_hash: Secret.hash(auth_req_id),
        data: %{
          acr_values: request.acr_values,
          binding_message: request.binding_message,
          client_id: request.client_id,
          client_notification_token: request.client_notification_token,
          delivery_mode: request.delivery_mode,
          dpop_jkt: Map.get(attrs, :dpop_jkt),
          resource: Map.get(attrs, :resource, []),
          scope: request.scope,
          subject: attrs.subject
        },
        status: :pending,
        subject: nil,
        interval: interval || 0,
        expires_at: now + expires_in,
        last_polled_at: nil
      }

      case store.put(record) do
        :ok -> {:ok, %{auth_req_id: auth_req_id, expires_in: expires_in, interval: interval}}
        _unexpected -> ciba_store_contract_error(:put)
      end
    end
  end

  @doc """
  Redeem an `auth_req_id` at the token endpoint
  (`grant_type=#{@grant_type}`), running the CIBA Core §10.1/§11 state
  machine.

  `params` carries the requesting client's `:client_id` (matched against the
  issue-time binding) and any `:dpop_jkt` (RFC 9449 holder-of-key, matched
  against a pre-bound key). Option: `:now`.

  Returns `{:ok, %Attesto.CIBA.Grant{}}` once the user has authenticated and
  the request is single-use consumed, or `{:error, reason}` where `reason` is
  the exact §11 code the token endpoint renders verbatim:

    * `:authorization_pending` - the user has not yet been authenticated.
    * `:slow_down` - the client polled faster than the interval it was told
      at issuance (the client must add >=5s to its interval, §11).
    * `:expired_token` - the `auth_req_id`'s lifetime elapsed (this wins over
      a stale approval).
    * `:access_denied` - the user denied the request (or the OP did).
    * `:unauthorized_client` - the request was registered for push-mode
      delivery, which (CIBA Core §11) MUST NOT be redeemed at the token
      endpoint; the token comes over the host's push transport instead.
    * `:invalid_grant` - unknown/garbage `auth_req_id`, a client mismatch
      ("issued to another Client", §11), DPoP mismatch, or an
      already-consumed request.

  All record validation - expiry, client binding, DPoP binding, push-mode
  rejection, and terminal status - runs on a NON-mutating read BEFORE any
  poll-interval throttling. `slow_down` is a variant of `authorization_pending`
  (§11): it is returned only when the request is genuinely still pending, so it
  can never mask an expired, denied, approved, consumed, wrong-client,
  wrong-DPoP, or push-mode outcome, and an unauthorized caller can never mutate
  another client's throttle state.
  """
  @spec redeem(module(), String.t(), map(), keyword()) :: {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, auth_req_id, params, opts \\ [])
      when is_atom(store) and is_binary(auth_req_id) and is_map(params) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)
    opts = Keyword.put(opts, :now, now)

    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_grant),
         {:ok, record} <- read_record(store, hash),
         :ok <- check_not_expired(record, opts),
         :ok <- check_decision_time(record, opts),
         :ok <- check_client(record, params),
         :ok <- check_dpop(record, params),
         :ok <- check_not_push(record) do
      resolve_status(store, hash, record, opts)
    end
  end

  defp read_record(store, hash) do
    case lookup_record(store, hash) do
      {:ok, record} -> {:ok, record}
      :error -> {:error, :invalid_grant}
    end
  end

  # Apply the §11 status outcome to a record that has already passed expiry, the
  # binding checks, and the push-mode guard. Only a genuinely-pending request
  # reaches `poll/2`, so the poll-interval throttle (which mutates
  # `last_polled_at` and can yield `slow_down`) can never fire for an expired,
  # denied, approved, consumed, wrong-client, wrong-DPoP, or push-mode request.
  # An approved request goes to the atomic `consume/2`; a wrong-client/DPoP
  # request never gets here, so the single-use auth_req_id is never burned by an
  # unauthorized caller.
  defp resolve_status(store, hash, record, opts) do
    case record.status do
      :approved -> consume(store, hash, record, opts)
      :denied -> {:error, :access_denied}
      :pending -> throttle_pending(store, hash, record, opts)
      :consumed -> {:error, :invalid_grant}
    end
  end

  # The request is still pending: NOW apply the §7.3 poll-interval throttle.
  # A poll accepted at the interval is `authorization_pending`; one inside the
  # interval is its `slow_down` variant. `poll/2` re-reads inside the store's
  # serialized transition, so a concurrent approval is not clobbered (its
  # status is preserved; terminal status is resolved by this same call).
  defp throttle_pending(store, hash, trusted_record, opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)

    case store.poll(hash, %{now: now}) do
      {:ok, polled_record} ->
        if valid_record?(polled_record, hash) and
             Map.get(polled_record, :last_polled_at) == now and
             fields_match?(trusted_record, polled_record, @poll_bound_fields) do
          resolve_polled_status(store, hash, polled_record, opts)
        else
          ciba_store_contract_error(:poll)
        end

      {:error, :slow_down} ->
        {:error, :slow_down}

      # Vanished between the read and the poll (e.g. swept): treat as unknown.
      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        ciba_store_contract_error(:poll)
    end
  end

  defp resolve_polled_status(_store, _hash, %{status: :pending}, _opts), do: {:error, :authorization_pending}
  defp resolve_polled_status(store, hash, %{status: :approved} = record, opts), do: consume(store, hash, record, opts)
  defp resolve_polled_status(_store, _hash, %{status: :denied}, _opts), do: {:error, :access_denied}
  defp resolve_polled_status(_store, _hash, %{status: :consumed}, _opts), do: {:error, :invalid_grant}

  defp consume(store, hash, trusted_record, opts) do
    case store.consume(hash, %{now: Keyword.fetch!(opts, :now)}) do
      {:ok, consumed_record} ->
        if valid_consume_transition?(trusted_record, consumed_record, hash) do
          {:ok, Grant.from_record(consumed_record)}
        else
          ciba_store_contract_error(:consume)
        end

      # Lost the consume race (a concurrent token request consumed it), or the
      # status/expiry moved out from under us between poll and consume.
      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        ciba_store_contract_error(:consume)
    end
  end

  @doc """
  Record a successful end-user authentication + consent for a pending
  authentication request (CIBA Core §10: the "authentication result is
  ready" transition).

  `approval` carries `:subject` (required - and it MUST be the same end-user
  the request was issued for; approving as anyone else fails with
  `:subject_mismatch`, fail-closed), and optionally `:acr` (the satisfied
  Authentication Context Class Reference; FAPI-CIBA §5.2.2 requires returning
  `acr` when the client requested one), `:scope` (what the user actually
  granted), `:claims`, and `:auth_time` (unix seconds, default `:now`).

  Atomic `pending` → `approved`. Returns `{:ok, decision}` with the ping-mode
  notification data (§10.2 - the notification fires on approval and denial
  alike), or `{:error, reason}` (`:not_found` / `:already_decided` /
  `:expired` / `:invalid_auth_req_id` / `:invalid_subject` /
  `:subject_mismatch`).
  """
  @spec approve(module(), String.t(), map(), keyword()) ::
          {:ok, decision()}
          | {:error,
             :not_found
             | :already_decided
             | :expired
             | :invalid_auth_req_id
             | :invalid_subject
             | :subject_mismatch
             | :invalid_acr
             | :invalid_auth_time
             | :invalid_scope
             | :invalid_claims}
  def approve(store, auth_req_id, approval, opts \\ [])
      when is_atom(store) and is_binary(auth_req_id) and is_map(approval) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)

    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_auth_req_id),
         :ok <- require_subject(approval),
         {:ok, trusted_record} <- check_subject_matches(store, hash, approval) do
      with {:ok, fields} <- approval_fields(approval, trusted_record, now) do
        store.approve(hash, fields, %{now: now})
        |> validate_approve_result(trusted_record, fields, hash)
      end
    end
  end

  defp validate_approve_result({:ok, record}, trusted_record, fields, hash) do
    if valid_approve_transition?(trusted_record, record, fields, hash),
      do: {:ok, decision_view(record)},
      else: ciba_store_contract_error(:approve)
  end

  defp validate_approve_result({:error, reason} = error, _trusted_record, _fields, _hash)
       when reason in @decision_errors, do: error

  defp validate_approve_result(_unexpected, _trusted_record, _fields, _hash), do: ciba_store_contract_error(:approve)

  @doc """
  Record a denial (the user refused, failed authentication, or the OP denied)
  for a pending authentication request: atomic `pending` → `denied`, so the
  client's next token request receives `access_denied` (§11).

  Returns `{:ok, decision}` with the ping-mode notification data - the §10.2
  notification is sent for denials too - or `{:error, reason}`.
  """
  @spec deny(module(), String.t(), keyword()) ::
          {:ok, decision()} | {:error, :not_found | :already_decided | :expired | :invalid_auth_req_id}
  def deny(store, auth_req_id, opts \\ []) when is_atom(store) and is_binary(auth_req_id) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)

    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_auth_req_id),
         {:ok, trusted_record} <- decision_record(store, hash) do
      store.deny(hash, %{now: now})
      |> validate_deny_result(trusted_record, hash)
    end
  end

  defp validate_deny_result({:ok, %{status: :denied} = record}, trusted_record, hash) do
    if valid_deny_transition?(trusted_record, record, hash),
      do: {:ok, decision_view(record)},
      else: ciba_store_contract_error(:deny)
  end

  defp validate_deny_result({:error, reason} = error, _trusted_record, _hash) when reason in @decision_errors, do: error

  defp validate_deny_result(_unexpected, _trusted_record, _hash), do: ciba_store_contract_error(:deny)

  @doc """
  Non-consuming lookup of an authentication request, for the
  authentication-device UI to show the user what they are approving (client,
  scope, `binding_message`) and for the host to route the flow. Returns
  `{:error, :invalid_auth_req_id}` for malformed input (before any store
  call) and `:error` for an unknown id.
  """
  @spec lookup(module(), String.t()) :: {:ok, map()} | :error | {:error, :invalid_auth_req_id}
  def lookup(store, auth_req_id) when is_atom(store) and is_binary(auth_req_id) do
    case presented_hash(auth_req_id, :invalid_auth_req_id) do
      {:ok, hash} ->
        case lookup_record(store, hash) do
          {:ok, record} -> {:ok, pending_view(record)}
          :error -> :error
        end

      {:error, :invalid_auth_req_id} = err ->
        err
    end
  end

  @doc """
  The HTTP status a backchannel authentication endpoint error is rendered
  with (CIBA Core §13): 401 for `invalid_client`, 403 for `access_denied`,
  400 for everything else. Token-endpoint errors (§11) are all 400 per
  RFC 6749 §5.2 and do not use this mapping (`access_denied` is 400 there).
  """
  @spec error_status(error()) :: 400 | 401 | 403
  def error_status(:invalid_client), do: 401
  def error_status(:access_denied), do: 403

  def error_status(error)
      when error in [
             :invalid_request,
             :invalid_scope,
             :expired_login_hint_token,
             :unknown_user_id,
             :unauthorized_client,
             :missing_user_code,
             :invalid_user_code,
             :invalid_binding_message
           ], do: 400

  # ----- internal -----

  # §7.3 fail-closed charset/length validation of a presented auth_req_id
  # BEFORE any store lookup, mirroring DeviceCode.normalize_user_code/2.
  defp presented_hash(auth_req_id, error) do
    if Regex.match?(@auth_req_id_pattern, auth_req_id),
      do: {:ok, Secret.hash(auth_req_id)},
      else: {:error, error}
  end

  defp effective_expires_in(%Request{requested_expiry: nil}, opts),
    do: Keyword.get(opts, :expires_in, @default_expires_in)

  # §7.1: requested_expiry lets the client ask for a specific lifetime; honour
  # it under the host's cap.
  defp effective_expires_in(%Request{requested_expiry: requested}, opts) do
    min(requested, Keyword.get(opts, :max_expires_in, @max_expires_in))
  end

  defp require_subject(%{subject: subject}) when is_binary(subject) and subject != "", do: :ok
  defp require_subject(_attrs), do: {:error, :invalid_subject}

  defp validate_request_for_issue(%Request{} = request, now) do
    if valid_ciba_request_data?(
         request.acr_values,
         request.binding_message,
         request.client_id,
         request.client_notification_token,
         request.delivery_mode
       ) and valid_ciba_hint?(request.hint) and valid_ciba_scope?(request.scope) and
         valid_optional_display_text?(request.user_code) and
         valid_requested_expiry?(request.requested_expiry) and
         valid_signed_request_state?(request, now) do
      :ok
    else
      {:error, :invalid_request}
    end
  end

  defp validate_issue_attrs(attrs) do
    cond do
      not valid_resource_list?(Map.get(attrs, :resource, [])) -> {:error, :invalid_resource}
      not valid_optional_jkt?(Map.get(attrs, :dpop_jkt)) -> {:error, :invalid_dpop_jkt}
      true -> :ok
    end
  end

  defp validate_issue_options!(opts) do
    positive_option!(opts, :expires_in, @default_expires_in)
    positive_option!(opts, :max_expires_in, @max_expires_in)
    positive_option!(opts, :interval, @default_interval)
    :ok
  end

  defp positive_option!(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, ":#{key} must be a positive integer"
    end
  end

  defp approval_fields(approval, trusted_record, now) do
    fields = %{
      acr: Map.get(approval, :acr),
      auth_time: Map.get(approval, :auth_time, now),
      granted_claims: Map.get(approval, :claims, %{}),
      # nil means "as requested": Grant.from_record falls back to the
      # request's scope; an explicit list (even []) narrows it.
      granted_scope: Map.get(approval, :scope),
      subject: approval.subject
    }

    with :ok <- validate_approval_types(fields, now),
         :ok <- require_requested_acr(fields.acr, trusted_record.data.acr_values),
         :ok <- validate_granted_scope(fields.granted_scope, trusted_record.data.scope) do
      {:ok, fields}
    end
  end

  defp validate_approval_types(fields, now) do
    cond do
      not valid_optional_non_empty_binary?(fields.acr) ->
        {:error, :invalid_acr}

      not (is_integer(fields.auth_time) and fields.auth_time >= 0 and fields.auth_time <= now) ->
        {:error, :invalid_auth_time}

      not valid_optional_scope_list?(fields.granted_scope) ->
        {:error, :invalid_scope}

      not is_map(fields.granted_claims) ->
        {:error, :invalid_claims}

      true ->
        :ok
    end
  end

  defp require_requested_acr(acr, [_requested | _]) when not (is_binary(acr) and acr != ""), do: {:error, :invalid_acr}

  defp require_requested_acr(_acr, _requested), do: :ok

  defp validate_granted_scope(nil, _requested_scope), do: :ok

  defp validate_granted_scope(granted_scope, requested_scope) do
    if MapSet.subset?(MapSet.new(granted_scope), MapSet.new(requested_scope)),
      do: :ok,
      else: {:error, :invalid_scope}
  end

  defp decision_record(store, hash) do
    case lookup_record(store, hash) do
      {:ok, record} -> {:ok, record}
      :error -> {:error, :not_found}
    end
  end

  # The approving subject must be the end-user the request was issued for.
  # This read-then-approve is race-free for security purposes: `data` is
  # immutable after `put`, and the store's `approve` remains the single
  # pending→approved gate.
  defp check_subject_matches(store, hash, %{subject: subject}) do
    case lookup_record(store, hash) do
      {:ok, %{data: %{subject: ^subject}} = record} -> {:ok, record}
      {:ok, _record} -> {:error, :subject_mismatch}
      :error -> {:error, :not_found}
    end
  end

  defp check_not_expired(%{expires_at: expires_at}, opts) do
    if expires_at > NumericDate.now(opts, default: :system), do: :ok, else: {:error, :expired_token}
  end

  defp check_decision_time(%{status: status, auth_time: auth_time}, opts) when status in [:approved, :consumed] do
    now = NumericDate.now(opts, default: :system)

    if auth_time <= now or auth_time - now <= @decision_clock_skew_seconds,
      do: :ok,
      else: ciba_store_contract_error(:lookup)
  end

  defp check_decision_time(_record, _opts), do: :ok

  # §11: an auth_req_id "issued to another Client" is invalid_grant.
  defp check_client(%{data: %{client_id: bound}}, %{client_id: presented}) do
    if is_binary(bound) and bound == presented, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_client(_record, _params), do: {:error, :invalid_grant}

  # CIBA Core §11: a push-mode client MUST NOT redeem the CIBA grant at the
  # token endpoint - the token is delivered over the host's push transport - so
  # a push-mode record fails closed with `unauthorized_client`. Checked after
  # the client/DPoP binding (a wrong caller learns `invalid_grant`, not that the
  # request is push mode) and BEFORE any status/throttle handling, so it never
  # consumes the request nor mutates throttle state.
  defp check_not_push(%{data: %{delivery_mode: :push}}), do: {:error, :unauthorized_client}
  defp check_not_push(_record), do: :ok

  # RFC 9449 §10 holder-of-key: a request pre-bound to a DPoP key may be
  # redeemed only with a matching proof. An unbound request accepts any (or
  # no) presented key, which the caller may use to mint a DPoP-bound token.
  defp check_dpop(%{data: %{dpop_jkt: bound}}, params) when is_binary(bound) and bound != "" do
    if Map.get(params, :dpop_jkt) == bound, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_dpop(_record, _params), do: :ok

  defp decision_view(record) do
    data = Map.get(record, :data, %{})

    %{
      client_id: Map.get(data, :client_id),
      client_notification_token: Map.get(data, :client_notification_token),
      delivery_mode: Map.get(data, :delivery_mode)
    }
  end

  defp pending_view(record) do
    data = Map.get(record, :data, %{})

    %{
      acr_values: Map.get(data, :acr_values, []),
      binding_message: Map.get(data, :binding_message),
      client_id: Map.get(data, :client_id),
      delivery_mode: Map.get(data, :delivery_mode),
      expires_at: record.expires_at,
      scope: Map.get(data, :scope, []),
      status: record.status,
      subject: Map.get(data, :subject)
    }
  end

  defp lookup_record(store, hash) do
    case store.lookup(hash) do
      {:ok, record} ->
        if valid_record?(record, hash),
          do: {:ok, record},
          else: ciba_store_contract_error(:lookup)

      :error ->
        :error

      _unexpected ->
        ciba_store_contract_error(:lookup)
    end
  end

  defp valid_record?(
         %{
           auth_req_id_hash: record_hash,
           data: %{
             acr_values: acr_values,
             binding_message: binding_message,
             client_id: client_id,
             client_notification_token: client_notification_token,
             delivery_mode: delivery_mode,
             dpop_jkt: dpop_jkt,
             resource: resource,
             scope: scope,
             subject: requested_subject
           },
           status: status,
           interval: interval,
           expires_at: expires_at
         } = record,
         expected_hash
       ) do
    record_hash == expected_hash and
      valid_ciba_request_data?(
        acr_values,
        binding_message,
        client_id,
        client_notification_token,
        delivery_mode
      ) and
      valid_ciba_grant_data?(dpop_jkt, resource, scope, requested_subject) and
      valid_ciba_state?(status, interval, expires_at) and valid_ciba_optional_fields?(record) and
      valid_decision_fields?(record)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_ciba_request_data?(acr_values, binding_message, client_id, notification_token, delivery_mode) do
    valid_non_empty_string_list?(acr_values) and valid_optional_display_text?(binding_message) and
      is_binary(client_id) and client_id != "" and
      valid_notification_binding?(delivery_mode, notification_token)
  end

  defp valid_notification_binding?(:poll, nil), do: true

  defp valid_notification_binding?(mode, token) when mode in [:ping, :push],
    do:
      is_binary(token) and token != "" and byte_size(token) <= @notification_token_max_length and
        Regex.match?(@notification_token_pattern, token)

  defp valid_notification_binding?(_mode, _token), do: false

  defp valid_ciba_hint?({kind, value}) when kind in [:login_hint, :login_hint_token, :id_token_hint],
    do: is_binary(value) and value != ""

  defp valid_ciba_hint?(_hint), do: false

  defp valid_ciba_scope?(scope), do: Scope.valid_list?(scope, allow_empty?: false) and "openid" in scope

  defp valid_optional_display_text?(nil), do: true

  defp valid_optional_display_text?(value) when is_binary(value) and value != "",
    do: String.valid?(value) and not Regex.match?(~r/[\x00-\x1F\x7F]/u, value)

  defp valid_optional_display_text?(_value), do: false

  defp valid_requested_expiry?(nil), do: true
  defp valid_requested_expiry?(value), do: is_integer(value) and value > 0

  defp valid_signed_request_state?(%Request{signed?: false, request_jti: nil, request_exp: nil}, _now), do: true

  defp valid_signed_request_state?(%Request{signed?: true, request_jti: jti, request_exp: request_exp}, now),
    do: is_binary(jti) and jti != "" and is_integer(request_exp) and request_exp > now

  defp valid_signed_request_state?(_request, _now), do: false

  defp valid_ciba_grant_data?(dpop_jkt, resource, scope, requested_subject) do
    valid_optional_jkt?(dpop_jkt) and valid_resource_list?(resource) and
      valid_scope_list?(scope) and is_binary(requested_subject) and requested_subject != ""
  end

  defp valid_ciba_state?(status, interval, expires_at) do
    status in @statuses and is_integer(interval) and interval >= 0 and
      is_integer(expires_at) and expires_at >= 0
  end

  defp valid_ciba_optional_fields?(record) do
    valid_optional_field?(record, :subject, &valid_optional_binary?/1) and
      valid_optional_field?(record, :acr, &valid_optional_binary?/1) and
      valid_optional_field?(record, :auth_time, &valid_optional_non_negative_integer?/1) and
      valid_optional_field?(record, :granted_scope, &valid_optional_scope_list?/1) and
      valid_optional_field?(record, :granted_claims, &valid_optional_map?/1) and
      valid_optional_field?(record, :last_polled_at, &valid_optional_non_negative_integer?/1)
  end

  defp valid_decision_fields?(%{status: status} = record) when status in [:approved, :consumed] do
    case record do
      %{
        subject: subject,
        acr: acr,
        auth_time: auth_time,
        granted_scope: granted_scope,
        granted_claims: granted_claims
      } ->
        valid_decision_subject?(subject, record.data.subject) and
          valid_decision_authentication?(acr, record.data.acr_values, auth_time, record.expires_at) and
          valid_decision_grant?(granted_scope, record.data.scope, granted_claims)

      _missing_decision_fields ->
        false
    end
  end

  defp valid_decision_fields?(_record), do: true

  defp valid_decision_subject?(subject, requested_subject),
    do: is_binary(subject) and subject != "" and subject == requested_subject

  defp valid_decision_authentication?(acr, requested_acrs, auth_time, expires_at) do
    valid_decision_acr?(acr, requested_acrs) and is_integer(auth_time) and
      auth_time >= 0 and auth_time <= expires_at
  end

  defp valid_decision_grant?(granted_scope, requested_scope, granted_claims) do
    valid_optional_scope_list?(granted_scope) and
      valid_granted_scope?(granted_scope, requested_scope) and is_map(granted_claims)
  end

  defp valid_decision_acr?(acr, [_requested | _]), do: is_binary(acr) and acr != ""
  defp valid_decision_acr?(acr, []), do: valid_optional_non_empty_binary?(acr)

  defp valid_consume_transition?(trusted_record, consumed_record, hash) do
    trusted_record.status == :approved and consumed_record.status == :consumed and
      valid_record?(consumed_record, hash) and
      fields_match?(trusted_record, consumed_record, @consume_bound_fields)
  end

  defp valid_approve_transition?(trusted_record, approved_record, approval_fields, hash) do
    trusted_record.status == :pending and approved_record.status == :approved and
      valid_record?(approved_record, hash) and
      fields_match?(trusted_record, approved_record, @poll_bound_fields) and
      Enum.all?([:subject, :acr, :auth_time, :granted_scope, :granted_claims], fn field ->
        Map.get(approved_record, field) == Map.get(approval_fields, field)
      end)
  end

  defp valid_deny_transition?(trusted_record, denied_record, hash) do
    trusted_record.status == :pending and denied_record.status == :denied and
      valid_record?(denied_record, hash) and
      fields_match?(trusted_record, denied_record, @poll_bound_fields)
  end

  defp fields_match?(left, right, fields) do
    Enum.all?(fields, fn field -> Map.get(left, field) == Map.get(right, field) end)
  end

  defp valid_optional_field?(record, field, validator) do
    case Map.fetch(record, field) do
      {:ok, value} -> validator.(value)
      :error -> true
    end
  end

  defp valid_non_empty_string_list?(value), do: is_list(value) and Enum.all?(value, &(is_binary(&1) and &1 != ""))

  defp valid_scope_list?(value), do: Scope.valid_list?(value)
  defp valid_resource_list?(value), do: valid_non_empty_string_list?(value)
  defp valid_optional_scope_list?(nil), do: true
  defp valid_optional_scope_list?(value), do: valid_scope_list?(value)
  defp valid_granted_scope?(nil, _requested), do: true

  defp valid_granted_scope?(granted, requested), do: MapSet.subset?(MapSet.new(granted), MapSet.new(requested))

  defp valid_optional_binary?(nil), do: true
  defp valid_optional_binary?(value), do: is_binary(value)
  defp valid_optional_non_empty_binary?(nil), do: true
  defp valid_optional_non_empty_binary?(value), do: is_binary(value) and value != ""
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)
  defp valid_optional_map?(nil), do: true
  defp valid_optional_map?(value), do: is_map(value)
  defp valid_optional_non_negative_integer?(nil), do: true
  defp valid_optional_non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp ciba_store_contract_error(:put) do
    raise RuntimeError, "CIBA store put/1 violated its contract"
  end

  defp ciba_store_contract_error(:lookup) do
    raise RuntimeError, "CIBA store lookup/1 violated its contract"
  end

  defp ciba_store_contract_error(:approve) do
    raise RuntimeError, "CIBA store approve/3 violated its contract"
  end

  defp ciba_store_contract_error(:deny) do
    raise RuntimeError, "CIBA store deny/2 violated its contract"
  end

  defp ciba_store_contract_error(:poll) do
    raise RuntimeError, "CIBA store poll/2 violated its contract"
  end

  defp ciba_store_contract_error(:consume) do
    raise RuntimeError, "CIBA store consume/2 violated its contract"
  end
end
