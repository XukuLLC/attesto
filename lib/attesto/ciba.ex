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
  alias Attesto.Secret

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
  @spec issue(module(), Request.t(), issue_attrs(), keyword()) :: {:ok, issued()} | {:error, :invalid_subject}
  def issue(store, %Request{} = request, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    with :ok <- require_subject(attrs) do
      now = unix_now(opts)
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

      :ok = store.put(record)
      {:ok, %{auth_req_id: auth_req_id, expires_in: expires_in, interval: interval}}
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
    * `:invalid_grant` - unknown/garbage `auth_req_id`, a client mismatch
      ("issued to another Client", §11), DPoP mismatch, or an
      already-consumed request.
  """
  @spec redeem(module(), String.t(), map(), keyword()) :: {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, auth_req_id, params, opts \\ [])
      when is_atom(store) and is_binary(auth_req_id) and is_map(params) and is_list(opts) do
    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_grant) do
      case store.poll(hash, %{now: unix_now(opts)}) do
        {:ok, record} -> redeem_polled(store, hash, record, params, opts)
        {:error, :slow_down} -> {:error, :slow_down}
        :error -> {:error, :invalid_grant}
      end
    end
  end

  # The poll was accepted. Apply the §11 precedence: expiry first (a stale
  # approval must not mint), then the binding checks, then the status outcome.
  # ALL validation runs on the polled record BEFORE `consume/2`, so a client-
  # or DPoP-mismatched request is rejected without burning the single-use
  # auth_req_id; only an approved, unexpired, correctly-bound request reaches
  # the atomic consume.
  defp redeem_polled(store, hash, record, params, opts) do
    with :ok <- check_not_expired(record, opts),
         :ok <- check_client(record, params),
         :ok <- check_dpop(record, params),
         :ok <- check_status(record) do
      consume(store, hash, opts)
    end
  end

  defp consume(store, hash, opts) do
    case store.consume(hash, %{now: unix_now(opts)}) do
      {:ok, record} ->
        {:ok, Grant.from_record(record)}

      # Lost the consume race (a concurrent token request consumed it), or the
      # status/expiry moved out from under us between poll and consume.
      :error ->
        {:error, :invalid_grant}
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
             :not_found | :already_decided | :expired | :invalid_auth_req_id | :invalid_subject | :subject_mismatch}
  def approve(store, auth_req_id, approval, opts \\ [])
      when is_atom(store) and is_binary(auth_req_id) and is_map(approval) and is_list(opts) do
    now = unix_now(opts)

    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_auth_req_id),
         :ok <- require_subject(approval),
         :ok <- check_subject_matches(store, hash, approval) do
      fields = %{
        acr: Map.get(approval, :acr),
        auth_time: Map.get(approval, :auth_time, now),
        granted_claims: Map.get(approval, :claims, %{}),
        # nil means "as requested": Grant.from_record falls back to the
        # request's scope; an explicit list (even []) narrows it.
        granted_scope: Map.get(approval, :scope),
        subject: approval.subject
      }

      case store.approve(hash, fields, %{now: now}) do
        {:ok, record} -> {:ok, decision_view(record)}
        {:error, _reason} = err -> err
      end
    end
  end

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
    with {:ok, hash} <- presented_hash(auth_req_id, :invalid_auth_req_id) do
      case store.deny(hash, %{now: unix_now(opts)}) do
        {:ok, record} -> {:ok, decision_view(record)}
        {:error, _reason} = err -> err
      end
    end
  end

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
        case store.lookup(hash) do
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

  # The approving subject must be the end-user the request was issued for.
  # This read-then-approve is race-free for security purposes: `data` is
  # immutable after `put`, and the store's `approve` remains the single
  # pending→approved gate.
  defp check_subject_matches(store, hash, %{subject: subject}) do
    case store.lookup(hash) do
      {:ok, %{data: %{subject: ^subject}}} -> :ok
      {:ok, _record} -> {:error, :subject_mismatch}
      :error -> {:error, :not_found}
    end
  end

  defp check_not_expired(%{expires_at: expires_at}, opts) do
    if expires_at > unix_now(opts), do: :ok, else: {:error, :expired_token}
  end

  # §11: an auth_req_id "issued to another Client" is invalid_grant.
  defp check_client(%{data: %{client_id: bound}}, %{client_id: presented}) do
    if is_binary(bound) and bound == presented, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_client(_record, _params), do: {:error, :invalid_grant}

  defp check_status(%{status: :approved}), do: :ok
  defp check_status(%{status: :pending}), do: {:error, :authorization_pending}
  defp check_status(%{status: :denied}), do: {:error, :access_denied}
  # consumed (or anything else) → already used.
  defp check_status(_record), do: {:error, :invalid_grant}

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

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> System.system_time(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
