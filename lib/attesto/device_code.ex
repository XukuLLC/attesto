defmodule Attesto.DeviceCode do
  @moduledoc """
  RFC 8628 Device Authorization Grant — the conn-free core.

  This is the storage-backed primitive behind the device flow, the analogue of
  `Attesto.AuthorizationCode` for a browserless, redirect-less, user-present
  grant. A headless/CLI client requests a `device_code` + a human-readable
  `user_code` (`issue/3`), shows the user the `user_code` and a verification
  URL, and polls the token endpoint (`redeem/4`) while the user approves on a
  second device (`approve/3` / `deny/2` from the verification page).

  Like `Attesto.AuthorizationCode`, every decision is data-only: this module
  reads no `Plug.Conn`, no clock except the passed `:now`, and drives all state
  through an `Attesto.DeviceCodeStore`. The polling state machine and its exact
  RFC 8628 §3.5 error vocabulary (`authorization_pending` / `slow_down` /
  `expired_token` / `access_denied`) live here.

  ## `user_code`

  The `user_code` is generated from an ambiguity-free base-20 alphabet
  (RFC 8628 §6.1: no vowels — so no accidental words — and no visually
  confusable `0/O/1/I`), 8 characters by default (~34.6 bits), displayed
  hyphenated (`BCDF-GHJK`). It is **normalized and charset-validated here before
  any store lookup** (`normalize_user_code/2`): upper-cased, separators
  stripped, and rejected outright if it falls outside the alphabet or length —
  so attacker-shaped input never reaches the store's unique-index query, the
  same fail-closed discipline `Attesto.ResourceIndicator.validate/1` applies.
  """

  alias Attesto.{Claims, NumericDate, Scope, Secret, Thumbprint}
  alias Attesto.DeviceCode.Grant

  # RFC 8628 §6.1: a base-20 alphabet with no vowels (no accidental words) and no
  # visually ambiguous characters (0/O, 1/I/L). 20^8 ≈ 2.56e10 ≈ 34.6 bits.
  @user_code_alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"
  @default_user_code_length 8
  @minimum_user_code_length 8
  @maximum_user_code_length 64
  @default_ttl_seconds 600
  @default_interval_seconds 5
  @statuses [:pending, :approved, :denied, :consumed]
  @decision_errors [:not_found, :already_decided, :expired]
  @canonical_data_keys [:client_id, :dpop_jkt, :resource, :scope]
  @consume_bound_fields [
    :device_code_hash,
    :user_code,
    :data,
    :subject,
    :granted_scope,
    :granted_claims,
    :expires_at
  ]
  @poll_bound_fields [:device_code_hash, :user_code, :data, :expires_at]

  @typedoc "What `issue/3` hands back: the secret device code and the display user code."
  @type issued :: %{device_code: String.t(), user_code: String.t()}

  @type issue_attrs :: %{
          required(:client_id) => String.t(),
          optional(:scope) => [String.t()],
          optional(:resource) => [String.t()],
          optional(:dpop_jkt) => String.t() | nil
        }

  @type redeem_error ::
          :authorization_pending
          | :slow_down
          | :expired_token
          | :access_denied
          | :invalid_grant

  @doc """
  Issue a device code + user code for an authenticated device-authorization
  request (RFC 8628 §3.1 / §3.2).

  `attrs` carries the issue-time binding: `:client_id` (required), and the
  optional `:scope` / `:resource` (RFC 8707) / `:dpop_jkt` (RFC 9449 §10
  pre-binding). Options: `:ttl` (seconds, default #{@default_ttl_seconds}),
  `:user_code_length` (default #{@default_user_code_length}), and `:now`.

  Returns `{:ok, %{device_code: ..., user_code: ...}}` with the plaintext device
  code (only its hash is stored) and the display-formatted user code.
  """
  # A `user_code` is short (≈34.6 bits), so a birthday collision against a live
  # code is rare but possible; retry with a fresh code a bounded number of times
  # rather than surfacing the store's uniqueness violation as an error.
  @user_code_collision_retries 5

  @spec issue(module(), issue_attrs(), keyword()) ::
          {:ok, issued()}
          | {:error, :invalid_client_id | :invalid_scope | :invalid_resource | :invalid_dpop_jkt}
          | {:error, :user_code_unavailable}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    length = user_code_length!(opts)
    ttl = ttl_seconds!(opts)
    now = NumericDate.non_negative_now!(opts, default: :system)

    with :ok <- validate_issue_attrs(attrs) do
      device_code = Secret.generate()

      data = %{
        client_id: attrs.client_id,
        scope: Map.get(attrs, :scope, []),
        resource: Map.get(attrs, :resource, []),
        dpop_jkt: Map.get(attrs, :dpop_jkt)
      }

      put_with_retry(
        store,
        device_code,
        data,
        length,
        now + ttl,
        @user_code_collision_retries
      )
    end
  end

  defp put_with_retry(_store, _device_code, _data, _length, _expires_at, 0), do: {:error, :user_code_unavailable}

  defp put_with_retry(store, device_code, data, length, expires_at, attempts_left) do
    user_code = generate_user_code(length)

    record = %{
      device_code_hash: Secret.hash(device_code),
      # Stored normalized (no separators); the display form is returned to the
      # client to show the user.
      user_code: normalize!(user_code, length),
      data: data,
      status: :pending,
      subject: nil,
      expires_at: expires_at,
      last_polled_at: nil
    }

    case store.put(record) do
      :ok -> {:ok, %{device_code: device_code, user_code: user_code}}
      {:error, :user_code_taken} -> put_with_retry(store, device_code, data, length, expires_at, attempts_left - 1)
      _unexpected -> device_store_contract_error(:put)
    end
  end

  @doc """
  Redeem a device code at the token endpoint, running the RFC 8628 §3.5 polling
  state machine.

  `params` carries the polling client's `:client_id` (matched against the
  issue-time binding) and any `:dpop_jkt` (RFC 9449 holder-of-key, matched
  against a pre-bound key). Options: `:now` and `:interval` (the minimum poll
  interval in seconds, default #{@default_interval_seconds}).

  Returns `{:ok, %Attesto.DeviceCode.Grant{}}` once the user has approved and the
  code is single-use consumed, or `{:error, reason}` where `reason` is the exact
  RFC 8628 §3.5 code the token endpoint renders verbatim:

    * `:authorization_pending` - the user has not yet approved.
    * `:slow_down` - the device polled faster than `:interval`.
    * `:expired_token` - the code's TTL elapsed (this wins over a stale approval).
    * `:access_denied` - the user denied the request.
    * `:invalid_grant` - unknown/garbage device code, client mismatch, DPoP
      mismatch, or an already-consumed code.
  """
  @spec redeem(module(), String.t(), map(), keyword()) :: {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, device_code, params, opts \\ [])
      when is_atom(store) and is_binary(device_code) and is_map(params) and is_list(opts) do
    interval = interval_seconds!(opts)
    now = NumericDate.non_negative_now!(opts, default: :system)
    hash = Secret.hash(device_code)

    with {:ok, record} <- read_record(store, hash),
         :ok <- check_not_expired(record, now),
         :ok <- check_client(record, params),
         :ok <- check_dpop(record, params) do
      resolve_status(store, hash, record, params, %{now: now, interval: interval})
    end
  end

  defp read_record(store, hash) do
    case store.get(hash) do
      {:ok, record} ->
        if valid_record?(record, hash), do: {:ok, record}, else: device_store_contract_error(:get)

      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        device_store_contract_error(:get)
    end
  end

  defp resolve_status(store, hash, %{status: :pending} = record, params, poll_opts) do
    store.poll(hash, poll_opts)
    |> handle_poll_result(store, hash, record, params, poll_opts)
  end

  defp resolve_status(store, hash, %{status: :approved} = record, _params, poll_opts),
    do: consume(store, hash, record, poll_opts.now)

  defp resolve_status(_store, _hash, %{status: :denied}, _params, _poll_opts), do: {:error, :access_denied}
  defp resolve_status(_store, _hash, %{status: :consumed}, _params, _poll_opts), do: {:error, :invalid_grant}

  defp handle_poll_result({:ok, record}, store, hash, trusted_record, params, poll_opts) do
    if valid_poll_transition?(trusted_record, record, hash, poll_opts.now) do
      with :ok <- check_not_expired(record, poll_opts.now),
           :ok <- check_client(record, params),
           :ok <- check_dpop(record, params) do
        resolve_polled_status(store, hash, record, poll_opts.now)
      end
    else
      device_store_contract_error(:poll)
    end
  end

  defp handle_poll_result({:error, :slow_down}, _store, _hash, _trusted, _params, _poll_opts), do: {:error, :slow_down}

  defp handle_poll_result(:error, _store, _hash, _trusted, _params, _poll_opts), do: {:error, :invalid_grant}

  defp handle_poll_result(_unexpected, _store, _hash, _trusted, _params, _poll_opts),
    do: device_store_contract_error(:poll)

  defp resolve_polled_status(_store, _hash, %{status: :pending}, _now), do: {:error, :authorization_pending}
  defp resolve_polled_status(store, hash, %{status: :approved} = record, now), do: consume(store, hash, record, now)
  defp resolve_polled_status(_store, _hash, %{status: :denied}, _now), do: {:error, :access_denied}
  defp resolve_polled_status(_store, _hash, %{status: :consumed}, _now), do: {:error, :invalid_grant}

  defp consume(store, hash, trusted_record, now) do
    case store.consume(hash, %{now: now}) do
      {:ok, consumed_record} ->
        if valid_consume_transition?(trusted_record, consumed_record, hash) do
          {:ok, Grant.from_record(consumed_record)}
        else
          device_store_contract_error(:consume)
        end

      # Lost the consume race (a concurrent poll consumed it), or the status
      # moved out from under us between poll and consume.
      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        device_store_contract_error(:consume)
    end
  end

  @doc """
  Approve a pending device code from the verification page (RFC 8628 §3.3),
  binding the resolved resource owner.

  `approval` carries `:subject` (required), the granted `:scope`, and a
  lossless, string-keyed I-JSON `:claims` object. Persisted claim numbers are
  exact-range integers, not floats. Atomic `pending` → `approved`. Returns `:ok`, or `{:error, reason}`
  (`:not_found` / `:already_decided` / `:expired` / `:invalid_user_code` /
  `:invalid_subject` / `:invalid_scope` / `:invalid_claims`). A granted scope
  must be a subset of the scope bound to the device code.
  """
  @spec approve(module(), String.t(), map(), keyword()) ::
          :ok
          | {:error,
             :not_found
             | :already_decided
             | :expired
             | :invalid_user_code
             | :invalid_subject
             | :invalid_scope
             | :invalid_claims}
  def approve(store, user_code, approval, opts \\ [])
      when is_atom(store) and is_binary(user_code) and is_map(approval) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)

    with {:ok, normalized} <- normalize_user_code(user_code, opts),
         :ok <- require_subject(approval),
         {:ok, fields} <- normalize_approval(approval),
         {:ok, trusted_record} <- read_user_record(store, normalized),
         :ok <- decision_available?(trusted_record, now),
         :ok <- require_scope_subset(trusted_record, fields.granted_scope) do
      store.approve(normalized, fields, %{now: now})
      |> validate_approve_result(trusted_record, fields, normalized)
    end
  end

  @doc """
  Deny a pending device code from the verification page (RFC 8628 §3.3): atomic
  `pending` → `denied`, so the device's next poll receives `access_denied`.
  """
  @spec deny(module(), String.t(), keyword()) ::
          :ok | {:error, :not_found | :already_decided | :expired | :invalid_user_code}
  def deny(store, user_code, opts \\ []) when is_atom(store) and is_binary(user_code) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts, default: :system)

    with {:ok, normalized} <- normalize_user_code(user_code, opts),
         {:ok, trusted_record} <- read_user_record(store, normalized),
         :ok <- decision_available?(trusted_record, now) do
      store.deny(normalized, %{now: now})
      |> validate_deny_result(trusted_record, normalized)
    end
  end

  @doc """
  Non-consuming lookup of a pending device code by `user_code`, for the
  verification page to show the user what they are approving. Returns
  `{:error, :invalid_user_code}` for malformed input (before any store call) and
  `:error` for an unknown code.
  """
  @spec lookup(module(), String.t(), keyword()) ::
          {:ok, Attesto.DeviceCodeStore.pending_view()} | :error | {:error, :invalid_user_code}
  def lookup(store, user_code, opts \\ []) when is_atom(store) and is_binary(user_code) and is_list(opts) do
    with {:ok, normalized} <- normalize_user_code(user_code, opts) do
      lookup_normalized(store, normalized)
    end
  end

  defp lookup_normalized(store, normalized) do
    case store.lookup_user_code(normalized) do
      {:ok, record} ->
        if valid_user_record?(record, normalized),
          do: {:ok, pending_view(record)},
          else: device_store_contract_error(:lookup_user_code)

      :error ->
        :error

      _unexpected ->
        device_store_contract_error(:lookup_user_code)
    end
  end

  @doc """
  Normalize and charset-validate a user-entered `user_code`: upper-case, strip
  separators (hyphens/whitespace), and reject anything outside the base-20
  alphabet or the expected length. Fail-closed — returns
  `{:error, :invalid_user_code}` rather than letting attacker-shaped input reach
  a store lookup.
  """
  @spec normalize_user_code(String.t(), keyword()) :: {:ok, String.t()} | {:error, :invalid_user_code}
  def normalize_user_code(user_code, opts \\ []) when is_binary(user_code) do
    length = user_code_length!(opts)

    normalized =
      user_code
      |> String.upcase()
      |> String.replace(~r/[\s-]/, "")

    cond do
      String.length(normalized) != length -> {:error, :invalid_user_code}
      not all_in_alphabet?(normalized) -> {:error, :invalid_user_code}
      true -> {:ok, normalized}
    end
  end

  @doc """
  Generate a fresh display-formatted user code (`BCDF-GHJK`).

  Each character is drawn from the base-20 alphabet using
  `:crypto.strong_rand_bytes/1` (a CSPRNG) with rejection sampling to keep the
  draw uniform — the `user_code` is an online authorization handle, so it must
  not come from the VM's non-cryptographic PRNG.
  """
  @spec generate_user_code(pos_integer()) :: String.t()
  def generate_user_code(length \\ @default_user_code_length)

  def generate_user_code(length)
      when is_integer(length) and length >= @minimum_user_code_length and length <= @maximum_user_code_length do
    code = for _ <- 1..length, into: "", do: <<random_alphabet_char()>>

    # Hyphenate into groups of 4 for readability (purely a display affordance;
    # the separator is stripped on input).
    code
    |> String.graphemes()
    |> Enum.chunk_every(4)
    |> Enum.map_join("-", &Enum.join/1)
  end

  def generate_user_code(_invalid) do
    raise ArgumentError,
          "user-code length must be an integer in #{@minimum_user_code_length}..#{@maximum_user_code_length}"
  end

  # ----- internal -----

  defp validate_issue_attrs(attrs) do
    cond do
      not (is_binary(Map.get(attrs, :client_id)) and Map.get(attrs, :client_id) != "") ->
        {:error, :invalid_client_id}

      not valid_scope_list?(Map.get(attrs, :scope, [])) ->
        {:error, :invalid_scope}

      not valid_resource_list?(Map.get(attrs, :resource, [])) ->
        {:error, :invalid_resource}

      not valid_optional_jkt?(Map.get(attrs, :dpop_jkt)) ->
        {:error, :invalid_dpop_jkt}

      true ->
        :ok
    end
  end

  defp ttl_seconds!(opts) do
    case Keyword.get(opts, :ttl, @default_ttl_seconds) do
      ttl when is_integer(ttl) and ttl > 0 -> ttl
      _invalid -> raise ArgumentError, ":ttl must be a positive integer"
    end
  end

  defp interval_seconds!(opts) do
    case Keyword.get(opts, :interval, @default_interval_seconds) do
      interval when is_integer(interval) and interval >= 0 -> interval
      _invalid -> raise ArgumentError, ":interval must be a non-negative integer"
    end
  end

  defp user_code_length!(opts) do
    case Keyword.get(opts, :user_code_length, @default_user_code_length) do
      length
      when is_integer(length) and length >= @minimum_user_code_length and
             length <= @maximum_user_code_length ->
        length

      _invalid ->
        raise ArgumentError,
              ":user_code_length must be an integer in #{@minimum_user_code_length}..#{@maximum_user_code_length}"
    end
  end

  defp require_subject(%{subject: subject}) when is_binary(subject) and subject != "", do: :ok
  defp require_subject(_approval), do: {:error, :invalid_subject}

  defp normalize_approval(approval) do
    scope = Map.get(approval, :scope, [])
    claims = Map.get(approval, :claims, %{})

    cond do
      not valid_scope_list?(scope) -> {:error, :invalid_scope}
      not Claims.portable_json_object?(claims) -> {:error, :invalid_claims}
      true -> {:ok, %{subject: approval.subject, granted_scope: scope, granted_claims: claims}}
    end
  end

  defp read_user_record(store, user_code) do
    case store.lookup_user_code(user_code) do
      {:ok, record} ->
        if valid_user_record?(record, user_code),
          do: {:ok, record},
          else: device_store_contract_error(:lookup_user_code)

      :error ->
        {:error, :not_found}

      _unexpected ->
        device_store_contract_error(:lookup_user_code)
    end
  end

  defp decision_available?(%{status: :pending, expires_at: expires_at}, now) do
    if expires_at > now, do: :ok, else: {:error, :expired}
  end

  defp decision_available?(_record, _now), do: {:error, :already_decided}

  defp require_scope_subset(%{data: %{scope: requested_scope}}, granted_scope) do
    if MapSet.subset?(MapSet.new(granted_scope), MapSet.new(requested_scope)),
      do: :ok,
      else: {:error, :invalid_scope}
  end

  defp check_not_expired(%{expires_at: expires_at}, now) do
    if expires_at > now, do: :ok, else: {:error, :expired_token}
  end

  # RFC 8628 §3.4: the polling client must be the one the code was issued to.
  defp check_client(%{data: %{client_id: bound}}, %{client_id: presented}) do
    if is_binary(bound) and bound == presented, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_client(_record, _params), do: {:error, :invalid_grant}

  # RFC 9449 §10 holder-of-key: a code pre-bound to a DPoP key may be redeemed
  # only with a matching proof. An unbound code accepts any (or no) presented
  # key, which the caller may use to mint a DPoP-bound token.
  defp check_dpop(%{data: %{dpop_jkt: bound}}, params) when is_binary(bound) and bound != "" do
    if Map.get(params, :dpop_jkt) == bound, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_dpop(_record, _params), do: :ok

  defp normalize!(user_code, length) do
    {:ok, normalized} = normalize_user_code(user_code, user_code_length: length)
    normalized
  end

  defp all_in_alphabet?(normalized) do
    String.to_charlist(normalized) |> Enum.all?(&(&1 in @user_code_alphabet))
  end

  @alphabet_size length(@user_code_alphabet)
  # Rejection sampling: the largest multiple of the alphabet size that fits in a
  # byte (240 for a 20-char alphabet); bytes at or above it are discarded so the
  # modulo is unbiased.
  @rejection_ceiling div(256, @alphabet_size) * @alphabet_size

  defp random_alphabet_char do
    case :crypto.strong_rand_bytes(1) do
      <<b>> when b < @rejection_ceiling -> Enum.at(@user_code_alphabet, rem(b, @alphabet_size))
      _ -> random_alphabet_char()
    end
  end

  defp valid_record?(
         %{
           device_code_hash: record_hash,
           user_code: user_code,
           data: %{client_id: client_id, scope: scope, resource: resource, dpop_jkt: dpop_jkt} = data,
           status: status,
           expires_at: expires_at
         } = record,
         expected_hash
       ) do
    valid_device_identity?(record_hash, expected_hash, user_code) and
      valid_device_data?(data, client_id, scope, resource, dpop_jkt) and
      valid_device_state?(status, expires_at) and valid_device_optional_fields?(record) and
      valid_decision_fields?(record)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_device_identity?(record_hash, expected_hash, user_code),
    do:
      record_hash == expected_hash and is_binary(record_hash) and record_hash != "" and
        valid_stored_user_code?(user_code)

  defp valid_stored_user_code?(user_code) do
    is_binary(user_code) and String.length(user_code) in @minimum_user_code_length..@maximum_user_code_length and
      all_in_alphabet?(user_code)
  end

  defp valid_device_data?(data, client_id, scope, resource, dpop_jkt) do
    exact_canonical_data_keys?(data) and is_binary(client_id) and client_id != "" and valid_scope_list?(scope) and
      valid_resource_list?(resource) and valid_optional_jkt?(dpop_jkt)
  end

  # The issue-time device context is canonical. Host-specific values do not
  # belong beside these protocol fields, so extra keys make a persisted record
  # malformed rather than being silently ignored.
  defp exact_canonical_data_keys?(data),
    do: map_size(data) == length(@canonical_data_keys) and Enum.all?(@canonical_data_keys, &Map.has_key?(data, &1))

  defp valid_device_state?(status, expires_at), do: status in @statuses and is_integer(expires_at) and expires_at >= 0

  defp valid_device_optional_fields?(record) do
    valid_optional_field?(record, :subject, &valid_optional_binary?/1) and
      valid_optional_field?(record, :granted_scope, &valid_optional_string_list?/1) and
      valid_optional_field?(record, :granted_claims, &valid_optional_json_object?/1) and
      valid_optional_field?(record, :last_polled_at, &valid_optional_non_negative_integer?/1)
  end

  defp valid_decision_fields?(%{status: status} = record) when status in [:approved, :consumed] do
    case record do
      %{subject: subject, granted_scope: granted_scope, granted_claims: granted_claims} ->
        is_binary(subject) and subject != "" and valid_scope_list?(granted_scope) and
          MapSet.subset?(MapSet.new(granted_scope), MapSet.new(record.data.scope)) and
          Claims.portable_json_object?(granted_claims)

      _missing_decision_fields ->
        false
    end
  end

  defp valid_decision_fields?(_record), do: true

  defp valid_consume_transition?(trusted_record, consumed_record, hash) do
    consumed_record.status == :consumed and valid_record?(consumed_record, hash) and
      Enum.all?(@consume_bound_fields, fn field ->
        Map.get(consumed_record, field) == Map.get(trusted_record, field)
      end)
  end

  defp valid_poll_transition?(trusted_record, polled_record, hash, now) do
    valid_record?(polled_record, hash) and Map.get(polled_record, :last_polled_at) == now and
      Enum.all?(@poll_bound_fields, fn field ->
        Map.get(polled_record, field) == Map.get(trusted_record, field)
      end)
  end

  defp valid_approve_transition?(trusted_record, approved_record, fields, user_code) do
    trusted_record.status == :pending and approved_record.status == :approved and
      valid_user_record?(approved_record, user_code) and
      Enum.all?(@poll_bound_fields, fn field ->
        Map.get(approved_record, field) == Map.get(trusted_record, field)
      end) and
      Enum.all?([:subject, :granted_scope, :granted_claims], fn field ->
        Map.get(approved_record, field) == Map.get(fields, field)
      end)
  end

  defp valid_deny_transition?(trusted_record, denied_record, user_code) do
    trusted_record.status == :pending and denied_record.status == :denied and
      valid_user_record?(denied_record, user_code) and
      Enum.all?(@poll_bound_fields, fn field ->
        Map.get(denied_record, field) == Map.get(trusted_record, field)
      end)
  end

  defp valid_user_record?(record, expected_user_code) when is_map(record) do
    case Map.get(record, :device_code_hash) do
      hash when is_binary(hash) and hash != "" ->
        valid_record?(record, hash) and Map.get(record, :user_code) == expected_user_code

      _invalid ->
        false
    end
  end

  defp valid_user_record?(_record, _expected_user_code), do: false

  defp pending_view(record) do
    %{
      user_code: record.user_code,
      client_id: record.data.client_id,
      scope: record.data.scope,
      resource: record.data.resource,
      status: record.status,
      expires_at: record.expires_at
    }
  end

  defp validate_approve_result({:ok, record}, trusted_record, fields, user_code) do
    if valid_approve_transition?(trusted_record, record, fields, user_code),
      do: :ok,
      else: device_store_contract_error(:approve)
  end

  defp validate_approve_result({:error, reason} = error, _trusted, _fields, _user_code) when reason in @decision_errors,
    do: error

  defp validate_approve_result(_unexpected, _trusted, _fields, _user_code), do: device_store_contract_error(:approve)

  defp validate_deny_result({:ok, record}, trusted_record, user_code) do
    if valid_deny_transition?(trusted_record, record, user_code),
      do: :ok,
      else: device_store_contract_error(:deny)
  end

  defp validate_deny_result({:error, reason} = error, _trusted, _user_code) when reason in @decision_errors, do: error

  defp validate_deny_result(_unexpected, _trusted, _user_code), do: device_store_contract_error(:deny)

  defp valid_optional_field?(record, field, validator) do
    case Map.fetch(record, field) do
      {:ok, value} -> validator.(value)
      :error -> true
    end
  end

  defp valid_scope_list?(value), do: Scope.valid_list?(value)

  defp valid_resource_list?(value), do: is_list(value) and Enum.all?(value, &(is_binary(&1) and &1 != ""))

  defp valid_optional_string_list?(nil), do: true
  defp valid_optional_string_list?(value), do: valid_scope_list?(value)
  defp valid_optional_binary?(nil), do: true
  defp valid_optional_binary?(value), do: is_binary(value)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(value), do: Thumbprint.valid?(value)
  defp valid_optional_json_object?(nil), do: true
  defp valid_optional_json_object?(value), do: Claims.portable_json_object?(value)
  defp valid_optional_non_negative_integer?(nil), do: true
  defp valid_optional_non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp device_store_contract_error(:put) do
    raise RuntimeError, "device code store put/1 violated its contract"
  end

  defp device_store_contract_error(:lookup_user_code) do
    raise RuntimeError, "device code store lookup_user_code/1 violated its contract"
  end

  defp device_store_contract_error(:get) do
    raise RuntimeError, "device code store get/1 violated its contract"
  end

  defp device_store_contract_error(:approve) do
    raise RuntimeError, "device code store approve/3 violated its contract"
  end

  defp device_store_contract_error(:deny) do
    raise RuntimeError, "device code store deny/2 violated its contract"
  end

  defp device_store_contract_error(:poll) do
    raise RuntimeError, "device code store poll/2 violated its contract"
  end

  defp device_store_contract_error(:consume) do
    raise RuntimeError, "device code store consume/2 violated its contract"
  end
end
