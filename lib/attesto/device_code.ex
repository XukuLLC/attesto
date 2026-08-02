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

  alias Attesto.DeviceCode.Grant
  alias Attesto.NumericDate
  alias Attesto.Secret

  # RFC 8628 §6.1: a base-20 alphabet with no vowels (no accidental words) and no
  # visually ambiguous characters (0/O, 1/I/L). 20^8 ≈ 2.56e10 ≈ 34.6 bits.
  @user_code_alphabet ~c"BCDFGHJKLMNPQRSTVWXZ"
  @default_user_code_length 8
  @default_ttl_seconds 600
  @default_interval_seconds 5

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
          {:ok, issued()} | {:error, :invalid_client_id | :user_code_unavailable}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    with :ok <- validate_issue_attrs(attrs) do
      length = Keyword.get(opts, :user_code_length, @default_user_code_length)
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)
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
        NumericDate.now(opts, default: :system) + ttl,
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
      user_code: normalize!(user_code),
      data: data,
      status: :pending,
      subject: nil,
      expires_at: expires_at,
      last_polled_at: nil
    }

    case store.put(record) do
      :ok -> {:ok, %{device_code: device_code, user_code: user_code}}
      {:error, :user_code_taken} -> put_with_retry(store, device_code, data, length, expires_at, attempts_left - 1)
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
    hash = Secret.hash(device_code)

    poll_opts = %{
      now: NumericDate.now(opts, default: :system),
      interval: Keyword.get(opts, :interval, @default_interval_seconds)
    }

    case store.poll(hash, poll_opts) do
      {:ok, record} -> redeem_polled(store, hash, record, params, opts)
      {:error, :slow_down} -> {:error, :slow_down}
      :error -> {:error, :invalid_grant}
    end
  end

  # The poll was accepted. Apply the §3.5 precedence: expiry first (a stale
  # approval must not mint), then the binding checks, then the status outcome.
  # ALL validation runs on the polled record BEFORE `consume/2`, so a client- or
  # DPoP-mismatched poll is rejected without burning the single-use code; only an
  # approved, unexpired, correctly-bound code reaches the atomic consume.
  defp redeem_polled(store, hash, record, params, opts) do
    with :ok <- check_not_expired(record, opts),
         :ok <- check_client(record, params),
         :ok <- check_dpop(record, params),
         :ok <- check_status(record) do
      consume(store, hash, opts)
    end
  end

  defp consume(store, hash, opts) do
    case store.consume(hash, %{now: NumericDate.now(opts, default: :system)}) do
      {:ok, record} ->
        {:ok, Grant.from_record(record)}

      # Lost the consume race (a concurrent poll consumed it), or the status
      # moved out from under us between poll and consume.
      :error ->
        {:error, :invalid_grant}
    end
  end

  @doc """
  Approve a pending device code from the verification page (RFC 8628 §3.3),
  binding the resolved resource owner.

  `approval` carries `:subject` (required), and the granted `:scope` /
  `:claims`. Atomic `pending` → `approved`. Returns `:ok`, or `{:error, reason}`
  (`:not_found` / `:already_decided` / `:expired` / `:invalid_user_code` /
  `:invalid_subject`).
  """
  @spec approve(module(), String.t(), map(), keyword()) ::
          :ok | {:error, :not_found | :already_decided | :expired | :invalid_user_code | :invalid_subject}
  def approve(store, user_code, approval, _opts \\ [])
      when is_atom(store) and is_binary(user_code) and is_map(approval) do
    with {:ok, normalized} <- normalize_user_code(user_code),
         :ok <- require_subject(approval) do
      store.approve(normalized, %{
        subject: approval.subject,
        granted_scope: Map.get(approval, :scope, []),
        granted_claims: Map.get(approval, :claims, %{})
      })
    end
  end

  @doc """
  Deny a pending device code from the verification page (RFC 8628 §3.3): atomic
  `pending` → `denied`, so the device's next poll receives `access_denied`.
  """
  @spec deny(module(), String.t(), keyword()) ::
          :ok | {:error, :not_found | :already_decided | :expired | :invalid_user_code}
  def deny(store, user_code, _opts \\ []) when is_atom(store) and is_binary(user_code) do
    with {:ok, normalized} <- normalize_user_code(user_code) do
      store.deny(normalized)
    end
  end

  @doc """
  Non-consuming lookup of a pending device code by `user_code`, for the
  verification page to show the user what they are approving. Returns
  `{:error, :invalid_user_code}` for malformed input (before any store call) and
  `:error` for an unknown code.
  """
  @spec lookup(module(), String.t()) ::
          {:ok, Attesto.DeviceCodeStore.pending_view()} | :error | {:error, :invalid_user_code}
  def lookup(store, user_code) when is_atom(store) and is_binary(user_code) do
    case normalize_user_code(user_code) do
      {:ok, normalized} -> store.lookup_user_code(normalized)
      {:error, :invalid_user_code} = err -> err
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
    length = Keyword.get(opts, :user_code_length, @default_user_code_length)

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
  def generate_user_code(length \\ @default_user_code_length) when is_integer(length) and length > 0 do
    code = for _ <- 1..length, into: "", do: <<random_alphabet_char()>>

    # Hyphenate into groups of 4 for readability (purely a display affordance;
    # the separator is stripped on input).
    code
    |> String.graphemes()
    |> Enum.chunk_every(4)
    |> Enum.map_join("-", &Enum.join/1)
  end

  # ----- internal -----

  defp validate_issue_attrs(%{client_id: client_id}) when is_binary(client_id) and client_id != "", do: :ok
  defp validate_issue_attrs(_attrs), do: {:error, :invalid_client_id}

  defp require_subject(%{subject: subject}) when is_binary(subject) and subject != "", do: :ok
  defp require_subject(_approval), do: {:error, :invalid_subject}

  defp check_not_expired(%{expires_at: expires_at}, opts) do
    if expires_at > NumericDate.now(opts, default: :system), do: :ok, else: {:error, :expired_token}
  end

  # RFC 8628 §3.4: the polling client must be the one the code was issued to.
  defp check_client(%{data: %{client_id: bound}}, %{client_id: presented}) do
    if is_binary(bound) and bound == presented, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_client(_record, _params), do: {:error, :invalid_grant}

  defp check_status(%{status: :approved}), do: :ok
  defp check_status(%{status: :pending}), do: {:error, :authorization_pending}
  defp check_status(%{status: :denied}), do: {:error, :access_denied}
  # consumed (or anything else) → already used.
  defp check_status(_record), do: {:error, :invalid_grant}

  # RFC 9449 §10 holder-of-key: a code pre-bound to a DPoP key may be redeemed
  # only with a matching proof. An unbound code accepts any (or no) presented
  # key, which the caller may use to mint a DPoP-bound token.
  defp check_dpop(%{data: %{dpop_jkt: bound}}, params) when is_binary(bound) and bound != "" do
    if Map.get(params, :dpop_jkt) == bound, do: :ok, else: {:error, :invalid_grant}
  end

  defp check_dpop(_record, _params), do: :ok

  defp normalize!(user_code) do
    {:ok, normalized} = normalize_user_code(user_code)
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
end
