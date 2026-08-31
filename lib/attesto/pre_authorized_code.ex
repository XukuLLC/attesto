defmodule Attesto.PreAuthorizedCode do
  @moduledoc """
  OID4VCI pre-authorized code issuance and redemption.

  This module is pure logic over an `Attesto.PreAuthorizedCodeStore`.
  `issue/3` binds the credential issuance context to a short-lived,
  single-use code. `redeem/4` atomically consumes the code before checking
  expiry or the optional transaction-code PIN and returns the grant context a
  token endpoint uses to mint a credential access token.

  The plaintext code is returned only from `issue/3`; the store receives its
  hash. When a transaction code is bound, only its hash is stored as well.
  """

  alias Attesto.{NumericDate, Scope, Secret, SecureCompare}

  @default_ttl_seconds 300

  @type issue_attrs :: %{
          required(:subject) => String.t(),
          required(:credential_configuration_ids) => [String.t(), ...],
          required(:authorized_scopes) => [String.t()],
          optional(:tx_code) => String.t() | nil
        }

  @type grant :: %{
          subject: String.t(),
          credential_configuration_ids: [String.t(), ...],
          authorized_scopes: [String.t()]
        }

  @doc """
  Mint a short-lived, single-use pre-authorized code and persist it via `store`.

  `attrs` must carry a non-empty `:subject`, a non-empty list of non-empty
  `:credential_configuration_ids`, and an `:authorized_scopes` list. An
  optional non-empty `:tx_code` is stored only as `:tx_code_hash`.

  Options include `:ttl` (seconds, default `#{@default_ttl_seconds}`) and
  `:now` (clock override). Returns `{:error, :invalid_attrs}` for malformed
  issuance attributes.
  """
  @spec issue(module(), issue_attrs(), keyword()) :: {:ok, String.t()} | {:error, :invalid_attrs}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    ttl = ttl_seconds!(opts)
    now = numeric_date!(opts)

    with {:ok, data} <- normalize_attrs(attrs) do
      code = Secret.generate()

      case store.put(%{
             code_hash: Secret.hash(code),
             data: data,
             expires_at: now + ttl
           }) do
        :ok -> {:ok, code}
        _unexpected -> store_contract_error(:put)
      end
    end
  end

  @doc """
  Atomically consume and redeem a pre-authorized code.

  The code is taken from the store before expiry or transaction-code
  validation. A failed PIN check therefore burns the code. Returns a plain
  grant-context map or an error atom.
  """
  @spec redeem(module(), String.t(), map(), keyword()) :: {:ok, grant()} | {:error, atom()}
  def redeem(store, code, params, opts \\ [])
      when is_atom(store) and is_binary(code) and is_map(params) and is_list(opts) do
    now = numeric_date!(opts)
    code_hash = Secret.hash(code)

    case store.take(code_hash) do
      {:ok, record} ->
        if valid_record?(record, code_hash) do
          redeem_taken(record.data, record.expires_at, params, now)
        else
          store_contract_error(:take)
        end

      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        store_contract_error(:take)
    end
  end

  defp redeem_taken(data, expires_at, params, now) do
    with :ok <- check_expiry(expires_at, now),
         :ok <- check_tx_code(data, params) do
      {:ok, Map.take(data, [:subject, :credential_configuration_ids, :authorized_scopes])}
    end
  end

  defp check_expiry(expires_at, now) do
    if expires_at > now, do: :ok, else: {:error, :expired}
  end

  defp check_tx_code(data, params) do
    case Map.fetch(data, :tx_code_hash) do
      {:ok, tx_code_hash} -> check_bound_tx_code(tx_code_hash, params)
      :error -> check_unbound_tx_code(params)
    end
  end

  defp check_bound_tx_code(tx_code_hash, params) when is_binary(tx_code_hash) do
    if Map.has_key?(params, :tx_code) do
      compare_presented_tx_code(Map.get(params, :tx_code), tx_code_hash)
    else
      {:error, :tx_code_required}
    end
  end

  defp check_bound_tx_code(_invalid_hash, _params), do: {:error, :tx_code_mismatch}

  defp compare_presented_tx_code(presented, tx_code_hash) when is_binary(presented) do
    if SecureCompare.equal?(Secret.hash(presented), tx_code_hash),
      do: :ok,
      else: {:error, :tx_code_mismatch}
  end

  defp compare_presented_tx_code(_presented, _tx_code_hash), do: {:error, :tx_code_mismatch}

  defp check_unbound_tx_code(params) do
    if Map.has_key?(params, :tx_code), do: {:error, :tx_code_unexpected}, else: :ok
  end

  defp normalize_attrs(attrs) do
    subject = Map.get(attrs, :subject)
    credential_configuration_ids = Map.get(attrs, :credential_configuration_ids)
    authorized_scopes = Map.get(attrs, :authorized_scopes)
    tx_code = Map.get(attrs, :tx_code)

    if valid_non_empty_string?(subject) and
         valid_non_empty_string_list?(credential_configuration_ids) and
         valid_string_list?(authorized_scopes) and valid_optional_tx_code?(tx_code) do
      data = %{
        subject: subject,
        credential_configuration_ids: credential_configuration_ids,
        authorized_scopes: authorized_scopes
      }

      data = if is_binary(tx_code), do: Map.put(data, :tx_code_hash, Secret.hash(tx_code)), else: data
      {:ok, data}
    else
      {:error, :invalid_attrs}
    end
  end

  defp valid_non_empty_string?(value), do: is_binary(value) and value != ""

  defp valid_non_empty_string_list?(value) do
    is_list(value) and value != [] and Enum.all?(value, &valid_non_empty_string?/1)
  end

  defp valid_string_list?(value), do: Scope.valid_list?(value)

  defp ttl_seconds!(opts) do
    case Keyword.get(opts, :ttl, @default_ttl_seconds) do
      ttl when is_integer(ttl) and ttl > 0 -> ttl
      _invalid -> raise ArgumentError, ":ttl must be a positive integer"
    end
  end

  defp numeric_date!(opts) do
    case NumericDate.now(opts) do
      now when is_integer(now) and now >= 0 -> now
      _invalid -> raise ArgumentError, ":now must be a non-negative NumericDate"
    end
  rescue
    ArgumentError ->
      reraise ArgumentError,
              [message: ":now must be a non-negative NumericDate"],
              __STACKTRACE__
  end

  defp valid_optional_tx_code?(nil), do: true
  defp valid_optional_tx_code?(value), do: valid_non_empty_string?(value)

  defp valid_record?(
         %{
           code_hash: record_hash,
           data:
             %{
               subject: subject,
               credential_configuration_ids: credential_configuration_ids,
               authorized_scopes: authorized_scopes
             } = data,
           expires_at: expires_at
         },
         expected_hash
       ) do
    record_hash == expected_hash and valid_non_empty_string?(subject) and
      valid_non_empty_string_list?(credential_configuration_ids) and
      valid_string_list?(authorized_scopes) and is_integer(expires_at) and
      valid_tx_code_hash?(data)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_tx_code_hash?(data) do
    case Map.fetch(data, :tx_code_hash) do
      {:ok, tx_code_hash} -> is_binary(tx_code_hash) and tx_code_hash != ""
      :error -> true
    end
  end

  defp store_contract_error(:put) do
    raise RuntimeError, "pre-authorized code store put/1 violated its contract"
  end

  defp store_contract_error(:take) do
    raise RuntimeError, "pre-authorized code store take/1 violated its contract"
  end
end
