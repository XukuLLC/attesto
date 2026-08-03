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

  alias Attesto.NumericDate
  alias Attesto.Secret
  alias Attesto.SecureCompare

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
    with {:ok, data} <- normalize_attrs(attrs) do
      code = Secret.generate()
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

      :ok =
        store.put(%{
          code_hash: Secret.hash(code),
          data: data,
          expires_at: NumericDate.now(opts) + ttl
        })

      {:ok, code}
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
    case store.take(Secret.hash(code)) do
      {:ok, %{data: data, expires_at: expires_at}} ->
        redeem_taken(data, expires_at, params, opts)

      :error ->
        {:error, :invalid_grant}
    end
  end

  defp redeem_taken(data, expires_at, params, opts) do
    with :ok <- check_expiry(expires_at, opts),
         :ok <- check_tx_code(data, params) do
      {:ok, Map.take(data, [:subject, :credential_configuration_ids, :authorized_scopes])}
    end
  end

  defp check_expiry(expires_at, opts) do
    if expires_at > NumericDate.now(opts), do: :ok, else: {:error, :expired}
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

  defp valid_string_list?(value), do: is_list(value) and Enum.all?(value, &is_binary/1)

  defp valid_optional_tx_code?(nil), do: true
  defp valid_optional_tx_code?(value), do: valid_non_empty_string?(value)
end
