defmodule Attesto.CredentialEncryption do
  @moduledoc """
  OpenID4VCI 1.0 Credential Request and Credential Response encryption (§8.2, §9, §10, §12.2.4).

  Pure, conn-free helpers built over `Attesto.JWE` for:

    * building `credential_request_encryption` and `credential_response_encryption`
      metadata blocks from an issuer `Attesto.Keystore`,
    * normalizing and validating `credential_response_encryption` request objects
      and Deferred Credential Request payloads,
    * decrypting compact `application/jwt` encrypted credential and deferred
      credential requests using keys from the configured keystore, and
    * encrypting Credential Response objects as `application/jwt` compact JWEs.
  """

  alias Attesto.{JWE, JWS, Key, MapParams, SigningAlg, StrictJSON}

  @supported_algs ["ECDH-ES"]
  @supported_encs ["A256GCM", "A128GCM"]
  @private_members ~w(d p q dp dq qi oth k)
  @allowed_ctys ["json", "application/json"]
  @max_compact_bytes 2_000_000
  @max_plaintext_bytes 2_000_000
  @max_kid_bytes 256

  @type encryption_error :: :invalid_encryption_parameters | :invalid_credential_request

  @doc "JWE key management algorithms supported for OID4VCI credential encryption."
  @spec supported_algs() :: [String.t()]
  def supported_algs, do: @supported_algs

  @doc "JWE content encryption algorithms supported for OID4VCI credential encryption."
  @spec supported_encs() :: [String.t()]
  def supported_encs, do: @supported_encs

  @doc """
  Build the `credential_request_encryption` metadata map (OID4VCI §12.2.4) from
  an `Attesto.Keystore` module providing EC P-256 keys.

  Every published public JWK carries `"alg" => "ECDH-ES"`, `"use" => "enc"`,
  and a distinct RFC 7638 `"kid"`. Raises `ArgumentError` if any keystore PEM
  cannot be decoded as a private EC P-256 key.
  """
  @spec request_metadata(module(), keyword()) :: %{required(String.t()) => term()}
  def request_metadata(keystore, opts \\ []) when is_atom(keystore) and is_list(opts) do
    encryption_required = Keyword.get(opts, :encryption_required, false)

    if not is_boolean(encryption_required) do
      raise ArgumentError, ":encryption_required must be a boolean; got #{inspect(encryption_required)}"
    end

    public_keys =
      keystore
      |> load_keystore_entries!()
      |> Enum.map(fn {_kid, _private_jwk, public_jwk} -> public_jwk end)

    %{
      "jwks" => %{"keys" => public_keys},
      "enc_values_supported" => @supported_encs,
      "encryption_required" => encryption_required
    }
  end

  @doc """
  Build the `credential_response_encryption` metadata map (OID4VCI §12.2.4).
  """
  @spec response_metadata(keyword()) :: %{required(String.t()) => term()}
  def response_metadata(opts \\ []) when is_list(opts) do
    encryption_required = Keyword.get(opts, :encryption_required, false)

    if not is_boolean(encryption_required) do
      raise ArgumentError, ":encryption_required must be a boolean; got #{inspect(encryption_required)}"
    end

    %{
      "alg_values_supported" => @supported_algs,
      "enc_values_supported" => @supported_encs,
      "zip_values_supported" => ["DEF"],
      "encryption_required" => encryption_required
    }
  end

  @doc """
  Normalize an optional `credential_response_encryption` object from an OID4VCI
  Credential Request or Deferred Credential Request (§8.2, §9.1, §10).

  Requires `jwk` (a map containing a non-empty string `alg`) and a non-empty
  string `enc`; accepts an optional non-empty string `zip` when present so the
  caller can reject unsupported compression parameters with
  `invalid_encryption_parameters`. Rejects top-level `alg` values that omit or
  contradict `jwk["alg"]`.
  """
  @spec parse_response_encryption(map()) ::
          {:ok, map() | nil} | {:error, :invalid_credential_response_encryption}
  def parse_response_encryption(request) when is_map(request) do
    if key_present?(request, :credential_response_encryption) do
      normalize_response_encryption(MapParams.fetch(request, :credential_response_encryption))
    else
      {:ok, nil}
    end
  end

  @doc """
  Parse an OID4VCI Deferred Credential Request (§9.1) containing `transaction_id`
  and optional `credential_response_encryption`.
  """
  @spec parse_deferred_request(map()) ::
          {:ok, %{required(:transaction_id) => String.t(), required(:response_encryption) => map() | nil}}
          | {:error, :missing_transaction_id | :invalid_credential_response_encryption}
  def parse_deferred_request(request) when is_map(request) do
    with {:ok, transaction_id} <- parse_transaction_id(request),
         {:ok, response_encryption} <- parse_response_encryption(request) do
      {:ok, %{transaction_id: transaction_id, response_encryption: response_encryption}}
    end
  end

  @doc """
  Validate that normalized `credential_response_encryption` parameters are
  cryptographically supported (ECDH-ES P-256 public JWK on the curve,
  A128GCM or A256GCM content encryption, optional outbound-only `zip: "DEF"`).
  """
  @spec validate_response_encryption(term()) :: :ok | {:error, :invalid_encryption_parameters}
  def validate_response_encryption(%{"jwk" => %{} = jwk, "enc" => enc} = params) do
    with true <- Map.fetch(params, "zip") in [:error, {:ok, "DEF"}],
         true <- enc in @supported_encs,
         true <- valid_recipient_jwk?(jwk) do
      :ok
    else
      _ -> {:error, :invalid_encryption_parameters}
    end
  end

  def validate_response_encryption(_params), do: {:error, :invalid_encryption_parameters}

  @doc """
  Validate whether `jwk` is a usable public ECDH-ES P-256 recipient key.
  """
  @spec valid_recipient_jwk?(term()) :: boolean()
  def valid_recipient_jwk?(%{"kty" => "EC", "crv" => "P-256", "alg" => "ECDH-ES", "x" => x, "y" => y} = key) do
    Attesto.Key.single_jwk_map?(key) and
      not Enum.any?(@private_members, &Map.has_key?(key, &1)) and
      valid_optional_kid?(key) and
      ecdh_usage?(key) and
      coordinate?(x) and
      coordinate?(y) and
      on_curve?(key)
  end

  def valid_recipient_jwk?(_key), do: false

  @doc """
  Decrypt an `application/jwt` compact JWE Credential Request or Deferred
  Credential Request using a key from `keystore`, enforce protected-header and
  size bounds, and strictly decode the JSON request object.
  """
  @spec decrypt_request(binary(), module(), keyword()) ::
          {:ok, map()} | {:error, encryption_error()}
  def decrypt_request(compact, keystore, opts \\ [])

  def decrypt_request(compact, keystore, opts) when is_binary(compact) and is_atom(keystore) and is_list(opts) do
    entries = load_keystore_entries!(keystore)
    decrypt_with_entries(compact, entries, opts)
  end

  def decrypt_request(_compact, _keystore, _opts), do: {:error, :invalid_encryption_parameters}

  @doc """
  Encrypt an OID4VCI Credential Response map as a compact `application/jwt` JWE
  to the wallet's validated `response_encryption` parameters.
  """
  @spec encrypt_response(map(), map(), keyword()) ::
          {:ok, binary()} | {:error, :invalid_encryption_parameters}
  def encrypt_response(response_map, response_encryption, opts \\ [])

  def encrypt_response(response_map, %{"jwk" => jwk, "enc" => enc} = response_encryption, opts)
      when is_map(response_map) and is_list(opts) do
    max_compact = Keyword.get(opts, :max_compact_bytes, @max_compact_bytes)
    max_plaintext = Keyword.get(opts, :max_plaintext_bytes, @max_plaintext_bytes)

    with :ok <- validate_response_encryption(response_encryption),
         header = response_header(jwk, enc),
         {:ok, compact} <-
           encrypt_response_bytes(jwk, JSON.encode!(response_map), header, Map.get(response_encryption, "zip"),
             accepted_algs: @supported_algs,
             accepted_encs: @supported_encs,
             max_compact_bytes: max_compact,
             max_plaintext_bytes: max_plaintext
           ) do
      {:ok, compact}
    else
      {:error, _reason} -> {:error, :invalid_encryption_parameters}
    end
  end

  def encrypt_response(_response_map, _response_encryption, _opts), do: {:error, :invalid_encryption_parameters}

  defp encrypt_response_bytes(jwk, plaintext, header, "DEF", opts),
    do: JWE.encrypt_deflated(jwk, plaintext, header, opts)

  defp encrypt_response_bytes(jwk, plaintext, header, nil, opts), do: JWE.encrypt(jwk, plaintext, header, opts)

  defp parse_transaction_id(request) do
    case MapParams.fetch(request, :transaction_id) do
      id when is_binary(id) and id != "" -> {:ok, id}
      _other -> {:error, :missing_transaction_id}
    end
  end

  defp normalize_response_encryption(value) when is_map(value) and not is_struct(value) do
    jwk = MapParams.fetch(value, :jwk)
    enc = MapParams.fetch(value, :enc)
    top_alg_present? = key_present?(value, :alg)
    top_alg = MapParams.fetch(value, :alg)
    zip_present? = key_present?(value, :zip)
    zip = MapParams.fetch(value, :zip)

    with true <- is_map(jwk) and not is_struct(jwk),
         jwk_map = MapParams.string_keyed_map(jwk),
         jwk_alg when is_binary(jwk_alg) and jwk_alg != "" <- Map.get(jwk_map, "alg"),
         true <- not top_alg_present? or top_alg == jwk_alg,
         true <- non_empty_string?(enc),
         {:ok, normalized_zip} <- normalize_zip(zip_present?, zip) do
      base = %{"jwk" => jwk_map, "enc" => enc}
      {:ok, if(is_binary(normalized_zip), do: Map.put(base, "zip", normalized_zip), else: base)}
    else
      _ -> {:error, :invalid_credential_response_encryption}
    end
  end

  defp normalize_response_encryption(_value), do: {:error, :invalid_credential_response_encryption}

  defp normalize_zip(false, _zip), do: {:ok, nil}
  defp normalize_zip(true, zip) when is_binary(zip) and zip != "", do: {:ok, zip}
  defp normalize_zip(true, _zip), do: :error

  defp key_present?(map, key), do: Map.has_key?(map, key) or Map.has_key?(map, Atom.to_string(key))
  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp decrypt_with_entries(compact, entries, opts) do
    max_compact = Keyword.get(opts, :max_compact_bytes, @max_compact_bytes)
    max_plaintext = Keyword.get(opts, :max_plaintext_bytes, @max_plaintext_bytes)

    with {:ok, header} <- JWE.peek_protected_header(compact),
         :ok <- validate_request_header(header),
         {:ok, private_jwk} <- select_entry_by_kid(entries, header["kid"]),
         {:ok, plaintext, _verified_header} <-
           JWE.decrypt(private_jwk, compact,
             accepted_algs: @supported_algs,
             accepted_encs: @supported_encs,
             max_compact_bytes: max_compact,
             max_plaintext_bytes: max_plaintext
           ) do
      decode_request_json(plaintext)
    else
      {:error, _reason} -> {:error, :invalid_encryption_parameters}
    end
  end

  defp validate_request_header(%{"alg" => "ECDH-ES", "enc" => enc, "kid" => kid} = header)
       when is_binary(kid) and kid != "" do
    if enc in @supported_encs and valid_cty?(Map.fetch(header, "cty")),
      do: :ok,
      else: {:error, :invalid_encryption_parameters}
  end

  defp validate_request_header(_header), do: {:error, :invalid_encryption_parameters}

  defp valid_cty?(:error), do: true

  defp valid_cty?({:ok, cty}) when is_binary(cty), do: String.downcase(cty) in @allowed_ctys

  defp valid_cty?(_other), do: false

  defp decode_request_json(plaintext) do
    case StrictJSON.decode(plaintext) do
      {:ok, %{} = map} -> {:ok, map}
      _other -> {:error, :invalid_credential_request}
    end
  end

  defp select_entry_by_kid(entries, kid) do
    case Enum.find(entries, fn {entry_kid, _private_jwk, _public_jwk} -> entry_kid == kid end) do
      {^kid, private_jwk, _public_jwk} -> {:ok, private_jwk}
      nil -> {:error, :invalid_encryption_parameters}
    end
  end

  defp load_keystore_entries!(keystore) do
    pems =
      [keystore.signing_pem() | verification_pems(keystore)]
      |> Enum.uniq()

    entries =
      Enum.reduce(pems, %{}, fn pem, acc ->
        {kid, private_jwk, public_jwk} = pem_to_entry!(pem, keystore)
        Map.put_new(acc, kid, {kid, private_jwk, public_jwk})
      end)

    if map_size(entries) == 0 do
      raise ArgumentError, "Attesto.CredentialEncryption keystore #{inspect(keystore)} has no usable P-256 keys"
    end

    Map.values(entries)
  end

  defp verification_pems(keystore) do
    if function_exported?(keystore, :verification_pems, 0) do
      keystore.verification_pems()
    else
      []
    end
  end

  defp pem_to_entry!(pem, keystore) when is_binary(pem) and pem != "" do
    jwk = Key.signing_jwk(pem)

    if SigningAlg.infer(jwk) != "ES256" do
      raise ArgumentError,
            "Attesto.CredentialEncryption keystore #{inspect(keystore)} requires EC P-256 keys"
    end

    kid = Key.kid(pem)
    {_kty, public_map} = JOSE.JWK.to_public_map(jwk)
    public_jwk = Map.merge(public_map, %{"kid" => kid, "alg" => "ECDH-ES", "use" => "enc"})
    {kid, jwk, public_jwk}
  end

  defp pem_to_entry!(_pem, keystore) do
    raise ArgumentError,
          "Attesto.CredentialEncryption keystore #{inspect(keystore)} returned an invalid PEM"
  end

  defp response_header(%{"kid" => kid}, enc) when is_binary(kid) and kid != "" do
    %{"alg" => "ECDH-ES", "enc" => enc, "cty" => "json", "kid" => kid}
  end

  defp response_header(_jwk, enc) do
    %{"alg" => "ECDH-ES", "enc" => enc, "cty" => "json"}
  end

  defp valid_optional_kid?(key) do
    case Map.fetch(key, "kid") do
      :error -> true
      {:ok, kid} -> is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes
    end
  end

  @doc false
  @spec ecdh_usage?(term()) :: boolean()
  def ecdh_usage?(key) when is_map(key) and not is_struct(key) do
    Map.fetch(key, "use") in [:error, {:ok, "enc"}] and key_ops?(Map.fetch(key, "key_ops"))
  end

  def ecdh_usage?(_key), do: false

  defp key_ops?(:error), do: true

  defp key_ops?({:ok, ops}) when is_list(ops) and ops != [], do: Enum.all?(ops, &(&1 in ["deriveKey", "deriveBits"]))

  defp key_ops?(_ops), do: false

  defp coordinate?(encoded) when is_binary(encoded) and byte_size(encoded) == 43,
    do: match?({:ok, <<_::binary-size(32)>>}, JWS.decode64(encoded))

  defp coordinate?(_encoded), do: false

  defp on_curve?(key) do
    {_type, pem} = key |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()
    [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

    {{:ECPoint, point}, {:namedCurve, _oid}} =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, der, :not_encrypted})

    :crypto.compute_key(:ecdh, point, <<1::256>>, :secp256r1)
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
