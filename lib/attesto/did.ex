defmodule Attesto.Did do
  @moduledoc """
  Connection-free resolution for self-contained DID methods.

  `did:jwk` identifiers contain an unpadded base64url-encoded public JWK.
  `did:key` identifiers contain a multibase/multicodec public key; this
  module supports base58btc (`z`) with Ed25519 (`0xed`) and compressed P-256
  (`0x1200`) keys.

  `did:web` is deliberately parser-only. Without a `:resolver`, resolution
  returns `{:needs_fetch, url}` so the host retains ownership of HTTP, TLS,
  caching, and DID-document key selection. A resolver may instead be supplied
  as `resolver: fn url -> {:ok, public_jwk} | {:error, reason} end`.

  > #### `did:web` fetch URL is ATTACKER-CONTROLLED {: .warning}
  >
  > The `{:needs_fetch, url}` / `:resolver` URL is derived entirely from the
  > presented DID text — a presenter controls it. `did:web:localhost` or
  > `did:web:internal-service.corp` yield `https://localhost/.well-known/did.json`
  > and the like (syntactically valid hostnames the IP-literal guard cannot
  > catch). A host fetching that URL without an allow-list has an SSRF sink. Do
  > NOT dereference it blindly: resolve only against a trusted-domain allow-list,
  > and use a DNS-rebinding-safe fetcher that pins the validated IP (see
  > `AttestoPhoenix.ClientIdMetadata.Fetcher.Req` for the reference pattern). Unlike
  > `did:key`/`did:jwk`, `did:web` keys are NOT self-certifying.
  """

  import Bitwise

  alias Attesto.JWS
  alias Attesto.SigningAlg

  @base58_alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @base58_indexes @base58_alphabet
                  |> :binary.bin_to_list()
                  |> Enum.with_index()
                  |> Map.new()
  @max_base58_length 64

  @ed25519_codec 0xED
  @p256_codec 0x1200
  @private_jwk_members ~w(d p q dp dq qi oth k)

  @p256_p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @p256_b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @p256_sqrt_exponent div(@p256_p + 1, 4)
  @coordinate_bytes 32

  @domain_label ~r/\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z/
  @web_path_segment ~r/\A(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2}|[!$&'()*+,;=@])+\z/

  @type jwk :: %{required(String.t()) => term()}
  @type result :: {:ok, jwk()} | {:needs_fetch, String.t()} | {:error, term()}

  @doc """
  Resolve a `did:jwk` or `did:key` to a public JWK, or parse a `did:web`
  identifier into its HTTPS resolution URL.

  This function never performs network I/O. If `:resolver` is supplied for a
  `did:web`, it is called with the parsed HTTPS URL and must return either a
  public JWK map or an error tuple.
  """
  @spec resolve(term(), term()) :: result()
  def resolve(did, opts \\ [])

  def resolve(did, opts) when is_binary(did) and is_list(opts) do
    if Keyword.keyword?(opts) and valid_resolver_option?(Keyword.get(opts, :resolver)) do
      do_resolve(did, opts)
    else
      {:error, :invalid_options}
    end
  end

  def resolve(did, _opts) when is_binary(did), do: {:error, :invalid_options}
  def resolve(_did, _opts), do: {:error, :invalid_did}

  defp valid_resolver_option?(nil), do: true
  defp valid_resolver_option?(resolver), do: is_function(resolver, 1)

  defp do_resolve("did:jwk:" <> encoded, _opts), do: resolve_jwk(encoded)
  defp do_resolve("did:key:" <> multibase, _opts), do: resolve_key(multibase)
  defp do_resolve("did:web:" <> identifier, opts), do: resolve_web(identifier, opts)

  defp do_resolve("did:" <> method_and_identifier, _opts) do
    if Regex.match?(~r/\A[a-z0-9]+:/, method_and_identifier),
      do: {:error, :unsupported_method},
      else: {:error, :invalid_did}
  end

  defp do_resolve(_did, _opts), do: {:error, :invalid_did}

  defp resolve_jwk(encoded) do
    with {:ok, json} <- decode_base64url(encoded),
         {:ok, jwk} <- decode_jwk(json),
         :ok <- validate_public_jwk(jwk) do
      {:ok, jwk}
    end
  end

  defp decode_base64url(""), do: {:error, :invalid_base64url}

  defp decode_base64url(encoded) do
    case JWS.decode64(encoded) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _reason} -> {:error, :invalid_base64url}
    end
  end

  defp decode_jwk(json) do
    safe(:invalid_jwk, fn ->
      case JSON.decode(json) do
        {:ok, %{} = jwk} -> {:ok, jwk}
        _other -> {:error, :invalid_jwk}
      end
    end)
  end

  defp validate_public_jwk(jwk) do
    cond do
      Enum.any?(@private_jwk_members, &Map.has_key?(jwk, &1)) ->
        {:error, :private_jwk}

      # A `did:jwk` payload is fully presenter-controlled and resolved without
      # authentication. Reject an oversized RSA modulus/exponent on the raw map
      # BEFORE `JOSE.JWK.from_map/1` bignum-decodes it, mirroring the gate every
      # other untrusted-JWK path uses (Key.verification_jwk, JWS.map_candidate!,
      # SD-JWT KB). Without it a ~256 KB modulus pins a scheduler for seconds.
      not SigningAlg.rsa_params_ok?(jwk) ->
        {:error, :invalid_jwk}

      true ->
        parse_public_jwk(jwk)
    end
  end

  defp parse_public_jwk(jwk) do
    safe(:invalid_jwk, fn ->
      jwk
      |> JOSE.JWK.from_map()
      |> JOSE.JWK.to_public_map()
      |> case do
        {_metadata, %{} = _public_jwk} -> :ok
        _other -> {:error, :invalid_jwk}
      end
    end)
  end

  defp resolve_key(multibase) do
    with {:ok, encoded_key} <- decode_multibase(multibase),
         {:ok, codec, public_key} <- decode_multicodec(encoded_key),
         {:ok, jwk} <- multicodec_to_jwk(codec, public_key),
         :ok <- validate_public_jwk(jwk) do
      {:ok, jwk}
    else
      {:error, :invalid_jwk} -> {:error, :invalid_public_key}
      {:error, _reason} = error -> error
    end
  end

  defp decode_multibase("z" <> encoded) when encoded != "", do: decode_base58(encoded)
  defp decode_multibase("z"), do: {:error, :invalid_multibase}
  defp decode_multibase(""), do: {:error, :invalid_multibase}
  defp decode_multibase(_encoded), do: {:error, :unsupported_multibase}

  defp decode_base58(encoded) when byte_size(encoded) <= @max_base58_length do
    with {:ok, number} <- decode_base58_integer(encoded, 0) do
      zeroes = count_leading_ones(encoded, 0)
      {:ok, :binary.copy(<<0>>, zeroes) <> unsigned_binary(number)}
    end
  end

  defp decode_base58(_encoded), do: {:error, :invalid_base58}

  defp decode_base58_integer(<<>>, number), do: {:ok, number}

  defp decode_base58_integer(<<character, rest::binary>>, number) do
    case Map.fetch(@base58_indexes, character) do
      {:ok, value} -> decode_base58_integer(rest, number * 58 + value)
      :error -> {:error, :invalid_base58}
    end
  end

  defp count_leading_ones(<<"1", rest::binary>>, count), do: count_leading_ones(rest, count + 1)
  defp count_leading_ones(_rest, count), do: count

  defp unsigned_binary(0), do: <<>>
  defp unsigned_binary(number), do: :binary.encode_unsigned(number)

  defp decode_multicodec(bytes), do: decode_varint(bytes, 0, 0, 0)

  defp decode_varint(<<>>, _value, _shift, _count), do: {:error, :invalid_multicodec}
  defp decode_varint(_bytes, _value, _shift, 9), do: {:error, :invalid_multicodec}

  defp decode_varint(<<byte, rest::binary>>, value, shift, count) do
    chunk = band(byte, 0x7F)
    decoded = bor(value, bsl(chunk, shift))

    if band(byte, 0x80) == 0 do
      if count > 0 and chunk == 0,
        do: {:error, :invalid_multicodec},
        else: {:ok, decoded, rest}
    else
      decode_varint(rest, decoded, shift + 7, count + 1)
    end
  end

  defp multicodec_to_jwk(@ed25519_codec, public_key) when byte_size(public_key) == 32 do
    {:ok,
     %{
       "crv" => "Ed25519",
       "kty" => "OKP",
       "x" => Base.url_encode64(public_key, padding: false)
     }}
  end

  defp multicodec_to_jwk(@ed25519_codec, _public_key), do: {:error, :invalid_public_key_length}

  defp multicodec_to_jwk(@p256_codec, public_key) when byte_size(public_key) == 33 do
    decompress_p256(public_key)
  end

  defp multicodec_to_jwk(@p256_codec, _public_key), do: {:error, :invalid_public_key_length}
  defp multicodec_to_jwk(_codec, _public_key), do: {:error, :unsupported_codec}

  defp decompress_p256(<<prefix, x_bytes::binary-size(@coordinate_bytes)>>) when prefix in [2, 3] do
    x = :binary.decode_unsigned(x_bytes)

    if x < @p256_p do
      p256_jwk(prefix, x, x_bytes)
    else
      {:error, :invalid_public_key}
    end
  end

  defp decompress_p256(_public_key), do: {:error, :invalid_public_key}

  defp p256_jwk(prefix, x, x_bytes) do
    square = Integer.mod(x * x * x - 3 * x + @p256_b, @p256_p)

    y =
      square
      |> :crypto.mod_pow(@p256_sqrt_exponent, @p256_p)
      |> :binary.decode_unsigned()

    if Integer.mod(y * y, @p256_p) == square do
      selected_y = if band(y, 1) == band(prefix, 1), do: y, else: @p256_p - y

      {:ok,
       %{
         "crv" => "P-256",
         "kty" => "EC",
         "x" => Base.url_encode64(x_bytes, padding: false),
         "y" => Base.url_encode64(pad_coordinate(selected_y), padding: false)
       }}
    else
      {:error, :invalid_public_key}
    end
  end

  defp pad_coordinate(integer) do
    bytes = :binary.encode_unsigned(integer)
    :binary.copy(<<0>>, @coordinate_bytes - byte_size(bytes)) <> bytes
  end

  defp resolve_web(identifier, opts) do
    with {:ok, url} <- web_url(identifier) do
      case Keyword.get(opts, :resolver) do
        nil -> {:needs_fetch, url}
        resolver -> invoke_resolver(resolver, url)
      end
    end
  end

  defp web_url(identifier) do
    case String.split(identifier, ":", trim: false) do
      [authority | path] when authority != "" -> build_web_url(authority, path)
      _other -> {:error, :invalid_web_did}
    end
  end

  defp build_web_url(authority, path) do
    with {:ok, decoded_authority} <- decode_web_authority(authority),
         true <- valid_web_path?(path) do
      suffix = if path == [], do: ".well-known/did.json", else: Enum.join(path, "/") <> "/did.json"
      {:ok, "https://" <> decoded_authority <> "/" <> suffix}
    else
      _other -> {:error, :invalid_web_did}
    end
  end

  defp decode_web_authority(authority) do
    case Regex.split(~r/%3A/i, authority) do
      [host] ->
        if valid_domain?(host), do: {:ok, host}, else: {:error, :invalid_web_did}

      [host, port] ->
        if valid_domain?(host) and valid_port?(port),
          do: {:ok, host <> ":" <> port},
          else: {:error, :invalid_web_did}

      _other ->
        {:error, :invalid_web_did}
    end
  end

  defp valid_domain?(host) do
    byte_size(host) <= 253 and not ip_address?(host) and
      host
      |> String.split(".", trim: false)
      |> Enum.all?(&Regex.match?(@domain_label, &1))
  end

  defp ip_address?(host) do
    match?({:ok, _address}, :inet.parse_address(String.to_charlist(host)))
  end

  defp valid_port?(port) do
    byte_size(port) in 1..5 and Regex.match?(~r/\A[0-9]+\z/, port) and
      String.to_integer(port) in 1..65_535
  end

  defp valid_web_path?(segments) do
    Enum.all?(segments, fn segment ->
      segment not in ["", ".", ".."] and Regex.match?(@web_path_segment, segment)
    end)
  end

  defp invoke_resolver(resolver, url) do
    safe(:resolver_failed, fn -> resolver.(url) |> normalize_resolver_response() end)
  end

  defp normalize_resolver_response({:ok, %{} = jwk}) do
    case validate_public_jwk(jwk) do
      :ok -> {:ok, jwk}
      {:error, _reason} = error -> error
    end
  end

  defp normalize_resolver_response({:error, _reason} = error), do: error
  defp normalize_resolver_response(_other), do: {:error, :invalid_resolver_response}

  defp safe(error, fun) do
    fun.()
  rescue
    _error -> {:error, error}
  catch
    _kind, _reason -> {:error, error}
  end
end
