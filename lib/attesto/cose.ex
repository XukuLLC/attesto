if Code.ensure_loaded?(CBOR) do
  defmodule Attesto.Cose do
    @moduledoc """
    Minimal COSE helpers for ISO 18013-5 issuer authentication.

    This slice supports `COSE_Sign1` with ES256 and EC2 P-256 `COSE_Key`
    conversion. It intentionally does not implement general-purpose COSE.
    """

    alias Attesto.{Key, SigningAlg}

    @alg_es256 -7
    @coordinate_bytes 32
    @ecdsa_signature_bytes 64

    @type verify_error ::
            :invalid_cose | :invalid_key | :invalid_signature | :unsupported_algorithm

    @doc """
    Sign `payload_bstr` as an ES256 `COSE_Sign1` and return its CBOR bytes.

    `:x5chain` may contain issuer-certificate DER binaries. Certificate-chain
    validation is outside this slice; the chain is carried in unprotected
    header label 33 for a verifier that implements that policy.
    """
    @spec sign1(String.t(), binary(), keyword()) :: binary()
    def sign1(pem, payload_bstr, opts) when is_binary(pem) and is_binary(payload_bstr) and is_list(opts) do
      protected = CBOR.encode(%{1 => @alg_es256})
      signing_input = signature_structure(protected, payload_bstr)
      jwk = Key.signing_jwk(pem)

      ensure_es256!(jwk)

      signature =
        signing_input
        |> :public_key.sign(:sha256, private_key(jwk))
        |> der_to_raw()

      [bytes(protected), unprotected_header(opts), bytes(payload_bstr), bytes(signature)]
      |> CBOR.encode()
    end

    @doc """
    Verify an ES256 `COSE_Sign1` against a supplied public JWK or PEM.

    Returns the signed payload byte string without decoding it.
    """
    @spec verify1(binary(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            {:ok, binary()} | {:error, verify_error()}
    def verify1(cose_sign1_bytes, jwk_or_pem, opts) when is_binary(cose_sign1_bytes) and is_list(opts) do
      with {:ok, protected, payload, signature} <- decode_sign1(cose_sign1_bytes),
           :ok <- validate_protected(protected),
           {:ok, jwk} <- verification_jwk(jwk_or_pem),
           true <- verify_signature(jwk, protected, payload, signature) do
        {:ok, payload}
      else
        false -> {:error, :invalid_signature}
        {:error, _reason} = error -> error
      end
    rescue
      _error -> {:error, :invalid_cose}
    catch
      _kind, _reason -> {:error, :invalid_cose}
    end

    @doc """
    Sign `external_payload` as an ES256 `COSE_Sign1` with a detached
    (`null`) payload and return its CBOR bytes.

    ISO 18013-5 `DeviceSignature` transmits its payload as `null`; the
    actual signed content (e.g. `DeviceAuthenticationBytes`) is
    reconstructed by both parties from context instead of being carried
    on the wire.
    """
    @spec sign1_detached(String.t(), binary(), keyword()) :: binary()
    def sign1_detached(pem, external_payload, opts)
        when is_binary(pem) and is_binary(external_payload) and is_list(opts) do
      protected = CBOR.encode(%{1 => @alg_es256})
      signing_input = signature_structure(protected, external_payload)
      jwk = Key.signing_jwk(pem)

      ensure_es256!(jwk)

      signature =
        signing_input
        |> :public_key.sign(:sha256, private_key(jwk))
        |> der_to_raw()

      [bytes(protected), unprotected_header(opts), nil, bytes(signature)]
      |> CBOR.encode()
    end

    @doc """
    Verify an ES256 `COSE_Sign1` with a detached (`null`) payload against
    `external_payload`, supplied out of band by the caller.

    Returns `:ok` on success, since (unlike `verify1/3`) there is no
    embedded payload to hand back.
    """
    @spec verify1_detached(binary(), binary(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            :ok | {:error, verify_error()}
    def verify1_detached(cose_sign1_bytes, external_payload, jwk_or_pem, opts)
        when is_binary(cose_sign1_bytes) and is_binary(external_payload) and is_list(opts) do
      with {:ok, protected, signature} <- decode_detached_sign1(cose_sign1_bytes),
           :ok <- validate_protected(protected),
           {:ok, jwk} <- verification_jwk(jwk_or_pem),
           true <- verify_signature(jwk, protected, external_payload, signature) do
        :ok
      else
        false -> {:error, :invalid_signature}
        {:error, _reason} = error -> error
      end
    rescue
      _error -> {:error, :invalid_cose}
    catch
      _kind, _reason -> {:error, :invalid_cose}
    end

    @doc "Convert an EC P-256 public JWK to an EC2 P-256 `COSE_Key` map."
    @spec key_to_cose(JOSE.JWK.t() | map()) :: map()
    def key_to_cose(public_jwk) do
      %{"crv" => "P-256", "kty" => "EC", "x" => x, "y" => y} = public_jwk_map(public_jwk)

      %{
        1 => 2,
        -1 => 1,
        -2 => bytes(decode_coordinate!(x, "x")),
        -3 => bytes(decode_coordinate!(y, "y"))
      }
    rescue
      error in ArgumentError -> reraise(error, __STACKTRACE__)
      _error -> reraise(ArgumentError, [message: "expected an EC P-256 public JWK"], __STACKTRACE__)
    end

    @doc "Convert an EC2 P-256 `COSE_Key` map to a public JWK map."
    @spec cose_to_key(map()) :: map()
    def cose_to_key(%{1 => 2, -1 => 1, -2 => x_value, -3 => y_value}) do
      x = coordinate_bytes!(x_value, "-2")
      y = coordinate_bytes!(y_value, "-3")

      %{
        "crv" => "P-256",
        "kty" => "EC",
        "x" => Base.url_encode64(x, padding: false),
        "y" => Base.url_encode64(y, padding: false)
      }
    end

    def cose_to_key(_cose_key), do: raise(ArgumentError, "expected an EC2 P-256 COSE_Key")

    defp signature_structure(protected, payload) do
      CBOR.encode(["Signature1", bytes(protected), bytes(""), bytes(payload)])
    end

    defp unprotected_header(opts) do
      case Keyword.get(opts, :x5chain) do
        nil -> %{}
        [] -> %{}
        chain when is_list(chain) -> %{33 => Enum.map(chain, &certificate_bytes!/1)}
        _other -> raise ArgumentError, ":x5chain must be a list of DER binaries"
      end
    end

    defp certificate_bytes!(der) when is_binary(der) and byte_size(der) > 0, do: bytes(der)
    defp certificate_bytes!(_der), do: raise(ArgumentError, ":x5chain must contain non-empty DER binaries")

    defp decode_detached_sign1(encoded) do
      with {:ok, [protected_value, unprotected, nil, signature_value]} <- decode_complete(encoded),
           true <- is_map(unprotected),
           {:ok, protected} <- byte_string(protected_value),
           {:ok, signature} <- byte_string(signature_value),
           true <- byte_size(signature) == @ecdsa_signature_bytes do
        {:ok, protected, signature}
      else
        _other -> {:error, :invalid_cose}
      end
    end

    defp decode_sign1(encoded) do
      with {:ok, [protected_value, unprotected, payload_value, signature_value]} <- decode_complete(encoded),
           true <- is_map(unprotected),
           {:ok, protected} <- byte_string(protected_value),
           {:ok, payload} <- byte_string(payload_value),
           {:ok, signature} <- byte_string(signature_value),
           true <- byte_size(signature) == @ecdsa_signature_bytes do
        {:ok, protected, payload, signature}
      else
        _other -> {:error, :invalid_cose}
      end
    end

    defp validate_protected(protected) do
      case decode_complete(protected) do
        {:ok, %{1 => @alg_es256}} -> :ok
        {:ok, %{} = header} when is_map_key(header, 1) -> {:error, :unsupported_algorithm}
        _other -> {:error, :invalid_cose}
      end
    end

    defp verification_jwk(%JOSE.JWK{} = jwk), do: validate_verification_jwk(jwk)

    defp verification_jwk(jwk_map) when is_map(jwk_map) do
      jwk_map
      |> JOSE.JWK.from_map()
      |> validate_verification_jwk()
    rescue
      _error -> {:error, :invalid_key}
    catch
      _kind, _reason -> {:error, :invalid_key}
    end

    defp verification_jwk(pem) when is_binary(pem) do
      pem
      |> Key.jwk()
      |> validate_verification_jwk()
    rescue
      _error -> {:error, :invalid_key}
    catch
      _kind, _reason -> {:error, :invalid_key}
    end

    defp verification_jwk(_other), do: {:error, :invalid_key}

    defp validate_verification_jwk(%JOSE.JWK{} = jwk) do
      if SigningAlg.infer(jwk) == "ES256", do: {:ok, jwk}, else: {:error, :invalid_key}
    rescue
      _error -> {:error, :invalid_key}
    end

    defp validate_verification_jwk(_other), do: {:error, :invalid_key}

    defp verify_signature(jwk, protected, payload, raw_signature) do
      :public_key.verify(
        signature_structure(protected, payload),
        :sha256,
        raw_to_der(raw_signature),
        public_key(jwk)
      )
    rescue
      _error -> false
    catch
      _kind, _reason -> false
    end

    defp ensure_es256!(jwk) do
      if SigningAlg.infer(jwk) != "ES256" do
        raise ArgumentError, "Attesto.Cose supports ES256 signing keys only"
      end
    end

    defp private_key(jwk), do: jwk |> JOSE.JWK.to_key() |> elem(1)

    defp public_key(jwk) do
      jwk
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_key()
      |> elem(1)
    end

    defp der_to_raw(der_signature) do
      {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_signature)
      <<r::unsigned-big-size(256), s::unsigned-big-size(256)>>
    end

    defp raw_to_der(<<r::unsigned-big-size(256), s::unsigned-big-size(256)>>) do
      :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    end

    defp public_jwk_map(%JOSE.JWK{} = jwk), do: jwk |> JOSE.JWK.to_public_map() |> elem(1)

    defp public_jwk_map(jwk_map) when is_map(jwk_map) do
      jwk_map
      |> JOSE.JWK.from_map()
      |> public_jwk_map()
    end

    defp public_jwk_map(_other), do: raise(ArgumentError, "expected an EC P-256 public JWK")

    defp decode_coordinate!(encoded, name) when is_binary(encoded) do
      case Base.url_decode64(encoded, padding: false) do
        {:ok, coordinate} when byte_size(coordinate) == @coordinate_bytes -> coordinate
        _other -> raise ArgumentError, "JWK #{name} must be a 32-byte base64url coordinate"
      end
    end

    defp coordinate_bytes!(value, label) do
      case byte_string(value) do
        {:ok, coordinate} when byte_size(coordinate) == @coordinate_bytes -> coordinate
        _other -> raise ArgumentError, "COSE_Key #{label} must be a 32-byte byte string"
      end
    end

    defp decode_complete(encoded) do
      case CBOR.decode(encoded) do
        {:ok, value, ""} -> {:ok, value}
        _other -> {:error, :invalid_cose}
      end
    rescue
      _error -> {:error, :invalid_cose}
    catch
      _kind, _reason -> {:error, :invalid_cose}
    end

    defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}

    defp byte_string(%CBOR.Tag{tag: :bytes, value: value}) when is_binary(value), do: {:ok, value}
    defp byte_string(_other), do: {:error, :invalid_cose}
  end
else
  defmodule Attesto.Cose do
    @moduledoc "Requires the optional `:cbor` dependency."

    @dep_error "Attesto.Cose requires the optional :cbor dependency. " <>
                 "Add {:cbor, \"~> 1.0\"} to your deps."

    def sign1(_pem, _payload_bstr, _opts), do: raise(@dep_error)
    def verify1(_cose_sign1_bytes, _jwk_or_pem, _opts), do: raise(@dep_error)
    def sign1_detached(_pem, _external_payload, _opts), do: raise(@dep_error)
    def verify1_detached(_cose_sign1_bytes, _external_payload, _jwk_or_pem, _opts), do: raise(@dep_error)
    def key_to_cose(_public_jwk), do: raise(@dep_error)
    def cose_to_key(_cose_key_map), do: raise(@dep_error)
  end
end
