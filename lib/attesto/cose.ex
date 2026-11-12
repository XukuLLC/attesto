if Code.ensure_loaded?(CBOR) do
  defmodule Attesto.Cose do
    @moduledoc """
    Minimal COSE helpers for ISO 18013-5 issuer authentication.

    Issuer `COSE_Sign1` verification supports ES256/P-256, ES384/P-384 and
    ES512/P-521, with `:accepted_algs` defaulting to `["ES256"]`. Signing,
    detached device verification, and EC2 `COSE_Key` conversion remain
    ES256/P-256 only. This is not general-purpose COSE.

    [RFC 9053 §2.1, Table 1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1)
    maps COSE -7/-35/-36 to SHA-256/384/512 and suggests, for example,
    "SHA-384 be used only with curve P-384". Attesto enforces all three
    recommended pairings strictly, returning `:algorithm_key_mismatch`
    before signature verification for a different EC curve. The raw ECDSA
    signature is two fixed-width integers: 32, 48 or 66 bytes each. P-521
    therefore uses a 132-byte signature with SHA-512. See `Attesto.Mdoc`
    for ISO/IEC 18013-5 and HAIP requirements and the unsupported curves.
    """

    alias Attesto.{Key, SigningAlg}

    @alg_es256 -7
    @coordinate_bytes 32
    @algorithms %{
      -7 => %{name: "ES256", curve: "P-256", hash: :sha256, coordinate_bytes: 32},
      -35 => %{name: "ES384", curve: "P-384", hash: :sha384, coordinate_bytes: 48},
      -36 => %{name: "ES512", curve: "P-521", hash: :sha512, coordinate_bytes: 66}
    }

    @type verify_error ::
            :algorithm_key_mismatch
            | :invalid_cose
            | :invalid_key
            | :invalid_signature
            | :unsupported_algorithm
            | :unsupported_critical_header

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
    Verify an ECDSA `COSE_Sign1` against a supplied public JWK or PEM.

    Returns the signed payload byte string without decoding it.
    `:accepted_algs` defaults to `["ES256"]`; supported additional values are
    `"ES384"` and `"ES512"`. A disallowed or unknown algorithm returns
    `:unsupported_algorithm`. A supported algorithm with a different EC curve
    returns `:algorithm_key_mismatch`, regardless of the acceptance policy.
    """
    @spec verify1(binary(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            {:ok, binary()} | {:error, verify_error()}
    def verify1(cose_sign1_bytes, jwk_or_pem, opts) when is_binary(cose_sign1_bytes) and is_list(opts) do
      with {:ok, protected, unprotected, payload, signature} <- decode_sign1(cose_sign1_bytes),
           {:ok, algorithm} <- validate_protected(protected, unprotected),
           {:ok, jwk} <- verification_jwk(jwk_or_pem),
           :ok <- validate_pairing(jwk, algorithm),
           :ok <- accepted_algorithm(algorithm, Keyword.get(opts, :accepted_algs, ["ES256"])),
           :ok <- validate_signature_length(signature, algorithm),
           true <- verify_signature(jwk, protected, payload, signature, algorithm) do
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
      with {:ok, protected, unprotected, signature} <- decode_detached_sign1(cose_sign1_bytes),
           {:ok, algorithm} <- validate_protected(protected, unprotected),
           {:ok, jwk} <- verification_jwk(jwk_or_pem),
           :ok <- validate_pairing(jwk, algorithm),
           :ok <- accepted_algorithm(algorithm, ["ES256"]),
           :ok <- validate_signature_length(signature, algorithm),
           true <- verify_signature(jwk, protected, external_payload, signature, algorithm) do
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
           true <- plain_map?(unprotected),
           {:ok, protected} <- byte_string(protected_value),
           {:ok, signature} <- byte_string(signature_value) do
        {:ok, protected, unprotected, signature}
      else
        _other -> {:error, :invalid_cose}
      end
    end

    defp decode_sign1(encoded) do
      with {:ok, [protected_value, unprotected, payload_value, signature_value]} <- decode_complete(encoded),
           true <- plain_map?(unprotected),
           {:ok, protected} <- byte_string(protected_value),
           {:ok, payload} <- byte_string(payload_value),
           {:ok, signature} <- byte_string(signature_value) do
        {:ok, protected, unprotected, payload, signature}
      else
        _other -> {:error, :invalid_cose}
      end
    end

    defp validate_protected(protected, unprotected) do
      with {:ok, header} <- decode_complete(protected),
           true <- plain_map?(header),
           :ok <- validate_header_locations(header, unprotected),
           {:ok, algorithm} <- validate_algorithm(header),
           :ok <- validate_critical_headers(header) do
        {:ok, algorithm}
      else
        {:error, _reason} = error -> error
        _other -> {:error, :invalid_cose}
      end
    end

    defp validate_header_locations(protected, unprotected) do
      protected_labels = Map.keys(protected)
      unprotected_labels = Map.keys(unprotected)

      if Map.has_key?(unprotected, 2) or
           not MapSet.disjoint?(MapSet.new(protected_labels), MapSet.new(unprotected_labels)) do
        {:error, :invalid_cose}
      else
        :ok
      end
    end

    defp validate_algorithm(%{1 => alg}) when is_map_key(@algorithms, alg), do: {:ok, Map.fetch!(@algorithms, alg)}
    defp validate_algorithm(header) when is_map_key(header, 1), do: {:error, :unsupported_algorithm}
    defp validate_algorithm(_header), do: {:error, :invalid_cose}

    defp accepted_algorithm(algorithm, accepted) when is_list(accepted) do
      if algorithm.name in accepted, do: :ok, else: {:error, :unsupported_algorithm}
    end

    defp accepted_algorithm(_algorithm, _accepted), do: {:error, :unsupported_algorithm}

    defp validate_pairing(jwk, algorithm) do
      case public_jwk_map(jwk) do
        %{"kty" => "EC", "crv" => curve} when curve == algorithm.curve -> :ok
        %{"kty" => "EC"} -> {:error, :algorithm_key_mismatch}
        _other -> {:error, :invalid_key}
      end
    end

    defp validate_signature_length(signature, algorithm) do
      if byte_size(signature) == 2 * algorithm.coordinate_bytes, do: :ok, else: {:error, :invalid_cose}
    end

    defp validate_critical_headers(header) do
      case Map.fetch(header, 2) do
        :error ->
          :ok

        {:ok, [_ | _] = labels} ->
          cond do
            not Enum.all?(labels, &valid_header_label?/1) ->
              {:error, :invalid_cose}

            not Enum.all?(labels, &Map.has_key?(header, &1)) ->
              {:error, :invalid_cose}

            not Enum.all?(labels, &understood_critical_header?/1) ->
              {:error, :unsupported_critical_header}

            true ->
              :ok
          end

        {:ok, _invalid} ->
          {:error, :invalid_cose}
      end
    end

    defp valid_header_label?(label), do: is_integer(label) or is_binary(label)
    defp understood_critical_header?(1), do: true
    defp understood_critical_header?(2), do: true
    defp understood_critical_header?(_label), do: false

    defp verification_jwk(%JOSE.JWK{} = jwk), do: validate_verification_jwk(jwk)

    defp verification_jwk(jwk_map) when is_map(jwk_map) do
      if Attesto.Key.single_jwk_map?(jwk_map) do
        jwk_map
        |> JOSE.JWK.from_map()
        |> validate_verification_jwk()
      else
        {:error, :invalid_key}
      end
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
      case public_jwk_map(jwk) do
        %{"kty" => "EC", "crv" => _curve} -> {:ok, jwk}
        _other -> {:error, :invalid_key}
      end
    rescue
      _error -> {:error, :invalid_key}
    end

    defp validate_verification_jwk(_other), do: {:error, :invalid_key}

    defp verify_signature(jwk, protected, payload, raw_signature, algorithm) do
      :public_key.verify(
        signature_structure(protected, payload),
        algorithm.hash,
        raw_to_der(raw_signature, algorithm.coordinate_bytes),
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

    defp raw_to_der(signature, coordinate_bytes) do
      r = signature |> binary_part(0, coordinate_bytes) |> :binary.decode_unsigned()
      s = signature |> binary_part(coordinate_bytes, coordinate_bytes) |> :binary.decode_unsigned()
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

    # Bound raw CBOR input before decoding: the decoder recurses per nesting byte
    # with no depth limit, so deep-nesting input amplifies into heap ahead of any
    # signature check. Amplification is linear; a 1 MiB ceiling bounds the
    # worst-case footprint. A COSE_Sign1 is well under this.
    @max_cbor_bytes 1_048_576

    defp decode_complete(encoded) when is_binary(encoded) and byte_size(encoded) > @max_cbor_bytes do
      {:error, :invalid_cose}
    end

    # `Attesto.StrictCBOR` refuses a map that repeats a key, at any depth: RFC
    # 9052 §3 says a message in which a header label appears more than once
    # MUST be rejected as malformed.
    defp decode_complete(encoded) do
      case Attesto.StrictCBOR.decode(encoded) do
        {:ok, value} -> {:ok, value}
        {:error, :invalid_cbor} -> {:error, :invalid_cose}
      end
    end

    defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}

    defp byte_string(%CBOR.Tag{tag: :bytes, value: value}) when is_binary(value), do: {:ok, value}
    defp byte_string(_other), do: {:error, :invalid_cose}

    defp plain_map?(value), do: is_map(value) and not is_struct(value)
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
