defmodule Attesto.X509 do
  @moduledoc """
  Bounded X.509 certificate path validation and SD-JWT VC issuer binding.

  `verify/2` accepts a leaf-first DER certificate chain and explicit DER trust
  anchors in `:trusted_certificates`. It validates the complete path with OTP's
  PKIX implementation, then applies an optional `:certificate_trust` callback
  for additional host policy. The callback cannot replace path validation.
  Returns the verified leaf public JWK and authority key identifiers from the
  validated chain. Hosts still own ecosystem policy and revocation checking.

  `:purpose` defaults to `:generic`. The `:mdoc_issuer` purpose recognizes a
  critical mdoc document-signer extended key usage on the leaf certificate.
  It does not accept that extension on a CA or bypass any path-validation error.

  PSS-specific SubjectPublicKeyInfo keys are rejected throughout the selected
  path, including its trust anchor, until complete PSS parameter propagation
  is supported. `rsaEncryption` parameters must be NULL; absent parameters are
  accepted for interoperability. Other parameter values fail closed.

  `:haip` defaults to `false`. With `true`, a self-signed leaf or any supplied
  trust anchor in the chain is refused. Both the chain and anchor list contain
  1..8 certificates, each at most 65,536 DER bytes. No certificates, revocation
  information, or issuer metadata are fetched. OTP uses the system clock for
  certificate validity; credential `:now` options do not change that clock.

  ## SD-JWT VC issuer binding

  `matches_issuer?/2` checks an already validated leaf against an HTTPS `iss`.
  URI SAN entries take precedence: if any exist, one must equal the complete
  issuer string. Only when none exist may a dNSName SAN equal its host, ignoring
  ASCII case. No wildcard, common-name, IP-address, IDNA, percent-decoding, or
  trailing-dot equivalence is applied. A matching URI wins even if a DNS SAN
  differs; a conflicting URI cannot be rescued by a matching DNS SAN.

  This precedence is an explicit conservative policy, not a rule established
  by the specifications below:

    * [SD-JWT VC draft -08 §3.5](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.5)
      says "iss value matches a uniformResourceIdentifier SAN entry" and also
      permits matching the issuer's domain against a dNSName SAN. It specifies
      no precedence between the alternatives.
    * [SD-JWT VC draft -13 §3.5](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html#section-3.5)
      requires the leaf key from `x5c` and "validates the X.509 certificate chain
      accordingly". It identifies the issuer by the certificate subject and
      does not retain the earlier SAN matching rule.
    * [HAIP 1.0 §6.1.1](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#section-6.1.1)
      states "The X.509 certificate of the trust anchor MUST NOT be included"
      in the SD-JWT VC `x5c` header. It also prohibits a self-signed signing
      certificate. HAIP §9.4 references SD-JWT VC draft -13.
    * [SD-JWT VC draft -26 §2.5](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-26.html#section-2.5)
      states "An iss claim, if present, is not authenticated by this mechanism".
      It permits recipients to require a binding according to their policy.

  Selecting `:trusted_certificates` in `Attesto.SdJwtVc.verify/3` opts into
  path validation and this issuer binding policy. It requires `iss` even in
  certificate identity mode. That opt-in path defaults to `haip: true`; this
  module's standalone `verify/2` retains `haip: false`. Host authorization and
  revocation remain the caller's responsibility.
  """

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:certificate, :Certificate, @records[:Certificate])
  Record.defrecordp(:tbs_certificate, :TBSCertificate, @records[:TBSCertificate])
  Record.defrecordp(:extension, :Extension, @records[:Extension])

  Record.defrecordp(
    :subject_public_key_info,
    :SubjectPublicKeyInfo,
    @records[:SubjectPublicKeyInfo]
  )

  Record.defrecordp(:algorithm_identifier, :AlgorithmIdentifier, @records[:AlgorithmIdentifier])

  Record.defrecordp(
    :authority_key_identifier,
    :AuthorityKeyIdentifier,
    @records[:AuthorityKeyIdentifier]
  )

  @max_cert_bytes 65_536
  @max_chain_length 8
  @extended_key_usage_oid {2, 5, 29, 37}
  @key_usage_oid {2, 5, 29, 15}
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @mdoc_document_signer_oid {1, 0, 18_013, 5, 1, 2}

  @type verified :: %{public_key: map(), authority_key_identifiers: [String.t()]}
  @type verify_error :: :untrusted_certificate | :invalid_certificate
  @type option ::
          {:trusted_certificates, [binary()]}
          | {:certificate_trust, ([binary()] -> :ok | {:error, term()})}
          | {:purpose, :generic | :mdoc_issuer}
          | {:haip, boolean()}

  @doc """
  Validate a leaf-first DER chain against explicit DER trust anchors.

  Options are `:trusted_certificates` (required), `:certificate_trust` (an
  optional function receiving the DER chain and returning `:ok` to allow it),
  `:purpose` (`:generic` or `:mdoc_issuer`), and `:haip` (default `false`).
  Path validation and signing-key checks precede the callback. A rejection is
  `:untrusted_certificate`; malformed inputs or raised/thrown failures may
  return `:invalid_certificate`. No unverified key is returned.
  """
  @spec verify([binary()], [option()]) :: {:ok, verified()} | {:error, verify_error()}
  def verify(chain, opts) when is_list(chain) and is_list(opts) do
    with true <- valid_chain?(chain),
         anchors when is_list(anchors) and anchors != [] <-
           Keyword.get(opts, :trusted_certificates),
         true <- valid_chain?(anchors),
         :ok <- profile_chain(chain, anchors, opts),
         true <- Enum.any?(anchors, &valid_path?(&1, chain, opts)),
         {:ok, key} <- leaf_public_key(hd(chain)),
         :ok <- host_policy(chain, Keyword.get(opts, :certificate_trust)) do
      {:ok, %{public_key: key, authority_key_identifiers: authority_key_identifiers(chain)}}
    else
      _ -> {:error, :untrusted_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  catch
    _, _ -> {:error, :invalid_certificate}
  end

  def verify(_chain, _opts), do: {:error, :invalid_certificate}

  @doc """
  Decode a leaf-first JOSE `x5c` list using standard base64 (not base64url).

  Enforces the chain and certificate size bounds; does not establish trust.
  """
  @spec decode_x5c(term()) :: {:ok, [binary()]} | {:error, :invalid_certificate}
  def decode_x5c(chain) when is_list(chain) and length(chain) in 1..@max_chain_length do
    Enum.reduce_while(chain, {:ok, []}, fn encoded, {:ok, acc} ->
      case decode_certificate(encoded) do
        {:ok, der} -> {:cont, {:ok, [der | acc]}}
        _ -> {:halt, {:error, :invalid_certificate}}
      end
    end)
    |> reverse_chain()
  end

  def decode_x5c(_chain), do: {:error, :invalid_certificate}

  @doc """
  Match a validated leaf DER certificate to an HTTPS issuer identifier.

  Returns `false` for a mismatch, absent names, or malformed input. This
  function only checks names: first validate the chain with `verify/2`.
  See the module documentation for URI precedence and specification versions.
  """
  @spec matches_issuer?(binary(), String.t()) :: boolean()
  def matches_issuer?(leaf, issuer)
      when is_binary(leaf) and byte_size(leaf) in 1..@max_cert_bytes and is_binary(issuer) do
    if Attesto.URI.https_identifier?(issuer) do
      names = subject_alternative_names(leaf)
      uris = for {:uniformResourceIdentifier, value} <- names, do: List.to_string(value)

      case uris do
        [] -> dns_name_matches?(names, URI.parse(issuer).host)
        _ -> issuer in uris
      end
    else
      false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  def matches_issuer?(_leaf, _issuer), do: false

  defp subject_alternative_names(leaf) do
    tbs = leaf |> :public_key.pkix_decode_cert(:plain) |> certificate(:tbsCertificate)

    case tbs_certificate(tbs, :extensions) do
      extensions when is_list(extensions) -> Enum.flat_map(extensions, &alternative_names/1)
      _ -> []
    end
  end

  defp alternative_names(extension(extnID: {2, 5, 29, 17}, extnValue: encoded)),
    do: :public_key.der_decode(:SubjectAltName, encoded)

  defp alternative_names(_extension), do: []

  defp dns_name_matches?(names, host) do
    # A dNSName is not an iPAddress SAN and does not authorize an IP literal.
    case :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, _address} -> false
      {:error, _} -> Enum.any?(names, &dns_name_matches_host?(&1, host))
    end
  end

  defp dns_name_matches_host?({:dNSName, name}, host) do
    name = List.to_string(name)
    not String.contains?(name, "*") and String.downcase(name, :ascii) == String.downcase(host, :ascii)
  end

  defp dns_name_matches_host?(_name, _host), do: false

  defp reverse_chain({:ok, chain}), do: {:ok, Enum.reverse(chain)}
  defp reverse_chain(error), do: error

  defp decode_certificate(encoded) when is_binary(encoded) and byte_size(encoded) <= 87_384 do
    with {:ok, der} <- Base.decode64(encoded),
         true <- byte_size(der) in 1..@max_cert_bytes,
         do: {:ok, der},
         else: (_ -> {:error, :invalid_certificate})
  end

  defp decode_certificate(_encoded), do: {:error, :invalid_certificate}

  defp valid_chain?(chain),
    do:
      length(chain) in 1..@max_chain_length and
        Enum.all?(chain, &(is_binary(&1) and byte_size(&1) in 1..@max_cert_bytes))

  defp valid_path?(anchor, chain, opts) do
    path = if List.last(chain) == anchor, do: Enum.drop(chain, -1), else: chain
    # An anchor alone still needs to be a valid, currently usable leaf certificate.
    path = if path == [], do: [anchor], else: path
    pkix_opts = pkix_options(hd(chain), Keyword.get(opts, :purpose, :generic))

    Enum.all?(Enum.uniq([anchor | chain]), &certificate_key_algorithm_allowed?/1) and
      match?({:ok, _}, :public_key.pkix_path_validation(anchor, Enum.reverse(path), pkix_opts))
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp pkix_options(leaf, :mdoc_issuer), do: [verify_fun: {&verify_mdoc_extension/4, leaf}]

  defp pkix_options(_leaf, :generic), do: []

  defp verify_mdoc_extension(_cert, _der, {:bad_cert, reason}, _leaf), do: {:fail, reason}

  defp verify_mdoc_extension(
         _cert,
         der,
         {:extension, extension(extnID: @extended_key_usage_oid, critical: true, extnValue: purposes)},
         leaf
       )
       when der == leaf and is_list(purposes) do
    if @mdoc_document_signer_oid in purposes, do: {:valid, leaf}, else: {:unknown, leaf}
  end

  defp verify_mdoc_extension(_cert, _der, {:extension, _extension}, leaf), do: {:unknown, leaf}

  defp verify_mdoc_extension(_cert, _der, valid, leaf) when valid in [:valid, :valid_peer], do: {:valid, leaf}

  defp profile_chain(chain, anchors, opts) do
    if Keyword.get(opts, :haip, false) and
         (:public_key.pkix_is_self_signed(hd(chain)) or Enum.any?(chain, &(&1 in anchors))),
       do: {:error, :invalid_certificate},
       else: :ok
  end

  defp host_policy(_chain, nil), do: :ok

  defp host_policy(chain, callback) when is_function(callback, 1) do
    case callback.(chain) do
      :ok -> :ok
      _ -> {:error, :untrusted_certificate}
    end
  end

  defp host_policy(_chain, _callback), do: {:error, :untrusted_certificate}

  defp leaf_public_key(der) do
    cert = :public_key.pkix_decode_cert(der, :plain)
    tbs = certificate(cert, :tbsCertificate)
    spki = tbs_certificate(tbs, :subjectPublicKeyInfo)

    with true <- signing_usage_allowed?(tbs),
         true <- signing_key_algorithm_allowed?(spki) do
      der = :public_key.der_encode(:SubjectPublicKeyInfo, spki)

      key =
        {:SubjectPublicKeyInfo, der, :not_encrypted}
        |> :public_key.pem_entry_decode()
        |> JOSE.JWK.from_key()

      {_type, public} = JOSE.JWK.to_public_map(key)
      {:ok, public}
    else
      false -> {:error, :unsupported_certificate_key}
    end
  end

  # RFC 5280 §4.2.1.3: a present KeyUsage limits the permitted uses even when
  # noncritical. These leaf keys authenticate signatures, not key agreement.
  defp signing_usage_allowed?(tbs) do
    case tbs_certificate(tbs, :extensions) do
      extensions when is_list(extensions) -> Enum.all?(extensions, &signing_usage_extension?/1)
      :asn1_NOVALUE -> true
    end
  end

  defp signing_usage_extension?(extension(extnID: @key_usage_oid, extnValue: encoded)) do
    :digitalSignature in :public_key.der_decode(:KeyUsage, encoded)
  end

  defp signing_usage_extension?(_extension), do: true

  defp certificate_key_algorithm_allowed?(der) do
    # OTP normalizes some rsaEncryption parameter values to NULL on decode.
    # Inspect the original DER before that normalization loses information.
    decoded_spki =
      der
      |> :public_key.pkix_decode_cert(:plain)
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:subjectPublicKeyInfo)

    decoded_algorithm =
      decoded_spki |> subject_public_key_info(:algorithm) |> algorithm_identifier(:algorithm)

    with {0x30, cert, ""} <- der_value(der),
         {0x30, tbs, _signature} <- der_value(cert),
         {0x30, spki, _extensions} <-
           tbs |> without_version() |> skip_der_fields(5) |> der_value(),
         {0x30, algorithm, _key} <- der_value(spki),
         {0x06, oid, parameters} <- der_value(algorithm) do
      case decoded_algorithm do
        @rsa_pss_oid ->
          false

        @rsa_encryption_oid ->
          oid == <<42, 134, 72, 134, 247, 13, 1, 1, 1>> and parameters in ["", <<5, 0>>]

        _ ->
          true
      end
    else
      _ -> false
    end
  end

  defp without_version(<<0xA0, _rest::binary>> = encoded) do
    {_tag, _version, rest} = der_value(encoded)
    rest
  end

  defp without_version(encoded), do: encoded
  defp skip_der_fields(encoded, 0), do: encoded

  defp skip_der_fields(encoded, count) do
    {_tag, _value, rest} = der_value(encoded)
    skip_der_fields(rest, count - 1)
  end

  defp der_value(<<tag, length, rest::binary>>) when length < 128 do
    <<value::binary-size(^length), tail::binary>> = rest
    {tag, value, tail}
  end

  defp der_value(<<tag, length, rest::binary>>) when length in 129..131 do
    count = length - 128
    <<length_bytes::binary-size(^count), rest::binary>> = rest
    <<first, _::binary>> = length_bytes
    size = :binary.decode_unsigned(length_bytes)
    true = first != 0 and size >= 128
    <<value::binary-size(^size), tail::binary>> = rest
    {tag, value, tail}
  end

  # OTP may accept a v1.5 child under a PSS-only CA with absent parameters.
  # Check the selected path ourselves before generic PKIX/JWK conversion.
  defp signing_key_algorithm_allowed?(spki) do
    algorithm = subject_public_key_info(spki, :algorithm)

    case algorithm_identifier(algorithm, :algorithm) do
      @rsa_pss_oid ->
        false

      @rsa_encryption_oid ->
        algorithm_identifier(algorithm, :parameters) in [:NULL, <<5, 0>>, :asn1_NOVALUE]

      _ ->
        true
    end
  end

  defp authority_key_identifiers(chain) do
    chain |> Enum.flat_map(&certificate_identifiers/1) |> Enum.uniq()
  end

  defp certificate_identifiers(der) do
    cert = :public_key.pkix_decode_cert(der, :plain)
    tbs = certificate(cert, :tbsCertificate)

    case tbs_certificate(tbs, :extensions) do
      extensions when is_list(extensions) -> Enum.flat_map(extensions, &extension_identifier/1)
      _ -> []
    end
  end

  defp extension_identifier(ext) do
    case extension(ext, :extnID) do
      {2, 5, 29, 35} ->
        value = :public_key.der_decode(:AuthorityKeyIdentifier, extension(ext, :extnValue))
        encode_identifier(authority_key_identifier(value, :keyIdentifier))

      _ ->
        []
    end
  end

  defp encode_identifier(value) when is_binary(value), do: [Base.url_encode64(value, padding: false)]

  defp encode_identifier(_value), do: []
end
