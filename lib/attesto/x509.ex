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
  @max_trust_anchors 64
  @extended_key_usage_oid {2, 5, 29, 37}
  @key_usage_oid {2, 5, 29, 15}
  @basic_constraints_oid {2, 5, 29, 19}
  @name_constraints_oid {2, 5, 29, 30}
  @subject_alt_name_oid {2, 5, 29, 17}
  @subject_key_id_oid {2, 5, 29, 14}
  @authority_key_id_oid {2, 5, 29, 35}
  @certificate_policies_oid {2, 5, 29, 32}
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @mgf1_oid {1, 2, 840, 113_549, 1, 1, 8}
  @sha256_oid {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @sha384_oid {2, 16, 840, 1, 101, 3, 4, 2, 2}
  @sha512_oid {2, 16, 840, 1, 101, 3, 4, 2, 3}
  @ed25519_oid {1, 3, 101, 112}
  @ed448_oid {1, 3, 101, 113}
  @mdoc_document_signer_oid {1, 0, 18_013, 5, 1, 2}

  @type verified :: %{public_key: map(), authority_key_identifiers: [String.t()]}
  @type verify_error :: :untrusted_certificate | :invalid_certificate
  @type option ::
          {:trusted_certificates, [binary()]}
          | {:certificate_trust, ([binary()] -> :ok | {:error, term()})}
          | {:purpose, :generic | :mdoc_issuer}
          | {:haip, boolean()}

  @doc "Maximum accepted DER certificate size in bytes."
  @spec max_cert_bytes() :: pos_integer()
  def max_cert_bytes, do: @max_cert_bytes

  @doc "Maximum accepted X.509 certificate chain length."
  @spec max_chain_length() :: pos_integer()
  def max_chain_length, do: @max_chain_length

  @doc "Maximum accepted number of trust anchors in a verification call."
  @spec max_trust_anchors() :: pos_integer()
  def max_trust_anchors, do: @max_trust_anchors

  @doc """
  Return `true` when `anchors` is a non-empty bounded list of valid DER certificate binaries.
  """
  @spec valid_trust_anchors?(term()) :: boolean()
  def valid_trust_anchors?(anchors) when is_list(anchors) and length(anchors) in 1..@max_trust_anchors do
    Enum.all?(anchors, &certificate_binary?/1)
  end

  def valid_trust_anchors?(_anchors), do: false

  @doc """
  Derive an OID4VP `x509_hash:<base64url-sha256>` client identifier from a leaf DER certificate.
  """
  @spec x509_hash_client_id(binary()) :: {:ok, String.t()} | {:error, :invalid_certificate}
  def x509_hash_client_id(leaf) when is_binary(leaf) and byte_size(leaf) in 1..@max_cert_bytes do
    {:ok, "x509_hash:" <> (:crypto.hash(:sha256, leaf) |> Base.url_encode64(padding: false))}
  end

  def x509_hash_client_id(_leaf), do: {:error, :invalid_certificate}

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
         anchors = Keyword.get(opts, :trusted_certificates),
         true <- valid_trust_anchors?(anchors),
         :ok <- profile_chain(chain, anchors, opts),
         true <- Enum.any?(anchors, &valid_path?(&1, chain, opts)),
         {:ok, key} <- leaf_public_key(hd(chain)),
         :ok <- host_policy(chain, Keyword.get(opts, :certificate_trust)) do
      {:ok, %{public_key: key, authority_key_identifiers: authority_key_identifiers(chain)}}
    else
      {:error, :invalid_certificate} = error -> error
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

  defp certificate_binary?(der), do: is_binary(der) and byte_size(der) in 1..@max_cert_bytes

  defp valid_chain?(chain), do: length(chain) in 1..@max_chain_length and Enum.all?(chain, &certificate_binary?/1)

  defp valid_path?(anchor, chain, opts) do
    purpose = Keyword.get(opts, :purpose, :generic)

    if purpose in [:generic, :mdoc_issuer] do
      path_to_leaf =
        case Enum.find_index(chain, &(&1 == anchor)) do
          nil -> chain
          idx -> Enum.take(chain, idx)
        end

      certs_in_path = Enum.uniq([anchor | path_to_leaf])

      Enum.all?(
        certs_in_path,
        &(certificate_key_algorithm_allowed?(&1) and certificate_signature_algorithm_allowed?(&1))
      ) and
        validate_anchored_path(anchor, path_to_leaf, purpose) and
        dns_constraints_hold_for_uri_sans?(anchor, path_to_leaf)
    else
      false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp validate_anchored_path(anchor, [], purpose) do
    anchor_otp = :public_key.pkix_decode_cert(anchor, :otp)

    if :public_key.pkix_is_self_signed(anchor_otp) do
      match?(
        {:ok, _},
        :public_key.pkix_path_validation(anchor, [anchor], pkix_options(anchor, purpose, nil))
      )
    else
      valid_pinned_leaf_anchor?(anchor_otp, purpose)
    end
  end

  defp validate_anchored_path(anchor, path_to_leaf, purpose) do
    issuer_path = Enum.reverse(path_to_leaf)
    leaf = hd(path_to_leaf)
    anchor_otp = :public_key.pkix_decode_cert(anchor, :otp)
    waive_anchor = if !:public_key.pkix_is_self_signed(anchor_otp), do: anchor
    pkix_opts = pkix_options(leaf, purpose, waive_anchor)

    match?(
      {:ok, _},
      :public_key.pkix_path_validation(anchor, [anchor | issuer_path], pkix_opts)
    )
  end

  defp valid_pinned_leaf_anchor?(anchor_otp, purpose) do
    tbs = certificate(anchor_otp, :tbsCertificate)
    extensions = otp_extensions(tbs)

    valid_certificate_time?(tbs) and
      Enum.all?(extensions, &valid_pinned_leaf_extension?(&1, purpose))
  end

  defp valid_pinned_leaf_extension?(extension(extnID: @key_usage_oid, extnValue: usages), _purpose)
       when is_list(usages) do
    :digitalSignature in usages
  end

  defp valid_pinned_leaf_extension?(
         extension(extnID: @extended_key_usage_oid, critical: true, extnValue: purposes),
         purpose
       ) do
    purpose == :mdoc_issuer and is_list(purposes) and @mdoc_document_signer_oid in purposes
  end

  defp valid_pinned_leaf_extension?(extension(critical: true, extnID: oid), _purpose) do
    oid in [
      @basic_constraints_oid,
      @subject_alt_name_oid,
      @subject_key_id_oid,
      @authority_key_id_oid,
      @certificate_policies_oid
    ]
  end

  defp valid_pinned_leaf_extension?(_extension, _purpose), do: true

  defp dns_constraints_hold_for_uri_sans?(_anchor, []), do: true

  defp dns_constraints_hold_for_uri_sans?(anchor, [leaf | intermediates]) do
    uri_sans =
      for {:uniformResourceIdentifier, uri} <- subject_alternative_names(leaf) do
        to_string(uri)
      end

    if uri_sans == [] do
      true
    else
      Enum.all?([anchor | intermediates], &ca_dns_constraints_allow_uris?(&1, uri_sans))
    end
  end

  defp ca_dns_constraints_allow_uris?(ca_der, uri_sans) do
    extensions =
      ca_der
      |> :public_key.pkix_decode_cert(:otp)
      |> certificate(:tbsCertificate)
      |> otp_extensions()

    case Enum.find(extensions, &(extension(&1, :extnID) == @name_constraints_oid)) do
      nil ->
        true

      extension(extnValue: {:NameConstraints, permitted, excluded}) ->
        uri_sans_allowed_by_name_constraints?(subtree_list(permitted), subtree_list(excluded), uri_sans)

      _other ->
        false
    end
  end

  defp uri_sans_allowed_by_name_constraints?(permitted_list, excluded_list, uri_sans) do
    # Only a permitted URI subtree bounds which URI hosts are allowed; an excluded
    # URI subtree leaves permitted dNSName constraints governing the leaf URIs.
    if Enum.any?(permitted_list, &(subtree_form(&1) == :uniformResourceIdentifier)) do
      true
    else
      dns_permitted = for {:GeneralSubtree, {:dNSName, constraint}, _, _} <- permitted_list, do: to_string(constraint)
      dns_excluded = for {:GeneralSubtree, {:dNSName, constraint}, _, _} <- excluded_list, do: to_string(constraint)

      (dns_permitted == [] and dns_excluded == []) or
        Enum.all?(uri_sans, &uri_satisfies_dns_constraints?(&1, dns_permitted, dns_excluded))
    end
  end

  defp uri_satisfies_dns_constraints?(uri, dns_permitted, dns_excluded) do
    case URI.new(uri) do
      {:ok, %URI{host: host}} when is_binary(host) and host != "" ->
        not Enum.any?(dns_excluded, &dns_matches_constraint?(host, &1)) and
          (dns_permitted == [] or Enum.any?(dns_permitted, &dns_matches_constraint?(host, &1)))

      _other ->
        dns_permitted == []
    end
  end

  defp subtree_list(:asn1_NOVALUE), do: []
  defp subtree_list(list) when is_list(list), do: list

  defp subtree_form({:GeneralSubtree, name, _min, _max}), do: elem(name, 0)

  defp dns_matches_constraint?(host, constraint) do
    host = host |> String.downcase() |> String.trim_trailing(".")
    constraint = constraint |> String.downcase() |> String.trim_trailing(".")

    cond do
      constraint == "" -> true
      String.starts_with?(constraint, ".") -> String.ends_with?(host, constraint)
      true -> host == constraint or String.ends_with?(host, "." <> constraint)
    end
  end

  defp valid_certificate_time?(tbs) do
    {:Validity, not_before, not_after} = tbs_certificate(tbs, :validity)
    now = System.system_time(:second)

    with {:ok, from_unix} <- asn1_time_to_unix(not_before),
         {:ok, to_unix} <- asn1_time_to_unix(not_after) do
      now >= from_unix and now <= to_unix
    else
      _ -> false
    end
  end

  defp asn1_time_to_unix({:utcTime, chars}) do
    with [y1, y2, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z] <- chars,
         {:ok, two_digit_year} <- parse_two_digits(y1, y2) do
      year = if two_digit_year >= 50, do: 1900 + two_digit_year, else: 2000 + two_digit_year
      fields_to_unix(year, [m1, m2], [d1, d2], [h1, h2], [min1, min2], [s1, s2])
    else
      _ -> :error
    end
  end

  defp asn1_time_to_unix({:generalTime, chars}) do
    with [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, min1, min2, s1, s2, ?Z] <- chars,
         {year, ""} <- Integer.parse(List.to_string([y1, y2, y3, y4])) do
      fields_to_unix(year, [m1, m2], [d1, d2], [h1, h2], [min1, min2], [s1, s2])
    else
      _ -> :error
    end
  end

  defp asn1_time_to_unix(_time), do: :error

  defp parse_two_digits(d1, d2) when d1 in ?0..?9 and d2 in ?0..?9 do
    {:ok, (d1 - ?0) * 10 + (d2 - ?0)}
  end

  defp parse_two_digits(_d1, _d2), do: :error

  defp fields_to_unix(year, m, d, h, min, s) do
    with {month, ""} <- Integer.parse(List.to_string(m)),
         {day, ""} <- Integer.parse(List.to_string(d)),
         {hour, ""} <- Integer.parse(List.to_string(h)),
         {minute, ""} <- Integer.parse(List.to_string(min)),
         {second, ""} <- Integer.parse(List.to_string(s)),
         {:ok, ndt} <- NaiveDateTime.new(year, month, day, hour, minute, second),
         {:ok, dt} <- DateTime.from_naive(ndt, "Etc/UTC") do
      {:ok, DateTime.to_unix(dt)}
    else
      _ -> :error
    end
  end

  defp otp_extensions(tbs) do
    case tbs_certificate(tbs, :extensions) do
      list when is_list(list) -> list
      :asn1_NOVALUE -> []
    end
  end

  defp certificate_signature_algorithm_allowed?(der) do
    otp = :public_key.pkix_decode_cert(der, :otp)
    tbs = certificate(otp, :tbsCertificate)
    outer_alg = certificate(otp, :signatureAlgorithm)
    tbs_alg = tbs_certificate(tbs, :signature)

    normalized_sig_alg(outer_alg) == normalized_sig_alg(tbs_alg) and
      allowed_signature_algorithm?(outer_alg)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp normalized_sig_alg({:SignatureAlgorithm, oid, :asn1_NOVALUE}), do: {:SignatureAlgorithm, oid, :NULL}

  defp normalized_sig_alg(alg), do: alg

  defp allowed_signature_algorithm?({:SignatureAlgorithm, @rsa_pss_oid, params}) do
    allowed_pss_signature_params?(params)
  end

  defp allowed_signature_algorithm?({:SignatureAlgorithm, oid, _params}) do
    case :public_key.pkix_sign_types(oid) do
      {hash, _alg} when hash in [:sha256, :sha384, :sha512] -> true
      {:none, :eddsa} when oid in [@ed25519_oid, @ed448_oid] -> true
      _other -> false
    end
  rescue
    _ -> false
  end

  defp allowed_signature_algorithm?(_alg), do: false

  defp allowed_pss_signature_params?(encoded) when is_binary(encoded) do
    :"RSASSA-PSS-params"
    |> :public_key.der_decode(encoded)
    |> allowed_pss_signature_params?()
  end

  defp allowed_pss_signature_params?({tag, hash_alg, mgf_alg, _salt_len, _trailer})
       when tag in [:RSASSA_PSS_params, :"RSASSA-PSS-params"] do
    with {:HashAlgorithm, hash_oid, hash_params}
         when hash_oid in [@sha256_oid, @sha384_oid, @sha512_oid] and
                hash_params in [:NULL, :asn1_NOVALUE] <- hash_alg,
         {:MaskGenAlgorithm, @mgf1_oid, {:HashAlgorithm, ^hash_oid, mgf_params}}
         when mgf_params in [:NULL, :asn1_NOVALUE] <- mgf_alg do
      true
    else
      _other -> false
    end
  end

  defp allowed_pss_signature_params?(_params), do: false

  defp pkix_options(_leaf, :generic, nil), do: []

  defp pkix_options(leaf, purpose, waive_anchor) do
    [verify_fun: {&verify_cert_extension/4, %{leaf: leaf, purpose: purpose, waive_anchor: waive_anchor}}]
  end

  defp verify_cert_extension(_cert, der, {:bad_cert, reason}, %{waive_anchor: anchor} = state)
       when is_binary(anchor) and der == anchor and reason in [:invalid_issuer, :invalid_signature] do
    {:valid, state}
  end

  defp verify_cert_extension(_cert, _der, {:bad_cert, reason}, _state), do: {:fail, reason}

  defp verify_cert_extension(
         _cert,
         der,
         {:extension, extension(extnID: @extended_key_usage_oid, critical: true, extnValue: purposes)},
         %{purpose: :mdoc_issuer, leaf: leaf} = state
       )
       when der == leaf and is_list(purposes) do
    if @mdoc_document_signer_oid in purposes, do: {:valid, state}, else: {:unknown, state}
  end

  defp verify_cert_extension(_cert, _der, {:extension, _extension}, state), do: {:unknown, state}

  defp verify_cert_extension(_cert, _der, valid, state) when valid in [:valid, :valid_peer], do: {:valid, state}

  defp profile_chain(chain, anchors, opts) do
    case Keyword.get(opts, :haip, false) do
      haip when is_boolean(haip) ->
        if haip and
             (:public_key.pkix_is_self_signed(hd(chain)) or Enum.any?(chain, &(&1 in anchors))),
           do: {:error, :untrusted_certificate},
           else: :ok

      _invalid ->
        {:error, :invalid_certificate}
    end
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

      {:ok, Attesto.Key.public_map(key)}
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
