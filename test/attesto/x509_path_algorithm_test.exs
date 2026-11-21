defmodule Attesto.X509PathAlgorithmTest do
  use ExUnit.Case, async: true

  alias Attesto.X509

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:cert, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:tbs, :OTPTBSCertificate, @records[:OTPTBSCertificate])
  Record.defrecordp(:spki, :OTPSubjectPublicKeyInfo, @records[:OTPSubjectPublicKeyInfo])
  Record.defrecordp(:algorithm, :PublicKeyAlgorithm, @records[:PublicKeyAlgorithm])
  @rsa {1, 2, 840, 113_549, 1, 1, 1}
  @pss {1, 2, 840, 113_549, 1, 1, 10}
  @dsa {1, 2, 840, 10_040, 4, 1}
  @dsa_sha256 {2, 16, 840, 1, 101, 3, 4, 3, 2}
  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

  setup_all do
    %{rsa_root: root(:rsa), ec_root: root(:ec)}
  end

  test "PSS-only trust anchors with absent parameters cannot authorize a v1.5 child", ctx do
    restricted = %{
      ctx.rsa_root
      | cert: replace_algorithm(ctx.rsa_root.cert, ctx.rsa_root.key, @pss, :asn1_NOVALUE)
    }

    leaf = peer(restricted, @curve)
    raw_pkix_control(restricted.cert, [leaf])

    assert {:error, :untrusted_certificate} =
             X509.verify([leaf], trusted_certificates: [restricted.cert])
  end

  test "PSS-only intermediates cannot authorize a v1.5 child", ctx do
    data =
      :public_key.pkix_test_data(%{
        root: ctx.ec_root,
        intermediates: [[key: {:rsa, 2048, 65_537}, digest: :sha256]],
        peer: [key: @curve, digest: :sha256]
      })

    intermediate = Enum.find(data[:cacerts], &(&1 != ctx.ec_root.cert))
    assert is_binary(intermediate)
    restricted = replace_algorithm(intermediate, ctx.ec_root.key, @pss, :asn1_NOVALUE)

    raw_pkix_control(ctx.ec_root.cert, [restricted, data[:cert]])

    assert {:error, :untrusted_certificate} =
             X509.verify([data[:cert], restricted],
               trusted_certificates: [ctx.ec_root.cert]
             )
  end

  test "non-NULL rsaEncryption parameters cannot become an unrestricted JWK", ctx do
    leaf = peer(ctx.ec_root, {:rsa, 2048, 65_537})
    hash = {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 3}, :NULL}
    mgf = {:MaskGenAlgorithm, {1, 2, 840, 113_549, 1, 1, 8}, hash}

    params =
      :public_key.der_encode(:"RSASSA-PSS-params", {:"RSASSA-PSS-params", hash, mgf, 64, 1})

    malformed = malformed_rsa_parameters(leaf, ctx.ec_root.key, params)

    assert {:error, :untrusted_certificate} =
             X509.verify([malformed], trusted_certificates: [ctx.ec_root.cert])
  end

  test "ordinary RSA and an unrelated unsupported anchor do not poison a valid path", ctx do
    unrelated = replace_algorithm(ctx.rsa_root.cert, ctx.rsa_root.key, @pss, :asn1_NOVALUE)

    for parameters <- [:NULL, :asn1_NOVALUE] do
      leaf =
        peer(ctx.ec_root, {:rsa, 2048, 65_537})
        |> replace_algorithm(ctx.ec_root.key, @rsa, parameters)

      assert {:ok, _} =
               X509.verify([leaf],
                 trusted_certificates: [unrelated, ctx.ec_root.cert]
               )
    end
  end

  test "RSA certificates need a 2048-bit modulus in the anchor and leaf", ctx do
    weak_key = {:rsa, 1024, 65_537}
    weak_root = :public_key.pkix_test_root_cert(~c"rsa-1024-root", key: weak_key, digest: :sha256)
    strong_leaf = peer(weak_root, ctx.rsa_root.key)
    weak_leaf = peer(ctx.rsa_root, weak_key)
    strong_leaf_under_strong_root = peer(ctx.rsa_root, {:rsa, 2048, 65_537})

    refute X509.valid_trust_anchors?([weak_root.cert])
    assert X509.valid_trust_anchors?([ctx.rsa_root.cert])

    for {anchor, leaf} <- [{weak_root.cert, strong_leaf}, {ctx.rsa_root.cert, weak_leaf}] do
      assert {:ok, _} = :public_key.pkix_path_validation(anchor, [anchor, leaf], [])
      assert {:error, :untrusted_certificate} = X509.verify([leaf], trusted_certificates: [anchor])
    end

    assert {:ok, %{public_key: %{"kty" => "RSA"}}} =
             X509.verify([strong_leaf_under_strong_root], trusted_certificates: [ctx.rsa_root.cert])
  end

  test "accepts P-256, P-384, P-521, Ed25519 and Ed448 certificate keys and signatures" do
    for {curve, digest, name} <- [
          {elem(@curve, 1), :sha256, "P-256"},
          {{1, 3, 132, 0, 34}, :sha384, "P-384"},
          {{1, 3, 132, 0, 35}, :sha512, "P-521"},
          {{1, 3, 101, 112}, :none, "Ed25519"},
          {{1, 3, 101, 113}, :none, "Ed448"}
        ] do
      key = {:namedCurve, curve}
      root = :public_key.pkix_test_root_cert(String.to_charlist(name), key: key, digest: digest)

      leaf =
        :public_key.pkix_test_data(%{root: root, intermediates: [], peer: [key: key, digest: digest]})[:cert]

      assert X509.valid_trust_anchors?([root.cert])
      assert {:ok, %{public_key: %{"crv" => ^name}}} = X509.verify([leaf], trusted_certificates: [root.cert])
    end
  end

  test "refuses a P-192 anchor that signs with ECDSA and SHA-256" do
    root =
      :public_key.pkix_test_root_cert(~c"p192-root", key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 1}}, digest: :sha256)

    leaf = peer(root, @curve)

    assert {:ok, _} = :public_key.pkix_path_validation(root.cert, [root.cert, leaf], [])
    refute X509.valid_trust_anchors?([root.cert])
    assert {:error, :untrusted_certificate} = X509.verify([leaf], trusted_certificates: [root.cert])
  end

  test "refuses a DSA anchor signing an ECDSA leaf and a pinned leaf with a DSA signature", ctx do
    {:DSAPrivateKey, _, p, q, g, y, _x} = key = dsa_key()
    dsa_algorithm = algorithm(algorithm: @dsa, parameters: {:params, {:"Dss-Parms", p, q, g}})
    dsa_spki = spki(algorithm: dsa_algorithm, subjectPublicKey: y)
    dsa_signature = {:SignatureAlgorithm, @dsa_sha256, :asn1_NOVALUE}

    anchor =
      ctx.ec_root.cert
      |> cert_tbs()
      |> tbs(subjectPublicKeyInfo: dsa_spki, signature: dsa_signature)
      |> :public_key.pkix_sign(key)

    leaf =
      ctx.ec_root
      |> peer(@curve)
      |> cert_tbs()
      |> tbs(signature: dsa_signature)
      |> :public_key.pkix_sign(key)

    assert {:ok, _} = :public_key.pkix_path_validation(anchor, [anchor, leaf], [])
    refute X509.valid_trust_anchors?([anchor])
    assert {:error, :untrusted_certificate} = X509.verify([leaf], trusted_certificates: [anchor])

    refute X509.valid_trust_anchors?([leaf])
    assert {:error, :untrusted_certificate} = X509.verify([leaf], trusted_certificates: [leaf])
  end

  test "accepts SHA-256 PSS certificate signatures with matching MGF1 digest", ctx do
    leaf_tbs = ctx.rsa_root |> peer(@curve) |> cert_tbs()
    hash = {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 1}, :NULL}
    other_hash = {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 2}, :NULL}
    mgf_oid = {1, 2, 840, 113_549, 1, 1, 8}

    for mgf_hash <- [hash, other_hash] do
      params = {:"RSASSA-PSS-params", hash, {:MaskGenAlgorithm, mgf_oid, mgf_hash}, 32, 1}
      signature = {:SignatureAlgorithm, @pss, params}
      leaf = leaf_tbs |> tbs(signature: signature) |> :public_key.pkix_sign({ctx.rsa_root.key, params})
      opts = [trusted_certificates: [ctx.rsa_root.cert]]

      if mgf_hash == hash do
        assert {:ok, _} = X509.verify([leaf], opts)
      else
        assert {:error, :untrusted_certificate} = X509.verify([leaf], opts)
      end
    end
  end

  defp dsa_key do
    # Public 2048-bit DSA domain parameters for the generated fixture key.
    p =
      String.to_integer(
        "F99A81F3C807E1BECDF6EEDBC24F369C42091F6F29C80C2A3AD27E9245719AF8A" <>
          "65FB786A4D3F40189C7FBED563E87E6A5EB5C01227D063345FD2AEB95760AB750" <>
          "F30B6A8A35B68243B94FADB71F2214AC94E9E94AF92454CB16C7AB0FCE3B97E1" <>
          "4560AF2B0ECD9A4EA5D4ACCB279A9DE98A5326B12D7D6A33C6659C07BE2AD963" <>
          "ABAE49D55187E45424C0DEFE2D820618AE904500DE33A940C1B9B29466602A735" <>
          "064753A80175440AEA4B6AE30ED269C885EF158D8251024B73D76EDFA4A6C698E" <>
          "2F6151E0DC94280593E7D9B745068EF538EEF2FC155E8E0E29ED4966EF168E68F" <>
          "BDFA315FF8F3D244D36883E893FAC11E1F144FD57323CEA47CBBB38C4B1",
        16
      )

    q = 0xE0E4751AEF060661B17B83B8330348318287C90EB9C37AEE7D875002062692A1

    g =
      String.to_integer(
        "072E6B2091AC742035BE0E3B14066449C9B1D4D45489A801053E3E94FD72818BE" <>
          "6393718ACF80E50245B1FE35056923B60E44C448E2B8AF109F5363BED41F15154" <>
          "E1AB7F68060657354AEF1FAC2FAF8AD069B67B5FDCD627DFB584349D41FF55240" <>
          "59370DBEC663C507AE1556117020BC2005D83FC74D134308CB8D960F6D7056382" <>
          "FE05C0CC26F1330042E9C2FDC3258DD441B75F541F7472C48EE85C5320C981867" <>
          "70BEEBDA8965FD0154F1DC90EA025E073668B112EB219808A60225905EA373990" <>
          "8371D8FAE4E7C631E33085C9E0D3B2D61154469FE2943617EE9EEC8D5C5A410" <>
          "95EDA103FE2B1AD81A12590E46B18A10BE1F6B723935BF13847C93571D1",
        16
      )

    x = 1 + rem(:binary.decode_unsigned(:crypto.strong_rand_bytes(32)), q - 1)
    y = :binary.decode_unsigned(:crypto.mod_pow(g, x, p))
    {:DSAPrivateKey, 0, p, q, g, y, x}
  end

  defp root(:rsa),
    do: :public_key.pkix_test_root_cert(~c"synthetic-rsa-path-root", key: {:rsa, 2048, 65_537}, digest: :sha256)

  defp root(:ec), do: :public_key.pkix_test_root_cert(~c"synthetic-ec-path-root", key: @curve, digest: :sha256)

  # OTP29 admits these correctly signed v1.5 children. Older OTP versions
  # can raise while decoding absent PSS parameters; the core rejection above
  # must still run and remain controlled on those runtimes.
  defp raw_pkix_control(anchor, path) do
    assert {:ok, _} = :public_key.pkix_path_validation(anchor, path, [])
  rescue
    error in CaseClauseError ->
      assert error.term == :asn1_NOVALUE
      assert :erlang.system_info(:otp_release) |> List.to_integer() < 29
  end

  defp peer(root, key) do
    :public_key.pkix_test_data(%{root: root, intermediates: [], peer: [key: key, digest: :sha256]})[:cert]
  end

  defp cert_tbs(der), do: der |> :public_key.pkix_decode_cert(:otp) |> cert(:tbsCertificate)

  defp replace_algorithm(der, signer, oid, parameters) do
    original = der |> :public_key.pkix_decode_cert(:otp) |> cert(:tbsCertificate)

    key =
      original
      |> tbs(:subjectPublicKeyInfo)
      |> spki(algorithm: algorithm(algorithm: oid, parameters: parameters))

    original |> tbs(subjectPublicKeyInfo: key) |> :public_key.pkix_sign(signer)
  end

  # Construct and sign raw DER: OTP's encoder normalizes the
  # rsaEncryption AlgorithmIdentifier and would erase the malformed fixture.
  defp malformed_rsa_parameters(der, signer, parameters) do
    {0x30, cert, ""} = tlv(der)
    {0x30, body, tail} = tlv(cert)
    {prefix, spki_der} = take_fields(body, 6, "")
    {0x30, spki_body, extensions} = tlv(spki_der)
    {0x30, _algorithm, key} = tlv(spki_body)
    algorithm = encode_tlv(0x30, <<6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1>> <> parameters)
    tbs = encode_tlv(0x30, prefix <> encode_tlv(0x30, algorithm <> key) <> extensions)
    {0x30, signature_algorithm, _old_signature} = tlv(tail)
    signature = :public_key.sign(tbs, :sha256, signer)

    encode_tlv(
      0x30,
      tbs <> encode_tlv(0x30, signature_algorithm) <> encode_tlv(3, <<0>> <> signature)
    )
  end

  defp take_fields(rest, 0, prefix), do: {prefix, rest}

  defp take_fields(encoded, count, prefix) do
    {tag, value, rest} = tlv(encoded)
    take_fields(rest, count - 1, prefix <> encode_tlv(tag, value))
  end

  defp tlv(<<tag, length, rest::binary>>) when length < 128 do
    <<value::binary-size(^length), tail::binary>> = rest
    {tag, value, tail}
  end

  defp tlv(<<tag, length, rest::binary>>) do
    count = length - 128
    <<bytes::binary-size(^count), rest::binary>> = rest
    size = :binary.decode_unsigned(bytes)
    <<value::binary-size(^size), tail::binary>> = rest
    {tag, value, tail}
  end

  defp encode_tlv(tag, value) when byte_size(value) < 128, do: <<tag, byte_size(value)>> <> value

  defp encode_tlv(tag, value) do
    size = :binary.encode_unsigned(byte_size(value))
    <<tag, 128 + byte_size(size)>> <> size <> value
  end
end
