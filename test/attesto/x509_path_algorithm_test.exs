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
        intermediates: [[key: {:rsa, 2048, 65_537}]],
        peer: [key: @curve]
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

  defp root(:rsa), do: :public_key.pkix_test_root_cert(~c"synthetic-rsa-path-root", key: {:rsa, 2048, 65_537})

  defp root(:ec), do: :public_key.pkix_test_root_cert(~c"synthetic-ec-path-root", key: @curve)

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
    :public_key.pkix_test_data(%{root: root, intermediates: [], peer: [key: key]})[:cert]
  end

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
