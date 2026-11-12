defmodule Attesto.X509SignaturePolicyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.X509

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:otp_certificate, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:otp_tbs, :OTPTBSCertificate, @records[:OTPTBSCertificate])
  Record.defrecordp(:otp_spki, :OTPSubjectPublicKeyInfo, @records[:OTPSubjectPublicKeyInfo])
  Record.defrecordp(:public_key_algorithm, :PublicKeyAlgorithm, @records[:PublicKeyAlgorithm])
  Record.defrecordp(:extension, :Extension, @records[:Extension])

  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
  @key_usage_oid {2, 5, 29, 15}
  @pss_oid {1, 2, 840, 113_549, 1, 1, 10}

  setup_all do
    root = :public_key.pkix_test_root_cert(~c"synthetic-signature-root", key: @curve)
    %{root: root}
  end

  for critical <- [true, false] do
    test "a #{critical}-critical leaf KU without digitalSignature cannot authenticate signatures",
         context do
      for usage <- [[:keyEncipherment], [:dataEncipherment], [:keyAgreement], [:nonRepudiation]] do
        issuer = issuer(context.root, usage, unquote(critical))

        assert {:error, :untrusted_certificate} =
                 X509.verify([issuer.leaf], options(issuer))

        refute_policy_bypass(issuer)
      end
    end
  end

  test "digitalSignature and absent KU permit a signing key",
       context do
    for usage <- [[:digitalSignature], [:digitalSignature, :keyAgreement], :absent] do
      issuer = issuer(context.root, usage, true)
      assert {:ok, _verified} = X509.verify([issuer.leaf], options(issuer))
    end
  end

  test "mdoc's critical signer EKU cannot override a conflicting key usage", context do
    signer_usage = {:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}
    issuer = issuer(context.root, [:keyAgreement], false, extensions: [signer_usage])
    opts = Keyword.put(options(issuer), :purpose, :mdoc_issuer)
    assert {:error, :untrusted_certificate} = X509.verify([issuer.leaf], opts)
  end

  test "PSS-specific SPKI is not silently converted to an unrestricted RSA key", context do
    issuer = issuer(context.root, [:digitalSignature], true, key: {:rsa, 2048, 65_537})
    assert {:ok, _verified} = X509.verify([issuer.leaf], options(issuer))

    # The leaf is re-signed by the same trusted CA. Its SPKI carries
    # SHA-512/MGF1-SHA-512 and minimum salt64 constraints, not a generic RSA key.
    parameters = pss_parameters()

    for params <- [parameters, :asn1_NOVALUE] do
      restricted = restrict_pss_spki(issuer, context.root, params)

      assert {:ok, _path} =
               :public_key.pkix_path_validation(context.root.cert, [restricted.leaf], [])

      assert {:error, :untrusted_certificate} =
               X509.verify([restricted.leaf], options(restricted))

      refute_policy_bypass(restricted)
    end
  end

  defp issuer(root, usage, critical, overrides \\ []) do
    extensions =
      [
        {:Extension, @key_usage_oid, critical, if(usage == :absent, do: [:digitalSignature], else: usage)}
      ] ++
        Keyword.get(overrides, :extensions, [])

    data =
      :public_key.pkix_test_data(%{
        root: root,
        intermediates: [],
        peer: [key: Keyword.get(overrides, :key, @curve), extensions: extensions]
      })

    leaf = if usage == :absent, do: remove_key_usage(data[:cert], root), else: data[:cert]
    %{leaf: leaf, anchors: [root.cert]}
  end

  defp remove_key_usage(leaf, root) do
    tbs = leaf |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)

    extensions =
      tbs |> otp_tbs(:extensions) |> Enum.reject(&(extension(&1, :extnID) == @key_usage_oid))

    tbs |> otp_tbs(extensions: extensions) |> :public_key.pkix_sign(root.key)
  end

  defp restrict_pss_spki(issuer, root, parameters) do
    tbs = issuer.leaf |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)
    spki = otp_tbs(tbs, :subjectPublicKeyInfo)
    algorithm = public_key_algorithm(algorithm: @pss_oid, parameters: parameters)
    spki = otp_spki(spki, algorithm: algorithm)
    leaf = tbs |> otp_tbs(subjectPublicKeyInfo: spki) |> :public_key.pkix_sign(root.key)
    %{issuer | leaf: leaf}
  end

  defp pss_parameters do
    hash = {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 3}, :NULL}
    mgf = {:MaskGenAlgorithm, {1, 2, 840, 113_549, 1, 1, 8}, hash}
    {:"RSASSA-PSS-params", hash, mgf, 64, 1}
  end

  defp refute_policy_bypass(issuer) do
    parent = self()

    policy = fn _chain ->
      send(parent, :policy_called)
      :ok
    end

    assert {:error, :untrusted_certificate} =
             X509.verify(
               [issuer.leaf],
               Keyword.put(options(issuer), :certificate_trust, policy)
             )

    refute_received :policy_called
  end

  defp options(issuer), do: [trusted_certificates: issuer.anchors, haip: true, accepted_algs: ["ES256"]]
end
