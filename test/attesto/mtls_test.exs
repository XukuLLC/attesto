defmodule Attesto.MTLSTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.MTLS

  # -----------------------------------------------------------------
  # helpers - generate self-signed X.509 test certificates via
  # `:public_key.pkix_test_root_cert/2` (OTP >= 24). Returns the DER
  # bytes a TLS layer would surface via `:ssl.peercert/1`.
  # -----------------------------------------------------------------

  defp gen_cert_der(name \\ "cn=attesto-mtls-test") do
    %{cert: der} = :public_key.pkix_test_root_cert(String.to_charlist(name), [])
    der
  end

  defp gen_san_cert_der do
    subject_alt_name =
      {:Extension, {2, 5, 29, 17}, false,
       [
         {:dNSName, ~c"client.example.com"},
         {:uniformResourceIdentifier, ~c"spiffe://example.com/client/123"},
         {:iPAddress, <<127, 0, 0, 1>>},
         {:rfc822Name, ~c"client@example.com"}
       ]}

    :public_key.pkix_test_data(%{
      root: [],
      intermediates: [],
      peer: [extensions: [subject_alt_name]]
    })[:cert]
  end

  defp sha256_b64url(bytes) do
    :sha256
    |> :crypto.hash(bytes)
    |> Base.url_encode64(padding: false)
  end

  describe "RFC 8705 section 2 client authentication" do
    test "extracts the registered PKI subject alternatives" do
      der = gen_san_cert_der()

      assert {:ok, identities} = MTLS.certificate_identities(der)
      assert identities.san_dns == ["client.example.com"]
      assert identities.san_uri == ["spiffe://example.com/client/123"]
      assert identities.san_ip == ["127.0.0.1"]
      assert identities.san_email == ["client@example.com"]
      assert is_binary(identities.subject_dn) and identities.subject_dn != ""
    end

    test "tls_client_auth accepts each RFC 8705 PKI identity type" do
      der = gen_san_cert_der()
      {:ok, identities} = MTLS.certificate_identities(der)

      for metadata <- [
            %{"tls_client_auth_subject_dn" => identities.subject_dn},
            %{"tls_client_auth_san_dns" => "CLIENT.EXAMPLE.COM"},
            %{"tls_client_auth_san_uri" => "spiffe://example.com/client/123"},
            %{"tls_client_auth_san_ip" => "127.0.0.1"},
            %{"tls_client_auth_san_email" => "client@EXAMPLE.COM"}
          ] do
        assert :ok = MTLS.authenticate_client(der, :tls_client_auth, metadata)
      end
    end

    test "email SAN comparison preserves the potentially case-sensitive local part" do
      der = gen_san_cert_der()

      assert {:error, :certificate_mismatch} =
               MTLS.authenticate_client(der, :tls_client_auth, %{
                 "tls_client_auth_san_email" => "CLIENT@example.com"
               })
    end

    test "tls_client_auth requires exactly one registered identity and rejects mismatches" do
      der = gen_san_cert_der()

      assert {:error, :invalid_client_metadata} =
               MTLS.authenticate_client(der, :tls_client_auth, %{})

      assert {:error, :invalid_client_metadata} =
               MTLS.authenticate_client(der, :tls_client_auth, %{
                 "tls_client_auth_san_dns" => "client.example.com",
                 "tls_client_auth_san_uri" => "spiffe://example.com/client/123"
               })

      assert {:error, :certificate_mismatch} =
               MTLS.authenticate_client(der, :tls_client_auth, %{
                 "tls_client_auth_san_dns" => "attacker.example.com"
               })
    end

    test "self_signed_tls_client_auth matches the exact registered x5c leaf" do
      der = gen_san_cert_der()
      other = gen_cert_der("other-client")
      registered = %{"keys" => [%{"kty" => "EC", "x5c" => [Base.encode64(der)]}]}

      assert :ok =
               MTLS.authenticate_client(der, :self_signed_tls_client_auth, %{
                 "jwks" => registered
               })

      assert {:error, :certificate_mismatch} =
               MTLS.authenticate_client(other, :self_signed_tls_client_auth, %{
                 "jwks" => registered
               })
    end

    test "self-signed method refuses unresolved jwks_uri and malformed certificates" do
      der = gen_san_cert_der()

      assert {:error, :invalid_client_metadata} =
               MTLS.authenticate_client(der, :self_signed_tls_client_auth, %{
                 "jwks_uri" => "https://client.example.com/jwks.json"
               })

      assert {:error, :invalid_certificate} =
               MTLS.authenticate_client("not-a-cert", :tls_client_auth, %{
                 "tls_client_auth_san_dns" => "client.example.com"
               })
    end

    test "bounds forwarded certificate and registered identity parsing" do
      der = gen_san_cert_der()

      assert {:error, :invalid_certificate} =
               MTLS.authenticate_client(
                 :binary.copy(<<0>>, 1_048_577),
                 :tls_client_auth,
                 %{"tls_client_auth_san_dns" => "client.example.com"}
               )

      assert {:error, :invalid_client_metadata} =
               MTLS.authenticate_client(der, :tls_client_auth, %{
                 "tls_client_auth_subject_dn" => String.duplicate("a", 4_097)
               })
    end
  end

  # -----------------------------------------------------------------
  # compute_thumbprint/1
  # -----------------------------------------------------------------

  describe "compute_thumbprint/1 happy path" do
    test "returns the SHA-256 thumbprint of a real DER-encoded X.509 cert" do
      der = gen_cert_der()
      expected = sha256_b64url(der)

      assert {:ok, thumbprint} = MTLS.compute_thumbprint(der)
      assert thumbprint == expected
    end

    test "produces a 43-character base64url thumbprint (RFC 8705 section 3.1 shape)" do
      der = gen_cert_der()
      assert {:ok, thumbprint} = MTLS.compute_thumbprint(der)

      # SHA-256 is 32 bytes; base64url-no-pad of 32 bytes is exactly 43 chars
      # drawn from `[A-Za-z0-9_-]`. The verifier downstream relies on this
      # being identical in shape to a JWK thumbprint, so the contract is
      # tight.
      assert byte_size(thumbprint) == 43
      assert Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, thumbprint)
      assert MTLS.thumbprint_shape?(thumbprint)
    end

    test "two independently-generated certs produce distinct thumbprints" do
      der1 = gen_cert_der("cn=attesto-mtls-test-a")
      der2 = gen_cert_der("cn=attesto-mtls-test-b")

      assert {:ok, t1} = MTLS.compute_thumbprint(der1)
      assert {:ok, t2} = MTLS.compute_thumbprint(der2)
      refute t1 == t2
    end

    test "is deterministic: same DER bytes always produce the same thumbprint" do
      der = gen_cert_der()

      assert {:ok, t1} = MTLS.compute_thumbprint(der)
      assert {:ok, t2} = MTLS.compute_thumbprint(der)
      assert t1 == t2
    end

    test "thumbprint round-trips against :public_key.pkix_decode_cert/2" do
      # compute_thumbprint only digests its input after confirming the bytes
      # parse as an X.509 certificate. Confirm the bytes we hash are the same
      # bytes Erlang accepts as a valid certificate.
      der = gen_cert_der()
      decoded = :public_key.pkix_decode_cert(der, :plain)

      assert elem(decoded, 0) == :Certificate
      assert {:ok, thumbprint} = MTLS.compute_thumbprint(der)
      assert thumbprint == sha256_b64url(der)
    end
  end

  describe "compute_thumbprint/1 rejects non-certificate input" do
    test "returns :invalid_certificate for the empty binary" do
      assert {:error, :invalid_certificate} = MTLS.compute_thumbprint(<<>>)
    end

    test "returns :invalid_certificate for a non-binary input" do
      for bad <- [nil, 42, %{}, :atom, ["a"], {:tuple, :ish}] do
        assert {:error, :invalid_certificate} = MTLS.compute_thumbprint(bad),
               "expected :invalid_certificate for #{inspect(bad)}"
      end
    end

    test "returns :invalid_certificate for random garbage bytes" do
      # A few classes of non-cert bytes: short binary, ASCII text, random
      # noise. None should ever produce a "thumbprint" - the security
      # property is that compute_thumbprint of any attacker-controlled blob
      # fails closed rather than producing a value the verifier might match
      # against an unrelated cert.
      bad_inputs = [
        "abc",
        "not a certificate",
        String.duplicate("\xff", 64),
        :crypto.strong_rand_bytes(128)
      ]

      for bad <- bad_inputs do
        assert {:error, :invalid_certificate} = MTLS.compute_thumbprint(bad),
               "expected :invalid_certificate for #{inspect(bad, limit: 16)}"
      end
    end

    test "returns :invalid_certificate for the DER bytes of a non-X.509 ASN.1 value" do
      # An ASN.1 INTEGER encoded in DER (`02 01 2A` = INTEGER 42) is valid
      # ASN.1 but is not a Certificate. pkix_decode_cert must reject it.
      not_a_cert = <<0x02, 0x01, 0x2A>>
      assert {:error, :invalid_certificate} = MTLS.compute_thumbprint(not_a_cert)
    end

    test "returns :invalid_certificate when a real cert's DER bytes are truncated" do
      # Truncating the DER necessarily breaks the ASN.1 length headers and
      # pkix_decode_cert rejects it. (Single-byte bit-flips deep inside the
      # DER are content-dependent: some live inside cert fields that BER is
      # lenient about and would still parse, which would make the test
      # flaky.)
      der = gen_cert_der()
      truncated = binary_part(der, 0, byte_size(der) - 16)

      assert {:error, :invalid_certificate} = MTLS.compute_thumbprint(truncated)
    end
  end

  # -----------------------------------------------------------------
  # thumbprint_shape?/1
  # -----------------------------------------------------------------

  describe "thumbprint_shape?/1" do
    test "accepts a well-formed 43-char base64url SHA-256 thumbprint" do
      der = gen_cert_der()
      assert {:ok, t} = MTLS.compute_thumbprint(der)
      assert MTLS.thumbprint_shape?(t)
    end

    test "rejects values of the wrong length" do
      for bad <- [
            "",
            "a",
            String.duplicate("a", 42),
            String.duplicate("a", 44),
            String.duplicate("a", 64)
          ] do
        refute MTLS.thumbprint_shape?(bad), "expected reject for length #{byte_size(bad)}"
      end
    end

    test "rejects 43-char strings drawn from outside the base64url alphabet" do
      # `+` and `/` are standard-base64 only; `=` is padding; whitespace is
      # never legal in JWS/JWK thumbprints.
      for bad <- [
            String.duplicate("a", 42) <> "+",
            String.duplicate("a", 42) <> "/",
            String.duplicate("a", 42) <> "=",
            String.duplicate("a", 42) <> " "
          ] do
        refute MTLS.thumbprint_shape?(bad), "expected reject for #{inspect(bad)}"
      end
    end

    test "rejects 43-char base64url strings that are not the canonical encoding of a 32-byte digest" do
      # 43 chars of valid base64url alphabet is necessary but not sufficient.
      # The last character carries 2 trailing bits that MUST be zero; a
      # non-zero value means `Base.url_encode64/2` could not have produced
      # this string from a 32-byte digest. `...dg2` decodes the same bytes as
      # canonical `...dg0` but cannot be the canonical encoding of any
      # 32-byte SHA-256 digest.
      non_canonical = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
      refute MTLS.thumbprint_shape?(non_canonical)

      # Sanity: the canonical sibling IS accepted.
      canonical = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg0"
      assert MTLS.thumbprint_shape?(canonical)
    end

    test "rejects non-binary values" do
      for bad <- [nil, 42, %{}, :atom, ["a"], {:thumb, :print}] do
        refute MTLS.thumbprint_shape?(bad), "expected reject for #{inspect(bad)}"
      end
    end
  end

  # -----------------------------------------------------------------
  # mtls_bound?/1
  # -----------------------------------------------------------------

  describe "mtls_bound?/1" do
    test "true for claims carrying cnf.x5t#S256 as a non-empty string" do
      assert MTLS.mtls_bound?(%{"cnf" => %{"x5t#S256" => "abc"}})

      der = gen_cert_der()
      {:ok, t} = MTLS.compute_thumbprint(der)
      assert MTLS.mtls_bound?(%{"cnf" => %{"x5t#S256" => t}})
    end

    test "false for claims with no cnf" do
      refute MTLS.mtls_bound?(%{})
      refute MTLS.mtls_bound?(%{"sub" => "oc_test"})
    end

    test "false for cnf without x5t#S256" do
      refute MTLS.mtls_bound?(%{"cnf" => %{}})
      refute MTLS.mtls_bound?(%{"cnf" => %{"jkt" => "abc"}})
    end

    test "false for x5t#S256 that is empty or non-string" do
      for bad <- ["", 42, nil, %{}, ["t"]] do
        refute MTLS.mtls_bound?(%{"cnf" => %{"x5t#S256" => bad}}),
               "expected false for x5t#S256=#{inspect(bad)}"
      end
    end

    test "false for non-map cnf" do
      for bad <- ["abc", 42, [], nil] do
        refute MTLS.mtls_bound?(%{"cnf" => bad}),
               "expected false for cnf=#{inspect(bad)}"
      end
    end

    test "false for non-map claims" do
      refute MTLS.mtls_bound?(nil)
      refute MTLS.mtls_bound?("oops")
      refute MTLS.mtls_bound?(42)
    end
  end

  # -----------------------------------------------------------------
  # thumbprint_length/0
  # -----------------------------------------------------------------

  describe "thumbprint_length/0" do
    test "returns 43 (SHA-256 -> base64url-no-pad shape)" do
      assert MTLS.thumbprint_length() == 43
    end
  end
end
