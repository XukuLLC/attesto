defmodule Attesto.JwtVcTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{JWS, JwtVc, Key}

  @issuer "https://issuer.example"
  @subject "did:example:holder"
  @context "https://www.w3.org/2018/credentials/v1"

  defmodule ProcessKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: Process.get({__MODULE__, :pem}) || raise("test signing PEM is not installed")

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_metadata, pem} = JOSE.JWK.to_pem(jwk)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    {jwk, pem, public}
  end

  defp trusted_jwks(jwk, public) do
    %{
      "keys" => [
        Map.merge(public, %{
          "alg" => "ES256",
          "kid" => JOSE.JWK.thumbprint(jwk),
          "use" => "sig"
        })
      ]
    }
  end

  defp signed(claims, jwk, header_overrides \\ %{}) do
    header =
      Map.merge(
        %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk), "typ" => "JWT"},
        header_overrides
      )

    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp valid_claims(now) do
    %{
      "iss" => @issuer,
      "sub" => @subject,
      "nbf" => now,
      "exp" => now + 600,
      "iat" => now,
      "jti" => "urn:uuid:6e09bcb4-5955-4a08-9a54-14f0833bd951",
      "vc" => %{
        "@context" => [@context],
        "type" => ["VerifiableCredential", "UniversityDegreeCredential"],
        "credentialSubject" => %{"degree" => "BSc"},
        "issuer" => @issuer
      }
    }
  end

  defp tamper_signature(jwt) do
    [protected, payload, signature] = String.split(jwt, ".")
    <<first, rest::binary>> = Base.url_decode64!(signature, padding: false)
    changed = <<:erlang.bxor(first, 1), rest::binary>> |> Base.url_encode64(padding: false)
    Enum.join([protected, payload, changed], ".")
  end

  describe "issue/2 and verify/3" do
    test "round-trips the exact W3C VC and registered JWT claims with a real P-256 PEM" do
      {jwk, pem, public} = keypair()
      now = 1_700_000_000
      jti = "https://issuer.example/credentials/degree-123"

      token =
        JwtVc.issue(
          [iss: @issuer, sub: @subject, pem: pem],
          claims: %{"degree" => %{"type" => "BachelorDegree", "name" => "BSc"}},
          context: [@context, "https://example.edu/credentials/v1"],
          type: ["VerifiableCredential", "UniversityDegreeCredential"],
          iat: now,
          nbf: now,
          exp: now + 600,
          jti: jti
        )

      assert {:ok, header} = JWS.peek_json(token, :protected)
      assert header == %{"alg" => "ES256", "kid" => Key.kid(pem), "typ" => "JWT"}

      assert {:ok, verified} =
               JwtVc.verify(token, trusted_jwks(jwk, public), now: now, issuer: @issuer)

      assert verified.iss == @issuer
      assert verified.sub == @subject
      assert verified.claims == %{"degree" => %{"type" => "BachelorDegree", "name" => "BSc"}}

      assert verified.vc == %{
               "@context" => [@context, "https://example.edu/credentials/v1"],
               "type" => ["VerifiableCredential", "UniversityDegreeCredential"],
               "credentialSubject" => verified.claims,
               "issuer" => @issuer
             }

      vc = verified.vc

      assert %{
               "iss" => @issuer,
               "sub" => @subject,
               "nbf" => ^now,
               "exp" => 1_700_000_600,
               "iat" => ^now,
               "jti" => ^jti,
               "vc" => ^vc
             } = verified.jwt_claims

      refute Map.has_key?(verified.jwt_claims, "cnf")
      assert verified.cnf == nil
    end

    test "uses JWS.sign_current for a keystore and supplies secure defaults" do
      {jwk, pem, public} = keypair()
      Process.put({ProcessKeystore, :pem}, pem)
      now = 1_700_000_000

      token =
        JwtVc.issue(ProcessKeystore,
          iss: @issuer,
          sub: @subject,
          credential_subject: %{"given_name" => "Alice"},
          now: now
        )

      assert {:ok, verified} = JwtVc.verify(token, trusted_jwks(jwk, public), now: now)
      assert verified.claims == %{"given_name" => "Alice"}
      assert verified.vc["@context"] == [@context]
      assert verified.vc["type"] == ["VerifiableCredential"]
      assert verified.jwt_claims["iat"] == now
      assert verified.jwt_claims["nbf"] == now
      assert verified.jwt_claims["exp"] == now + 3600
      assert verified.jwt_claims["jti"] =~ ~r/^urn:uuid:[0-9a-f-]{36}$/
    end

    test "returns and cryptographically preserves RFC 7800 holder binding" do
      {issuer_jwk, issuer_pem, issuer_public} = keypair()
      {_holder_jwk, holder_pem, holder_public} = keypair()
      now = 1_700_000_000
      cnf = %{"jwk" => holder_public}

      token =
        JwtVc.issue(
          [iss: @issuer, sub: @subject, pem: issuer_pem],
          claims: %{"given_name" => "Alice"},
          cnf: cnf,
          now: now
        )

      assert {:ok, verified} =
               JwtVc.verify(token, trusted_jwks(issuer_jwk, issuer_public), now: now)

      assert verified.cnf == cnf
      refute Map.has_key?(verified.cnf["jwk"], "d")

      holder_proof =
        JWS.sign_compact(
          holder_pem,
          %{"alg" => "ES256", "typ" => "holder-proof+jwt"},
          %{"nonce" => "n-123", "iat" => now}
        )

      candidates = JWS.verification_candidates(verified.cnf["jwk"], accepted_algs: ["ES256"])
      assert {:ok, %{"nonce" => "n-123"}} = JWS.verify_strict(holder_proof, candidates)
    end
  end

  describe "signature and header verification" do
    test "rejects a tampered signature" do
      {jwk, pem, public} = keypair()
      now = 1_700_000_000
      token = JwtVc.issue([iss: @issuer, sub: @subject, pem: pem], now: now)

      assert {:error, :invalid_signature} =
               token |> tamper_signature() |> JwtVc.verify(trusted_jwks(jwk, public), now: now)
    end

    test "rejects a credential signed by a different issuer key" do
      {_signer_jwk, signer_pem, _signer_public} = keypair()
      {other_jwk, _other_pem, other_public} = keypair()
      now = 1_700_000_000
      token = JwtVc.issue([iss: @issuer, sub: @subject, pem: signer_pem], now: now)

      assert {:error, :invalid_signature} =
               JwtVc.verify(token, trusted_jwks(other_jwk, other_public), now: now)
    end

    test "requires the W3C typ and rejects unsupported critical headers" do
      {jwk, _pem, public} = keypair()
      now = 1_700_000_000

      wrong_typ = signed(valid_claims(now), jwk, %{"typ" => "vc+sd-jwt"})
      assert {:error, :invalid_typ} = JwtVc.verify(wrong_typ, trusted_jwks(jwk, public), now: now)

      critical = signed(valid_claims(now), jwk, %{"crit" => ["unknown"], "unknown" => true})

      assert {:error, :unsupported_critical_header} =
               JwtVc.verify(critical, trusted_jwks(jwk, public), now: now)
    end
  end

  describe "fail-closed claim and temporal validation" do
    test "rejects an expired credential at the exact exp boundary" do
      {jwk, pem, public} = keypair()
      now = 1_700_000_000

      token =
        JwtVc.issue([iss: @issuer, sub: @subject, pem: pem],
          iat: now - 60,
          nbf: now - 60,
          exp: now,
          now: now
        )

      assert {:error, :expired} = JwtVc.verify(token, trusted_jwks(jwk, public), now: now)
    end

    test "rejects missing and malformed iat, nbf, and exp" do
      {jwk, _pem, public} = keypair()
      now = 1_700_000_000
      jwks = trusted_jwks(jwk, public)

      for claims <- [
            Map.delete(valid_claims(now), "iat"),
            Map.put(valid_claims(now), "iat", "now"),
            Map.delete(valid_claims(now), "nbf"),
            Map.put(valid_claims(now), "nbf", -1),
            Map.delete(valid_claims(now), "exp"),
            Map.put(valid_claims(now), "exp", "later")
          ] do
        assert {:error, :invalid_claims} = claims |> signed(jwk) |> JwtVc.verify(jwks, now: now)
      end
    end

    test "rejects future issuance/not-before and contradictory nested issuer" do
      {jwk, _pem, public} = keypair()
      now = 1_700_000_000
      jwks = trusted_jwks(jwk, public)

      future = valid_claims(now) |> Map.put("iat", now + 61) |> Map.put("exp", now + 600)
      assert {:error, :not_yet_valid} = future |> signed(jwk) |> JwtVc.verify(jwks, now: now)

      not_before = valid_claims(now) |> Map.put("nbf", now + 61) |> Map.put("exp", now + 600)
      assert {:error, :not_yet_valid} = not_before |> signed(jwk) |> JwtVc.verify(jwks, now: now)

      mismatched = put_in(valid_claims(now), ["vc", "issuer"], "https://other-issuer.example")
      assert {:error, :invalid_issuer} = mismatched |> signed(jwk) |> JwtVc.verify(jwks, now: now)
    end

    test "rejects an invalid cnf instead of returning unusable holder material" do
      {jwk, _pem, public} = keypair()
      now = 1_700_000_000

      claims = Map.put(valid_claims(now), "cnf", %{"jwk" => %{"not" => "a-jwk"}})

      assert {:error, :invalid_cnf} =
               claims |> signed(jwk) |> JwtVc.verify(trusted_jwks(jwk, public), now: now)
    end
  end
end
