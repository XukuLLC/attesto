defmodule Attesto.DPoP.ProofTest do
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.DPoP.Proof

  @htu "https://issuer.example.com/credential"
  @now 1_700_000_000

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "build/4" do
    test "builds a verifiable proof with only the public JWK in its header" do
      key = ec_key()

      assert {:ok, proof} =
               Proof.build(key, " post ", @htu,
                 now: @now,
                 jti: "proof-1",
                 access_token: "access-token",
                 nonce: "nonce-1"
               )

      assert %{
               "htm" => "POST",
               "htu" => @htu,
               "iat" => @now,
               "jti" => "proof-1",
               "ath" => ath,
               "nonce" => "nonce-1"
             } = claims(proof)

      assert ath == DPoP.compute_ath("access-token")
      assert %{"typ" => "dpop+jwt", "alg" => "ES256", "jwk" => public_jwk} = header(proof)
      refute Map.has_key?(public_jwk, "d")

      assert {:ok, %{jti: "proof-1"}} =
               DPoP.verify_proof(proof,
                 http_method: "POST",
                 http_uri: @htu,
                 access_token: "access-token",
                 now: @now
               )
    end

    test "strips query and fragment after validating the complete HTTPS URI" do
      assert {:ok, proof} = Proof.build(ec_key(), "GET", @htu <> "?page=1#result", now: @now)
      assert claims(proof)["htu"] == @htu

      for invalid <- [
            "http://issuer.example.com/credential",
            "https://user:password@issuer.example.com/credential",
            "https:///credential",
            "/credential",
            "https://issuer.example.com/credential?bad=%zz"
          ] do
        assert {:error, :invalid_htu} = Proof.build(ec_key(), "GET", invalid, now: @now)
      end
    end

    test "normalizes a pathless target to the equivalent slash path" do
      assert {:ok, proof} = Proof.build(ec_key(), "GET", "https://issuer.example.com", now: @now)
      assert claims(proof)["htu"] == "https://issuer.example.com/"

      assert {:ok, _verified} =
               DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://issuer.example.com",
                 now: @now
               )
    end

    test "accepts a DateTime clock and validates method, jti, nonce, and access token" do
      datetime = DateTime.from_unix!(@now)
      assert {:ok, proof} = Proof.build(ec_key(), "GET", @htu, now: datetime)
      assert claims(proof)["iat"] == @now

      assert {:error, :invalid_htm} = Proof.build(ec_key(), "", @htu)
      assert {:error, :invalid_htm} = Proof.build(ec_key(), nil, @htu)
      assert {:error, :invalid_time} = Proof.build(ec_key(), "GET", @htu, now: -1)

      assert {:error, :invalid_time} =
               Proof.build(ec_key(), "GET", @htu, now: DateTime.from_unix!(-1))

      assert {:error, :invalid_jti} = Proof.build(ec_key(), "GET", @htu, jti: "")

      assert {:error, :invalid_jti} =
               Proof.build(ec_key(), "GET", @htu, jti: String.duplicate("j", 257))

      for nonce <- [nil, "", 42, String.duplicate("n", 4_097)] do
        assert {:error, :invalid_nonce} = Proof.build(ec_key(), "GET", @htu, nonce: nonce)
      end

      for token <- [nil, "", 42] do
        assert {:error, :invalid_access_token} =
                 Proof.build(ec_key(), "GET", @htu, access_token: token)
      end
    end

    test "honors declared alg and kid and rejects a conflicting override" do
      key = JOSE.JWK.generate_key({:rsa, 2048})
      {_type, private_jwk} = JOSE.JWK.to_map(key)
      configured = Map.merge(private_jwk, %{"alg" => "PS256", "kid" => "dpop-rsa"})

      assert {:ok, proof} = Proof.build(configured, "POST", @htu, now: @now)
      assert %{"alg" => "PS256", "kid" => "dpop-rsa"} = header(proof)

      assert {:ok, _verified} =
               DPoP.verify_proof(proof, http_method: "POST", http_uri: @htu, now: @now)

      assert {:error, :unsupported_alg} =
               Proof.build(configured, "POST", @htu, alg: "RS256", now: @now)
    end

    test "supports the verifier's broader RSA algorithm set with exact PSS signing" do
      key = JOSE.JWK.generate_key({:rsa, 2048})

      assert {:ok, proof} = Proof.build(key, "GET", @htu, alg: "PS384", now: @now)
      assert header(proof)["alg"] == "PS384"

      assert {:ok, _verified} =
               DPoP.verify_proof(proof, http_method: "GET", http_uri: @htu, now: @now)
    end

    test "returns the established errors for invalid key and JOSE metadata" do
      assert {:error, :invalid_key} = Proof.build(%{"kty" => "bogus"}, "GET", @htu)
      assert {:error, :unsupported_key} = Proof.build(JOSE.JWK.generate_key({:oct, 32}), "GET", @htu)
      assert {:error, :unsupported_alg} = Proof.build(ec_key(), "GET", @htu, alg: "none")
      assert {:error, :invalid_kid} = Proof.build(ec_key(), "GET", @htu, kid: nil)
    end
  end
end
