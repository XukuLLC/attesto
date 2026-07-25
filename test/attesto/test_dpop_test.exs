defmodule Attesto.Test.DPoPTest do
  use ExUnit.Case, async: true

  alias Attesto.Test.DPoP, as: Fixture
  alias Attesto.Test.Factory

  setup do
    config = Factory.config(Factory.rsa_pem())
    jwk = Fixture.generate_key()

    principal = %{kind: "client", sub: "oc_acme", scopes: ["read"], claims: %{"client_id" => "acme"}}

    {:ok, config: config, jwk: jwk, principal: principal}
  end

  describe "mint_access_token/4" do
    test "mints a DPoP-bound token that verifies against the proof key", ctx do
      {token, response} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)

      assert response.token_type == "DPoP"

      jkt = Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(ctx.jwk))
      assert {:ok, %{"cnf" => %{"jkt" => ^jkt}}} = Attesto.Token.verify(ctx.config, token, dpop_jkt: jkt)
    end

    test "passes mint opts through (e.g. clock)", ctx do
      now = 1_700_000_000
      {token, _} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk, now: now)

      assert {:ok, claims} =
               Attesto.Token.verify(ctx.config, token,
                 now: now,
                 dpop_jkt: Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(ctx.jwk))
               )

      assert claims["iat"] == now
    end

    test "raises when mint would fail", ctx do
      assert_raise ArgumentError, fn ->
        Fixture.mint_access_token(ctx.config, %{ctx.principal | kind: "nope"}, ctx.jwk)
      end
    end
  end

  describe "proof/4" do
    test "produces a proof the verifier accepts at the token endpoint", ctx do
      proof = Fixture.proof(ctx.jwk, "POST", "https://api.example/oauth/token")

      assert {:ok, %{jkt: jkt, htm: "POST"}} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "POST",
                 http_uri: "https://api.example/oauth/token"
               )

      assert jkt == Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(ctx.jwk))
    end

    test "embeds only the public key half", ctx do
      proof = Fixture.proof(ctx.jwk, "GET", "https://api.example/x")
      [header_b64, _, _] = String.split(proof, ".")
      header = header_b64 |> Base.url_decode64!(padding: false) |> JSON.decode!()

      assert header["typ"] == "dpop+jwt"
      refute Map.has_key?(header["jwk"], "d")
    end

    test "can opt into RFC 9864's explicit Ed25519 identifier" do
      jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
      proof = Fixture.proof(jwk, "GET", "https://api.example/x", alg: "Ed25519")
      [header_b64, _, _] = String.split(proof, ".")
      header = header_b64 |> Base.url_decode64!(padding: false) |> JSON.decode!()

      assert header["alg"] == "Ed25519"

      assert {:ok, _result} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example/x"
               )
    end

    test "algorithm override retains the broader DPoP RSA allowlist" do
      jwk = JOSE.JWK.generate_key({:rsa, 2048})
      proof = Fixture.proof(jwk, "GET", "https://api.example/x", alg: "PS384")

      assert {:ok, _result} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example/x"
               )
    end

    test "binds ath to a presented access token", ctx do
      {token, _} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)

      proof = Fixture.proof(ctx.jwk, "GET", "https://api.example/thing", access_token: token)

      assert {:ok, %{ath: ath}} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example/thing",
                 access_token: token
               )

      assert ath == Attesto.DPoP.compute_ath(token)
    end

    test "carries a server nonce when given", ctx do
      proof = Fixture.proof(ctx.jwk, "GET", "https://api.example/x", nonce: "n-123")

      nonce_check = fn
        "n-123" -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:ok, _} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example/x",
                 nonce_check: nonce_check
               )
    end

    test "an overridden jti drives a replay collision", ctx do
      proof = Fixture.proof(ctx.jwk, "GET", "https://api.example/x", jti: "fixed-jti")

      seen = :ets.new(:t, [:set, :private])

      replay_check = fn jti, _ttl ->
        if :ets.insert_new(seen, {jti, true}), do: :ok, else: {:error, :replay}
      end

      opts = [http_method: "GET", http_uri: "https://api.example/x", replay_check: replay_check]

      assert {:ok, _} = Attesto.DPoP.verify_proof(proof, opts)
      assert {:error, :replay} = Attesto.DPoP.verify_proof(proof, opts)
    end
  end

  describe "invalid_proof/5" do
    test ":wrong_htm is rejected", ctx do
      proof = Fixture.invalid_proof(ctx.jwk, :wrong_htm, "GET", "https://api.example/x")

      assert {:error, :invalid_htm} =
               Attesto.DPoP.verify_proof(proof, http_method: "GET", http_uri: "https://api.example/x")
    end

    test ":wrong_htu is rejected", ctx do
      proof = Fixture.invalid_proof(ctx.jwk, :wrong_htu, "GET", "https://api.example/x")

      assert {:error, :invalid_htu} =
               Attesto.DPoP.verify_proof(proof, http_method: "GET", http_uri: "https://api.example/x")
    end

    test ":missing_ath is rejected when a token is presented", ctx do
      {token, _} = Fixture.mint_access_token(ctx.config, ctx.principal, ctx.jwk)

      proof =
        Fixture.invalid_proof(ctx.jwk, :missing_ath, "GET", "https://api.example/x", access_token: token)

      assert {:error, :missing_ath} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example/x",
                 access_token: token
               )
    end

    test ":expired is rejected", ctx do
      proof = Fixture.invalid_proof(ctx.jwk, :expired, "GET", "https://api.example/x")

      assert {:error, :proof_expired} =
               Attesto.DPoP.verify_proof(proof, http_method: "GET", http_uri: "https://api.example/x")
    end
  end
end
