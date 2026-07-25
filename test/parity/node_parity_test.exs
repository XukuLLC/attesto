defmodule Attesto.Parity.NodeParityTest do
  @moduledoc false
  # JavaScript cross-language CONTRACT parity: prove that artifacts Attesto
  # produces (and accepts) are bit-compatible with the reference JS `jose`
  # library - the largest JWT ecosystem. This is the JavaScript counterpart to
  # `CrossLanguageParityTest`'s Python legs (joserfc / cryptography): a real
  # third-party JS verifier decoding Attesto's tokens, thumbprints, and proofs,
  # driven through `Attesto.Test.NodeBridge` (a persistent Node worker pool).
  #
  # The reference helpers live in `test/support/js/attesto_compat.js`. The
  # tests receive a visible ExUnit skip tag when Node or `jose` is unavailable
  # rather than silently passing without exercising their assertions.

  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Test.NodeBridge

  @moduletag :parity

  case NodeBridge.availability() do
    :ok ->
      @moduletag node_ready: true

    {:skip, reason} ->
      @moduletag node_ready: false
      @moduletag skip: "Node/jose parity unavailable: #{reason}"
  end

  describe "JWT verify parity (Attesto RS256 -> JS jose)" do
    test "an Attesto-minted token decodes to identical claims in jose", %{node_ready: ready} do
      if ready do
        pem = Factory.rsa_pem()
        config = Factory.config(pem)
        public_pem = Attesto.Key.public_pem(pem)

        {:ok, token} =
          Attesto.Token.mint(config, %{
            kind: "client",
            sub: "oc_live_parity",
            scopes: ["documents.read", "documents.write"],
            claims: %{"client_id" => "oc_live_parity"}
          })

        %{"payload" => payload, "header" => header} =
          NodeBridge.call!("attesto_compat", :verifyJwt, [
            token.access_token,
            public_pem,
            "RS256"
          ])

        assert payload["sub"] == "oc_live_parity"
        assert payload["iss"] == "https://api.example.com/"
        assert payload["scope"] == "documents.read documents.write"
        assert header["alg"] == "RS256"

        # jose agrees with Attesto's own verifier on the load-bearing claims.
        {:ok, attesto_claims} = Attesto.Token.verify(config, token.access_token)

        for key <- ["sub", "iss", "scope"] do
          assert payload[key] == attesto_claims[key]
        end
      end
    end
  end

  describe "thumbprint parity (Attesto compute_jkt -> jose RFC 7638)" do
    test "an EC P-256 JWK yields the same RFC 7638 thumbprint in both stacks", %{node_ready: ready} do
      if ready do
        jwk = JOSE.JWK.generate_key({:ec, "P-256"})
        {_, public_map} = JOSE.JWK.to_public_map(jwk)

        attesto_jkt = Attesto.DPoP.compute_jkt(jwk)
        jose_jkt = NodeBridge.call!("attesto_compat", :jwkThumbprint, [public_map])

        assert attesto_jkt == jose_jkt
      end
    end
  end

  # FAPI 2 mandates PS256 and also permits ES256 / EdDSA over Ed25519 plus
  # RFC 9864's exact Ed25519 identifier (RS256 and Ed448 are excluded).
  # Prove Attesto mints each of the FAPI signing algorithms to wire that the
  # JS `jose` verifier accepts and decodes identically.
  describe "FAPI algorithm parity (Attesto -> JS jose)" do
    for alg <- ~w(PS256 ES256 EdDSA Ed25519) do
      test "an Attesto-minted #{alg} token verifies in jose with identical claims",
           %{node_ready: ready} do
        if ready do
          alg = unquote(alg)
          pem = alg_pem(alg)
          config = Factory.config(pem, signing_alg: alg, key_algs: %{Attesto.Key.kid(pem) => alg})
          # jose's importSPKI needs SPKI: Attesto.Key.public_pem gives that for
          # RSA (PS256); JOSE gives SPKI for the EC/OKP public keys.
          public_pem =
            if alg == "PS256", do: Attesto.Key.public_pem(pem), else: jose_public_pem(pem)

          {:ok, token} =
            Attesto.Token.mint(config, %{
              kind: "client",
              sub: "oc_fapi_#{String.downcase(alg)}",
              scopes: ["documents.read"],
              claims: %{"client_id" => "oc_fapi"}
            })

          %{"payload" => payload, "header" => header} =
            NodeBridge.call!("attesto_compat", :verifyJwt, [token.access_token, public_pem, alg])

          assert header["alg"] == alg
          assert payload["sub"] == "oc_fapi_#{String.downcase(alg)}"

          {:ok, attesto_claims} = Attesto.Token.verify(config, token.access_token)
          assert payload["sub"] == attesto_claims["sub"]
        end
      end
    end
  end

  # Apply OIDC's generic hash-claim rule to RFC 8032's hash functions and
  # cross-check the result outside the Elixir/JOSE implementation. Ed448 is
  # intentionally included here even though FAPI 2 excludes that curve.
  describe "Edwards OIDC hash parity (Attesto -> Node crypto)" do
    for {alg, curve} <- [
          {"EdDSA", "Ed25519"},
          {"EdDSA", "Ed448"},
          {"Ed25519", "Ed25519"},
          {"Ed448", "Ed448"}
        ] do
      test "an #{alg}/#{curve} ID Token at_hash matches the independent JS OIDC calculation",
           %{node_ready: ready} do
        if ready do
          alg = unquote(alg)
          curve = unquote(curve)
          maybe_enable_ed448(curve)
          pem = if curve == "Ed448", do: Factory.ed448_pem(), else: Factory.ed_pem()
          config_opts = if alg in ["Ed25519", "Ed448"], do: [signing_alg: alg], else: []
          config = Factory.config(pem, config_opts)
          access_token = "#{String.downcase(alg)}-#{String.downcase(curve)}-reference-access-token"

          assert {:ok, jwt} =
                   Attesto.IDToken.mint(config, "usr_#{String.downcase(curve)}", "client-#{String.downcase(curve)}",
                     access_token: access_token
                   )

          verifier = if alg == "Ed448", do: :verifyEdwardsJwt, else: :verifyJwt

          verifier_args =
            if alg == "Ed448", do: [jwt, jose_public_pem(pem)], else: [jwt, jose_public_pem(pem), alg]

          %{"payload" => payload, "header" => header} =
            NodeBridge.call!("attesto_compat", verifier, verifier_args)

          expected = NodeBridge.call!("attesto_compat", :oidcHash, [access_token, alg, curve])

          assert header["alg"] == alg
          assert payload["at_hash"] == expected
        end
      end
    end
  end

  # The signed FAPI artifacts Attesto emits are ordinary compact JWS: prove a
  # third-party JS verifier accepts each and decodes the artifact-specific
  # claims (the event object, the RFC 7662 body, the authorization params).
  describe "FAPI artifact parity (Attesto -> JS jose)" do
    test "a back-channel logout token verifies in jose with its event claim intact",
         %{node_ready: ready} do
      if ready do
        pem = Factory.rsa_pem()
        config = Factory.config(pem)
        public_pem = Attesto.Key.public_pem(pem)

        {:ok, jwt} = Attesto.LogoutToken.mint(config, "client-123", sub: "usr_1", sid: "sess-9")

        %{"payload" => p, "header" => h} =
          NodeBridge.call!("attesto_compat", :verifyJwt, [jwt, public_pem, "RS256"])

        assert h["alg"] == "RS256"
        assert p["aud"] == "client-123"
        assert p["sub"] == "usr_1"
        assert p["sid"] == "sess-9"
        # Back-Channel Logout 1.0 §2.4: the events claim names the event -> {}.
        assert p["events"] == %{"http://schemas.openid.net/event/backchannel-logout" => %{}}
        # §2.4: a logout token MUST NOT contain a nonce.
        refute Map.has_key?(p, "nonce")
      end
    end

    test "a signed introspection response verifies in jose and wraps the RFC 7662 body",
         %{node_ready: ready} do
      if ready do
        pem = Factory.rsa_pem()
        config = Factory.config(pem)
        public_pem = Attesto.Key.public_pem(pem)
        body = %{"active" => true, "scope" => "documents.read", "client_id" => "c", "sub" => "usr_1"}

        {:ok, jwt} = Attesto.SignedIntrospection.response_jwt(config, "rs-audience", body)

        %{"payload" => p, "header" => h} =
          NodeBridge.call!("attesto_compat", :verifyJwt, [jwt, public_pem, "RS256"])

        # RFC 9701 §5: the explicit media type on the header.
        assert h["typ"] == "token-introspection+jwt"
        assert p["aud"] == "rs-audience"
        assert p["token_introspection"] == body
      end
    end

    test "a JARM authorization response verifies in jose with the response params",
         %{node_ready: ready} do
      if ready do
        pem = Factory.rsa_pem()
        config = Factory.config(pem)
        public_pem = Attesto.Key.public_pem(pem)

        {:ok, jwt} = Attesto.JARM.response_jwt(config, "client-123", %{"code" => "abc", "state" => "xyz"})

        %{"payload" => p} =
          NodeBridge.call!("attesto_compat", :verifyJwt, [jwt, public_pem, "RS256"])

        assert p["aud"] == "client-123"
        assert p["code"] == "abc"
        assert p["state"] == "xyz"
      end
    end

    test "an mTLS cnf.x5t#S256 matches an independent JS SHA-256 over the cert DER",
         %{node_ready: ready} do
      if ready do
        %{cert: der} = :public_key.pkix_test_root_cert(~c"cn=attesto-parity", [])

        {:ok, attesto_x5t} = Attesto.MTLS.compute_thumbprint(der)
        js_x5t = NodeBridge.call!("attesto_compat", :x5tS256, [Base.encode64(der)])

        assert attesto_x5t == js_x5t
      end
    end
  end

  # The bug-rich direction: a fully independent JS issuer/client produces the
  # artifacts and Attesto's verifiers must accept the valid ones and reject the
  # adversarial ones (typ confusion, tampered signature).
  describe "inbound + adversarial parity (JS jose -> Attesto verifier)" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {_meta, priv_jwk} = pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()
      now = System.system_time(:second)

      base = %{
        "iss" => config.issuer,
        "sub" => "usr_js",
        "aud" => "client-js",
        "iat" => now,
        "exp" => now + 3600,
        "nonce" => "n-js"
      }

      {:ok, config: config, priv_jwk: priv_jwk, public_pem: Attesto.Key.public_pem(pem), now: now, base: base}
    end

    test "a jose-signed ID Token verifies in Attesto", ctx do
      if ctx.node_ready do
        id_token = NodeBridge.call!("attesto_compat", :signJwtJwk, [ctx.base, ctx.priv_jwk, "RS256", "JWT"])

        assert {:ok, verified} =
                 Attesto.IDToken.verify(ctx.config, id_token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )

        assert verified["sub"] == "usr_js"
      end
    end

    test "a jose-signed at+jwt typ is rejected as an ID Token", ctx do
      if ctx.node_ready do
        token = NodeBridge.call!("attesto_compat", :signJwtJwk, [ctx.base, ctx.priv_jwk, "RS256", "at+jwt"])

        assert {:error, :unexpected_typ} =
                 Attesto.IDToken.verify(ctx.config, token, client_id: "client-js", now: ctx.now)
      end
    end

    test "jose-signed resource audiences obey Attesto's explicit trust policy", ctx do
      if ctx.node_ready do
        resource_a = "https://resource.example/a"
        resource_b = "https://resource.example/b"

        base_claims = %{
          "iss" => ctx.config.issuer,
          "sub" => "oc_js_resource",
          "iat" => ctx.now,
          "exp" => ctx.now + 3600,
          "jti" => "js-resource-token",
          "scope" => "documents.read",
          "principal_kind" => "client",
          "typ" => "access",
          "client_id" => "oc_js_resource"
        }

        scalar_claims = Map.put(base_claims, "aud", resource_a)

        scalar =
          NodeBridge.call!("attesto_compat", :signJwtJwk, [
            scalar_claims,
            ctx.priv_jwk,
            "RS256",
            "at+jwt"
          ])

        assert {:ok, %{"aud" => ^resource_a}} =
                 Attesto.Token.verify(ctx.config, scalar,
                   now: ctx.now,
                   trusted_audiences: [resource_a]
                 )

        multiple_claims = Map.put(base_claims, "aud", [resource_a, resource_b])

        multiple =
          NodeBridge.call!("attesto_compat", :signJwtJwk, [
            multiple_claims,
            ctx.priv_jwk,
            "RS256",
            "at+jwt"
          ])

        assert {:ok, %{"aud" => [^resource_a, ^resource_b]}} =
                 Attesto.Token.verify(ctx.config, multiple,
                   now: ctx.now,
                   trusted_audiences: [resource_a, resource_b]
                 )

        assert {:error, :invalid_audience} =
                 Attesto.Token.verify(ctx.config, multiple,
                   now: ctx.now,
                   trusted_audiences: [resource_a]
                 )
      end
    end

    test "a jose-signed ID Token with a tampered signature is rejected", ctx do
      if ctx.node_ready do
        id_token = NodeBridge.call!("attesto_compat", :signJwtJwk, [ctx.base, ctx.priv_jwk, "RS256", "JWT"])
        [h, p, s] = String.split(id_token, ".")
        flipped = if String.first(s) == "a", do: "b", else: "a"
        tampered = "#{h}.#{p}.#{flipped}#{String.slice(s, 1..-1//1)}"

        assert {:error, reason} =
                 Attesto.IDToken.verify(ctx.config, tampered,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )

        assert reason == :invalid_signature
      end
    end

    test "a jose alg:none ID Token is rejected on alg grounds", ctx do
      if ctx.node_ready do
        token = NodeBridge.call!("attesto_compat", :signAlgNone, [ctx.base, "JWT"])

        # :invalid_signature (not a claim error) proves the alg pinning fired
        # before any claim was trusted - an alg != RS256 has no trusted key.
        assert {:error, :invalid_signature} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )
      end
    end

    test "an HS256 alg-confusion token (public key as HMAC secret) is rejected on alg grounds", ctx do
      if ctx.node_ready do
        # The classic RS256->HS256 attack: sign HS256 using the server's own
        # RSA public key bytes as the shared secret. Attesto pins asymmetric
        # algs, so no trusted key matches -> :invalid_signature, never accepted.
        secret = Base.encode64(ctx.public_pem)
        token = NodeBridge.call!("attesto_compat", :signHs256, [ctx.base, secret, "JWT"])

        assert {:error, :invalid_signature} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )
      end
    end

    test "a jose-signed ID Token with the wrong issuer is rejected", ctx do
      if ctx.node_ready do
        claims = %{ctx.base | "iss" => "https://evil.example/"}
        token = NodeBridge.call!("attesto_compat", :signJwtJwk, [claims, ctx.priv_jwk, "RS256", "JWT"])

        assert {:error, _reason} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )
      end
    end

    test "a jose-signed ID Token for a different audience is rejected", ctx do
      if ctx.node_ready do
        claims = %{ctx.base | "aud" => "some-other-client"}
        token = NodeBridge.call!("attesto_compat", :signJwtJwk, [claims, ctx.priv_jwk, "RS256", "JWT"])

        assert {:error, _reason} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )
      end
    end

    test "a jose-signed expired ID Token is rejected", ctx do
      if ctx.node_ready do
        claims = %{ctx.base | "exp" => ctx.now - 30, "iat" => ctx.now - 3600}
        token = NodeBridge.call!("attesto_compat", :signJwtJwk, [claims, ctx.priv_jwk, "RS256", "JWT"])

        assert {:error, _reason} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "n-js",
                   now: ctx.now
                 )
      end
    end

    test "a jose-signed ID Token with a mismatched nonce is rejected", ctx do
      if ctx.node_ready do
        token = NodeBridge.call!("attesto_compat", :signJwtJwk, [ctx.base, ctx.priv_jwk, "RS256", "JWT"])

        assert {:error, _reason} =
                 Attesto.IDToken.verify(ctx.config, token,
                   client_id: "client-js",
                   nonce: "a-different-nonce",
                   now: ctx.now
                 )
      end
    end

    test "a jose ES256 DPoP proof verifies in Attesto with the matching jkt", ctx do
      if ctx.node_ready do
        htu = "https://api.example.com/oauth/token"
        jti = "parity-#{System.unique_integer([:positive])}"

        %{"proof" => proof, "jkt" => js_jkt} =
          NodeBridge.call!("attesto_compat", :buildDpopProof, ["POST", htu, ctx.now, jti])

        assert {:ok, verified} =
                 Attesto.DPoP.verify_proof(proof, http_method: "POST", http_uri: htu, now: ctx.now)

        assert verified.jkt == js_jkt
        assert verified.htu == htu
        assert verified.jti == jti
      end
    end
  end

  defp alg_pem("PS256"), do: Factory.rsa_pem()
  defp alg_pem("ES256"), do: Factory.ec_pem()
  defp alg_pem("EdDSA"), do: Factory.ed_pem()
  defp alg_pem("Ed25519"), do: Factory.ed_pem()

  defp jose_public_pem(pem) do
    pem
    |> JOSE.JWK.from_pem()
    |> JOSE.JWK.to_public()
    |> JOSE.JWK.to_pem()
    |> case do
      {_meta, public_pem} when is_binary(public_pem) -> public_pem
      public_pem when is_binary(public_pem) -> public_pem
    end
  end

  defp maybe_enable_ed448("Ed25519"), do: :ok

  defp maybe_enable_ed448("Ed448") do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end
