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
  # module self-skips when Node or `jose` is unavailable rather than failing
  # the suite.

  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Test.NodeBridge

  @moduletag :parity

  setup_all do
    case NodeBridge.availability() do
      :ok ->
        %{node_ready: true}

      {:skip, reason} ->
        # ExUnit does not honor a `skip` set from setup (tags are resolved
        # before setup runs), so gate each test body on this flag instead -
        # a machine without Node/jose passes trivially rather than failing.
        IO.puts("\n[node parity] skipped - #{reason}")
        %{node_ready: false}
    end
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

  # FAPI 2 mandates PS256 and also permits ES256 / EdDSA (RS256 is excluded).
  # Prove Attesto mints each of the FAPI signing algorithms to wire that the
  # JS `jose` verifier accepts and decodes identically.
  describe "FAPI algorithm parity (Attesto -> JS jose)" do
    for alg <- ~w(PS256 ES256 EdDSA) do
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

      {:ok, config: config, priv_jwk: priv_jwk, now: now, base: base}
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
end
