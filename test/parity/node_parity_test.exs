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
end
