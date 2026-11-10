defmodule Attesto.JwkSetAsJwkTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialProof
  alias Attesto.Did
  alias Attesto.DPoP
  alias Attesto.JWS
  alias Attesto.Key
  alias Attesto.SigningAlg
  alias Attesto.Thumbprint

  @http_uri "https://rs.example/resource"

  defp ec_pem do
    {_meta, pem} = {:ec, "P-256"} |> JOSE.JWK.generate_key() |> JOSE.JWK.to_pem()
    pem
  end

  defp public_map(pem) do
    {_meta, public} = pem |> Key.signing_jwk() |> JOSE.JWK.to_public_map()
    public
  end

  # JOSE does not terminate on some of these inputs, so every call under test
  # runs in a task that is killed when it overruns.
  defp bounded(fun) do
    task = Task.async(fun)

    case Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      nil -> flunk("call did not return within 2 seconds")
    end
  end

  defp dpop_proof(signing_pem, jwk) do
    JWS.sign_compact(signing_pem, %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => jwk}, %{
      "htm" => "GET",
      "htu" => @http_uri,
      "iat" => System.system_time(:second),
      "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    })
  end

  defp set_shapes(public) do
    [
      {"a keys member beside kty", Map.put(public, "keys", [public])},
      {"an empty keys member beside kty", Map.put(public, "keys", [])},
      {"a nested empty set beside kty", Map.put(public, "keys", [%{"keys" => []}])},
      {"only a keys member", %{"keys" => [public]}},
      {"only an empty keys member", %{"keys" => []}}
    ]
  end

  describe "DPoP.verify_proof/2" do
    test "refuses a proof whose jwk names one key and carries the signing key in keys" do
      victim = public_map(ec_pem())
      attacker_pem = ec_pem()
      attacker = public_map(attacker_pem)

      proof = dpop_proof(attacker_pem, Map.put(victim, "keys", [attacker]))

      assert {:error, _reason} =
               bounded(fn -> DPoP.verify_proof(proof, http_method: "GET", http_uri: @http_uri) end)
    end

    test "refuses a proof whose jwk is a JWK Set" do
      pem = ec_pem()

      for {_label, shape} <- set_shapes(public_map(pem)) do
        proof = dpop_proof(pem, shape)

        assert {:error, _reason} =
                 bounded(fn -> DPoP.verify_proof(proof, http_method: "GET", http_uri: @http_uri) end)
      end
    end

    test "still accepts a proof signed by the key in jwk" do
      pem = ec_pem()
      public = public_map(pem)
      {:ok, jkt} = Thumbprint.of_jwk(public)

      assert {:ok, %{jkt: ^jkt}} =
               DPoP.verify_proof(dpop_proof(pem, public), http_method: "GET", http_uri: @http_uri)
    end
  end

  describe "CredentialProof.verify_jwt/2" do
    test "returns an error for a jwk header that is a JWK Set" do
      pem = ec_pem()

      for {_label, shape} <- set_shapes(public_map(pem)) do
        proof =
          JWS.sign_compact(pem, %{"alg" => "ES256", "typ" => "openid4vci-proof+jwt", "jwk" => shape}, %{
            "aud" => "https://issuer.example",
            "iat" => System.system_time(:second),
            "nonce" => "n1"
          })

        assert {:error, _reason} =
                 bounded(fn ->
                   CredentialProof.verify_jwt(proof, issuer: "https://issuer.example", nonce: "n1")
                 end)
      end
    end
  end

  describe "JWS.verify_trusted/4" do
    setup do
      pem = ec_pem()
      other_pem = ec_pem()
      jwt = JWS.sign_compact(pem, %{"alg" => "ES256"}, %{"sub" => "alice"})
      %{jwt: jwt, signer: public_map(pem), other: public_map(other_pem)}
    end

    test "does not verify against the keys carried by a single JWK", ctx do
      keys = Map.put(ctx.other, "keys", [ctx.signer])

      assert {:error, :invalid_signature} =
               bounded(fn -> JWS.verify_trusted(ctx.jwt, %{"alg" => "ES256"}, keys, alg: "ES256") end)
    end

    test "still verifies against a JWK Set, a list of JWKs and one JWK", ctx do
      for keys <- [%{"keys" => [ctx.other, ctx.signer]}, [ctx.other, ctx.signer], ctx.signer] do
        assert {:ok, %{"sub" => "alice"}} =
                 JWS.verify_trusted(ctx.jwt, %{"alg" => "ES256"}, keys, alg: "ES256")
      end
    end
  end

  describe "single-JWK functions given a JWK Set" do
    setup do
      %{shapes: set_shapes(public_map(ec_pem()))}
    end

    test "Key.single_jwk_map?/1 is false", ctx do
      for {label, shape} <- ctx.shapes do
        refute Key.single_jwk_map?(shape), label
      end

      refute Key.single_jwk_map?(%{"kty" => 1})
      refute Key.single_jwk_map?("EC")
      assert Key.single_jwk_map?(public_map(ec_pem()))
    end

    test "Key.verification_jwk/2 returns :malformed_jwk", ctx do
      for {label, shape} <- ctx.shapes do
        assert {:error, :malformed_jwk} == bounded(fn -> Key.verification_jwk(shape, alg: "ES256") end),
               label
      end
    end

    test "Thumbprint.of_jwk/1 returns :malformed_jwk for a map and for a parsed set", ctx do
      for {label, shape} <- ctx.shapes do
        assert {:error, :malformed_jwk} == bounded(fn -> Thumbprint.of_jwk(shape) end), label
      end

      public = public_map(ec_pem())

      for shape <- [%{"keys" => [public]}, Map.put(public, "keys", [public])] do
        parsed = JOSE.JWK.from_map(shape)
        assert {:error, :malformed_jwk} == bounded(fn -> Thumbprint.of_jwk(parsed) end)
      end
    end

    test "SigningAlg.infer/1 raises for a parsed set" do
      public = public_map(ec_pem())

      for shape <- [%{"keys" => [public]}, Map.put(public, "keys", [public])] do
        parsed = JOSE.JWK.from_map(shape)

        result =
          bounded(fn ->
            try do
              SigningAlg.infer(parsed)
            rescue
              error in ArgumentError -> {:raised, Exception.message(error)}
            end
          end)

        assert {:raised, message} = result
        assert message =~ "not a JWK Set"
      end
    end

    test "Did.resolve/2 refuses a did:jwk that encodes a set", ctx do
      for {label, shape} <- ctx.shapes do
        did = "did:jwk:" <> Base.url_encode64(JSON.encode!(shape), padding: false)
        assert {:error, _reason} = bounded(fn -> Did.resolve(did) end), label
      end
    end
  end
end
