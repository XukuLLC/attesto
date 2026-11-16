defmodule Attesto.KeyPolicyTest do
  use ExUnit.Case, async: true

  alias Attesto.DPoP.Proof
  alias Attesto.{JWS, Key}

  test "missing identifiers are checked against every original key entry" do
    public = JOSE.JWK.generate_key({:ec, "P-256"}) |> Key.public_map() |> Map.put("kid", "one")
    other = Map.put(public, "use", "enc")
    opts = [presented_alg: "ES256", require_kid: :multiple]
    assert [_] = JWS.verification_candidates([public], opts)
    assert [] = JWS.verification_candidates([public, other], opts)
    assert [_] = JWS.verification_candidates([public, other], Keyword.put(opts, :kid, "one"))
    assert {:error, :missing_kid} = Key.validate_kid([public], nil, require_kid: true)
    assert :ok = Key.validate_kid([public, other], nil)
    assert_raise ArgumentError, fn -> Key.validate_kid([public], nil, require_kid: :invalid) end
  end

  test "PEM import distinguishes malformed input from unsupported curves" do
    {_, pem} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem()
    assert {:ok, %JOSE.JWK{}} = Key.import_pem(pem)

    for input <- [
          nil,
          [],
          "",
          "private-key-bytes",
          "-----BEGIN PRIVATE KEY-----\nbad\n-----END PRIVATE KEY-----",
          pem <> pem
        ] do
      assert {:error, :malformed_key} = Key.import_pem(input)
    end

    {_, unsupported} = JOSE.JWK.generate_key({:ec, "secp256k1"}) |> JOSE.JWK.to_pem()
    assert {:error, :unsupported_key} = Key.import_pem(unsupported)
    {_, unsupported_type} = JOSE.JWK.generate_key({:okp, :X25519}) |> JOSE.JWK.to_pem()
    assert {:error, :unsupported_key} = Key.import_pem(unsupported_type)

    malformed = {:ECPrivateKey, 1, <<>>, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}, :asn1_NOVALUE, :asn1_NOVALUE}
    malformed_pem = :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, malformed)])
    assert {:error, :malformed_key} = Key.import_pem(malformed_pem)
  end

  test "signing usage is independent of derived public verification usage" do
    {_, fields} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map()

    for ops <- [:absent, ["sign"], ["sign", "verify"]] do
      input = if ops == :absent, do: fields, else: Map.put(fields, "key_ops", ops)

      for key <- [input, JOSE.JWK.from_map(input)] do
        jwk = Key.signing_jwk(key)
        public = Key.public_map(jwk)
        refute Map.has_key?(public, "key_ops")
        assert {:ok, verified} = Key.verification_jwk(public, alg: "ES256")
        jwt = JWS.sign_compact_jwk(jwk, %{"alg" => "ES256"}, %{"test" => true})
        assert {true, _, _} = JOSE.JWS.verify_strict(verified, ["ES256"], jwt)
      end
    end

    for ops <- [[], ["verify"], ["sign", 7], nil, "sign"] do
      key = JOSE.JWK.from_map(Map.put(fields, "key_ops", ops))
      assert_raise ArgumentError, fn -> Key.signing_jwk(key) end
      assert_raise ArgumentError, fn -> JWS.sign_compact_jwk(key, %{"alg" => "ES256"}, %{}) end
    end

    public = fields |> Key.public_map() |> Map.put("key_ops", ["sign"])
    assert Key.public_map(public)["key_ops"] == ["sign"]
    assert {:error, :invalid_use} = Key.verification_jwk(public, alg: "ES256")
    assert_raise ArgumentError, fn -> fields |> Map.put("use", "enc") |> Key.signing_jwk() end
  end

  test "DPoP signing-only keys produce proofs accepted by the core verifier" do
    {_, fields} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map()
    key = Map.put(fields, "key_ops", ["sign"])
    assert {:ok, proof} = Proof.build(key, "POST", "https://issuer.example/token")
    assert {:ok, _} = Attesto.DPoP.verify_proof(proof, http_method: "POST", http_uri: "https://issuer.example/token")

    assert {:error, {:signing_failed, "signing operation failed"}} =
             Proof.build(Map.put(key, "key_ops", ["verify"]), "POST", "https://issuer.example/token")
  end
end
