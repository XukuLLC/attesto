defmodule Attesto.KeyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Key

  defp public_map(key) do
    {_, jwk_map} = JOSE.JWK.to_public_map(key)
    jwk_map
  end

  describe "verification_jwk/2" do
    test "accepts a public verification key with consistent signing metadata" do
      jwk_map =
        JOSE.JWK.generate_key({:ec, "P-256"})
        |> public_map()
        |> Map.merge(%{"alg" => "ES256", "key_ops" => ["verify"], "use" => "sig"})

      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: "ES256")
    end

    test "rejects every private JWK member before parsing" do
      public_map = JOSE.JWK.generate_key({:ec, "P-256"}) |> public_map()

      for member <- ~w(d p q dp dq qi oth k) do
        assert {:error, :private_material} =
                 Key.verification_jwk(Map.put(public_map, member, "private"), alg: "ES256")
      end
    end

    test "can explicitly allow private material for non-boundary callers" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, private_map} = JOSE.JWK.to_map(key)

      assert {:ok, %JOSE.JWK{}} =
               Key.verification_jwk(private_map, alg: "ES256", require_public?: false)
    end

    test "rejects encryption use and key operations that omit verify" do
      public_map = JOSE.JWK.generate_key({:ec, "P-256"}) |> public_map()

      assert {:error, :invalid_use} =
               Key.verification_jwk(Map.put(public_map, "use", "enc"), alg: "ES256")

      assert {:error, :invalid_use} =
               Key.verification_jwk(Map.put(public_map, "key_ops", ["sign"]), alg: "ES256")

      assert {:error, :invalid_use} =
               Key.verification_jwk(Map.put(public_map, "key_ops", "verify"), alg: "ES256")
    end

    test "rejects a JWK alg inconsistent with the protected header alg" do
      jwk_map =
        JOSE.JWK.generate_key({:ec, "P-256"})
        |> public_map()
        |> Map.put("alg", "ES384")

      assert {:error, :alg_mismatch} = Key.verification_jwk(jwk_map, alg: "ES256")
    end

    test "rejects malformed JWK material" do
      assert {:error, :malformed_jwk} =
               Key.verification_jwk(%{}, alg: "RS256")
    end

    test "rejects RSA keys below the default minimum" do
      jwk_map = JOSE.JWK.generate_key({:rsa, 1024}) |> public_map()

      assert {:error, :weak_key} = Key.verification_jwk(jwk_map, alg: "RS256")
      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: "RS256", minimum_rsa_bits: 1024)
    end

    test "rejects explicit Edwards algorithms on the wrong curve" do
      jwk_map = JOSE.JWK.generate_key({:okp, :Ed25519}) |> public_map()

      assert {:error, :incompatible_key} = Key.verification_jwk(jwk_map, alg: "Ed448")
    end

    test "leaves other key-type and algorithm mismatches to signature verification" do
      jwk_map = JOSE.JWK.generate_key({:ec, "P-256"}) |> public_map()

      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: "RS256")
    end
  end
end
