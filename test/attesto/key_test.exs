defmodule Attesto.KeyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Key

  defp public_map(key) do
    {_, jwk_map} = JOSE.JWK.to_public_map(key)
    jwk_map
  end

  describe "public_pem/1" do
    test "normalizes malformed DER decoder failures to ArgumentError" do
      malformed = "-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----\n"

      assert_raise ArgumentError, fn -> Key.public_pem(malformed) end
    end
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

    test "rejects a present null use, key_ops, or alg instead of treating it as omitted" do
      public_map = JOSE.JWK.generate_key({:ec, "P-256"}) |> public_map()

      assert {:error, :invalid_use} = Key.verification_jwk(Map.put(public_map, "use", nil), alg: "ES256")
      assert {:error, :invalid_use} = Key.verification_jwk(Map.put(public_map, "key_ops", nil), alg: "ES256")
      assert {:error, :alg_mismatch} = Key.verification_jwk(Map.put(public_map, "alg", nil), alg: "ES256")
      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(public_map, alg: "ES256")
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

    test "accepts generated NIST curve verification keys" do
      for {curve, alg} <- [{"P-256", "ES256"}, {"P-384", "ES384"}, {"P-521", "ES512"}] do
        jwk_map = JOSE.JWK.generate_key({:ec, curve}) |> public_map()
        assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: alg)
      end
    end

    test "requires an EC point on the curve with full-width field coordinates" do
      {{:prime_field, prime_bytes}, {_, b, _}, _, _, _} = :crypto.ec_curve(:secp256r1)
      prime = :binary.decode_unsigned(prime_bytes)
      y = :crypto.mod_pow(b, div(prime + 1, 4), prime)
      zero = Base.url_encode64(<<0::256>>, padding: false)

      jwk_map = %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => zero,
        "y" => Base.url_encode64(y, padding: false)
      }

      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: "ES256")

      for invalid <- [
            Map.put(jwk_map, "y", zero),
            Map.put(jwk_map, "x", Base.url_encode64(prime_bytes, padding: false)),
            Map.put(jwk_map, "x", Base.url_encode64(<<0>>, padding: false))
          ] do
        assert {:error, :malformed_jwk} = Key.verification_jwk(invalid, alg: "ES256")
      end
    end

    test "requires canonical Ed25519 and Ed448 verification keys" do
      for {curve, size, prime} <- [
            {:Ed25519, 256, Bitwise.bsl(1, 255) - 19},
            {:Ed448, 456, Bitwise.bsl(1, 448) - Bitwise.bsl(1, 224) - 1}
          ] do
        alg = Atom.to_string(curve)
        jwk_map = JOSE.JWK.generate_key({:okp, curve}) |> public_map()
        assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: alg)

        sign_bit = Bitwise.bsl(1, size - 1)

        for value <- [prime, sign_bit + 1, sign_bit + prime - 1] do
          encoded = Base.url_encode64(<<value::little-size(size)>>, padding: false)
          assert {:error, :malformed_jwk} = Key.verification_jwk(Map.put(jwk_map, "x", encoded), alg: alg)
        end
      end
    end

    test "accepts ES256K with a secp256k1 verification key" do
      jwk_map = JOSE.JWK.generate_key({:ec, "secp256k1"}) |> public_map()

      assert {:ok, %JOSE.JWK{}} = Key.verification_jwk(jwk_map, alg: "ES256K")
      assert {:error, :incompatible_key} = Key.verification_jwk(jwk_map, alg: "ES256")
    end

    test "rejects every key-type and algorithm mismatch before signature verification" do
      jwk_map = JOSE.JWK.generate_key({:ec, "P-256"}) |> public_map()

      assert {:error, :incompatible_key} = Key.verification_jwk(jwk_map, alg: "RS256")
    end
  end

  describe "EC curve parameters" do
    test "the curve-equation constants match OTP's curve data" do
      for {crv, otp_curve} <- [
            {"P-256", :secp256r1},
            {"P-384", :secp384r1},
            {"P-521", :secp521r1},
            {"secp256k1", :secp256k1}
          ] do
        {{:prime_field, prime}, {a, b, _seed}, _generator, _order, _cofactor} = :crypto.ec_curve(otp_curve)

        assert Map.fetch!(Key.verification_ec_curve_parameters(), crv) ==
                 {byte_size(prime), :binary.decode_unsigned(prime), :binary.decode_unsigned(a),
                  :binary.decode_unsigned(b)}
      end
    end
  end
end
