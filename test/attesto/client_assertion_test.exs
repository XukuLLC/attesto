defmodule Attesto.ClientAssertionTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.ClientAssertion

  @client_id "client-123"
  @audience "https://issuer.example/oauth/token"

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256"}, overrides))
  end

  defp assertion(jwk, overrides \\ %{}, alg \\ "ES256") do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "sub" => @client_id,
          "aud" => @audience,
          "iat" => now,
          "exp" => now + 60,
          "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
        },
        overrides
      )

    header = %{"alg" => alg, "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  test "verifies a valid private_key_jwt assertion against a trusted JWK" do
    key = ec_key()
    jwt = assertion(key)

    assert {:ok, claims} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [public_jwk(key)]})

    assert claims["iss"] == @client_id
    assert claims["sub"] == @client_id
  end

  test "keeps zero expiry leeway and 60-second future iat skew" do
    key = ec_key()
    now = 1_700_000_000
    trusted = %{"keys" => [public_jwk(key)]}

    assert {:error, :expired} =
             ClientAssertion.verify(
               assertion(key, %{"iat" => now, "exp" => now}),
               @client_id,
               @audience,
               trusted,
               now: now
             )

    assert {:ok, _} =
             ClientAssertion.verify(
               assertion(key, %{"iat" => now + 60, "exp" => now + 300}),
               @client_id,
               @audience,
               trusted,
               now: now
             )

    assert {:error, :not_yet_valid} =
             ClientAssertion.verify(
               assertion(key, %{"iat" => now + 61, "exp" => now + 300}),
               @client_id,
               @audience,
               trusted,
               now: now
             )
  end

  test "rejects the whole trusted set when one candidate JWK is malformed" do
    key = ec_key()
    jwt = assertion(key)

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(
               jwt,
               @client_id,
               @audience,
               %{"keys" => [public_jwk(key), %{"not" => "a jwk"}]}
             )
  end

  test "rejects alg confusion: token header alg must match the trusted key alg" do
    key = ec_key()
    jwt = assertion(key)
    jwk = public_jwk(key, %{"alg" => "RS256"})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [jwk]})
  end

  test "rejects wrong audience and missing jti" do
    key = ec_key()

    assert {:error, :invalid_audience} =
             key
             |> assertion(%{"aud" => "https://other.example/token"})
             |> ClientAssertion.verify(@client_id, @audience, %{"keys" => [public_jwk(key)]})

    assert {:error, :missing_jti} =
             key
             |> assertion(%{"jti" => ""})
             |> ClientAssertion.verify(@client_id, @audience, %{"keys" => [public_jwk(key)]})
  end

  test "rejects an array aud even when it contains the expected audience - FAPI 2 requires a single-valued aud" do
    key = ec_key()

    assert {:error, :invalid_audience} =
             key
             |> assertion(%{"aud" => [@audience, "https://other.example/token"]})
             |> ClientAssertion.verify(@client_id, @audience, %{"keys" => [public_jwk(key)]})
  end

  test "peek_client_id reads iss without trusting the assertion" do
    key = ec_key()
    assert {:ok, @client_id} = ClientAssertion.peek_client_id(assertion(key))
  end

  test "rejects an RS256-signed assertion - FAPI 2 forbids RS256 for client auth" do
    key = JOSE.JWK.generate_key({:rsa, 2048})
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "sub" => @client_id,
      "aud" => @audience,
      "iat" => now,
      "exp" => now + 60,
      "jti" => "jti-rs256"
    }

    header = %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)}
    {_header, jwt} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

    {_kty, jwk} = JOSE.JWK.to_public_map(key)
    jwk = Map.merge(jwk, %{"kid" => JOSE.JWK.thumbprint(key), "alg" => "RS256"})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [jwk]})
  end

  test "the FAPI default rejects PS256 with an RSA modulus below 2048 bits" do
    key = JOSE.JWK.generate_key({:rsa, 1024})
    jwt = assertion(key, %{}, "PS256")
    trusted = public_jwk(key, %{"alg" => "PS256"})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]})

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]},
               accepted_algs: ["PS256"],
               enforce_fapi_alg_policy: true
             )

    assert {:ok, _claims} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]}, accepted_algs: ["PS256"])
  end

  test "default :accepted_algs keeps the FAPI set (current behaviour)" do
    key = ec_key()
    jwt = assertion(key)

    assert {:ok, _claims} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [public_jwk(key)]})
  end

  test "explicitly narrowing :accepted_algs rejects an otherwise-accepted alg" do
    key = ec_key()
    jwt = assertion(key)

    assert {:error, :invalid_signature} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [public_jwk(key)]},
               accepted_algs: ["EdDSA"]
             )
  end

  test "explicit :accepted_algs including the key's alg still verifies" do
    key = ec_key()
    jwt = assertion(key)

    assert {:ok, _claims} =
             ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [public_jwk(key)]},
               accepted_algs: ["ES256"]
             )
  end

  test "the FAPI default accepts legacy EdDSA and RFC 9864 Ed25519 only over Ed25519" do
    key = JOSE.JWK.generate_key({:okp, :Ed25519})

    for alg <- ["EdDSA", "Ed25519"] do
      jwt = assertion(key, %{}, alg)
      trusted = public_jwk(key, %{"alg" => alg})

      assert {:ok, _claims} =
               ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]})
    end
  end

  test "the FAPI default rejects Ed448 but an explicit non-FAPI policy can opt in" do
    enable_ed448_support()
    key = JOSE.JWK.generate_key({:okp, :Ed448})

    for alg <- ["EdDSA", "Ed448"] do
      jwt = assertion(key, %{}, alg)
      trusted = public_jwk(key, %{"alg" => alg})

      assert {:error, :invalid_signature} =
               ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]})

      assert {:error, :invalid_signature} =
               ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]},
                 accepted_algs: [alg],
                 enforce_fapi_alg_policy: true
               )

      assert {:ok, _claims} =
               ClientAssertion.verify(jwt, @client_id, @audience, %{"keys" => [trusted]}, accepted_algs: [alg])
    end
  end

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end
