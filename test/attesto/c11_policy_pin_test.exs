defmodule Attesto.C11PolicyPinTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.CIBA.Request, as: CIBARequest
  alias Attesto.ClientAssertion
  alias Attesto.IdentityAssertion
  alias Attesto.IDToken
  alias Attesto.Key
  alias Attesto.RequestObject
  alias Attesto.Test.Factory
  alias Attesto.Token

  @client_id "client-123"
  @issuer "https://issuer.example/"
  @audience "https://issuer.example/oauth/token"
  @identity_audience "https://as.example.com"
  @ciba_issuer "https://op.example.com"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, alg \\ "ES256") do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => alg})
  end

  defp client_assertion(jwk, overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "sub" => @client_id,
          "aud" => @audience,
          "iat" => now,
          "exp" => now + 60,
          "jti" => "jti-#{System.unique_integer([:positive])}"
        },
        overrides
      )

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, jwt} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end

  test "ClientAssertion keeps scalar-only audience acceptance" do
    key = ec_key()
    trusted = %{"keys" => [public_jwk(key)]}

    assert {:ok, _claims} =
             ClientAssertion.verify(client_assertion(key), @client_id, @audience, trusted)

    assert {:error, :invalid_audience} =
             ClientAssertion.verify(
               client_assertion(key, %{"aud" => [@audience]}),
               @client_id,
               @audience,
               trusted
             )
  end

  defp identity_assertion(jwk, overrides) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => "https://idp.example.com",
          "sub" => "user-123",
          "aud" => @identity_audience,
          "client_id" => @client_id,
          "jti" => "jti-#{System.unique_integer([:positive])}",
          "exp" => now + 300,
          "iat" => now
        },
        overrides
      )

    header = %{
      "alg" => "ES256",
      "kid" => JOSE.JWK.thumbprint(jwk),
      "typ" => "oauth-id-jag+jwt"
    }

    {_header, jwt} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end

  test "IdentityAssertion accepts one-element audience arrays and rejects longer arrays" do
    key = ec_key()
    trusted = %{"keys" => [public_jwk(key)]}
    opts = [issuer: "https://idp.example.com", audience: @identity_audience, client_id: @client_id]

    assert {:ok, _claims} =
             IdentityAssertion.verify(
               identity_assertion(key, %{"aud" => [@identity_audience]}),
               trusted,
               opts
             )

    assert {:error, :invalid_audience} =
             IdentityAssertion.verify(
               identity_assertion(key, %{"aud" => [@identity_audience, "https://other.example"]}),
               trusted,
               opts
             )
  end

  test "Token and OIDC verification retain array audience acceptance", %{config: config} do
    configured_audience = config.audience

    principal = %{
      kind: "client",
      sub: "oc_abc123",
      scopes: ["documents.read"],
      claims: %{"client_id" => "oc_abc123"}
    }

    assert {:ok, %{access_token: access_token}} =
             Token.mint(config, principal, audience: [configured_audience, "https://resource.example"])

    assert {:ok, %{"aud" => [^configured_audience, "https://resource.example"]}} =
             Token.verify(config, access_token)

    id_token = signed_id_token(config, %{"aud" => [@client_id, "https://other-rp.example"]})

    assert {:ok, %{"aud" => [@client_id, "https://other-rp.example"]}} =
             IDToken.verify(config, id_token, client_id: @client_id)
  end

  defp signed_id_token(config, overrides) do
    now = System.system_time(:second)
    pem = config.keystore.signing_pem()
    jwk = Key.signing_jwk(pem)

    claims =
      Map.merge(
        %{
          "iss" => config.issuer,
          "sub" => "user-123",
          "aud" => @client_id,
          "iat" => now,
          "exp" => now + 3600
        },
        overrides
      )

    header = %{"alg" => "RS256", "kid" => Key.kid(pem), "typ" => "JWT"}
    {_header, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp request_object(jwk, header_typ) do
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "client_id" => @client_id,
      "aud" => @issuer,
      "iat" => now,
      "exp" => now + 300
    }

    header = %{
      "alg" => "ES256",
      "kid" => JOSE.JWK.thumbprint(jwk),
      "typ" => header_typ
    }

    {_header, jwt} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end

  test "RequestObject normalizes application/ typ prefixes case-insensitively" do
    key = ec_key()
    jwt = request_object(key, "APPLICATION/OAUTH-AUTHZ-REQ+JWT")
    trusted = %{"keys" => [public_jwk(key)]}

    assert {:ok, _params} =
             RequestObject.verify(
               jwt,
               trusted,
               issuer: @client_id,
               audience: @issuer,
               accepted_typ: ["oauth-authz-req+jwt"]
             )
  end

  defp ciba_request(jwk, typ) do
    now = System.system_time(:second)

    claims = %{
      "iss" => @client_id,
      "aud" => @ciba_issuer,
      "iat" => now,
      "nbf" => now,
      "exp" => now + 300,
      "jti" => "jti-#{System.unique_integer([:positive])}",
      "scope" => "openid",
      "login_hint" => "user@example.com"
    }

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    header = if is_nil(typ), do: header, else: Map.put(header, "typ", typ)
    payload = JSON.encode!(claims)
    {_header, jwt} = jwk |> JOSE.JWS.sign(payload, header) |> JOSE.JWS.compact()
    jwt
  end

  defp ciba_client(jwk) do
    %{
      client_id: @client_id,
      token_delivery_mode: :poll,
      jwks: %{"keys" => [public_jwk(jwk)]}
    }
  end

  test "CIBA pins accepted_typ to nil/JWT and rejects authorization JAR types" do
    key = ec_key()

    assert {:ok, _request} =
             CIBARequest.validate(
               ciba_client(key),
               %{"request" => ciba_request(key, nil)},
               issuer: @ciba_issuer
             )

    assert {:ok, _request} =
             CIBARequest.validate(
               ciba_client(key),
               %{"request" => ciba_request(key, "application/JWT")},
               issuer: @ciba_issuer
             )

    for typ <- ["oauth-authz-req+jwt", "application/oauth-authz-req+jwt"] do
      assert {:error, :invalid_request} =
               CIBARequest.validate(
                 ciba_client(key),
                 %{"request" => ciba_request(key, typ)},
                 issuer: @ciba_issuer
               )
    end
  end
end
