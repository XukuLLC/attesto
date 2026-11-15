defmodule Attesto.SignedIntrospectionTest do
  @moduledoc false
  # Factory.config installs key material into the application env, so these are
  # not async-safe.
  use ExUnit.Case, async: false

  alias Attesto.Key
  alias Attesto.SignedIntrospection
  alias Attesto.SigningAlg
  alias Attesto.Test.Factory

  setup do
    {:ok, config: Factory.config(Factory.rsa_pem())}
  end

  defp verify(config, jwt) do
    pem = config.keystore.signing_pem()
    jwk = Key.jwk(pem)
    alg = SigningAlg.for_key(config.keystore, pem, signing?: true)

    assert {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(jwk, [alg], jwt)

    claims
  end

  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  test "wraps the RFC 7662 response in token_introspection with iss/aud/iat", %{config: config} do
    now = 1_700_000_000
    response = %{"active" => true, "scope" => "openid", "client_id" => "client-123"}

    {:ok, jwt} = SignedIntrospection.response_jwt(config, "rs-1", response, now: now)

    claims = verify(config, jwt)
    assert claims["iss"] == config.issuer
    assert claims["aud"] == "rs-1"
    assert claims["iat"] == now
    assert claims["token_introspection"] == response
    # RFC 9701 does not require exp; none is emitted by default.
    refute Map.has_key?(claims, "exp")
  end

  test "carries an inactive response too", %{config: config} do
    {:ok, jwt} = SignedIntrospection.response_jwt(config, "rs-1", %{"active" => false})
    assert verify(config, jwt)["token_introspection"] == %{"active" => false}
  end

  test "pins the RFC 9701 typ header (token-introspection+jwt)", %{config: config} do
    {:ok, jwt} = SignedIntrospection.response_jwt(config, "rs-1", %{"active" => false})
    %{"typ" => typ, "alg" => alg, "kid" => kid} = header(jwt)

    assert typ == "token-introspection+jwt"
    assert typ == SignedIntrospection.header_typ()
    assert alg in ~w(RS256 PS256 ES256 Ed25519 EdDSA)
    assert is_binary(kid) and kid != ""
  end

  test ":lifetime adds an exp relative to iat", %{config: config} do
    now = 1_700_000_000
    {:ok, jwt} = SignedIntrospection.response_jwt(config, "rs-1", %{"active" => true}, now: now, lifetime: 120)
    assert verify(config, jwt)["exp"] == now + 120
  end
end
