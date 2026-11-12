defmodule Attesto.SignedUserInfoTest do
  @moduledoc false
  # Factory.config installs key material into the application env, so these are
  # not async-safe.
  use ExUnit.Case, async: false

  alias Attesto.Key
  alias Attesto.SignedUserInfo
  alias Attesto.SigningAlg
  alias Attesto.Test.Factory

  setup do
    config = Factory.config(Factory.rsa_pem())
    pem = config.keystore.signing_pem()
    {:ok, config: config, pem: pem, alg: SigningAlg.for_key(config.keystore, pem, signing?: true)}
  end

  test "signing_algs/1 is the advertised ID Token algorithm list", %{config: config, alg: alg} do
    assert SignedUserInfo.signing_algs(config) == [alg]
    assert SignedUserInfo.signing_algs(config.keystore) == Attesto.OpenIDDiscovery.signing_algs(config)
  end

  test "signs the claims with iss and aud, which the caller cannot override", %{config: config, pem: pem, alg: alg} do
    claims = %{"sub" => "usr_1", "email" => "ada@example.com", "iss" => "https://evil.example", "aud" => "other"}

    assert {:ok, jwt} = SignedUserInfo.response_jwt(config, "client-1", claims, alg)
    assert {true, %JOSE.JWT{fields: signed}, %JOSE.JWS{}} = JOSE.JWT.verify_strict(Key.jwk(pem), [alg], jwt)

    assert signed == %{"sub" => "usr_1", "email" => "ada@example.com", "iss" => config.issuer, "aud" => "client-1"}
    assert %{"alg" => ^alg, "kid" => kid} = jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()
    assert is_binary(kid)
  end

  test "refuses an algorithm that is not the signing key's, including none", %{config: config} do
    for alg <- ["none", "HS256", "ES512", nil] do
      assert {:error, :unsupported_alg} = SignedUserInfo.response_jwt(config, "client-1", %{"sub" => "usr_1"}, alg)
    end
  end
end
