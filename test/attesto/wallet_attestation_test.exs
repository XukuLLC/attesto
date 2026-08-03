defmodule Attesto.WalletAttestationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.WalletAttestation

  @client_id "https://wallet.example.org"
  @audience "https://as.example.com"
  @now 1_772_487_595

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_map(key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  defp sign(key, header, claims) do
    {_header, compact} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp attestation(wallet_provider_key, instance_jwk_map, overrides \\ %{}) do
    header = %{"alg" => "ES256", "typ" => "oauth-client-attestation+jwt", "kid" => "wp-1"}

    claims =
      Map.merge(
        %{
          "sub" => @client_id,
          "iat" => @now,
          "exp" => @now + 3600,
          "cnf" => %{"jwk" => instance_jwk_map}
        },
        overrides
      )

    sign(wallet_provider_key, header, claims)
  end

  defp pop(instance_key, overrides \\ %{}) do
    header = %{"alg" => "ES256", "typ" => "oauth-client-attestation-pop+jwt"}

    claims =
      Map.merge(
        %{
          "aud" => @audience,
          "jti" => "pop-" <> Integer.to_string(System.unique_integer([:positive])),
          "iat" => @now
        },
        overrides
      )

    sign(instance_key, header, claims)
  end

  defp trusted(wallet_provider_key), do: %{"keys" => [Map.put(public_map(wallet_provider_key), "kid", "wp-1")]}

  defp verify_opts(overrides \\ []) do
    Keyword.merge([audience: @audience, now: @now], overrides)
  end

  test "verifies a valid attestation + PoP pair and returns the instance key" do
    wallet_provider = ec_key()
    instance = ec_key()
    instance_jwk_map = public_map(instance)

    att = attestation(wallet_provider, instance_jwk_map)
    pop_jwt = pop(instance)

    assert {:ok, result} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])

    assert result.instance_key.jwk == instance_jwk_map
    assert result.instance_key.jkt == JOSE.JWK.thumbprint(instance)
    assert result.attestation_claims["sub"] == @client_id
    assert result.pop_claims["aud"] == @audience
    assert is_binary(result.replay_key)
    assert is_integer(result.replay_ttl)
  end

  test "rejects an attestation not signed by a trusted wallet provider" do
    wallet_provider = ec_key()
    impostor = ec_key()
    instance = ec_key()

    att = attestation(impostor, public_map(instance))
    pop_jwt = pop(instance)

    assert {:error, :invalid_signature} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects an expired attestation" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance), %{"exp" => @now - 1})
    pop_jwt = pop(instance)

    assert {:error, :expired} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects a PoP JWT with the wrong audience" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(instance, %{"aud" => "https://other-as.example.com"})

    assert {:error, :invalid_pop_audience} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects a PoP JWT signed by a key other than the attestation's cnf key" do
    wallet_provider = ec_key()
    instance = ec_key()
    wrong_key = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(wrong_key)

    assert {:error, :invalid_pop_signature} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects an expired PoP JWT (stale iat beyond max_age_seconds)" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(instance, %{"iat" => @now - 301})

    assert {:error, :pop_expired} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects a PoP JWT whose iat is unreasonably in the future" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(instance, %{"iat" => @now + 61})

    assert {:error, :invalid_pop_iat} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "enforces client_id against the attestation's sub when supplied" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(instance)

    opts = [{:trusted_wallet_provider_jwks, trusted(wallet_provider)}, {:client_id, "not-the-wallet"} | verify_opts()]
    assert {:error, :invalid_client_id} = WalletAttestation.verify(att, pop_jwt, opts)
  end

  test "matches an expected challenge and rejects a mismatched one" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))

    good_pop = pop(instance, %{"challenge" => "chal-1"})
    bad_pop = pop(instance, %{"challenge" => "chal-wrong"})
    missing_pop = pop(instance)

    opts = [{:trusted_wallet_provider_jwks, trusted(wallet_provider)}, {:expected_challenge, "chal-1"} | verify_opts()]

    assert {:ok, _} = WalletAttestation.verify(att, good_pop, opts)
    assert {:error, :invalid_pop_challenge} = WalletAttestation.verify(att, bad_pop, opts)
    assert {:error, :invalid_pop_challenge} = WalletAttestation.verify(att, missing_pop, opts)
  end

  test "rejects a cnf key that carries private material" do
    wallet_provider = ec_key()
    instance = ec_key()
    leaky_jwk = Map.put(public_map(instance), "d", "leaked-private-scalar")

    att = attestation(wallet_provider, leaky_jwk)
    pop_jwt = pop(instance)

    assert {:error, :invalid_cnf} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects an attestation with the wrong typ header" do
    wallet_provider = ec_key()
    instance = ec_key()

    header = %{"alg" => "ES256", "typ" => "some-other+jwt", "kid" => "wp-1"}
    claims = %{"sub" => @client_id, "iat" => @now, "exp" => @now + 3600, "cnf" => %{"jwk" => public_map(instance)}}
    att = sign(wallet_provider, header, claims)
    pop_jwt = pop(instance)

    assert {:error, :invalid_typ} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "rejects a PoP JWT with the wrong typ header" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    header = %{"alg" => "ES256", "typ" => "dpop+jwt"}
    claims = %{"aud" => @audience, "jti" => "x", "iat" => @now}
    pop_jwt = sign(instance, header, claims)

    assert {:error, :invalid_pop_typ} =
             WalletAttestation.verify(att, pop_jwt, [
               {:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()
             ])
  end

  test "invokes :replay_check with a stable, key-namespaced replay_key and honors {:error, :replay}" do
    wallet_provider = ec_key()
    instance = ec_key()

    att = attestation(wallet_provider, public_map(instance))
    pop_jwt = pop(instance, %{"jti" => "fixed-jti"})

    base_opts = [{:trusted_wallet_provider_jwks, trusted(wallet_provider)} | verify_opts()]

    assert {:ok, %{replay_key: replay_key}} =
             WalletAttestation.verify(att, pop_jwt, [{:replay_check, fn _key, _ttl -> :ok end} | base_opts])

    assert {:error, :replay} =
             WalletAttestation.verify(att, pop_jwt, [
               {:replay_check, fn _key, _ttl -> {:error, :replay} end} | base_opts
             ])

    assert is_binary(replay_key)
  end
end
