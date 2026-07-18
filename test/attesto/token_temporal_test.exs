defmodule Attesto.TokenTemporalTest do
  @moduledoc false
  # Temporal and audience edge cases for Attesto.Token.verify/3, exercised
  # by forging tokens with the fixture's trusted RS256 key and arbitrary claims.
  #
  # Each case mints a baseline valid token via Token.mint, decodes its
  # claims, overrides ONLY the claim under test, and re-signs with the same
  # keystore key (Key.signing_jwk) so the signature stays valid and the
  # sole reason verify can fail is the claim being probed.
  #
  # Factory.config/2 and Attesto.Keystore.Static mutate the global :attesto
  # app env, so this module runs serially.
  use ExUnit.Case, async: false

  alias Attesto.Key
  alias Attesto.Test.Factory
  alias Attesto.Token

  @audience "https://api.example.com/"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  # A frozen reference clock. Verifying with :now pinned to this value makes
  # every "future"/"past" delta exact and immune to wall-clock drift.
  @now 1_700_000_000

  # Mint a baseline valid client access token at @now and return its decoded
  # string-keyed claim map. This is the canonical, verify-passing payload; a
  # caller overrides a single member and re-signs.
  defp baseline_claims(config) do
    assert {:ok, %{access_token: jwt}} =
             Token.mint(
               config,
               %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
               now: @now
             )

    decode_payload(jwt)
  end

  # Read the (unverified) payload segment of a compact JWS as a string-keyed
  # map. Used only to recover the baseline claims for re-signing.
  defp decode_payload(jwt) do
    [_header, payload, _sig] = String.split(jwt, ".")
    payload |> Base.url_decode64!(padding: false) |> JSON.decode!()
  end

  # Re-sign `claims` with the config's keystore key the way Token.sign/2 does
  # for this default RSA fixture: RS256 over the key's kid. The signature is
  # genuine, so verify can only fail on the claim content.
  defp resign(pem, claims) do
    jwk = Key.signing_jwk(pem)

    {_header, compact} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => Token.signing_alg(), "kid" => Key.kid(pem)}, claims)
      |> JOSE.JWS.compact()

    compact
  end

  # Override a single claim on the baseline and re-sign.
  defp forge_with(config, pem, key, value) do
    resign(pem, Map.put(baseline_claims(config), key, value))
  end

  # Override (or drop, with :__drop__) several claims on the baseline.
  defp forge_merge(config, pem, overrides) do
    merged =
      baseline_claims(config)
      |> Map.merge(overrides)
      |> Enum.reject(fn {_k, v} -> v == :__drop__ end)
      |> Map.new()

    resign(pem, merged)
  end

  describe "verify/3 nbf (not-before)" do
    test "a future nbf fails with :not_yet_valid", %{config: config, pem: pem} do
      # nbf well beyond the 60s skew window is not yet valid.
      jwt = forge_with(config, pem, "nbf", @now + 3600)
      assert {:error, :not_yet_valid} = Token.verify(config, jwt, now: @now)
    end

    test "an nbf at or before now is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "nbf", @now - 60)
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["nbf"] == @now - 60
    end

    test "a non-integer nbf fails with :invalid_claims", %{config: config, pem: pem} do
      for bad <- ["1700000000", 1.5, ["x"], %{}] do
        jwt = forge_with(config, pem, "nbf", bad)

        assert {:error, :invalid_claims} = Token.verify(config, jwt, now: @now),
               "expected :invalid_claims for nbf=#{inspect(bad)}"
      end
    end

    test "an nbf exactly at now (within skew) is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "nbf", @now)
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["nbf"] == @now
    end
  end

  describe "verify/3 iat (issued-at) future" do
    test "a far-future iat fails with :not_yet_valid", %{config: config, pem: pem} do
      # iat beyond the 60s skew window: issued by a clock far ahead, or forged.
      jwt = forge_with(config, pem, "iat", @now + 3600)
      assert {:error, :not_yet_valid} = Token.verify(config, jwt, now: @now)
    end

    test "an iat slightly in the future but within the 60s skew is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "iat", @now + 30)
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["iat"] == @now + 30
    end

    test "an iat exactly at now is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "iat", @now)
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["iat"] == @now
    end
  end

  describe "verify/3 exp (expiry)" do
    test "an exp just in the past fails with :expired", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "exp", @now - 1)
      assert {:error, :expired} = Token.verify(config, jwt, now: @now)
    end

    test "an exp exactly at now fails with :expired (not strictly greater)", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "exp", @now)
      assert {:error, :expired} = Token.verify(config, jwt, now: @now)
    end
  end

  describe "verify/3 aud (audience)" do
    test "aud as the bare expected string is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "aud", @audience)
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["aud"] == @audience
    end

    test "aud as a single-element array holding the expected value is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "aud", [@audience])
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["aud"] == [@audience]
    end

    test "aud as an array of strings containing the expected value is accepted", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "aud", [@audience, "https://other.example/"])
      assert {:ok, claims} = Token.verify(config, jwt, now: @now)
      assert claims["aud"] == [@audience, "https://other.example/"]
    end

    test "aud as a mixed array with a non-string member fails with :invalid_audience", %{config: config, pem: pem} do
      # The expected audience is present, but a non-string sibling makes the
      # array malformed: an all-strings array is required.
      jwt = forge_with(config, pem, "aud", [@audience, 42])
      assert {:error, :invalid_audience} = Token.verify(config, jwt, now: @now)
    end

    test "aud as an empty array fails with :invalid_audience", %{config: config, pem: pem} do
      jwt = forge_with(config, pem, "aud", [])
      assert {:error, :invalid_audience} = Token.verify(config, jwt, now: @now)
    end

    test "aud as a nested array fails with :invalid_audience", %{config: config, pem: pem} do
      # A nested array is not an array of strings, even though the expected
      # value appears inside the inner array.
      jwt = forge_with(config, pem, "aud", [[@audience]])
      assert {:error, :invalid_audience} = Token.verify(config, jwt, now: @now)
    end

    test "a missing aud fails with :invalid_audience", %{config: config, pem: pem} do
      jwt = forge_merge(config, pem, %{"aud" => :__drop__})
      assert {:error, :invalid_audience} = Token.verify(config, jwt, now: @now)
    end
  end
end
