defmodule Attesto.LogoutTokenTest do
  @moduledoc false
  # Factory.config installs the signing PEM into the global :attesto app env
  # (Attesto.Keystore.Static singleton), so these run serially.
  use ExUnit.Case, async: false

  alias Attesto.IDToken
  alias Attesto.Key
  alias Attesto.LogoutToken
  alias Attesto.Test.Factory

  @client_id "client-abc"
  @subject "usr_end_user_1"
  @sid "sess-123"
  @event_uri "http://schemas.openid.net/event/backchannel-logout"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  defp payload!(jwt) when is_binary(jwt) do
    [_h, payload_b64 | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(payload_b64, padding: false)
    JSON.decode!(decoded)
  end

  defp header!(jwt) when is_binary(jwt) do
    [header_b64 | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(header_b64, padding: false)
    JSON.decode!(decoded)
  end

  describe "mint/3 success" do
    test "produces the Back-Channel Logout 1.0 §2.4 claim set", %{config: config} do
      now = 1_700_000_000

      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject, sid: @sid, now: now)

      claims = payload!(jwt)
      assert claims["iss"] == config.issuer
      assert claims["aud"] == @client_id
      assert claims["sub"] == @subject
      assert claims["sid"] == @sid
      assert claims["iat"] == now
      assert claims["exp"] == now + 120
      assert is_binary(claims["jti"]) and claims["jti"] != ""
      assert claims["events"] == %{@event_uri => %{}}
    end

    test "the default RSA JOSE header is logout+jwt with RS256/kid", %{config: config, pem: pem} do
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject)
      header = header!(jwt)
      assert header["typ"] == "logout+jwt"
      assert header["alg"] == "RS256"
      assert header["kid"] == Key.kid(pem)
    end

    test "MUST NOT contain a nonce claim (§2.4)", %{config: config} do
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject, sid: @sid)
      refute Map.has_key?(payload!(jwt), "nonce")
    end

    test "sub alone is sufficient", %{config: config} do
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject)
      claims = payload!(jwt)
      assert claims["sub"] == @subject
      refute Map.has_key?(claims, "sid")
    end

    test "sid alone is sufficient", %{config: config} do
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sid: @sid)
      claims = payload!(jwt)
      assert claims["sid"] == @sid
      refute Map.has_key?(claims, "sub")
    end

    test "honours an explicit jti", %{config: config} do
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject, jti: "fixed-jti")
      assert payload!(jwt)["jti"] == "fixed-jti"
    end

    test "lifetime may only shorten the short default", %{config: config} do
      now = 1_700_000_000
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject, now: now, lifetime: 999_999)
      assert payload!(jwt)["exp"] == now + 120

      assert {:ok, short} = LogoutToken.mint(config, @client_id, sub: @subject, now: now, lifetime: 30)
      assert payload!(short)["exp"] == now + 30
    end

    test "the token verifies under the same keystore (it is a real JWS)", %{config: config} do
      # A logout token is not an ID token, but it is signed by the same key, so
      # JOSE strict verification with the signing alg succeeds.
      assert {:ok, jwt} = LogoutToken.mint(config, @client_id, sub: @subject, sid: @sid)
      [pem | _] = config.keystore.verification_pems()
      jwk = Key.jwk(pem)
      assert {true, _, _} = JOSE.JWT.verify_strict(jwk, [IDToken.signing_alg()], jwt)
    end
  end

  describe "mint/3 errors" do
    test "neither sub nor sid is :missing_subject_identifier", %{config: config} do
      assert {:error, :missing_subject_identifier} = LogoutToken.mint(config, @client_id, [])
      assert {:error, :missing_subject_identifier} = LogoutToken.mint(config, @client_id, sub: "", sid: "")
    end

    test "an empty client_id is :invalid_client_id", %{config: config} do
      assert {:error, :invalid_client_id} = LogoutToken.mint(config, "", sub: @subject)
    end
  end

  test "event_uri/0 and header_typ/0 expose the constants" do
    assert LogoutToken.event_uri() == @event_uri
    assert LogoutToken.header_typ() == "logout+jwt"
  end
end
