defmodule Attesto.IDTokenTest do
  @moduledoc false
  # Factory.config/2 installs the signing PEM into the global :attesto app
  # env (Attesto.Keystore.Static singleton), so these run serially.
  use ExUnit.Case, async: false

  alias __MODULE__.RotatingKeystore
  alias Attesto.IDToken
  alias Attesto.Key
  alias Attesto.Test.Factory
  alias Attesto.Token

  @client_id "client-abc"
  @subject "usr_end_user_1"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  # Decode a JWT payload/header without verifying the signature, to assert
  # on the exact claim/header set the minter produced.
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

  describe "mint/4 success" do
    test "produces an ID token with the OIDC registered claims", %{config: config} do
      now = 1_700_000_000

      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, now: now)

      claims = payload!(jwt)
      assert claims["iss"] == "https://api.example.com/"
      assert claims["sub"] == @subject
      # aud is the client_id, NOT the RFC 9068 resource audience (OIDC §2).
      assert claims["aud"] == @client_id
      assert claims["aud"] != config.audience
      assert claims["iat"] == now
      assert claims["exp"] == now + 3600
    end

    test "carries no access-token scope claim", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      refute Map.has_key?(payload!(jwt), "scope")
    end

    test "the default RSA JOSE header is RS256/kid and typ JWT, never at+jwt", %{config: config, pem: pem} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)

      header = header!(jwt)
      assert header["alg"] == "RS256"
      assert header["kid"] == Key.kid(pem)
      # OIDC Core §2: generic JWT type; RFC 9068's at+jwt MUST NOT appear.
      assert header["typ"] == "JWT"
      refute header["typ"] == "at+jwt"
    end

    test "omits optional claims when not requested", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      claims = payload!(jwt)

      for key <- ~w(nonce azp auth_time acr amr at_hash c_hash) do
        refute Map.has_key?(claims, key), "expected #{key} to be absent"
      end
    end

    test "includes optional/conditional claims when supplied", %{config: config} do
      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id,
                 nonce: "n-0S6_WzA2Mj",
                 azp: @client_id,
                 auth_time: 1_700_000_000,
                 acr: "urn:mace:incommon:iap:silver",
                 amr: ["pwd", "otp"]
               )

      claims = payload!(jwt)
      assert claims["nonce"] == "n-0S6_WzA2Mj"
      assert claims["azp"] == @client_id
      assert claims["auth_time"] == 1_700_000_000
      assert claims["acr"] == "urn:mace:incommon:iap:silver"
      assert claims["amr"] == ["pwd", "otp"]
    end

    test "includes auth_time alone when supplied (OIDC Core §2)", %{config: config} do
      # auth_time is REQUIRED when the request asked for it or carried
      # max_age (OIDC Core §2); supplied on its own it stands without acr/amr.
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, auth_time: 1_700_000_500)
      claims = payload!(jwt)
      assert claims["auth_time"] == 1_700_000_500
      refute Map.has_key?(claims, "acr")
      refute Map.has_key?(claims, "amr")
    end

    test "includes azp alone when supplied (OIDC Core §2)", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, azp: @client_id)
      assert payload!(jwt)["azp"] == @client_id
    end

    test "computes at_hash per OIDC Core §3.1.3.6", %{config: config} do
      # Canonical vector (OIDC Core §3.1.3.6, RS256/SHA-256):
      # access_token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
      # yields at_hash "77QmUPtjPfzWtF2AnpK9RQ".
      access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"

      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, access_token: access_token)
      assert payload!(jwt)["at_hash"] == "77QmUPtjPfzWtF2AnpK9RQ"
    end

    test "computes c_hash with the same construction", %{config: config} do
      code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"

      expected =
        :crypto.hash(:sha256, code) |> binary_part(0, 16) |> Base.url_encode64(padding: false)

      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, code: code)
      assert payload!(jwt)["c_hash"] == expected
    end

    test "merges :extra_claims", %{config: config} do
      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id,
                 extra_claims: %{"email" => "u@example.test", "email_verified" => true}
               )

      claims = payload!(jwt)
      assert claims["email"] == "u@example.test"
      assert claims["email_verified"] == true
    end

    test ":extra_claims survive a verify/3 round-trip", %{config: config} do
      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id,
                 extra_claims: %{"email" => "u@example.test", "groups" => ["admin", "ops"]}
               )

      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
      assert claims["email"] == "u@example.test"
      assert claims["groups"] == ["admin", "ops"]
    end

    test "a lifetime larger than the default is capped to the default", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, lifetime: 999_999, now: 0)
      claims = payload!(jwt)
      assert claims["exp"] - claims["iat"] == 3600
    end

    test "a shorter lifetime is honored", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, lifetime: 60, now: 0)
      claims = payload!(jwt)
      assert claims["exp"] - claims["iat"] == 60
    end

    test "accepts a DateTime as :now", %{config: config} do
      dt = ~U[2026-01-01 00:00:00Z]
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, now: dt)
      assert payload!(jwt)["iat"] == DateTime.to_unix(dt, :second)
    end
  end

  describe "trusted key-bound signing algorithms" do
    for {alg, key, digest, half_bytes} <- [
          {"RS256", :rsa, :sha256, 16},
          {"PS256", :rsa, :sha256, 16},
          {"ES256", {:ec, "P-256"}, :sha256, 16},
          {"ES384", {:ec, "P-384"}, :sha384, 24},
          {"ES512", {:ec, "P-521"}, :sha512, 32},
          {"EdDSA", :ed25519, :sha512, 32},
          {"Ed25519", :ed25519, :sha512, 32}
        ] do
      test "#{alg} mint, verify, and OIDC hash claims agree" do
        alg = unquote(alg)
        digest = unquote(digest)
        half_bytes = unquote(half_bytes)
        pem = signing_pem(unquote(Macro.escape(key)))
        config_opts = if alg in ["PS256", "Ed25519"], do: [signing_alg: alg], else: []
        config = Factory.config(pem, config_opts)
        access_token = "access-token-#{alg}"
        code = "authorization-code-#{alg}"

        assert {:ok, jwt} =
                 IDToken.mint(config, @subject, @client_id,
                   access_token: access_token,
                   code: code
                 )

        assert header!(jwt) == %{
                 "alg" => alg,
                 "kid" => Key.kid(pem),
                 "typ" => "JWT"
               }

        assert payload!(jwt)["at_hash"] == oidc_hash(access_token, digest, half_bytes)
        assert payload!(jwt)["c_hash"] == oidc_hash(code, digest, half_bytes)

        assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
        assert claims["sub"] == @subject
      end
    end

    test "Ed448 mint, verify, and OIDC hash claims use SHAKE256/114 left 57" do
      enable_ed448_support()
      pem = Factory.ed448_pem()
      config = Factory.config(pem)
      access_token = "access-token-Ed448"
      code = "authorization-code-Ed448"

      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id,
                 access_token: access_token,
                 code: code
               )

      assert header!(jwt) == %{
               "alg" => "EdDSA",
               "kid" => Key.kid(pem),
               "typ" => "JWT"
             }

      assert payload!(jwt)["at_hash"] == oidc_shake256_hash(access_token)
      assert payload!(jwt)["c_hash"] == oidc_shake256_hash(code)

      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
      assert claims["sub"] == @subject
    end

    test "RFC 9864 Ed448 mint and verify uses the explicit identifier with the same hash profile" do
      enable_ed448_support()
      pem = Factory.ed448_pem()
      config = Factory.config(pem, signing_alg: "Ed448")
      access_token = "access-token-explicit-Ed448"

      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id, access_token: access_token)

      assert header!(jwt)["alg"] == "Ed448"
      assert payload!(jwt)["at_hash"] == oidc_shake256_hash(access_token)
      assert {:ok, _claims} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "mint reads a rotating keystore's signing PEM exactly once" do
      first_pem = Factory.rsa_pem()
      second_pem = Factory.ed_pem()
      RotatingKeystore.install([first_pem, second_pem])
      config = %{Factory.config(first_pem) | keystore: RotatingKeystore}

      assert {:ok, jwt} =
               IDToken.mint(config, @subject, @client_id, access_token: "rotation-race-access-token")

      assert RotatingKeystore.signing_pem_calls() == 1
      assert header!(jwt)["alg"] == "RS256"
      assert header!(jwt)["kid"] == Key.kid(first_pem)
      assert {:ok, _claims} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "a malformed PEM candidate retains the keystore failure behavior", %{pem: pem} do
      RotatingKeystore.install([pem, "not a pem"])
      config = %{Factory.config(pem) | keystore: RotatingKeystore}
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)

      assert_raise ArgumentError, fn -> IDToken.verify(config, jwt, client_id: @client_id) end
    end
  end

  describe "mint/4 validation" do
    test "rejects an empty or non-binary subject", %{config: config} do
      assert {:error, :invalid_subject} = IDToken.mint(config, "", @client_id)
      assert {:error, :invalid_subject} = IDToken.mint(config, 42, @client_id)
    end

    test "rejects an empty client_id", %{config: config} do
      assert {:error, :invalid_client_id} = IDToken.mint(config, @subject, "")
    end

    test "rejects :extra_claims that is not a map or has non-string keys", %{config: config} do
      assert {:error, :invalid_extra_claims} =
               IDToken.mint(config, @subject, @client_id, extra_claims: "nope")

      assert {:error, :invalid_extra_claims} =
               IDToken.mint(config, @subject, @client_id, extra_claims: %{email: "x"})
    end

    test "rejects an :extra_claims key colliding with a reserved claim", %{config: config} do
      for reserved <- ~w(iss sub aud exp iat nonce azp auth_time acr amr at_hash c_hash sid) do
        assert {:error, :reserved_claim_conflict} =
                 IDToken.mint(config, @subject, @client_id, extra_claims: %{reserved => "shadow"}),
               "expected :reserved_claim_conflict for #{reserved}"
      end
    end

    test "threads :sid into the claims (OIDC Back-Channel Logout §2.1)", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, sid: "sess-123")
      assert payload!(jwt)["sid"] == "sess-123"
    end

    test "omits sid when none is supplied", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      refute Map.has_key?(payload!(jwt), "sid")
    end
  end

  describe "verify_logout_hint/2" do
    test "accepts a valid hint and returns its claims", %{config: config} do
      {:ok, jwt} = IDToken.mint(config, @subject, @client_id, sid: "sess-123")
      assert {:ok, claims} = IDToken.verify_logout_hint(config, jwt)
      assert claims["sub"] == @subject
      assert claims["aud"] == @client_id
      assert claims["sid"] == "sess-123"
    end

    test "tolerates an expired hint (RP-Initiated Logout §2)", %{config: config} do
      {:ok, jwt} = IDToken.mint(config, @subject, @client_id, now: 1_500_000_000)
      assert {:ok, claims} = IDToken.verify_logout_hint(config, jwt)
      assert claims["sub"] == @subject
    end

    test "rejects a tampered hint", %{config: config} do
      {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      assert {:error, _} = IDToken.verify_logout_hint(config, jwt <> "tamper")
    end
  end

  describe "verify/3 success" do
    test "round-trips a minted ID token", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
      assert claims["sub"] == @subject
      assert claims["aud"] == @client_id
    end

    test "verifies with a matching nonce", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, nonce: "n-1")
      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id, nonce: "n-1")
      assert claims["nonce"] == "n-1"
    end

    test "verifies a token carrying an explicit matching azp", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, azp: @client_id)
      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
      assert claims["azp"] == @client_id
    end

    test "accepts the client present in an aud array (OIDC Core §3.1.3.7 item 3)", %{config: config} do
      # The minter always sets aud to a single client_id, so exercise the
      # array branch of verify with a hand-built token signed by the same
      # keystore key. aud carries the client among multiple audiences, with
      # azp naming the client per OIDC Core §2.
      jwt = signed_id_token(config, %{aud: [@client_id, "another-rp"], azp: @client_id})

      assert {:ok, claims} = IDToken.verify(config, jwt, client_id: @client_id)
      assert claims["aud"] == [@client_id, "another-rp"]
    end
  end

  # Sign an arbitrary ID-token claim set with the configured keystore key
  # and the same JOSE header IDToken emits, so verify/3's array/azp branches
  # can be exercised with shapes the minter does not itself produce.
  defp signed_id_token(config, overrides) do
    now = System.system_time(:second)
    pem = config.keystore.signing_pem()
    jwk = Key.signing_jwk(pem)

    claims =
      %{
        "iss" => config.issuer,
        "sub" => @subject,
        "aud" => @client_id,
        "iat" => now,
        "exp" => now + 3600
      }
      |> Map.merge(Map.new(overrides, fn {k, v} -> {Atom.to_string(k), v} end))

    header = %{"alg" => "RS256", "kid" => Key.kid(pem), "typ" => "JWT"}
    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  describe "verify/3 failures" do
    test "requires a client_id", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      assert {:error, :missing_client_id} = IDToken.verify(config, jwt, [])
      assert {:error, :missing_client_id} = IDToken.verify(config, jwt, client_id: "")
    end

    test "rejects a token addressed to a different client", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      assert {:error, :invalid_audience} = IDToken.verify(config, jwt, client_id: "other-client")
    end

    test "rejects a token whose azp is not the client", %{config: config} do
      # OIDC Core §3.1.3.7 item 4/5: a present azp MUST equal the client.
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, azp: "someone-else")
      assert {:error, :invalid_azp} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "requires the nonce claim when the caller supplies a nonce", %{config: config} do
      # Minted without a nonce, but the caller expected one: fail closed.
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)

      assert {:error, :nonce_required} =
               IDToken.verify(config, jwt, client_id: @client_id, nonce: "expected")
    end

    test "rejects a mismatched nonce", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, nonce: "minted")

      assert {:error, :nonce_mismatch} =
               IDToken.verify(config, jwt, client_id: @client_id, nonce: "different")
    end

    test "does not require a nonce when the caller supplies none", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, nonce: "minted")
      # No :nonce opt: the unverifiable claim is simply not checked.
      assert {:ok, _claims} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects an expired token", %{config: config} do
      past = System.system_time(:second) - 10_000
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, now: past)
      assert {:error, :expired} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects a token from a foreign signing key", %{config: config} do
      foreign = Factory.foreign_config(Factory.rsa_pem())
      assert {:ok, jwt} = IDToken.mint(foreign, @subject, @client_id)
      # Signed by a key the primary config does not hold.
      assert {:error, :invalid_signature} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects a wrong issuer", %{config: config} do
      other_issuer = Factory.config(Factory.rsa_pem(), issuer: "https://evil.example/")
      assert {:ok, jwt} = IDToken.mint(other_issuer, @subject, @client_id)
      # Signed by the same global keystore singleton, but iss differs.
      assert {:error, :invalid_issuer} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects a critical JOSE header", %{config: config} do
      jwt = signed_id_token(config, %{}, %{"crit" => ["exp"]})
      assert {:error, :unsupported_critical_header} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects an access-token JOSE typ", %{config: config} do
      jwt = signed_id_token(config, %{}, %{"typ" => "at+jwt"})
      assert {:error, :unexpected_typ} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects an access token even when access-token JOSE typ is disabled", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: nil)

      principal = %{
        kind: "client",
        sub: "oc_client_1",
        scopes: ["read"],
        claims: %{"client_id" => "client-1"}
      }

      assert {:ok, %{access_token: access_token}} = Token.mint(config, principal)
      refute Map.has_key?(header!(access_token), "typ")

      assert {:error, :unexpected_typ} =
               IDToken.verify(config, access_token, client_id: config.audience)
    end

    test "rejects alg none as invalid_signature", %{config: config} do
      now = System.system_time(:second)

      header = %{"alg" => "none", "typ" => "JWT"} |> JSON.encode!() |> Base.url_encode64(padding: false)

      payload =
        %{
          "iss" => config.issuer,
          "sub" => @subject,
          "aud" => @client_id,
          "iat" => now,
          "exp" => now + 3600
        }
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      assert {:error, :invalid_signature} =
               IDToken.verify(config, header <> "." <> payload <> ".", client_id: @client_id)
    end

    test "rejects malformed required claims", %{config: config} do
      assert {:error, :invalid_claims} =
               IDToken.verify(config, signed_id_token(config, %{sub: ""}), client_id: @client_id)

      assert {:error, :invalid_claims} =
               IDToken.verify(config, signed_id_token(config, %{iat: "now"}), client_id: @client_id)

      assert {:error, :expired} =
               IDToken.verify(config, signed_id_token(config, %{exp: "later"}), client_id: @client_id)
    end

    test "rejects mixed-type audience arrays", %{config: config} do
      jwt = signed_id_token(config, %{aud: [@client_id, 42], azp: @client_id})
      assert {:error, :invalid_audience} = IDToken.verify(config, jwt, client_id: @client_id)
    end

    test "rejects iat meaningfully in the future", %{config: config} do
      now = System.system_time(:second)
      jwt = signed_id_token(config, %{iat: now + 120, exp: now + 3600})

      assert {:error, :not_yet_valid} =
               IDToken.verify(config, jwt, client_id: @client_id, now: now)
    end

    test "rejects a structurally broken token", %{config: config} do
      assert {:error, :invalid_token} = IDToken.verify(config, "not.a.jwt", client_id: @client_id)
    end

    test "rejects non-canonical base64url padding in any compact segment", %{config: config} do
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id)
      segments = String.split(jwt, ".")

      for index <- 0..2 do
        padded =
          segments
          |> List.update_at(index, &(&1 <> "="))
          |> Enum.join(".")

        assert {:error, :invalid_token} = IDToken.verify(config, padded, client_id: @client_id),
               "expected padding in segment #{index} to be rejected"
      end
    end

    # RFC 4648 §3.5: the 342-byte RS256 signature segment is a partial
    # quantum, so its last character has unused low-order bits and several
    # distinct characters decode to the same signature bytes. Swapping the
    # trailing character for a same-decoding sibling is a different string
    # that decodes to the issuer's signature; the canonical-form boundary
    # MUST reject it before JOSE's liberal decoder normalises and accepts it.
    test "rejects a non-canonical trailing signature character (malleability)", %{config: config} do
      now = 1_700_000_000
      assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, now: now)
      mutated = swap_trailing_sibling(jwt)

      assert mutated != jwt
      assert {:error, :invalid_token} = IDToken.verify(config, mutated, client_id: @client_id, now: now)
    end
  end

  # Replace the final base64url character of the signature segment with a
  # different character that decodes to the same bytes (RFC 4648 §3.5).
  defp swap_trailing_sibling(jwt) do
    [header, payload, sig] = String.split(jwt, ".")
    decoded = Base.url_decode64!(sig, padding: false)
    prefix = binary_part(sig, 0, byte_size(sig) - 1)
    last = :binary.at(sig, byte_size(sig) - 1)

    sibling =
      Enum.find(~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", fn c ->
        c != last and match?({:ok, ^decoded}, Base.url_decode64(prefix <> <<c>>, padding: false))
      end)

    Enum.join([header, payload, prefix <> <<sibling>>], ".")
  end

  defp signed_id_token(config, overrides, header_overrides) do
    now = System.system_time(:second)
    pem = config.keystore.signing_pem()
    jwk = Key.signing_jwk(pem)

    claims =
      %{
        "iss" => config.issuer,
        "sub" => @subject,
        "aud" => @client_id,
        "iat" => now,
        "exp" => now + 3600
      }
      |> Map.merge(Map.new(overrides, fn {k, v} -> {Atom.to_string(k), v} end))

    header =
      %{"alg" => "RS256", "kid" => Key.kid(pem), "typ" => "JWT"}
      |> Map.merge(header_overrides)

    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp signing_pem(:rsa), do: Factory.rsa_pem()
  defp signing_pem({:ec, curve}), do: Factory.ec_pem(curve)
  defp signing_pem(:ed25519), do: Factory.ed_pem()

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end

  defp oidc_hash(value, digest, half_bytes) do
    value
    |> then(&:crypto.hash(digest, &1))
    |> binary_part(0, half_bytes)
    |> Base.url_encode64(padding: false)
  end

  defp oidc_shake256_hash(value) do
    value
    |> JOSE.sha3_module().shake256(114)
    |> binary_part(0, 57)
    |> Base.url_encode64(padding: false)
  end

  defmodule RotatingKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    def install(pems) do
      Process.put({__MODULE__, :remaining}, pems)
      Process.put({__MODULE__, :all}, pems)
      Process.put({__MODULE__, :calls}, 0)
    end

    def signing_pem_calls, do: Process.get({__MODULE__, :calls}, 0)

    @impl true
    def signing_pem do
      [pem | rest] = Process.get({__MODULE__, :remaining})
      Process.put({__MODULE__, :remaining}, rest)
      Process.put({__MODULE__, :calls}, signing_pem_calls() + 1)
      pem
    end

    @impl true
    def verification_pems, do: Process.get({__MODULE__, :all})
  end
end
