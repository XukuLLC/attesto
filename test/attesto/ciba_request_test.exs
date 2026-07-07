defmodule Attesto.CIBA.RequestTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CIBA.Request

  @client_id "ciba-client-1"
  @issuer "https://op.example.com"

  defp client(overrides \\ %{}) do
    Map.merge(%{client_id: @client_id, token_delivery_mode: :poll}, overrides)
  end

  defp params(overrides \\ %{}) do
    Map.merge(%{"scope" => "openid accounts.read", "login_hint" => "user@example.com"}, overrides)
  end

  # A 160-bit-looking client_notification_token (ping/push).
  @notification_token "8d67dc78-7faa-4d41-aabd-67707b374255"

  describe "plain-parameter requests (§7.1)" do
    test "accepts a minimal poll-mode request" do
      assert {:ok, %Request{} = request} = Request.validate(client(), params())
      assert request.client_id == @client_id
      assert request.delivery_mode == :poll
      assert request.scope == ["openid", "accounts.read"]
      assert request.hint == {:login_hint, "user@example.com"}
      refute request.signed?
      assert request.client_notification_token == nil
    end

    test "a client without a registered delivery mode is unauthorized_client" do
      assert {:error, :unauthorized_client} = Request.validate(%{client_id: @client_id}, params())
      assert {:error, :unauthorized_client} = Request.validate(client(%{token_delivery_mode: "poll"}), params())
    end

    test "scope is required and must contain openid" do
      assert {:error, :invalid_request} = Request.validate(client(), Map.delete(params(), "scope"))
      assert {:error, :invalid_request} = Request.validate(client(), params(%{"scope" => ""}))
      assert {:error, :invalid_scope} = Request.validate(client(), params(%{"scope" => "accounts.read"}))
    end

    test "a malformed scope token is invalid_scope" do
      # A raw double-quote is outside the RFC 6749 Appendix A NQCHAR set.
      assert {:error, :invalid_scope} = Request.validate(client(), params(%{"scope" => ~s(openid bad"scope)}))
    end

    test "exactly one hint is required (§7.1)" do
      no_hint = Map.delete(params(), "login_hint")
      assert {:error, :invalid_request} = Request.validate(client(), no_hint)

      two_hints = params(%{"login_hint_token" => "token"})
      assert {:error, :invalid_request} = Request.validate(client(), two_hints)

      assert {:error, :invalid_request} = Request.validate(client(), params(%{"login_hint" => ""}))
      assert {:error, :invalid_request} = Request.validate(client(), params(%{"login_hint" => 42}))
    end

    test "each hint kind is carried with its value" do
      base = Map.delete(params(), "login_hint")

      assert {:ok, %Request{hint: {:login_hint_token, "lht"}}} =
               Request.validate(client(), Map.put(base, "login_hint_token", "lht"))

      assert {:ok, %Request{hint: {:id_token_hint, "idt"}}} =
               Request.validate(client(), Map.put(base, "id_token_hint", "idt"))
    end

    test "request_uri is rejected (undefined at this endpoint)" do
      assert {:error, :invalid_request} = Request.validate(client(), params(%{"request_uri" => "https://x"}))
    end
  end

  describe "client_notification_token (§7.1: required for ping and push)" do
    test "ping mode requires it" do
      assert {:error, :invalid_request} = Request.validate(client(%{token_delivery_mode: :ping}), params())

      assert {:ok, %Request{client_notification_token: @notification_token}} =
               Request.validate(
                 client(%{token_delivery_mode: :ping}),
                 params(%{"client_notification_token" => @notification_token})
               )
    end

    test "push mode requires it too" do
      assert {:error, :invalid_request} = Request.validate(client(%{token_delivery_mode: :push}), params())
    end

    test "rejects a token outside the RFC 6750 b64token syntax" do
      for bad <- ["has space", "quote\"quote", "ünïcode-token-of-plausible-length"] do
        assert {:error, :invalid_request} =
                 Request.validate(
                   client(%{token_delivery_mode: :ping}),
                   params(%{"client_notification_token" => bad})
                 ),
               "expected reject for #{inspect(bad)}"
      end
    end

    test "enforces the 1024-char ceiling and the entropy-floor length" do
      too_long = String.duplicate("a", 1025)

      assert {:error, :invalid_request} =
               Request.validate(
                 client(%{token_delivery_mode: :ping}),
                 params(%{"client_notification_token" => too_long})
               )

      # 128 bits base64-encoded is 22 chars; shorter cannot carry the §7.1 minimum.
      assert {:error, :invalid_request} =
               Request.validate(
                 client(%{token_delivery_mode: :ping}),
                 params(%{"client_notification_token" => "short-token"})
               )
    end

    test "poll mode ignores a supplied token (not carried)" do
      assert {:ok, %Request{client_notification_token: nil}} =
               Request.validate(client(), params(%{"client_notification_token" => @notification_token}))
    end
  end

  describe "binding_message (§7.1 / FAPI-CIBA §5.2.2)" do
    test "carries a displayable message" do
      assert {:ok, %Request{binding_message: "S24R"}} =
               Request.validate(client(), params(%{"binding_message" => "S24R"}))
    end

    test "rejects control characters and over-length messages" do
      assert {:error, :invalid_binding_message} =
               Request.validate(client(), params(%{"binding_message" => "line\nbreak"}))

      assert {:error, :invalid_binding_message} =
               Request.validate(client(), params(%{"binding_message" => String.duplicate("x", 129)}))

      assert {:ok, _request} =
               Request.validate(client(), params(%{"binding_message" => String.duplicate("x", 20)}),
                 binding_message_max_length: 20
               )

      assert {:error, :invalid_binding_message} =
               Request.validate(client(), params(%{"binding_message" => String.duplicate("x", 21)}),
                 binding_message_max_length: 20
               )
    end

    test "rejects a non-string and an empty message" do
      assert {:error, :invalid_binding_message} = Request.validate(client(), params(%{"binding_message" => 42}))
      assert {:error, :invalid_binding_message} = Request.validate(client(), params(%{"binding_message" => ""}))
    end

    test "require_binding_message: true rejects its absence" do
      assert {:error, :invalid_binding_message} = Request.validate(client(), params(), require_binding_message: true)

      assert {:ok, _request} =
               Request.validate(client(), params(%{"binding_message" => "S24R"}), require_binding_message: true)
    end
  end

  describe "user_code (§7.1: only when OP + client registration support it)" do
    test "accepted only when both the OP and the client advertise support" do
      p = params(%{"user_code" => "1234"})

      assert {:error, :invalid_request} = Request.validate(client(), p)
      assert {:error, :invalid_request} = Request.validate(client(%{user_code_parameter: true}), p)
      assert {:error, :invalid_request} = Request.validate(client(), p, user_code_supported: true)

      assert {:ok, %Request{user_code: "1234"}} =
               Request.validate(client(%{user_code_parameter: true}), p, user_code_supported: true)
    end

    test "absence is fine (missing_user_code is the host's post-resolution call)" do
      assert {:ok, %Request{user_code: nil}} = Request.validate(client(%{user_code_parameter: true}), params())
    end
  end

  describe "requested_expiry (§7.1: positive integer; §7.1.1 allows a JSON string)" do
    test "accepts integer and digit-string forms" do
      assert {:ok, %Request{requested_expiry: 300}} =
               Request.validate(client(), params(%{"requested_expiry" => 300}))

      assert {:ok, %Request{requested_expiry: 300}} =
               Request.validate(client(), params(%{"requested_expiry" => "300"}))
    end

    test "rejects zero, negatives, and garbage" do
      for bad <- [0, -5, "0", "abc", "12abc", 1.5] do
        assert {:error, :invalid_request} =
                 Request.validate(client(), params(%{"requested_expiry" => bad})),
               "expected reject for #{inspect(bad)}"
      end
    end
  end

  describe "acr_values" do
    test "splits the space-separated preference list" do
      assert {:ok, %Request{acr_values: ["urn:mace:phr", "urn:mace:pwd"]}} =
               Request.validate(client(), params(%{"acr_values" => "urn:mace:phr urn:mace:pwd"}))
    end

    test "rejects a non-string" do
      assert {:error, :invalid_request} = Request.validate(client(), params(%{"acr_values" => ["a"]}))
    end
  end

  # ----- signed authentication requests (§7.1.1 / FAPI-CIBA §5.2.2) -----

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256"}, overrides))
  end

  defp signed_request(jwk, claim_overrides \\ %{}, header_overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      %{
        "iss" => @client_id,
        "aud" => @issuer,
        "iat" => now,
        "nbf" => now,
        "exp" => now + 300,
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "scope" => "openid accounts.read",
        "login_hint" => "user@example.com",
        "binding_message" => "S24R"
      }
      |> Map.merge(claim_overrides)
      |> Map.reject(fn {_k, v} -> v == :absent end)

    header = Map.merge(%{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}, header_overrides)
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp signing_client(jwk, overrides \\ %{}) do
    client(Map.merge(%{jwks: %{"keys" => [public_jwk(jwk)]}}, overrides))
  end

  defp signed_opts, do: [issuer: @issuer]

  describe "signed authentication requests (§7.1.1)" do
    test "verifies a well-formed signed request and extracts the parameters" do
      key = ec_key()
      jwt = signed_request(key)

      assert {:ok, %Request{} = request} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())

      assert request.signed?
      assert request.scope == ["openid", "accounts.read"]
      assert request.hint == {:login_hint, "user@example.com"}
      assert request.binding_message == "S24R"
    end

    test "requested_expiry survives the claim → param round trip as a JSON number" do
      key = ec_key()
      jwt = signed_request(key, %{"requested_expiry" => 240})

      assert {:ok, %Request{requested_expiry: 240}} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())
    end

    test "parameters outside the JWT are rejected (§7.1.1: request must be alone)" do
      key = ec_key()
      jwt = signed_request(key)

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => jwt, "scope" => "openid"}, signed_opts())
    end

    test "a bad signature is rejected" do
      key = ec_key()
      other_key = ec_key()
      jwt = signed_request(other_key, %{}, %{"kid" => JOSE.JWK.thumbprint(key)})

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())
    end

    test "alg confusion: an RS256-signed request is rejected by the FAPI default allowlist" do
      key = JOSE.JWK.generate_key({:rsa, 2048})
      jwt = signed_request(key, %{}, %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)})
      client = client(%{jwks: %{"keys" => [public_jwk(key, %{"alg" => "RS256"})]}})

      assert {:error, :invalid_request} = Request.validate(client, %{"request" => jwt}, signed_opts())
    end

    test "the client's registered signing alg pins the accepted algorithm" do
      key = ec_key()
      jwt = signed_request(key)

      # Registered for PS256; an ES256-signed request must be refused.
      assert {:error, :invalid_request} =
               Request.validate(
                 signing_client(key, %{request_signing_alg: "PS256"}),
                 %{"request" => jwt},
                 signed_opts()
               )

      assert {:ok, _request} =
               Request.validate(
                 signing_client(key, %{request_signing_alg: "ES256"}),
                 %{"request" => jwt},
                 signed_opts()
               )
    end

    test "a registered alg outside the caller's policy set is refused" do
      key = ec_key()
      jwt = signed_request(key)

      assert {:error, :invalid_request} =
               Request.validate(
                 signing_client(key, %{request_signing_alg: "ES256"}),
                 %{"request" => jwt},
                 signed_opts() ++ [accepted_algs: ["PS256"]]
               )
    end

    test "each of the §7.1.1 REQUIRED claims is enforced" do
      key = ec_key()

      for claim <- ["aud", "iss", "exp", "iat", "nbf", "jti"] do
        jwt = signed_request(key, %{claim => :absent})

        assert {:error, :invalid_request} =
                 Request.validate(signing_client(key), %{"request" => jwt}, signed_opts()),
               "expected reject for missing #{claim}"
      end
    end

    test "iss must be the client_id and aud the OP issuer" do
      key = ec_key()

      wrong_iss = signed_request(key, %{"iss" => "someone-else"})

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => wrong_iss}, signed_opts())

      wrong_aud = signed_request(key, %{"aud" => "https://other-op.example.com"})

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => wrong_aud}, signed_opts())
    end

    test "an expired request and an over-long nbf→exp lifetime are rejected" do
      key = ec_key()
      now = System.system_time(:second)

      expired = signed_request(key, %{"nbf" => now - 600, "exp" => now - 300})
      assert {:error, :invalid_request} = Request.validate(signing_client(key), %{"request" => expired}, signed_opts())

      # FAPI-CIBA §5.2.2: lifetime over 60 minutes.
      long = signed_request(key, %{"exp" => now + 3601})
      assert {:error, :invalid_request} = Request.validate(signing_client(key), %{"request" => long}, signed_opts())

      assert {:ok, _request} =
               Request.validate(
                 signing_client(key),
                 %{"request" => signed_request(key, %{"exp" => now + 3601})},
                 signed_opts() ++ [max_request_lifetime_seconds: 7200]
               )
    end

    test "a client with no registered JWKS cannot present a signed request" do
      key = ec_key()
      jwt = signed_request(key)

      assert {:error, :invalid_request} = Request.validate(client(), %{"request" => jwt}, signed_opts())
    end

    test "accepting signed requests without :issuer is a host configuration error" do
      key = ec_key()
      jwt = signed_request(key)

      assert_raise ArgumentError, ~r/:issuer/, fn ->
        Request.validate(signing_client(key), %{"request" => jwt})
      end
    end

    test "the CIBA request-shape rules still run on the unwrapped parameters" do
      key = ec_key()

      no_openid = signed_request(key, %{"scope" => "accounts.read"})
      assert {:error, :invalid_scope} = Request.validate(signing_client(key), %{"request" => no_openid}, signed_opts())

      two_hints = signed_request(key, %{"login_hint_token" => "also"})

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => two_hints}, signed_opts())
    end
  end

  describe "signed-request jti/exp exposure (FAPI-CIBA replay defense)" do
    test "a signed request surfaces its jti and exp for host-side dedupe" do
      key = ec_key()
      exp = System.system_time(:second) + 300
      jwt = signed_request(key, %{"jti" => "replay-key-1", "exp" => exp})

      assert {:ok, %Request{signed?: true, request_jti: "replay-key-1", request_exp: ^exp}} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())
    end

    test "an unsigned request has no jti/exp to track" do
      assert {:ok, %Request{signed?: false, request_jti: nil, request_exp: nil}} =
               Request.validate(client(), params())
    end
  end

  describe "signed-request known-parameter typing (§7.1.1: JSON strings)" do
    test "a non-string known parameter is invalid_request, never coerced" do
      key = ec_key()

      for {claim, bad} <- [
            {"scope", ["openid", "email"]},
            {"login_hint", 123},
            {"binding_message", 456},
            {"acr_values", ["urn:mace:phr"]},
            {"user_code", 987_654}
          ] do
        # `scope`/hints are also required; keep the request otherwise well-formed
        # by only overriding the one claim under test to a non-string value.
        jwt = signed_request(key, %{claim => bad})

        assert {:error, :invalid_request} =
                 Request.validate(signing_client(key), %{"request" => jwt}, signed_opts()),
               "expected reject for #{claim} = #{inspect(bad)}"
      end
    end

    test "an array-containing-an-object returns an error instead of raising" do
      key = ec_key()
      jwt = signed_request(key, %{"scope" => ["openid", %{"nested" => "object"}]})

      assert {:error, :invalid_request} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())
    end

    test "requested_expiry may still be a JSON number (§7.1.1 exception)" do
      key = ec_key()
      jwt = signed_request(key, %{"requested_expiry" => 240})

      assert {:ok, %Request{requested_expiry: 240}} =
               Request.validate(signing_client(key), %{"request" => jwt}, signed_opts())
    end
  end

  describe "require_signed_request (FAPI-CIBA §5.2.2)" do
    test "rejects a plain-parameter request when signing is required" do
      assert {:error, :invalid_request} = Request.validate(client(), params(), require_signed_request: true)
    end

    test "still accepts a signed request" do
      key = ec_key()
      jwt = signed_request(key)

      assert {:ok, %Request{signed?: true}} =
               Request.validate(
                 signing_client(key),
                 %{"request" => jwt},
                 signed_opts() ++ [require_signed_request: true]
               )
    end
  end
end
