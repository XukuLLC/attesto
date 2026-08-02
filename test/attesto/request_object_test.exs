defmodule Attesto.RequestObjectTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.RequestObject
  alias Attesto.RequestObject.Policy

  @client_id "client-123"
  @issuer @client_id
  @audience "https://issuer.example/authorize"

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jwk, overrides \\ %{}) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    Map.merge(map, Map.merge(%{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => "ES256"}, overrides))
  end

  defp request_object(jwk, claim_overrides \\ %{}, header_overrides \\ %{}) do
    now = System.system_time(:second)

    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "client_id" => @client_id,
          "aud" => @audience,
          "iat" => now,
          "exp" => now + 300,
          "scope" => "openid"
        },
        claim_overrides
      )

    header = Map.merge(%{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}, header_overrides)
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp base_opts, do: [issuer: @issuer, audience: @audience]

  test "verifies a valid signed request object with default opts" do
    key = ec_key()
    jwt = request_object(key)

    assert {:ok, params} =
             RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())

    assert params["scope"] == "openid"
  end

  test "rejects the whole trusted set when one candidate JWK is malformed" do
    key = ec_key()
    jwt = request_object(key)

    assert {:error, :invalid_signature} =
             RequestObject.verify(
               jwt,
               %{"keys" => [public_jwk(key), %{"not" => "a jwk"}]},
               base_opts()
             )
  end

  describe ":accepted_algs" do
    test "default rejects an RS256-signed object (FAPI 2 forbids RS256)" do
      key = JOSE.JWK.generate_key({:rsa, 2048})
      jwt = request_object(key, %{}, %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)})
      jwk = public_jwk(key, %{"alg" => "RS256"})

      assert {:error, :invalid_signature} =
               RequestObject.verify(jwt, %{"keys" => [jwk]}, base_opts())
    end

    test "the FAPI default rejects PS256 with an RSA modulus below 2048 bits" do
      key = JOSE.JWK.generate_key({:rsa, 1024})
      jwt = request_object(key, %{}, %{"alg" => "PS256"})
      trusted = public_jwk(key, %{"alg" => "PS256"})

      assert {:error, :invalid_signature} =
               RequestObject.verify(jwt, %{"keys" => [trusted]}, base_opts())

      assert {:error, :invalid_signature} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [trusted]},
                 base_opts() ++ [accepted_algs: ["PS256"], enforce_fapi_alg_policy: true]
               )

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [trusted]},
                 base_opts() ++ [accepted_algs: ["PS256"]]
               )
    end

    test "explicitly narrowing accepted_algs rejects an otherwise-accepted alg" do
      key = ec_key()
      jwt = request_object(key)

      assert {:error, :invalid_signature} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_algs: ["EdDSA"]]
               )
    end

    test "explicit accepted_algs that includes the key's alg still verifies" do
      key = ec_key()
      jwt = request_object(key)

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_algs: ["ES256"]]
               )
    end

    test "the FAPI default accepts legacy EdDSA and RFC 9864 Ed25519 only over Ed25519" do
      key = JOSE.JWK.generate_key({:okp, :Ed25519})

      for alg <- ["EdDSA", "Ed25519"] do
        jwt = request_object(key, %{}, %{"alg" => alg})
        trusted = public_jwk(key, %{"alg" => alg})

        assert {:ok, _params} =
                 RequestObject.verify(jwt, %{"keys" => [trusted]}, base_opts())
      end
    end

    test "the FAPI default rejects Ed448 but an explicit non-FAPI policy can opt in" do
      enable_ed448_support()
      key = JOSE.JWK.generate_key({:okp, :Ed448})

      for alg <- ["EdDSA", "Ed448"] do
        jwt = request_object(key, %{}, %{"alg" => alg})
        trusted = public_jwk(key, %{"alg" => alg})

        assert {:error, :invalid_signature} =
                 RequestObject.verify(jwt, %{"keys" => [trusted]}, base_opts())

        assert {:error, :invalid_signature} =
                 RequestObject.verify(
                   jwt,
                   %{"keys" => [trusted]},
                   base_opts() ++ [accepted_algs: [alg], enforce_fapi_alg_policy: true]
                 )

        assert {:ok, _params} =
                 RequestObject.verify(
                   jwt,
                   %{"keys" => [trusted]},
                   base_opts() ++ [accepted_algs: [alg]]
                 )
      end
    end

    test "a narrowed FAPI policy retains RSA strength and Edwards curve checks" do
      weak_rsa = JOSE.JWK.generate_key({:rsa, 1024})
      weak_rsa_jwt = request_object(weak_rsa, %{}, %{"alg" => "PS256", "typ" => "oauth-authz-req+jwt"})
      weak_rsa_trusted = public_jwk(weak_rsa, %{"alg" => "PS256"})

      rsa_policy = %{Policy.fapi_message_signing() | accepted_algs: ["PS256"]}
      rsa_opts = base_opts() ++ Policy.to_verify_opts(rsa_policy)

      assert {:error, :invalid_signature} =
               RequestObject.verify(weak_rsa_jwt, %{"keys" => [weak_rsa_trusted]}, rsa_opts)

      enable_ed448_support()
      ed448 = JOSE.JWK.generate_key({:okp, :Ed448})
      ed448_jwt = request_object(ed448, %{}, %{"alg" => "EdDSA", "typ" => "oauth-authz-req+jwt"})
      ed448_trusted = public_jwk(ed448, %{"alg" => "EdDSA"})

      edwards_policy = %{Policy.fapi_message_signing() | accepted_algs: ["EdDSA"]}
      edwards_opts = base_opts() ++ Policy.to_verify_opts(edwards_policy)

      assert {:error, :invalid_signature} =
               RequestObject.verify(ed448_jwt, %{"keys" => [ed448_trusted]}, edwards_opts)
    end
  end

  describe ":require_nbf and :max_nbf_age_seconds" do
    test "default accepts an object without nbf" do
      key = ec_key()
      jwt = request_object(key)

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "require_nbf rejects an object without nbf" do
      key = ec_key()
      jwt = request_object(key)

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end

    test "require_nbf accepts an object that carries nbf" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now})

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end

    test "max_nbf_age_seconds rejects an nbf older than the bound" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now - 600})

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_nbf_age_seconds: 60, now: now]
               )
    end

    test "default ignores a stale nbf (lenient JAR behaviour preserved)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now - 600})

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts() ++ [now: now])
    end

    test "rejects a future nbf even without require_nbf (RFC 7519 §4.1.5 not-before)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now + 600})

      assert {:error, :not_yet_valid} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts() ++ [now: now])
    end

    test "require_nbf rejects a non-integer nbf" do
      key = ec_key()
      jwt = request_object(key, %{"nbf" => "soon"})

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end

    test "require_nbf rejects a negative nbf" do
      key = ec_key()
      jwt = request_object(key, %{"nbf" => -1})

      assert {:error, :not_yet_valid} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_nbf: true]
               )
    end
  end

  describe ":require_exp and :max_lifetime_seconds" do
    test "default accepts an object without exp" do
      key = ec_key()
      jwt = sign_without(key, "exp")

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "require_exp rejects an object without exp" do
      key = ec_key()
      jwt = sign_without(key, "exp")

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_exp: true]
               )
    end

    test "max_lifetime_seconds rejects exp beyond nbf + N" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 3600})

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end

    test "max_lifetime_seconds accepts exp within nbf + N" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 30})

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end

    test "default ignores a long lifetime (lenient JAR behaviour preserved)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"nbf" => now, "exp" => now + 3600})

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts() ++ [now: now])
    end

    test "require_exp rejects a non-integer exp" do
      key = ec_key()
      jwt = request_object(key, %{"exp" => "later"})

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_exp: true]
               )
    end

    test "require_exp rejects a negative exp" do
      key = ec_key()
      jwt = request_object(key, %{"exp" => -1})

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_exp: true]
               )
    end

    test "max_lifetime_seconds rejects a missing nbf (the bound needs both anchors)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = request_object(key, %{"exp" => now + 30})

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end

    test "max_lifetime_seconds rejects a missing exp (the bound needs both anchors)" do
      key = ec_key()
      now = System.system_time(:second)
      jwt = sign_without(key, "exp")

      assert {:error, :expired} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [max_lifetime_seconds: 60, now: now]
               )
    end
  end

  describe ":require_iat and :require_jti (CIBA Core §7.1.1)" do
    test "default accepts an object without iat or jti" do
      key = ec_key()
      jwt = sign_without(key, "iat")

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "require_iat rejects an object without iat" do
      key = ec_key()
      jwt = sign_without(key, "iat")

      assert {:error, :invalid_request_object} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_iat: true]
               )
    end

    test "require_iat accepts an object with a valid iat" do
      key = ec_key()
      jwt = request_object(key)

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_iat: true]
               )
    end

    test "require_jti rejects a missing, empty, or non-string jti" do
      key = ec_key()

      for claims <- [%{}, %{"jti" => ""}, %{"jti" => 42}] do
        jwt = request_object(key, claims)

        assert {:error, :invalid_request_object} =
                 RequestObject.verify(
                   jwt,
                   %{"keys" => [public_jwk(key)]},
                   base_opts() ++ [require_jti: true]
                 ),
               "expected reject for #{inspect(claims)}"
      end
    end

    test "require_jti accepts an object with a jti" do
      key = ec_key()
      jwt = request_object(key, %{"jti" => "jti-1"})

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_jti: true]
               )
    end
  end

  describe ":require_client_id_claim (CIBA Core §7.1.1 profile)" do
    test "default requires the client_id claim to match iss" do
      key = ec_key()
      jwt = sign_without(key, "client_id")

      assert {:error, :invalid_issuer} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "when disabled, iss alone names the client and is still matched against :issuer" do
      key = ec_key()
      jwt = sign_without(key, "client_id")

      assert {:ok, _params} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [require_client_id_claim: false]
               )

      # A wrong iss still fails against the caller-supplied :issuer.
      wrong_iss = request_object(key, %{"iss" => "someone-else"})

      assert {:error, :invalid_issuer} =
               RequestObject.verify(
                 wrong_iss,
                 %{"keys" => [public_jwk(key)]},
                 issuer: @issuer,
                 audience: @audience,
                 require_client_id_claim: false
               )
    end
  end

  describe ":accepted_typ" do
    test "default accepts any typ including absence" do
      key = ec_key()
      jwt = request_object(key)
      jwt_with_typ = request_object(key, %{}, %{"typ" => "oauth-authz-req+jwt"})
      jwt_no_typ = request_object_without_typ(key)

      assert {:ok, _} = RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())

      assert {:ok, _} =
               RequestObject.verify(jwt_with_typ, %{"keys" => [public_jwk(key)]}, base_opts())

      assert {:ok, _} =
               RequestObject.verify(jwt_no_typ, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "accepted_typ list requires the header typ to match" do
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "oauth-authz-req+jwt"})

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ list rejects a non-member typ" do
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "JWT"})

      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ matches case-insensitively (media types per RFC 2045)" do
      key = ec_key()
      # The FAPI Message Signing conformance suite signs the request object with
      # a randomly-cased typ (e.g. "OautH-auThZ-REQ+jWt") to verify the OP treats
      # the media type case-insensitively.
      jwt = request_object(key, %{}, %{"typ" => "OautH-auThZ-REQ+jWt"})

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ treats a bare subtype and its application/ form as equal" do
      # RFC 7515 §4.1.9: the `application/` prefix may be omitted for a bare
      # subtype, so `application/oauth-authz-req+jwt` == `oauth-authz-req+jwt`.
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "application/oauth-authz-req+jwt"})

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )
    end

    test "accepted_typ does NOT collapse a multi-slash value onto its application/-stripped form" do
      # The prefix convention is only for a bare subtype (no further `/`).
      # `application/text/example` must NOT be treated as `text/example`.
      key = ec_key()
      jwt = request_object(key, %{}, %{"typ" => "application/text/example"})

      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["text/example"]]
               )
    end

    test "accepted_typ rejects an absent typ unless nil is a member" do
      key = ec_key()
      jwt = request_object_without_typ(key)

      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt"]]
               )

      assert {:ok, _} =
               RequestObject.verify(
                 jwt,
                 %{"keys" => [public_jwk(key)]},
                 base_opts() ++ [accepted_typ: ["oauth-authz-req+jwt", nil]]
               )
    end
  end

  describe "audience claim hardening (RFC 7519 §4.1.3)" do
    test "accepts an all-string aud array containing the expected audience" do
      key = ec_key()
      jwt = request_object(key, %{"aud" => [@audience, "https://other.example"]})

      assert {:ok, _params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "rejects an aud array with a non-string member even if a string matches" do
      key = ec_key()
      jwt = request_object(key, %{"aud" => [@audience, 42]})

      assert {:error, :invalid_audience} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "rejects an empty aud array" do
      key = ec_key()
      jwt = request_object(key, %{"aud" => []})

      assert {:error, :invalid_audience} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end
  end

  describe "parameter coercion is total (never raises)" do
    test "an extension claim that is an array with a non-string member is dropped, not raised on" do
      # Under the default JAR path (no `:string_valued_claims` constraint) an
      # arbitrary passthrough claim reaches `claims_to_params/1`. A list member
      # that is not a binary must make the whole claim drop out - never reach
      # `Enum.join/2`, which raises `Protocol.UndefinedError` on a non-string.
      # A registered client with a valid signing key could otherwise crash the
      # auth-request process at will.
      key = ec_key()
      jwt = request_object(key, %{"ext_list" => ["ok", %{"nested" => 1}]})

      assert {:ok, params} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())

      refute Map.has_key?(params, "ext_list")
    end

    test "an all-string extension array is still joined into a space-delimited param" do
      key = ec_key()
      jwt = request_object(key, %{"ext_list" => ["a", "b"]})

      assert {:ok, %{"ext_list" => "a b"}} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end
  end

  describe "forbidden nested request parameters (RFC 9101 §4)" do
    test "rejects a request object that carries a nested request claim" do
      key = ec_key()
      jwt = request_object(key, %{"request" => "nested.jwt.here"})

      assert {:error, :invalid_request_object} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end

    test "rejects a request object that carries a nested request_uri claim" do
      key = ec_key()
      jwt = request_object(key, %{"request_uri" => "https://attacker.example/ro"})

      assert {:error, :invalid_request_object} =
               RequestObject.verify(jwt, %{"keys" => [public_jwk(key)]}, base_opts())
    end
  end

  # Helpers that build a signed object lacking a given claim entirely.
  defp sign_without(jwk, claim) do
    now = System.system_time(:second)

    claims =
      %{
        "iss" => @client_id,
        "client_id" => @client_id,
        "aud" => @audience,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "openid"
      }
      |> Map.delete(claim)

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  # JOSE.JWT.sign injects `typ: "JWT"`; JOSE.JWS.sign leaves the protected
  # header exactly as given, letting us produce an object with no `typ`.
  defp request_object_without_typ(jwk) do
    now = System.system_time(:second)

    payload =
      JSON.encode!(%{
        "iss" => @client_id,
        "client_id" => @client_id,
        "aud" => @audience,
        "iat" => now,
        "exp" => now + 300,
        "scope" => "openid"
      })

    header = %{"alg" => "ES256", "kid" => JOSE.JWK.thumbprint(jwk)}
    {_meta, compact} = jwk |> JOSE.JWS.sign(payload, header) |> JOSE.JWS.compact()
    compact
  end

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end
