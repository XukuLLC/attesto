defmodule Attesto.IdentityAssertionTest do
  use ExUnit.Case, async: true

  alias Attesto.IdentityAssertion
  alias Attesto.Test.JWT

  @iss "https://idp.example.com"
  @aud "https://as.example.com"
  @cid "client-abc"
  @typ "oauth-id-jag+jwt"

  # A fixed RSA key (RS256) - the algorithm enterprise IdPs most commonly sign
  # with, and the one the FAPI request-object default would reject.
  defp rsa_key, do: JOSE.JWK.generate_key({:rsa, 2048})
  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwks(jwk, alg) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    %{"keys" => [Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => alg})]}
  end

  defp claims(overrides) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => @iss,
        "sub" => "user-123",
        "aud" => @aud,
        "client_id" => @cid,
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "exp" => now + 300,
        "iat" => now
      },
      overrides
    )
  end

  defp assertion(jwk, alg, claim_overrides \\ %{}, header_overrides \\ %{}) do
    header = Map.merge(%{"alg" => alg, "kid" => JOSE.JWK.thumbprint(jwk), "typ" => @typ}, header_overrides)
    JWT.sign_compact(jwk, header, claims(claim_overrides))
  end

  defp opts(extra \\ []) do
    Keyword.merge([issuer: @iss, audience: @aud, client_id: @cid], extra)
  end

  describe "verify/3 - happy path" do
    test "RS256 assertion returns the claims" do
      key = rsa_key()
      jwt = assertion(key, "RS256")

      assert {:ok, claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      assert claims["iss"] == @iss
      assert claims["sub"] == "user-123"
      assert claims["client_id"] == @cid
    end

    test "ES256 assertion returns the claims" do
      key = ec_key()
      jwt = assertion(key, "ES256")

      assert {:ok, _claims} = IdentityAssertion.verify(jwt, public_jwks(key, "ES256"), opts())
    end

    test "rejects the whole trusted set when one candidate JWK is malformed" do
      key = ec_key()
      jwt = assertion(key, "ES256")
      {_kty, trusted} = JOSE.JWK.to_public_map(key)
      trusted = Map.merge(trusted, %{"kid" => JOSE.JWK.thumbprint(key), "alg" => "ES256"})

      assert {:error, :invalid_signature} =
               IdentityAssertion.verify(jwt, %{"keys" => [trusted, %{"not" => "a jwk"}]}, opts())
    end

    test "carries optional claims (scope, email) through" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"scope" => "mcp:read mcp:write", "email" => "a@example.com"})

      assert {:ok, claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      assert claims["scope"] == "mcp:read mcp:write"
      assert claims["email"] == "a@example.com"
    end

    test "accepts valid resource and DPoP confirmation claims" do
      key = rsa_key()
      jkt = Attesto.Thumbprint.of("id-jag-holder-key")

      jwt =
        assertion(key, "RS256", %{
          "resource" => ["https://api.example/a", "https://api.example/b"],
          "cnf" => %{"jkt" => jkt}
        })

      assert {:ok, claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      assert claims["cnf"]["jkt"] == jkt
    end

    test "accepts aud as a single-element array" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"aud" => [@aud]})

      assert {:ok, _claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end
  end

  describe "verify/3 - signature & header" do
    test "rejects a signature from an unknown key" do
      signer = rsa_key()
      other = rsa_key()
      jwt = assertion(signer, "RS256")

      assert {:error, :invalid_signature} =
               IdentityAssertion.verify(jwt, public_jwks(other, "RS256"), opts())
    end

    test "rejects a wrong typ header" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{}, %{"typ" => "JWT"})

      assert {:error, :invalid_typ} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a missing typ header" do
      key = rsa_key()
      header = %{"alg" => "RS256", "kid" => JOSE.JWK.thumbprint(key)}
      {_h, jwt} = key |> JOSE.JWT.sign(header, claims(%{})) |> JOSE.JWS.compact()

      assert {:error, :invalid_typ} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "accepts a case-variant typ (media types are case-insensitive)" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{}, %{"typ" => "OAuth-ID-JAG+JWT"})

      assert {:ok, _claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects alg none" do
      key = rsa_key()
      jwks = public_jwks(key, "RS256")
      # alg:none unsigned token
      header = %{"alg" => "none", "typ" => @typ}
      payload = claims(%{}) |> JSON.encode!() |> Base.url_encode64(padding: false)
      h = header |> JSON.encode!() |> Base.url_encode64(padding: false)
      jwt = h <> "." <> payload <> "."

      assert {:error, :unsupported_alg} = IdentityAssertion.verify(jwt, jwks, opts())
    end

    test "does not treat a trusted RSA public key as an HS256 secret" do
      rsa = rsa_key()
      {_kty, public_map} = JOSE.JWK.to_public_map(rsa)
      hmac_key = public_map |> JSON.encode!() |> JOSE.JWK.from_oct()

      header = %{"alg" => "HS256", "kid" => JOSE.JWK.thumbprint(rsa), "typ" => @typ}
      {_header, jwt} = hmac_key |> JOSE.JWT.sign(header, claims(%{})) |> JOSE.JWS.compact()

      assert {:error, :unsupported_alg} =
               IdentityAssertion.verify(jwt, public_jwks(rsa, "RS256"), opts())
    end

    test "reports an algorithm outside the caller allowlist as unsupported" do
      key = ec_key()
      jwt = assertion(key, "ES256")

      assert {:error, :unsupported_alg} =
               IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "ES256"),
                 opts(accepted_algs: ["RS256"])
               )
    end

    test "rejects a non-compact token" do
      assert {:error, :malformed} = IdentityAssertion.verify("not-a-jwt", %{"keys" => []}, opts())
    end
  end

  describe "verify/3 - claim validation" do
    test "rejects a wrong issuer" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"iss" => "https://evil.example.com"})

      assert {:error, :invalid_issuer} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a wrong audience" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"aud" => "https://other.example.com"})

      assert {:error, :invalid_audience} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a multi-element aud array even if one matches (draft §6.1)" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"aud" => [@aud, "https://other.example.com"]})

      assert {:error, :invalid_audience} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a client_id mismatch" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"client_id" => "someone-else"})

      assert {:error, :client_mismatch} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    for claim <- ~w(sub client_id jti) do
      test "rejects a missing #{claim} claim" do
        key = rsa_key()
        jwt = assertion(key, "RS256", %{unquote(claim) => nil})

        assert {:error, :missing_claim} =
                 IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      end
    end

    test "rejects a missing exp claim" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"exp" => nil})

      assert {:error, :missing_claim} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects an oversized jti before it can reach a replay store" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"jti" => String.duplicate("j", 257)})

      assert {:error, :invalid_claims} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a malformed optional scope instead of dropping its ceiling" do
      key = rsa_key()

      for scope <- [123, "", "   ", "mcp:read\tmcp:write", "bad\\scope"] do
        jwt = assertion(key, "RS256", %{"scope" => scope})

        assert {:error, :invalid_claims} =
                 IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      end
    end

    test "rejects malformed optional resource and cnf claims" do
      key = rsa_key()

      for overrides <- [
            %{"resource" => "relative/resource"},
            %{"resource" => []},
            %{"cnf" => "not-an-object"},
            %{"cnf" => %{}},
            %{"cnf" => %{"x5t#S256" => Attesto.Thumbprint.of("unsupported-binding")}},
            %{
              "cnf" => %{
                "jkt" => Attesto.Thumbprint.of("supported-binding"),
                "x5t#S256" => Attesto.Thumbprint.of("unsupported-binding")
              }
            },
            %{"cnf" => %{"jkt" => "not-a-thumbprint"}}
          ] do
        jwt = assertion(key, "RS256", overrides)

        assert {:error, :invalid_claims} =
                 IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      end
    end

    test "returns typed authorization details and optional identity claims" do
      key = ec_key()

      optional = %{
        "tenant" => "issuer-tenant",
        "aud_tenant" => "recipient-tenant",
        "aud_sub" => "recipient-user",
        "email" => "a@example.com",
        "auth_time" => 1_728_000_000.5,
        "amr" => ["pwd", "otp"],
        "acr" => "mfa",
        "sub_id" => %{"format" => "opaque", "id" => "user-123"},
        "authorization_details" => [%{"type" => "example_authorization", "actions" => ["read"]}]
      }

      jwt = assertion(key, "ES256", optional)
      assert {:ok, claims} = IdentityAssertion.verify(jwt, public_jwks(key, "ES256"), opts())
      assert Map.take(claims, Map.keys(optional)) == optional

      empty = assertion(key, "ES256", %{"authorization_details" => []})

      assert {:ok, %{"authorization_details" => []}} =
               IdentityAssertion.verify(empty, public_jwks(key, "ES256"), opts())
    end

    test "rejects optional claims with the wrong JSON type" do
      key = ec_key()

      for {claim, value} <- [
            {"tenant", []},
            {"aud_tenant", nil},
            {"aud_sub", 10},
            {"email", %{}},
            {"auth_time", "1728000000"},
            {"amr", ["pwd", 10]},
            {"amr", "pwd"},
            {"acr", true},
            {"sub_id", []},
            {"authorization_details", %{"type" => "example"}},
            {"authorization_details", ["example"]},
            {"authorization_details", [%{}]},
            {"authorization_details", [%{"type" => 10}]}
          ] do
        jwt = assertion(key, "ES256", %{claim => value})
        assert {:error, :invalid_claims} = IdentityAssertion.verify(jwt, public_jwks(key, "ES256"), opts())
      end
    end
  end

  describe "verify/3 - temporal" do
    test "rejects an expired assertion" do
      key = rsa_key()
      now = System.system_time(:second)
      jwt = assertion(key, "RS256", %{"iat" => now - 600, "exp" => now - 300})

      assert {:error, :expired} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects an iat in the future beyond skew" do
      key = rsa_key()
      now = System.system_time(:second)
      jwt = assertion(key, "RS256", %{"iat" => now + 3600, "exp" => now + 3900})

      assert {:error, :not_yet_valid} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects an nbf in the future beyond skew" do
      key = rsa_key()
      now = System.system_time(:second)
      jwt = assertion(key, "RS256", %{"nbf" => now + 3600})

      assert {:error, :not_yet_valid} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects a present non-integer nbf rather than treating it as absent" do
      # A malformed `nbf` (string, not a NumericDate) must fail closed. If it
      # fell through to the not-present clause, a garbage `nbf` would bypass the
      # not-yet-valid check entirely.
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"nbf" => "soon"})

      assert {:error, :invalid_claims} =
               IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
    end

    test "rejects an assertion exceeding max_lifetime_seconds" do
      key = rsa_key()
      now = System.system_time(:second)
      jwt = assertion(key, "RS256", %{"iat" => now, "exp" => now + 3600})

      assert {:error, :expired} =
               IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "RS256"),
                 opts(max_lifetime_seconds: 600)
               )
    end

    test "accepts within max_lifetime_seconds" do
      key = rsa_key()
      now = System.system_time(:second)
      jwt = assertion(key, "RS256", %{"iat" => now, "exp" => now + 300})

      assert {:ok, _} =
               IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "RS256"),
                 opts(max_lifetime_seconds: 600)
               )
    end

    test "rejects expiry before issued-at even inside clock skew" do
      key = rsa_key()
      now = 1_700_000_000
      jwt = assertion(key, "RS256", %{"iat" => now + 60, "exp" => now + 30})

      assert {:error, :expired} =
               IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "RS256"),
                 opts(now: now)
               )
    end

    test "keeps zero expiry leeway and 60-second future skew" do
      key = rsa_key()
      now = 1_700_000_000
      trusted = public_jwks(key, "RS256")

      assert {:error, :expired} =
               IdentityAssertion.verify(
                 assertion(key, "RS256", %{"iat" => now, "exp" => now}),
                 trusted,
                 opts(now: now)
               )

      assert {:ok, _} =
               IdentityAssertion.verify(
                 assertion(key, "RS256", %{
                   "iat" => now + 60,
                   "exp" => now + 300,
                   "nbf" => now + 60
                 }),
                 trusted,
                 opts(now: now)
               )

      assert {:error, :not_yet_valid} =
               IdentityAssertion.verify(
                 assertion(key, "RS256", %{"iat" => now + 61, "exp" => now + 300}),
                 trusted,
                 opts(now: now)
               )
    end
  end

  describe "peek_issuer/1" do
    test "reads the unverified iss" do
      key = rsa_key()
      jwt = assertion(key, "RS256")
      assert {:ok, @iss} = IdentityAssertion.peek_issuer(jwt)
    end

    test "returns :error for a malformed token" do
      assert :error = IdentityAssertion.peek_issuer("garbage")
    end
  end

  test "peek_claims returns unverified routing claims within the assertion size cap" do
    jwt = assertion(ec_key(), "ES256", %{"aud_tenant" => "recipient"})
    assert {:ok, %{"iss" => @iss, "aud_tenant" => "recipient"}} = IdentityAssertion.peek_claims(jwt)
    assert {:error, :malformed} = IdentityAssertion.peek_claims(String.duplicate("x", 65_537))
  end

  describe "sign/3 - Domain A ID-JAG issuance" do
    test "signs an ID-JAG that verifies cleanly with IdentityAssertion.verify/3" do
      key = ec_key()
      pem = JOSE.JWK.to_pem(key) |> elem(1)

      defmodule DomainAKeystore do
        @moduledoc false
        @behaviour Attesto.Keystore

        def signing_pem, do: Process.get({__MODULE__, :pem})
        def verification_pems, do: [Process.get({__MODULE__, :pem})]
      end

      Process.put({DomainAKeystore, :pem}, pem)

      config =
        Attesto.Config.new(
          issuer: @iss,
          audience: @iss,
          keystore: DomainAKeystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "u_")]
        )

      now = 1_750_000_000

      assert {:ok, jwt} =
               IdentityAssertion.sign(
                 config,
                 %{
                   sub: "user-123",
                   aud: @aud,
                   client_id: @cid,
                   scope: ["read", "write"],
                   resource: "https://api.example/mcp"
                 },
                 now: now,
                 lifetime: 45
               )

      assert {:ok, verified} = IdentityAssertion.verify(jwt, public_jwks(key, "ES256"), opts(now: now))
      assert verified["iss"] == @iss

      assert {:error, :invalid_claims} =
               IdentityAssertion.sign(
                 config,
                 %{sub: "user-123", aud: @aud, client_id: @cid, iss: "https://another-issuer.example"},
                 now: now
               )

      assert {:ok, same_issuer} =
               IdentityAssertion.sign(
                 config,
                 %{sub: "user-123", aud: @aud, client_id: @cid, iss: @iss},
                 now: now
               )

      assert {:ok, same_claims} = IdentityAssertion.verify(same_issuer, public_jwks(key, "ES256"), opts(now: now))
      assert same_claims["iss"] == @iss
      assert verified["sub"] == "user-123"
      assert verified["aud"] == @aud
      assert verified["client_id"] == @cid
      assert verified["scope"] == "read write"
      assert verified["resource"] == "https://api.example/mcp"
      assert verified["exp"] == now + 45
      assert is_binary(verified["jti"])
    end

    test "rejects missing required claims and invalid optional claims" do
      key = ec_key()
      pem = JOSE.JWK.to_pem(key) |> elem(1)

      defmodule InvalidSignKeystore do
        @moduledoc false
        @behaviour Attesto.Keystore

        def signing_pem, do: Process.get({__MODULE__, :pem})
        def verification_pems, do: [Process.get({__MODULE__, :pem})]
      end

      Process.put({InvalidSignKeystore, :pem}, pem)

      config =
        Attesto.Config.new(
          issuer: @iss,
          audience: @iss,
          keystore: InvalidSignKeystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "u_")]
        )

      assert {:error, :missing_claim} = IdentityAssertion.sign(config, %{aud: @aud, client_id: @cid})

      assert {:error, :invalid_claims} =
               IdentityAssertion.sign(config, %{sub: "u", aud: @aud, client_id: @cid, resource: "not-a-uri"})

      assert {:error, :invalid_claims} =
               IdentityAssertion.sign(config, %{sub: "u", aud: @aud, client_id: @cid, cnf: %{"jkt" => "bad"}})
    end

    test "supports typ: \"JWT\" for plain RFC 7523 grants while verify/3 continues requiring ID-JAG typ" do
      key = ec_key()
      pem = JOSE.JWK.to_pem(key) |> elem(1)

      defmodule PlainJwtSignKeystore do
        @moduledoc false
        @behaviour Attesto.Keystore

        def signing_pem, do: Process.get({__MODULE__, :pem})
        def verification_pems, do: [Process.get({__MODULE__, :pem})]
      end

      Process.put({PlainJwtSignKeystore, :pem}, pem)

      config =
        Attesto.Config.new(
          issuer: @iss,
          audience: @iss,
          keystore: PlainJwtSignKeystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "u_")]
        )

      now = 1_750_000_000

      assert {:ok, jwt} =
               IdentityAssertion.sign(config, %{sub: "user-123", aud: @aud, client_id: @cid},
                 now: now,
                 typ: "JWT"
               )

      assert {:ok, %{"typ" => "JWT"}} = Attesto.JWS.peek_json(jwt, :protected)
      assert {:error, :invalid_typ} = IdentityAssertion.verify(jwt, public_jwks(key, "ES256"), opts(now: now))

      assert_raise ArgumentError, fn ->
        IdentityAssertion.sign(config, %{sub: "user-123", aud: @aud, client_id: @cid}, typ: "at+jwt")
      end
    end
  end
end
