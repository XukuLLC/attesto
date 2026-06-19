defmodule Attesto.IdentityAssertionTest do
  use ExUnit.Case, async: true

  alias Attesto.IdentityAssertion

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
    {_header, compact} = jwk |> JOSE.JWT.sign(header, claims(claim_overrides)) |> JOSE.JWS.compact()
    compact
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

    test "carries optional claims (scope, email) through" do
      key = rsa_key()
      jwt = assertion(key, "RS256", %{"scope" => "mcp:read mcp:write", "email" => "a@example.com"})

      assert {:ok, claims} = IdentityAssertion.verify(jwt, public_jwks(key, "RS256"), opts())
      assert claims["scope"] == "mcp:read mcp:write"
      assert claims["email"] == "a@example.com"
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
end
