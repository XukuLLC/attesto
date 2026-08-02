defmodule Attesto.AttackClassRegressionTest do
  @moduledoc false
  # Tripwires for recurring OAuth/OIDC attack classes: each test drives a
  # specific attack against a security-critical, SILENTLY-failing control and
  # asserts attesto rejects it. Public CVEs are cited only as the canonical
  # example of a class - never to describe an unpatched bug anywhere.
  #
  # Attribution rule: cite only the governing RFC requirement or an ALREADY-
  # PUBLIC CVE. Do not describe an unpatched or undisclosed vulnerability in any
  # other project - this file is public, and a comment naming a peer's live bug
  # would be a disclosure. The value here is protecting attesto's own controls,
  # not cataloguing anyone else's.
  #
  # These are not tests of attesto features - they are tests that a control has
  # not regressed into a weakened shape. Every one was verified to FAIL if the
  # control is removed; a regression test that cannot fail is false confidence,
  # not coverage. When adding one, revert the guard once to watch it go red.
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationRequest
  alias Attesto.DPoP
  alias Attesto.RedirectURI
  alias Attesto.RequestObject
  alias Attesto.Test.Factory

  @registered ["https://app.example.com/cb"]

  describe "open redirect via error emitted before redirect_uri validation" do
    # Authlib CVE-2026-41479: an unsupported response_type with an
    # attacker-controlled redirect_uri turned the authorization endpoint into an
    # unauthenticated open redirect, because the error was produced BEFORE the
    # redirect_uri was validated against the client. attesto establishes the
    # redirect target first, so an unregistered URI is a DIRECT (non-redirected)
    # error under every failure it could otherwise ride out on.
    test "an unsupported response_type with an unregistered redirect_uri is a direct error" do
      result =
        AuthorizationRequest.validate(
          %{
            "client_id" => "c1",
            "response_type" => "token",
            "redirect_uri" => "https://evil.example/cb",
            "scope" => "openid",
            "state" => "s"
          },
          registered_redirect_uris: @registered,
          require_pkce: false
        )

      assert match?({:error, {:direct, _}}, result),
             "an error must not be redirected to an unregistered redirect_uri (Authlib CVE-2026-41479 class)"
    end

    # Same class via an invalid scope rather than response_type.
    test "an invalid scope with an unregistered redirect_uri is a direct error" do
      result =
        AuthorizationRequest.validate(
          %{
            "client_id" => "c1",
            "response_type" => "code",
            "redirect_uri" => "https://evil.example/cb",
            "scope" => "nope",
            "state" => "s"
          },
          registered_redirect_uris: @registered,
          require_pkce: false
        )

      assert match?({:error, {:direct, _}}, result)
    end
  end

  describe "redirect_uri validation bypass via crafted authority" do
    # Keycloak CVE-2026-7504: an `@` in the authority (userinfo) bypassed
    # redirect validation - `https://app.example.com@evil.example/cb` has host
    # `evil.example`, not `app.example.com`. attesto matches byte-exactly (no
    # wildcards, so it never matches the registered URI) AND unambiguous?/1
    # refuses userinfo outright, so it can never enter a registered set either.
    test "an @-authority (userinfo) redirect_uri is neither a match nor admissible" do
      crafted = "https://app.example.com@evil.example/cb"
      refute RedirectURI.registered?(crafted, @registered, :exact)
      refute RedirectURI.unambiguous?(crafted)
    end

    # An `@` in the PATH (not the authority) is legitimate and must stay
    # admissible - guards the assertion above against over-rejecting.
    test "an @ in the path is still admissible" do
      assert RedirectURI.unambiguous?("https://app.example.com/@handle/cb")
    end

    # Keycloak CVE-2026-3872: `..;/` path traversal bypassed validation.
    # Byte-exact matching has no normalization to exploit.
    test "a ..;/ path-traversal redirect_uri does not match a registered one" do
      refute RedirectURI.registered?("https://app.example.com/..;/cb", @registered, :exact)
    end

    # The parser-differential class attesto fixed in 1.5.0 (RFC 3986 vs WHATWG):
    # a backslash-userinfo authority two parsers read differently.
    test "a parser-ambiguous backslash-userinfo redirect_uri is inadmissible" do
      refute RedirectURI.unambiguous?("https://evil.example\\@app.example.com/cb")
    end
  end

  describe "DPoP proof is signature-verified with alg constrained" do
    # RFC 9449 §4.3: a DPoP proof MUST be a JWS verified against the key in its
    # own header, and §4.2 restricts the algorithm to asymmetric. attesto
    # verifies the signature and whitelists asymmetric algs, so alg:none (and
    # symmetric algs) are refused rather than trusted.
    test "a proof with alg:none is refused" do
      # Build a syntactically shaped proof claiming alg:none.
      header = Base.url_encode64(JSON.encode!(%{"typ" => "dpop+jwt", "alg" => "none", "jwk" => %{}}), padding: false)
      payload = Base.url_encode64(JSON.encode!(%{"htm" => "GET", "htu" => "https://api.example.com/x"}), padding: false)
      none_proof = header <> "." <> payload <> "."

      assert {:error, _} =
               DPoP.verify_proof(none_proof, http_method: "GET", http_uri: "https://api.example.com/x")
    end

    test "a well-formed proof verifies (guards against a vacuous refusal above)" do
      {proof, _jkt} = Factory.dpop_proof(htm: "GET", htu: "https://api.example.com/x")

      assert {:ok, _} =
               DPoP.verify_proof(proof, http_method: "GET", http_uri: "https://api.example.com/x")
    end
  end

  describe "request object (JAR) is signature-verified" do
    # RFC 9101 §6.3: the authorization server MUST validate the signature of a
    # request object against the client's registered keys. Decoding its claims
    # without verifying the signature (a "peek") would let an attacker forge
    # authorization parameters. attesto verifies against the client's trusted
    # JWKS and constrains the algorithm, so alg:none and unknown-key request
    # objects are refused.
    setup do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, pub} = JOSE.JWK.to_public_map(jwk)
      %{jwk: jwk, trusted: %{"keys" => [pub]}}
    end

    test "an alg:none request object is refused", %{trusted: trusted} do
      header = Base.url_encode64(JSON.encode!(%{"alg" => "none"}), padding: false)

      payload =
        Base.url_encode64(JSON.encode!(%{"client_id" => "c1", "scope" => "admin", "iss" => "c1"}), padding: false)

      none = header <> "." <> payload <> "."

      assert {:error, _} = RequestObject.verify(none, trusted)
    end

    test "a request object signed by a key the server does not trust is refused", %{trusted: trusted} do
      attacker = JOSE.JWK.generate_key({:ec, "P-256"})
      now = System.system_time(:second)

      {_, forged} =
        attacker
        |> JOSE.JWT.sign(%{"alg" => "ES256"}, %{
          "client_id" => "c1",
          "scope" => "admin",
          "iss" => "c1",
          "exp" => now + 300
        })
        |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = RequestObject.verify(forged, trusted)
    end
  end
end
