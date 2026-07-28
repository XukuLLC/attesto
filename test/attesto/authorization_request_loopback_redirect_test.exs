defmodule Attesto.AuthorizationRequestLoopbackRedirectTest do
  @moduledoc """
  RFC 8252 §7.3 loopback interface redirection, exercised through the public
  `Attesto.AuthorizationRequest.validate/2` surface.

  Every case is run in both configurations - the default `:exact` and the opt-in
  `:exact_allow_loopback_port` - because the guarantee under test is as much
  "nothing changes unless the host asks for it" as it is "the loopback port
  varies when it does".
  """

  use ExUnit.Case, async: true

  alias Attesto.AuthorizationRequest

  # BASE64URL(SHA256(verifier)), 43 chars, no padding (RFC 7636 §4.2).
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  defp params(redirect_uri) do
    %{
      "response_type" => "code",
      "client_id" => "native-client",
      "redirect_uri" => redirect_uri,
      "scope" => "openid",
      "state" => "xyz",
      "code_challenge" => @code_challenge,
      "code_challenge_method" => "S256"
    }
  end

  defp validate(redirect_uri, registered, opts \\ []) do
    AuthorizationRequest.validate(
      params(redirect_uri),
      [registered_redirect_uris: registered] ++ opts
    )
  end

  defp validate_exact(redirect_uri, registered) do
    validate(redirect_uri, registered, redirect_uri_matching: :exact)
  end

  defp validate_loopback(redirect_uri, registered) do
    validate(redirect_uri, registered, redirect_uri_matching: :exact_allow_loopback_port)
  end

  describe "default matching (RFC 6749 §3.1.2.3)" do
    test "is exact when no :redirect_uri_matching option is passed" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate("http://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"])
    end

    test "raises on an unrecognized matching mode rather than picking one" do
      assert_raise ArgumentError, ~r/invalid redirect_uri matching mode/, fn ->
        validate("http://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"], redirect_uri_matching: :loopback)
      end
    end
  end

  describe "exact match (both configurations)" do
    test "an exact match still wins when the loopback rule is enabled" do
      registered = ["https://app.example/cb"]

      assert {:ok, request} = validate_loopback("https://app.example/cb", registered)
      assert request.redirect_uri == "https://app.example/cb"

      assert {:ok, request} = validate_exact("https://app.example/cb", registered)
      assert request.redirect_uri == "https://app.example/cb"
    end

    test "an exactly matching loopback URI is accepted in both configurations" do
      registered = ["http://127.0.0.1:51823/cb"]

      assert {:ok, _request} = validate_exact("http://127.0.0.1:51823/cb", registered)
      assert {:ok, _request} = validate_loopback("http://127.0.0.1:51823/cb", registered)
    end
  end

  describe "loopback interface redirection (RFC 8252 §7.3)" do
    test "an IPv4 loopback request matches the registered URI on a different port" do
      assert {:ok, request} = validate_loopback("http://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"])

      # The validated request carries the URI the client actually asked for -
      # the ephemeral port the app is listening on - not the registered one.
      assert request.redirect_uri == "http://127.0.0.1:51823/cb"
    end

    test "the same request is rejected with the rule off" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_exact("http://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"])
    end

    test "an IPv6 loopback request behaves identically to the IPv4 case" do
      assert {:ok, request} = validate_loopback("http://[::1]:51823/cb", ["http://[::1]:0/cb"])
      assert request.redirect_uri == "http://[::1]:51823/cb"

      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_exact("http://[::1]:51823/cb", ["http://[::1]:0/cb"])
    end

    test "a portless registration also matches any request port" do
      assert {:ok, _request} = validate_loopback("http://127.0.0.1:51823/cb", ["http://127.0.0.1/cb"])
      assert {:ok, _request} = validate_loopback("http://[::1]:51823/cb", ["http://[::1]/cb"])
    end

    # RFC 8252 §8.3: `localhost` is NOT acceptable - the literal IP is required.
    test "localhost is rejected in all configurations" do
      for registered <- [["http://127.0.0.1:0/cb"], ["http://localhost:0/cb"]] do
        assert {:error, {:direct, :redirect_uri_not_registered}} =
                 validate_loopback("http://localhost:51823/cb", registered)

        assert {:error, {:direct, :redirect_uri_not_registered}} =
                 validate_exact("http://localhost:51823/cb", registered)
      end
    end

    test "a differing path is rejected even when scheme and host match" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("http://127.0.0.1:51823/other", ["http://127.0.0.1:0/cb"])
    end

    test "a differing query is rejected" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("http://127.0.0.1:51823/cb?a=2", ["http://127.0.0.1:0/cb?a=1"])
    end

    test "https loopback is not relaxed" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("https://127.0.0.1:51823/cb", ["https://127.0.0.1:0/cb"])
    end

    test "a remote host is not relaxed" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("https://example.com:8443/cb", ["https://example.com:443/cb"])
    end

    test "a private-use URI scheme redirect is unaffected in both configurations" do
      registered = ["com.example.app:/cb"]

      assert {:ok, _request} = validate_exact("com.example.app:/cb", registered)
      assert {:ok, _request} = validate_loopback("com.example.app:/cb", registered)

      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("com.example.app:/other", registered)
    end

    test "the loopback rule also governs the request-object error path" do
      # A request object that cannot be verified is only reportable BY REDIRECT
      # once the redirect_uri is trusted (OIDC Core §3.1.2.6). Reaching the
      # redirect classification proves the loopback URI was matched there too.
      params = Map.put(params("http://127.0.0.1:51823/cb"), "request", "not-a-jwt")

      assert {:error, {:redirect, error}} =
               AuthorizationRequest.validate(params,
                 registered_redirect_uris: ["http://127.0.0.1:0/cb"],
                 redirect_uri_matching: :exact_allow_loopback_port
               )

      assert error.error == "invalid_request_object"
      assert error.redirect_uri == "http://127.0.0.1:51823/cb"

      assert {:error, {:direct, :redirect_uri_not_registered}} =
               AuthorizationRequest.validate(params,
                 registered_redirect_uris: ["http://127.0.0.1:0/cb"],
                 redirect_uri_matching: :exact
               )
    end
  end

  describe "open-redirect regression" do
    # An unmatched redirect_uri must always be classified as a DIRECT error, so
    # the transport has no validated URI to redirect to. If any of these leaked
    # a `{:redirect, _}`, the endpoint would be an open redirect.
    test "an unregistered host is never returned as a redirect target" do
      registered = ["http://127.0.0.1:0/cb", "https://app.example/cb"]

      for uri <- [
            "https://evil.example/cb",
            "http://evil.example:51823/cb",
            "http://127.0.0.1:51823@evil.example/cb",
            "http://evil.example@127.0.0.1:51823/cb",
            "http://localhost:51823/cb",
            "http://0177.0.0.1:51823/cb",
            "http://2130706433:51823/cb",
            "http://127.0.0.2:51823/cb",
            "http://[::1]:51823/cb",
            "https://127.0.0.1:51823/cb",
            "HTTP://127.0.0.1:51823/cb"
          ] do
        assert {:error, {:direct, :redirect_uri_not_registered}} = validate_loopback(uri, registered),
               "#{uri} must not be trusted as a redirect target"

        assert {:error, {:direct, :redirect_uri_not_registered}} = validate_exact(uri, registered),
               "#{uri} must not be trusted as a redirect target"
      end
    end

    test "an empty registered set rejects every redirect URI" do
      assert {:error, {:direct, :redirect_uri_not_registered}} =
               validate_loopback("http://127.0.0.1:51823/cb", [])
    end
  end
end
