defmodule Attesto.DiscoveryTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Config
  alias Attesto.Discovery
  alias Attesto.DPoP
  alias Attesto.Keystore.Static
  alias Attesto.PrincipalKind

  # A Config whose keystore is never called (Discovery reads only the
  # issuer and token-endpoint path), so no app env is needed.
  defp config(overrides \\ []) do
    [
      issuer: "https://auth.example.com/",
      audience: "https://api.example.com/",
      keystore: Static,
      principal_kinds: [PrincipalKind.new("client", "oc_")]
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  describe "metadata/2 protocol-fixed and derived fields" do
    test "derives issuer, token_endpoint, and jwks_uri" do
      meta = Discovery.metadata(config())

      assert meta["issuer"] == "https://auth.example.com/"
      assert meta["token_endpoint"] == "https://auth.example.com/oauth/token"
      assert meta["jwks_uri"] == "https://auth.example.com/.well-known/jwks.json"
    end

    test "advertises S256 PKCE and the DPoP algorithm set" do
      meta = Discovery.metadata(config())

      assert meta["code_challenge_methods_supported"] == ["S256"]
      assert meta["dpop_signing_alg_values_supported"] == DPoP.allowed_algs()
    end

    test "defaults grant_types_supported to client_credentials" do
      assert Discovery.metadata(config())["grant_types_supported"] == ["client_credentials"]
    end

    test "honors a custom token_endpoint_path in the derived token_endpoint" do
      meta = Discovery.metadata(config(token_endpoint_path: "/oauth2/v1/token"))
      assert meta["token_endpoint"] == "https://auth.example.com/oauth2/v1/token"
    end
  end

  describe "metadata/2 host-supplied fields" do
    test "includes only the host endpoints and lists that are provided" do
      meta =
        Discovery.metadata(config(),
          authorization_endpoint: "https://auth.example.com/authorize",
          scopes_supported: ["documents.read", "documents.write"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
          token_endpoint_auth_signing_alg_values_supported: ["ES256", "PS256"],
          authorization_response_iss_parameter_supported: true
        )

      assert meta["authorization_endpoint"] == "https://auth.example.com/authorize"
      assert meta["scopes_supported"] == ["documents.read", "documents.write"]
      assert meta["token_endpoint_auth_methods_supported"] == ["client_secret_basic", "none"]
      assert meta["token_endpoint_auth_signing_alg_values_supported"] == ["ES256", "PS256"]
      assert meta["authorization_response_iss_parameter_supported"] == true

      # Endpoints not supplied are absent, not nil.
      refute Map.has_key?(meta, "revocation_endpoint")
      refute Map.has_key?(meta, "registration_endpoint")
      refute Map.has_key?(meta, "userinfo_endpoint")
    end

    test "a nil host value is dropped rather than advertised" do
      meta = Discovery.metadata(config(), revocation_endpoint: nil)
      refute Map.has_key?(meta, "revocation_endpoint")
    end

    test "advertises the RFC 9101 signed-request-object metadata when supplied" do
      meta =
        Discovery.metadata(config(),
          require_signed_request_object: true,
          request_object_signing_alg_values_supported: ["PS256", "ES256", "EdDSA"]
        )

      assert meta["require_signed_request_object"] == true
      assert meta["request_object_signing_alg_values_supported"] == ["PS256", "ES256", "EdDSA"]
    end

    test "omits the signed-request-object metadata when not supplied" do
      meta = Discovery.metadata(config())
      refute Map.has_key?(meta, "require_signed_request_object")
      refute Map.has_key?(meta, "request_object_signing_alg_values_supported")
    end

    test "advertises the front-channel logout and session-management metadata when supplied" do
      meta =
        Discovery.metadata(config(),
          frontchannel_logout_supported: true,
          frontchannel_logout_session_supported: true,
          check_session_iframe: "https://auth.example.com/oauth/check_session"
        )

      assert meta["frontchannel_logout_supported"] == true
      assert meta["frontchannel_logout_session_supported"] == true
      assert meta["check_session_iframe"] == "https://auth.example.com/oauth/check_session"
    end

    test "omits the front-channel logout and session-management metadata when not supplied" do
      meta = Discovery.metadata(config())
      refute Map.has_key?(meta, "frontchannel_logout_supported")
      refute Map.has_key?(meta, "frontchannel_logout_session_supported")
      refute Map.has_key?(meta, "check_session_iframe")
    end

    test "advertises client_id_metadata_document_supported when supplied" do
      meta = Discovery.metadata(config(), client_id_metadata_document_supported: true)
      assert meta["client_id_metadata_document_supported"] == true
    end

    test "omits client_id_metadata_document_supported when not supplied" do
      meta = Discovery.metadata(config())
      refute Map.has_key?(meta, "client_id_metadata_document_supported")
    end

    test "an explicit jwks_uri overrides the derived one" do
      meta = Discovery.metadata(config(), jwks_uri: "https://keys.example.com/jwks")
      assert meta["jwks_uri"] == "https://keys.example.com/jwks"
    end

    test "grant_types_supported can be overridden" do
      meta =
        Discovery.metadata(config(), grant_types_supported: ~w(client_credentials authorization_code refresh_token))

      assert meta["grant_types_supported"] == ~w(client_credentials authorization_code refresh_token)
    end
  end
end
