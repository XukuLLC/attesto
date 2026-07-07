defmodule Attesto.ProtectedResourceMetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Config
  alias Attesto.Keystore.Static
  alias Attesto.PrincipalKind
  alias Attesto.ProtectedResourceMetadata, as: PRM

  # A Config whose keystore is never called (the renderer reads only the
  # audience), so no app env is needed.
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

  describe "metadata/2 resource identifier (RFC 9728 §2)" do
    test "defaults resource to the config audience" do
      meta = PRM.metadata(config())
      assert meta["resource"] == "https://api.example.com/"
    end

    test "an explicit :resource overrides the audience default" do
      meta = PRM.metadata(config(), resource: "https://resource.example.com/")
      assert meta["resource"] == "https://resource.example.com/"
    end

    test "a nil :resource falls back to the config audience (not a nil member)" do
      meta = PRM.metadata(config(), resource: nil)
      assert meta["resource"] == "https://api.example.com/"
    end

    test "a present-but-malformed :resource fails fast (REQUIRED member)" do
      # Empty, non-https, non-URI, relative, fragment-bearing, bad-percent, and
      # non-string values are all rejected: the RFC 9728 §2 `resource` must be an
      # absolute https URL with a host and no fragment.
      for bad <- [
            "",
            "x",
            "/path",
            "http://a.example",
            "ftp://a.example",
            "https://a.example#frag",
            "https://a.example/a b",
            "https://a.example/\x01",
            "https://a.example/%ZZ",
            "https://a.example/%2",
            "https://a.example/%",
            ["https://a.example/"],
            %{"a" => 1},
            123
          ] do
        assert_raise ArgumentError, ~r/must be an absolute https URL with a host and no fragment/, fn ->
          PRM.metadata(config(), resource: bad)
        end
      end
    end

    test "under require_https: false a loopback http resource renders (dev carve-out)" do
      cfg =
        config(
          issuer: "http://localhost:4000",
          audience: "http://localhost:4000/mcp",
          require_https: false
        )

      assert PRM.metadata(cfg)["resource"] == "http://localhost:4000/mcp"

      assert PRM.metadata(cfg, resource: "http://127.0.0.1:4000/mcp")["resource"] ==
               "http://127.0.0.1:4000/mcp"
    end

    test "under require_https: false a NON-loopback http resource still fails fast" do
      cfg = config(issuer: "http://localhost:4000", audience: "https://api.example.com/", require_https: false)

      assert_raise ArgumentError, ~r/must be an absolute https URL/, fn ->
        PRM.metadata(cfg, resource: "http://api.example.com/mcp")
      end
    end

    test "under the default require_https: true a loopback http resource fails fast" do
      assert_raise ArgumentError, ~r/must be an absolute https URL/, fn ->
        PRM.metadata(config(), resource: "http://localhost:4000/mcp")
      end
    end

    test "every key is a string (JSON-serialisable shape)" do
      meta =
        PRM.metadata(config(),
          authorization_servers: ["https://auth.example.com/"],
          scopes_supported: ["documents.read"]
        )

      assert Enum.all?(Map.keys(meta), &is_binary/1)
    end
  end

  describe "metadata/2 host-supplied §2 fields" do
    test "includes only the fields that are provided" do
      meta =
        PRM.metadata(config(),
          authorization_servers: ["https://auth.example.com/", "https://auth2.example.com/"],
          jwks_uri: "https://api.example.com/.well-known/jwks.json",
          scopes_supported: ["documents.read", "documents.write"],
          bearer_methods_supported: ["header"],
          resource_signing_alg_values_supported: ["ES256", "PS256"],
          authorization_details_types_supported: ["payment_initiation"],
          resource_name: "Documents API",
          resource_documentation: "https://docs.example.com/api",
          resource_policy_uri: "https://example.com/policy",
          resource_tos_uri: "https://example.com/tos",
          tls_client_certificate_bound_access_tokens: true,
          dpop_bound_access_tokens_required: true,
          dpop_signing_alg_values_supported: ["ES256"],
          signed_metadata: "eyJ.signed.jwt"
        )

      assert meta["authorization_servers"] == ["https://auth.example.com/", "https://auth2.example.com/"]
      assert meta["jwks_uri"] == "https://api.example.com/.well-known/jwks.json"
      assert meta["scopes_supported"] == ["documents.read", "documents.write"]
      assert meta["bearer_methods_supported"] == ["header"]
      assert meta["resource_signing_alg_values_supported"] == ["ES256", "PS256"]
      assert meta["authorization_details_types_supported"] == ["payment_initiation"]
      assert meta["resource_name"] == "Documents API"
      assert meta["resource_documentation"] == "https://docs.example.com/api"
      assert meta["resource_policy_uri"] == "https://example.com/policy"
      assert meta["resource_tos_uri"] == "https://example.com/tos"
      assert meta["tls_client_certificate_bound_access_tokens"] == true
      assert meta["dpop_bound_access_tokens_required"] == true
      assert meta["dpop_signing_alg_values_supported"] == ["ES256"]
      assert meta["signed_metadata"] == "eyJ.signed.jwt"
    end

    test "fields not supplied are absent, not nil" do
      meta = PRM.metadata(config())

      for field <- ~w(
            authorization_servers jwks_uri scopes_supported bearer_methods_supported
            resource_signing_alg_values_supported authorization_details_types_supported
            resource_name resource_documentation
            resource_policy_uri resource_tos_uri tls_client_certificate_bound_access_tokens
            dpop_bound_access_tokens_required dpop_signing_alg_values_supported signed_metadata
          ) do
        refute Map.has_key?(meta, field)
      end
    end

    test "a nil host value is dropped rather than advertised" do
      meta = PRM.metadata(config(), authorization_servers: nil, resource_name: nil)
      refute Map.has_key?(meta, "authorization_servers")
      refute Map.has_key?(meta, "resource_name")
    end

    test "an unknown opt key is ignored" do
      meta = PRM.metadata(config(), not_a_real_field: "x")
      refute Map.has_key?(meta, "not_a_real_field")
    end
  end
end
