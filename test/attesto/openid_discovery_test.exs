defmodule Attesto.OpenIDDiscoveryTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Config
  alias Attesto.Keystore.Static
  alias Attesto.OpenIDDiscovery
  alias Attesto.PrincipalKind
  alias Attesto.Test.PS256Keystore

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

  describe "metadata/2 protocol fields" do
    test "adds OpenID Provider required metadata over the OAuth discovery base" do
      meta = OpenIDDiscovery.metadata(config())

      assert meta["issuer"] == "https://auth.example.com/"
      assert meta["token_endpoint"] == "https://auth.example.com/oauth/token"
      assert meta["jwks_uri"] == "https://auth.example.com/.well-known/jwks.json"
      assert meta["response_types_supported"] == ["code"]
      assert meta["subject_types_supported"] == ["public"]
      assert meta["id_token_signing_alg_values_supported"] == ["RS256"]
      assert meta["claim_types_supported"] == ["normal"]
      assert meta["request_parameter_supported"] == false
      assert meta["code_challenge_methods_supported"] == ["S256"]
    end

    test "loads keystore modules before deriving advertised ID Token algorithms" do
      module_path = :code.which(PS256Keystore)
      :code.purge(PS256Keystore)
      :code.delete(PS256Keystore)

      assert function_exported?(PS256Keystore, :verification_pems, 0) == false
      assert is_list(module_path)

      meta = OpenIDDiscovery.metadata(config(keystore: PS256Keystore))

      assert meta["id_token_signing_alg_values_supported"] == ["PS256"]
      assert function_exported?(PS256Keystore, :verification_pems, 0)
    end

    test "does not advertise optional host fields when omitted" do
      meta = OpenIDDiscovery.metadata(config())

      refute Map.has_key?(meta, "authorization_endpoint")
      refute Map.has_key?(meta, "userinfo_endpoint")
      refute Map.has_key?(meta, "claims_supported")
      refute Map.has_key?(meta, "scopes_supported")
    end
  end

  describe "metadata/2 host fields" do
    test "includes supplied endpoints, scopes, claims, and OIDC options" do
      meta =
        OpenIDDiscovery.metadata(config(),
          authorization_endpoint: "https://auth.example.com/oauth/authorize",
          userinfo_endpoint: "https://auth.example.com/userinfo",
          registration_endpoint: "https://auth.example.com/oauth/register",
          scopes_supported: ["profile", "email"],
          claims_supported: ["sub", "email", "email_verified"],
          acr_values_supported: ["phr"],
          request_parameter_supported: true,
          claims_parameter_supported: false
        )

      assert meta["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
      assert meta["userinfo_endpoint"] == "https://auth.example.com/userinfo"
      assert meta["registration_endpoint"] == "https://auth.example.com/oauth/register"
      assert meta["scopes_supported"] == ["openid", "profile", "email"]
      assert meta["claims_supported"] == ["sub", "email", "email_verified"]
      assert meta["acr_values_supported"] == ["phr"]
      assert meta["request_parameter_supported"] == true
      assert meta["claims_parameter_supported"] == false
    end

    test "preserves a valid host-supplied scope catalog" do
      meta = OpenIDDiscovery.metadata(config(), scopes_supported: ["openid", "profile"])
      assert meta["scopes_supported"] == ["openid", "profile"]
    end

    test "normalizes a catalog that omits the required openid scope" do
      meta = OpenIDDiscovery.metadata(config(), scopes_supported: ["profile"])
      assert meta["scopes_supported"] == ["openid", "profile"]
    end

    test "honors host response_types_supported override" do
      meta = OpenIDDiscovery.metadata(config(), response_types_supported: ["code", "code id_token"])
      assert meta["response_types_supported"] == ["code", "code id_token"]
    end
  end
end
