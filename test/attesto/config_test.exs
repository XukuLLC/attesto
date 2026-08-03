defmodule Attesto.ConfigTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CNonceStore.ETS
  alias Attesto.Config
  alias Attesto.PrincipalKind

  # A keystore module that exists at compile time. Config.new/1 only checks
  # that :keystore is a module (an atom); it never calls into it, so no app
  # env and no real signing material is required for these pure tests.
  defmodule DummyKeystore do
    @moduledoc false
    def signing_pem, do: "unused"
    def verification_pems, do: ["unused"]
  end

  defp client_kind do
    PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
  end

  defp user_kind do
    PrincipalKind.new("user", "usr_",
      required_claims: [
        {"act", :non_empty_string},
        {"sid", :non_empty_string},
        {"token_version", :non_neg_integer}
      ]
    )
  end

  defp base_opts(overrides \\ []) do
    Keyword.merge(
      [
        issuer: "https://api.example.com/",
        audience: "https://api.example.com/",
        keystore: DummyKeystore,
        principal_kinds: [client_kind(), user_kind()]
      ],
      overrides
    )
  end

  describe "new/1 success and defaults" do
    test "builds a config and applies documented defaults" do
      config = Config.new(base_opts())

      assert config.issuer == "https://api.example.com/"
      assert config.audience == "https://api.example.com/"
      assert config.keystore == DummyKeystore
      assert config.c_nonce_store == nil
      assert config.credential_offer_store == nil
      assert config.principal_kind_claim == "principal_kind"
      assert config.default_lifetime_seconds == 900
      assert config.token_endpoint_path == "/oauth/token"
    end

    test "accepts an overridden principal_kind_claim, lifetime, and token path" do
      config =
        Config.new(
          base_opts(
            principal_kind_claim: "https://example.com/pk",
            default_lifetime_seconds: 300,
            token_endpoint_path: "/auth/token"
          )
        )

      assert config.principal_kind_claim == "https://example.com/pk"
      assert config.default_lifetime_seconds == 300
      assert config.token_endpoint_path == "/auth/token"
    end

    test "accepts and exposes the OID4VCI store modules" do
      config =
        Config.new(
          base_opts(
            c_nonce_store: ETS,
            credential_offer_store: Attesto.CredentialOfferStore.ETS
          )
        )

      assert Config.c_nonce_store(config) == ETS
      assert Config.credential_offer_store(config) == Attesto.CredentialOfferStore.ETS
    end
  end

  describe "new/1 validation" do
    test "raises on a blank issuer" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(issuer: "")) end
    end

    test "raises on a non-binary issuer" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(issuer: nil)) end
    end

    test "raises on a blank audience" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(audience: "")) end
    end

    test "raises when keystore is not a module" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(keystore: "not a module")) end
      assert_raise ArgumentError, fn -> Config.new(base_opts(keystore: nil)) end
    end

    test "raises when principal_kinds is empty" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(principal_kinds: [])) end
    end

    test "raises when principal_kinds is not a list" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(principal_kinds: client_kind())) end
    end

    test "raises when a principal_kinds entry is not a PrincipalKind struct" do
      assert_raise ArgumentError, fn ->
        Config.new(base_opts(principal_kinds: [client_kind(), %{claim_value: "x"}]))
      end
    end

    test "raises on duplicate claim_value across kinds" do
      dup =
        PrincipalKind.new("client", "other_", required_claims: [{"client_id", :non_empty_string}])

      assert_raise ArgumentError, fn ->
        Config.new(base_opts(principal_kinds: [client_kind(), dup]))
      end
    end

    test "raises on duplicate sub_prefix across kinds" do
      dup = PrincipalKind.new("other", "oc_", required_claims: [{"client_id", :non_empty_string}])

      assert_raise ArgumentError, fn ->
        Config.new(base_opts(principal_kinds: [client_kind(), dup]))
      end
    end

    test "raises when principal_kind_claim collides with a reserved claim" do
      assert_raise ArgumentError, fn ->
        Config.new(base_opts(principal_kind_claim: "sub"))
      end

      assert_raise ArgumentError, fn ->
        Config.new(base_opts(principal_kind_claim: "iss"))
      end
    end

    test "raises when principal_kind_claim is blank" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(principal_kind_claim: "")) end
    end

    test "raises on a non-positive default_lifetime_seconds" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(default_lifetime_seconds: 0)) end
      assert_raise ArgumentError, fn -> Config.new(base_opts(default_lifetime_seconds: -1)) end
    end

    test "raises on a non-integer default_lifetime_seconds" do
      assert_raise ArgumentError, fn -> Config.new(base_opts(default_lifetime_seconds: 1.5)) end
    end

    test "raises on a token_endpoint_path that is not an absolute path" do
      assert_raise ArgumentError, ~r/token_endpoint_path/, fn ->
        Config.new(base_opts(token_endpoint_path: "oauth/token"))
      end

      assert_raise ArgumentError, ~r/token_endpoint_path/, fn ->
        Config.new(base_opts(token_endpoint_path: nil))
      end
    end

    test "raises on token_endpoint_path with authority, query, or fragment" do
      for bad <- ["//evil.example/token", "/oauth/token?x=1", "/oauth/token#frag"] do
        assert_raise ArgumentError, ~r/token_endpoint_path/, fn ->
          Config.new(base_opts(token_endpoint_path: bad))
        end
      end
    end

    test "accepts an absolute token_endpoint_path" do
      config = Config.new(base_opts(token_endpoint_path: "/auth/token"))
      assert config.token_endpoint_path == "/auth/token"
    end

    test "raises on an empty-string or non-binary access_token_header_typ" do
      assert_raise ArgumentError, ~r/access_token_header_typ/, fn ->
        Config.new(base_opts(access_token_header_typ: ""))
      end

      assert_raise ArgumentError, ~r/access_token_header_typ/, fn ->
        Config.new(base_opts(access_token_header_typ: :at_jwt))
      end
    end

    test "accepts a nil access_token_header_typ (emit no typ header)" do
      config = Config.new(base_opts(access_token_header_typ: nil))
      assert config.access_token_header_typ == nil
    end
  end

  describe "principal_kind/2" do
    test "finds a configured kind by its claim_value" do
      config = Config.new(base_opts())

      assert %PrincipalKind{claim_value: "client", sub_prefix: "oc_"} =
               Config.principal_kind(config, "client")

      assert %PrincipalKind{claim_value: "user", sub_prefix: "usr_"} =
               Config.principal_kind(config, "user")
    end

    test "returns nil for an unknown claim_value" do
      config = Config.new(base_opts())
      assert Config.principal_kind(config, "device") == nil
      assert Config.principal_kind(config, nil) == nil
    end
  end

  describe "token_endpoint_url/1" do
    test "merges the issuer origin with the configured token_endpoint_path" do
      config = Config.new(base_opts())
      assert Config.token_endpoint_url(config) == "https://api.example.com/oauth/token"
    end

    test "honors a custom token_endpoint_path" do
      config = Config.new(base_opts(token_endpoint_path: "/auth/token"))
      assert Config.token_endpoint_url(config) == "https://api.example.com/auth/token"
    end

    test "uses the issuer's host even when the issuer carries a path" do
      config = Config.new(base_opts(issuer: "https://id.example.com/tenant/"))
      assert Config.token_endpoint_url(config) == "https://id.example.com/oauth/token"
    end
  end

  describe "reserved_claims/1" do
    test "includes the standard protocol claims and the configured principal_kind_claim" do
      config = Config.new(base_opts())
      reserved = Config.reserved_claims(config)

      for claim <- ~w(iss aud exp iat jti sub scope typ cnf principal_kind) do
        assert claim in reserved
      end
    end

    test "reflects a custom principal_kind_claim" do
      config = Config.new(base_opts(principal_kind_claim: "https://example.com/pk"))
      reserved = Config.reserved_claims(config)

      assert "https://example.com/pk" in reserved
      refute "principal_kind" in reserved
    end
  end
end
