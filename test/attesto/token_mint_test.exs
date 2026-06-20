defmodule Attesto.TokenMintTest do
  @moduledoc false
  # Factory.config/2 mutates the global :attesto app env (installs the
  # signing PEM into Attesto.Keystore.Static), so these tests run serially.
  use ExUnit.Case, async: false

  alias Attesto.Key
  alias Attesto.MTLS
  alias Attesto.Test.Factory
  alias Attesto.Token

  # A canonical RFC 7638 SHA-256 JWK thumbprint: 43 base64url chars that
  # decode to exactly 32 bytes and re-encode unchanged.
  @valid_jkt "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  # A canonical RFC 8705 x5t#S256 certificate thumbprint, same shape.
  @valid_x5t "6HaiSqyZAX9r-v9TpDb-B5z-k6tS0_yfWo10dgy0PbM"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  # Decode a JWT payload without verifying the signature, so we can assert
  # on the exact claim set the minter produced.
  defp payload!(jwt) when is_binary(jwt) do
    [_header, payload_b64 | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(payload_b64, padding: false)
    JSON.decode!(decoded)
  end

  defp header!(jwt) when is_binary(jwt) do
    [header_b64 | _] = String.split(jwt, ".")
    {:ok, decoded} = Base.url_decode64(header_b64, padding: false)
    JSON.decode!(decoded)
  end

  defp client_principal(overrides \\ %{}) do
    Map.merge(
      %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
      overrides
    )
  end

  defp user_principal(overrides) do
    Map.merge(
      %{
        kind: "user",
        sub: "usr_abc123",
        scopes: ["documents.read"],
        claims: %{"act" => "ac_7", "sid" => "sess_1", "token_version" => 0}
      },
      overrides
    )
  end

  describe "mint/3 success - client kind" do
    test "mints a Bearer access token carrying the standard claim set", %{config: config} do
      now = 1_700_000_000

      assert {:ok, %{access_token: jwt, token_type: "Bearer", expires_in: 900, scope: "documents.read"}} =
               Token.mint(config, client_principal(%{scopes: ["documents.read"]}), now: now)

      claims = payload!(jwt)
      assert claims["iss"] == "https://api.example.com/"
      assert claims["aud"] == "https://api.example.com/"
      assert claims["sub"] == "oc_abc123"
      assert claims["iat"] == now
      assert claims["exp"] == now + 900
      assert claims["scope"] == "documents.read"
      assert claims["principal_kind"] == "client"
      assert claims["typ"] == "access"
      assert claims["client_id"] == "oc_abc123"
      assert is_binary(claims["jti"])
      assert byte_size(claims["jti"]) >= 16
      refute Map.has_key?(claims, "cnf")
      refute Map.has_key?(claims, "act")
    end

    test "jti is unique across mints", %{config: config} do
      jtis =
        for _ <- 1..20 do
          assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())
          payload!(jwt)["jti"]
        end

      assert length(Enum.uniq(jtis)) == 20
    end

    test "the JWS header pins alg=RS256 and carries the signing key kid", %{config: config, pem: pem} do
      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = header!(jwt)
      assert header["alg"] == "RS256"
      assert header["kid"] == Key.kid(pem)
    end
  end

  describe "mint/3 success - user kind" do
    test "mints a token carrying user identity claims (act/sid/token_version)", %{config: config} do
      assert {:ok, %{access_token: jwt, scope: "documents.read positions.read"}} =
               Token.mint(config, user_principal(%{scopes: ["documents.read", "positions.read"]}))

      claims = payload!(jwt)
      assert claims["principal_kind"] == "user"
      assert claims["sub"] == "usr_abc123"
      assert claims["act"] == "ac_7"
      assert claims["sid"] == "sess_1"
      assert claims["token_version"] == 0
      assert claims["typ"] == "access"
      refute Map.has_key?(claims, "client_id")
    end
  end

  describe "mint/3 scope claim" do
    test "joins the scope list with single spaces", %{config: config} do
      assert {:ok, %{scope: "documents.read positions.read webhooks.read"}} =
               Token.mint(config, client_principal(%{scopes: ["documents.read", "positions.read", "webhooks.read"]}))
    end

    test "dedupes repeated scopes", %{config: config} do
      assert {:ok, %{access_token: jwt, scope: "documents.read"}} =
               Token.mint(config, client_principal(%{scopes: ["documents.read", "documents.read"]}))

      assert payload!(jwt)["scope"] == "documents.read"
    end

    test "an empty scope list mints an empty scope claim", %{config: config} do
      assert {:ok, %{scope: ""}} = Token.mint(config, client_principal(%{scopes: []}))
    end
  end

  describe "mint/3 sub validation" do
    test "rejects a sub that does not start with the kind's prefix", %{config: config} do
      assert {:error, :invalid_sub} = Token.mint(config, client_principal(%{sub: "usr_wrong"}))
      assert {:error, :invalid_sub} = Token.mint(config, user_principal(%{sub: "oc_wrong"}))
    end

    test "rejects an empty or non-binary sub", %{config: config} do
      assert {:error, :invalid_sub} = Token.mint(config, client_principal(%{sub: ""}))
      assert {:error, :invalid_sub} = Token.mint(config, client_principal(%{sub: 42}))
      assert {:error, :invalid_sub} = Token.mint(config, client_principal(%{sub: nil}))
    end
  end

  describe "mint/3 required claims" do
    test "rejects a client missing client_id", %{config: config} do
      assert {:error, :invalid_claims} =
               Token.mint(config, %{kind: "client", sub: "oc_x", scopes: []})
    end

    test "rejects a client whose client_id is the wrong shape (empty string)", %{config: config} do
      assert {:error, :invalid_claims} =
               Token.mint(config, client_principal(%{claims: %{"client_id" => ""}}))
    end

    test "rejects a user missing any of act/sid/token_version", %{config: config} do
      assert {:error, :invalid_claims} =
               Token.mint(config, user_principal(%{claims: %{"sid" => "sess_1", "token_version" => 0}}))

      assert {:error, :invalid_claims} =
               Token.mint(config, user_principal(%{claims: %{"act" => "ac_7", "token_version" => 0}}))

      assert {:error, :invalid_claims} =
               Token.mint(config, user_principal(%{claims: %{"act" => "ac_7", "sid" => "sess_1"}}))
    end

    test "rejects a user whose token_version is not a non-negative integer", %{config: config} do
      assert {:error, :invalid_claims} =
               Token.mint(
                 config,
                 user_principal(%{claims: %{"act" => "ac_7", "sid" => "sess_1", "token_version" => "0"}})
               )

      assert {:error, :invalid_claims} =
               Token.mint(
                 config,
                 user_principal(%{claims: %{"act" => "ac_7", "sid" => "sess_1", "token_version" => -1}})
               )
    end

    test "rejects a :claims that is not a map or whose keys are not strings", %{config: config} do
      assert {:error, :invalid_claims} = Token.mint(config, client_principal(%{claims: "not-a-map"}))
      assert {:error, :invalid_claims} = Token.mint(config, client_principal(%{claims: %{client_id: "oc_abc123"}}))
    end
  end

  describe "mint/3 reserved claim conflict" do
    test "rejects an extra claim colliding with a reserved protocol name", %{config: config} do
      for reserved <- ~w(iss aud exp iat jti sub scope typ cnf principal_kind) do
        extra = Map.put(%{"client_id" => "oc_abc123"}, reserved, "shadow")

        assert {:error, :reserved_claim_conflict} = Token.mint(config, client_principal(%{claims: extra})),
               "expected :reserved_claim_conflict for extra claim #{inspect(reserved)}"
      end
    end
  end

  describe "mint/3 scope shape" do
    test "rejects a non-list scopes value", %{config: config} do
      for bad <- ["documents.read", 42, %{}, nil] do
        assert {:error, :invalid_scopes} = Token.mint(config, client_principal(%{scopes: bad})),
               "expected :invalid_scopes for scopes=#{inspect(bad)}"
      end
    end

    test "rejects a list containing a non-binary element", %{config: config} do
      assert {:error, :invalid_scopes} = Token.mint(config, client_principal(%{scopes: ["documents.read", 42]}))
      assert {:error, :invalid_scopes} = Token.mint(config, client_principal(%{scopes: [nil]}))
      assert {:error, :invalid_scopes} = Token.mint(config, client_principal(%{scopes: [:documents_read]}))
    end
  end

  describe "mint/3 typ" do
    test "typ defaults to access", %{config: config} do
      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())
      assert payload!(jwt)["typ"] == "access"
    end

    test "typ: \"refresh\" mints a refresh token", %{config: config} do
      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), typ: "refresh")
      assert payload!(jwt)["typ"] == "refresh"
    end

    test "an unknown typ is rejected with :invalid_typ", %{config: config} do
      for bad <- ["bearer", "Access", "", :access, 1] do
        assert {:error, :invalid_typ} = Token.mint(config, client_principal(), typ: bad),
               "expected :invalid_typ for typ=#{inspect(bad)}"
      end
    end
  end

  describe "mint/3 lifetime" do
    test "a lifetime larger than the default is capped to the default", %{config: config} do
      assert {:ok, %{access_token: jwt, expires_in: 900}} =
               Token.mint(config, client_principal(), lifetime: 999_999, now: 0)

      claims = payload!(jwt)
      assert claims["exp"] - claims["iat"] == 900
    end

    test "a shorter lifetime is honored", %{config: config} do
      assert {:ok, %{access_token: jwt, expires_in: 60}} =
               Token.mint(config, client_principal(), lifetime: 60, now: 0)

      claims = payload!(jwt)
      assert claims["exp"] - claims["iat"] == 60
    end

    test "a non-positive or non-integer lifetime falls back to the default", %{config: config} do
      for bad <- [0, -1, "300", 300.5, nil] do
        assert {:ok, %{expires_in: 900}} = Token.mint(config, client_principal(), lifetime: bad),
               "expected default lifetime for lifetime=#{inspect(bad)}"
      end
    end
  end

  describe "mint/3 now option" do
    test "accepts a DateTime as :now", %{config: config} do
      dt = ~U[2026-01-01 00:00:00Z]
      unix = DateTime.to_unix(dt, :second)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: dt)
      assert payload!(jwt)["iat"] == unix
    end

    test "accepts a unix integer as :now", %{config: config} do
      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: 1_700_000_000)
      assert payload!(jwt)["iat"] == 1_700_000_000
    end
  end

  # RFC 8707 §2: a per-call `:audience` override (a validated `resource`
  # indicator) overrides config.audience for this token's `aud` only.
  describe "mint/3 audience option" do
    test "an :audience option overrides config.audience in the aud claim", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(config, client_principal(), audience: "https://resource.example/api")

      assert payload!(jwt)["aud"] == "https://resource.example/api"
    end

    test "without :audience the aud claim is config.audience", %{config: config} do
      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())
      assert payload!(jwt)["aud"] == "https://api.example.com/"
    end

    test "a present-but-malformed :audience fails closed as :invalid_audience", %{config: config} do
      # RFC 8707 §2: the override is a single resource identifier. A miswired
      # caller must not mint a malformed/attacker-influenced aud.
      for bad <- [nil, "", ["https://a.example/"], %{"a" => 1}, :atom, 123] do
        assert {:error, :invalid_audience} =
                 Token.mint(config, client_principal(), audience: bad),
               "expected :invalid_audience for #{inspect(bad)}"
      end
    end
  end

  describe "mint/3 DPoP binding" do
    test "embeds cnf.jkt and switches token_type to DPoP", %{config: config} do
      assert {:ok, %{access_token: jwt, token_type: "DPoP", scope: "documents.read"}} =
               Token.mint(config, client_principal(%{scopes: ["documents.read"]}), dpop_jkt: @valid_jkt)

      claims = payload!(jwt)
      assert claims["cnf"] == %{"jkt" => @valid_jkt}
      assert claims["sub"] == "oc_abc123"
    end

    test "a nil :dpop_jkt leaves the token a plain Bearer with no cnf", %{config: config} do
      assert {:ok, %{access_token: jwt, token_type: "Bearer"}} =
               Token.mint(config, client_principal(), dpop_jkt: nil)

      refute Map.has_key?(payload!(jwt), "cnf")
    end

    test "an empty-string :dpop_jkt is rejected with :invalid_dpop_jkt", %{config: config} do
      assert {:error, :invalid_dpop_jkt} = Token.mint(config, client_principal(), dpop_jkt: "")
    end

    test "a malformed :dpop_jkt is rejected with :invalid_dpop_jkt", %{config: config} do
      malformed = [
        "tooshort",
        String.duplicate("a", 42),
        String.duplicate("a", 44),
        String.duplicate("a", 42) <> "+",
        String.duplicate("a", 42) <> "/",
        String.duplicate("a", 42) <> "=",
        String.duplicate("a", 42) <> " ",
        # 43-char base64url alphabet but non-canonical trailing bits.
        "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
        42,
        %{},
        [:thumbprint],
        true
      ]

      for bad <- malformed do
        assert {:error, :invalid_dpop_jkt} = Token.mint(config, client_principal(), dpop_jkt: bad),
               "expected :invalid_dpop_jkt for dpop_jkt=#{inspect(bad)}"
      end
    end
  end

  describe "mint/3 mTLS binding" do
    test "embeds cnf.x5t#S256 and keeps token_type Bearer", %{config: config} do
      assert {:ok, %{access_token: jwt, token_type: "Bearer", scope: "documents.read"}} =
               Token.mint(config, client_principal(%{scopes: ["documents.read"]}), mtls_cert_thumbprint: @valid_x5t)

      claims = payload!(jwt)
      assert claims["cnf"] == %{"x5t#S256" => @valid_x5t}
      assert claims["sub"] == "oc_abc123"
    end

    test "a nil :mtls_cert_thumbprint leaves the token a plain Bearer with no cnf", %{config: config} do
      assert {:ok, %{access_token: jwt, token_type: "Bearer"}} =
               Token.mint(config, client_principal(), mtls_cert_thumbprint: nil)

      refute Map.has_key?(payload!(jwt), "cnf")
    end

    test "an empty-string :mtls_cert_thumbprint is rejected with :invalid_mtls_thumbprint", %{config: config} do
      assert {:error, :invalid_mtls_thumbprint} = Token.mint(config, client_principal(), mtls_cert_thumbprint: "")
    end

    test "a malformed :mtls_cert_thumbprint is rejected with :invalid_mtls_thumbprint", %{config: config} do
      malformed = [
        "tooshort",
        String.duplicate("a", 42),
        String.duplicate("a", 44),
        String.duplicate("a", 42) <> "+",
        String.duplicate("a", 42) <> "/",
        String.duplicate("a", 42) <> "=",
        String.duplicate("a", 42) <> " ",
        "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
        42,
        %{},
        [:thumb],
        true
      ]

      for bad <- malformed do
        assert {:error, :invalid_mtls_thumbprint} =
                 Token.mint(config, client_principal(), mtls_cert_thumbprint: bad),
               "expected :invalid_mtls_thumbprint for mtls_cert_thumbprint=#{inspect(bad)}"
      end
    end
  end

  describe "mint/3 conflicting confirmation" do
    test "supplying both :dpop_jkt and :mtls_cert_thumbprint is :conflicting_confirmation", %{config: config} do
      assert {:error, :conflicting_confirmation} =
               Token.mint(config, client_principal(), dpop_jkt: @valid_jkt, mtls_cert_thumbprint: @valid_x5t)
    end
  end

  describe "mint/3 unknown principal kind" do
    test "an unconfigured kind is rejected with :unknown_principal_kind", %{config: config} do
      assert {:error, :unknown_principal_kind} =
               Token.mint(config, %{kind: "admin", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}})
    end

    test "a principal with no :kind is rejected with :unknown_principal_kind", %{config: config} do
      assert {:error, :unknown_principal_kind} = Token.mint(config, %{sub: "oc_x", scopes: []})
    end
  end

  describe "mint/3 end-to-end with MTLS.compute_thumbprint" do
    test "a minted mTLS-bound token's cnf.x5t#S256 matches the thumbprint of the bound cert", %{config: config} do
      %{cert: der} = :public_key.pkix_test_root_cert(~c"cn=attesto-mtls-mint", [])
      assert {:ok, thumbprint} = MTLS.compute_thumbprint(der)

      assert {:ok, %{access_token: jwt, token_type: "Bearer"}} =
               Token.mint(config, client_principal(), mtls_cert_thumbprint: thumbprint)

      assert payload!(jwt)["cnf"]["x5t#S256"] == thumbprint
    end
  end
end
