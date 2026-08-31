defmodule Attesto.TokenVerifyTest do
  @moduledoc false
  # Factory.config/2 and Attesto.Keystore.Static both mutate the global
  # :attesto app env, so these tests run serially.
  use ExUnit.Case, async: false

  alias Attesto.Keystore.Static
  alias Attesto.Test.Factory
  alias Attesto.Test.RotationKeystore
  alias Attesto.Token

  @issuer "https://api.example.com/"
  @audience "https://api.example.com/"

  @valid_jkt "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  @valid_x5t "6HaiSqyZAX9r-v9TpDb-B5z-k6tS0_yfWo10dgy0PbM"

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  defp unix_now, do: DateTime.utc_now() |> DateTime.to_unix(:second)
  defp unix_in(delta) when is_integer(delta), do: unix_now() + delta

  # Sign an arbitrary claim map with `pem` so the signature is structurally
  # valid under Attesto.Token's default RSA path (RS256 + the key's kid). The
  # mandatory `principal_kind` and `typ` claims default so claim-rejection
  # tests that do not care about them exercise an otherwise valid token; a
  # claim may be forced ABSENT with the :__drop__ sentinel.
  defp forge(pem, claims, opts \\ []) when is_map(claims) do
    with_defaults =
      claims
      |> put_default("typ", "access")
      |> put_default("principal_kind", default_kind_for(claims))
      |> Enum.reject(fn {_k, v} -> v == :__drop__ end)
      |> Map.new()

    jwk = Attesto.Key.signing_jwk(pem)
    kid = Keyword.get(opts, :kid, Attesto.Key.kid(pem))
    alg = Keyword.get(opts, :alg, Token.signing_alg())

    {_header, compact} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => alg, "kid" => kid}, with_defaults)
      |> JOSE.JWS.compact()

    compact
  end

  defp put_default(map, key, value) do
    if Map.has_key?(map, key), do: map, else: Map.put(map, key, value)
  end

  defp default_kind_for(%{"sub" => sub}) when is_binary(sub) do
    if String.starts_with?(sub, "usr_"), do: "user", else: "client"
  end

  defp default_kind_for(_), do: "client"

  defp client_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "aud" => @audience,
        "client_id" => "oc_abc123",
        "exp" => unix_in(3600),
        "iat" => unix_now(),
        "iss" => @issuer,
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "scope" => "documents.read",
        "sub" => "oc_abc123"
      },
      overrides
    )
  end

  defp mint_client!(config, opts \\ []) do
    assert {:ok, %{access_token: jwt}} =
             Token.mint(
               config,
               %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
               opts
             )

    jwt
  end

  describe "verify/3 happy path" do
    test "round-trips a minted client token and returns its claims", %{config: config} do
      jwt = mint_client!(config)

      assert {:ok, claims} = Token.verify(config, jwt)
      assert claims["sub"] == "oc_abc123"
      assert claims["client_id"] == "oc_abc123"
      assert claims["scope"] == "documents.read"
      assert claims["principal_kind"] == "client"
      assert claims["typ"] == "access"
      assert is_integer(claims["iat"])
      assert is_integer(claims["exp"])
    end

    test "round-trips a minted user token", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(config, %{
                 kind: "user",
                 sub: "usr_abc",
                 scopes: ["documents.read"],
                 claims: %{"act" => "ac_7", "sid" => "sess_1", "token_version" => 0}
               })

      assert {:ok, claims} = Token.verify(config, jwt)
      assert claims["principal_kind"] == "user"
      assert claims["sub"] == "usr_abc"
      assert claims["act"] == "ac_7"
    end

    test "honors :now as a unix integer and a DateTime", %{config: config} do
      iat = 1_700_000_000
      jwt = mint_client!(config, now: iat)

      assert {:ok, _} = Token.verify(config, jwt, now: iat)
      assert {:ok, _} = Token.verify(config, jwt, now: iat + 899)
      assert {:ok, _} = Token.verify(config, jwt, now: DateTime.from_unix!(iat + 899, :second))
    end
  end

  describe "verify/3 signature failures" do
    test "a tampered payload fails with :invalid_signature", %{config: config} do
      jwt = mint_client!(config)
      [h, _payload, s] = String.split(jwt, ".")

      tampered_payload =
        %{"sub" => "oc_attacker", "scope" => "documents.read"}
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      tampered = Enum.join([h, tampered_payload, s], ".")
      assert {:error, :invalid_signature} = Token.verify(config, tampered)
    end

    test "a token signed by a foreign key fails with :invalid_signature", %{config: config} do
      foreign = Factory.foreign_config(Factory.rsa_pem())

      assert {:ok, %{access_token: jwt}} =
               Token.mint(foreign, %{kind: "client", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}})

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end

    test "alg-confusion: an HS256 token (public PEM as HMAC secret) fails with :invalid_signature",
         %{config: config, pem: pem} do
      public_pem = Attesto.Key.public_pem(pem)
      hs256_jwk = JOSE.JWK.from_oct(public_pem)

      {_, hs256_jwt} =
        hs256_jwk
        |> JOSE.JWT.sign(%{"alg" => "HS256"}, client_claims())
        |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = Token.verify(config, hs256_jwt)
    end

    test "alg=none unsecured JWT fails with :invalid_signature", %{config: config} do
      header_b64 = JSON.encode!(%{"alg" => "none", "typ" => "JWT"}) |> Base.url_encode64(padding: false)
      payload_b64 = JSON.encode!(client_claims()) |> Base.url_encode64(padding: false)
      unsigned = header_b64 <> "." <> payload_b64 <> "."

      assert {:error, :invalid_signature} = Token.verify(config, unsigned)
    end
  end

  describe "verify/3 malformed input" do
    test "non-binary input is :invalid_token", %{config: config} do
      for bad <- [nil, 42, %{}, :atom, ["a", "b"]] do
        assert {:error, :invalid_token} = Token.verify(config, bad),
               "expected :invalid_token for #{inspect(bad)}"
      end
    end

    test "garbage strings are :invalid_token", %{config: config} do
      for bad <- ["", "not-a-jwt", "only.two", "four.parts.are.bad", "!!!.@@@.###"] do
        assert {:error, :invalid_token} = Token.verify(config, bad),
               "expected :invalid_token for #{inspect(bad)}"
      end
    end
  end

  describe "verify/3 issuer" do
    test "a mismatched iss fails with :invalid_issuer", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"iss" => "https://evil.example/"}))
      assert {:error, :invalid_issuer} = Token.verify(config, forged)
    end

    test "a missing iss fails with :invalid_issuer", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"iss" => :__drop__}))
      assert {:error, :invalid_issuer} = Token.verify(config, forged)
    end
  end

  describe "verify/3 audience" do
    test "a mismatched aud fails with :invalid_audience", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"aud" => "https://evil.example/"}))
      assert {:error, :invalid_audience} = Token.verify(config, forged)
    end

    test "an aud array not containing the configured audience fails with :invalid_audience",
         %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"aud" => ["https://evil.example/", "https://other.example/"]}))
      assert {:error, :invalid_audience} = Token.verify(config, forged)
    end

    test "a missing aud fails with :invalid_audience", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"aud" => :__drop__}))
      assert {:error, :invalid_audience} = Token.verify(config, forged)
    end

    test "an aud array containing the configured audience is accepted", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"aud" => ["https://other.example/", @audience]}))
      assert {:ok, claims} = Token.verify(config, forged)
      assert claims["aud"] == ["https://other.example/", @audience]
    end

    test ":trusted_audiences replaces the default rule and requires every array member", %{
      config: config,
      pem: pem
    } do
      resource_a = "https://resource.example/a"
      resource_b = "https://resource.example/b"
      scalar = forge(pem, client_claims(%{"aud" => resource_a}))
      multiple = forge(pem, client_claims(%{"aud" => [resource_a, resource_b]}))
      default = forge(pem, client_claims())

      assert {:error, :invalid_audience} = Token.verify(config, scalar)
      assert {:ok, %{"aud" => ^resource_a}} = Token.verify(config, scalar, trusted_audiences: [resource_a])

      assert {:ok, %{"aud" => [^resource_a, ^resource_b]}} =
               Token.verify(config, multiple, trusted_audiences: [resource_a, resource_b])

      assert {:error, :invalid_audience} =
               Token.verify(config, multiple, trusted_audiences: [resource_a])

      assert {:error, :invalid_audience} =
               Token.verify(config, default, trusted_audiences: [resource_a])
    end

    test ":trusted_audiences rejects malformed lists and resolver results", %{config: config, pem: pem} do
      resource = "https://resource.example/a"
      token = forge(pem, client_claims(%{"aud" => resource}))

      policies = [
        [],
        [resource, ""],
        [resource, 123],
        resource,
        fn _claims -> [] end,
        fn _claims -> [resource, ""] end,
        fn _claims -> [resource, 123] end,
        fn _claims -> resource end,
        fn _claims -> raise "policy failed" end,
        fn _claims -> throw(:policy_failed) end,
        fn _claims -> exit(:policy_failed) end
      ]

      for policy <- policies do
        assert {:error, :invalid_audience} =
                 Token.verify(config, token, trusted_audiences: policy)
      end
    end

    test "an audience resolver runs only after every other token check succeeds", %{
      config: config,
      pem: pem
    } do
      now = unix_now()
      resource = "https://resource.example/a"
      test_pid = self()

      resolver = fn claims ->
        send(test_pid, {:audience_resolved, claims["client_id"]})
        [resource]
      end

      foreign_pem = Factory.rsa_pem()

      rejected = [
        {forge(foreign_pem, client_claims(%{"aud" => resource})), :invalid_signature},
        {forge(pem, client_claims(%{"aud" => resource, "iss" => "https://wrong.example"})), :invalid_issuer},
        {forge(pem, client_claims(%{"aud" => resource, "exp" => now - 1, "iat" => now - 10})), :expired},
        {forge(pem, client_claims(%{"aud" => resource, "nbf" => now + 3600})), :not_yet_valid},
        {forge(pem, client_claims(%{"aud" => resource, "iat" => now + 3600, "exp" => now + 7200})), :not_yet_valid},
        {forge(pem, client_claims(%{"aud" => resource, "client_id" => :__drop__})), :invalid_claims},
        {forge(pem, client_claims(%{"aud" => resource, "client_id" => ""})), :invalid_claims},
        {forge(
           pem,
           client_claims(%{
             "aud" => resource,
             "principal_kind" => "client",
             "sub" => "usr_wrong_prefix"
           })
         ), :invalid_principal},
        {forge(pem, client_claims(%{"aud" => resource, "typ" => "refresh"})), :unexpected_typ},
        {forge(pem, client_claims(%{"aud" => resource, "cnf" => %{"jkt" => "invalid"}})), :unsupported_confirmation}
      ]

      for {token, reason} <- rejected do
        assert {:error, ^reason} =
                 Token.verify(config, token, now: now, trusted_audiences: resolver)

        refute_received {:audience_resolved, _client_id}
      end

      valid = forge(pem, client_claims(%{"aud" => resource, "iat" => now, "exp" => now + 3600}))

      assert {:ok, _claims} =
               Token.verify(config, valid, now: now, trusted_audiences: resolver)

      assert_received {:audience_resolved, "oc_abc123"}
    end
  end

  describe "verify/3 expiry" do
    test "a past exp fails with :expired", %{config: config} do
      iat = 1_700_000_000
      jwt = mint_client!(config, now: iat)
      assert {:error, :expired} = Token.verify(config, jwt, now: iat + 901)
    end

    test "exactly at exp fails with :expired (strict boundary)", %{config: config} do
      iat = 1_700_000_000
      jwt = mint_client!(config, now: iat)
      assert {:error, :expired} = Token.verify(config, jwt, now: iat + 900)
    end

    test "a missing or non-integer exp fails with :expired", %{config: config, pem: pem} do
      assert {:error, :expired} = Token.verify(config, forge(pem, client_claims(%{"exp" => :__drop__})))
      assert {:error, :expired} = Token.verify(config, forge(pem, client_claims(%{"exp" => "soon"})))
    end
  end

  describe "verify/3 required claims" do
    test "rejects a missing or empty/non-binary sub with :invalid_claims", %{config: config, pem: pem} do
      assert {:error, :invalid_claims} = Token.verify(config, forge(pem, client_claims(%{"sub" => :__drop__})))

      for bad <- ["", 0, %{}, ["oc_x"]] do
        forged = forge(pem, client_claims(%{"sub" => bad}))

        assert {:error, :invalid_claims} = Token.verify(config, forged),
               "expected :invalid_claims for sub=#{inspect(bad)}"
      end
    end

    test "rejects a missing or non-binary jti with :invalid_claims", %{config: config, pem: pem} do
      assert {:error, :invalid_claims} = Token.verify(config, forge(pem, client_claims(%{"jti" => :__drop__})))

      for bad <- ["", 42, ["x"]] do
        forged = forge(pem, client_claims(%{"jti" => bad}))

        assert {:error, :invalid_claims} = Token.verify(config, forged),
               "expected :invalid_claims for jti=#{inspect(bad)}"
      end
    end

    test "rejects a missing or non-binary scope with :invalid_claims", %{config: config, pem: pem} do
      assert {:error, :invalid_claims} = Token.verify(config, forge(pem, client_claims(%{"scope" => :__drop__})))

      for bad <- [["documents.read"], 42, %{}] do
        forged = forge(pem, client_claims(%{"scope" => bad}))

        assert {:error, :invalid_claims} = Token.verify(config, forged),
               "expected :invalid_claims for scope=#{inspect(bad)}"
      end
    end

    test "accepts an empty-string scope", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"scope" => ""}))
      assert {:ok, claims} = Token.verify(config, forged)
      assert claims["scope"] == ""
    end

    test "rejects a missing or non-negative-integer iat with :invalid_claims", %{config: config, pem: pem} do
      assert {:error, :invalid_claims} = Token.verify(config, forge(pem, client_claims(%{"iat" => :__drop__})))

      for bad <- ["1700000000", -1, 1.5] do
        forged = forge(pem, client_claims(%{"iat" => bad}))

        assert {:error, :invalid_claims} = Token.verify(config, forged),
               "expected :invalid_claims for iat=#{inspect(bad)}"
      end
    end

    test "rejects a token missing the principal_kind claim with :invalid_claims", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"principal_kind" => :__drop__}))
      assert {:error, :invalid_claims} = Token.verify(config, forged)
    end

    test "rejects a user token missing any per-kind claim with :invalid_claims", %{config: config, pem: pem} do
      base = %{
        "aud" => @audience,
        "exp" => unix_in(3600),
        "iat" => unix_now(),
        "iss" => @issuer,
        "jti" => "user-jti",
        "principal_kind" => "user",
        "scope" => "documents.read",
        "sub" => "usr_abc"
      }

      # missing act
      assert {:error, :invalid_claims} =
               Token.verify(config, forge(pem, Map.merge(base, %{"sid" => "sess_1", "token_version" => 0})))

      # missing sid
      assert {:error, :invalid_claims} =
               Token.verify(config, forge(pem, Map.merge(base, %{"act" => "ac_7", "token_version" => 0})))

      # missing token_version
      assert {:error, :invalid_claims} =
               Token.verify(config, forge(pem, Map.merge(base, %{"act" => "ac_7", "sid" => "sess_1"})))

      # non-integer token_version
      assert {:error, :invalid_claims} =
               Token.verify(
                 config,
                 forge(pem, Map.merge(base, %{"act" => "ac_7", "sid" => "sess_1", "token_version" => "0"}))
               )
    end

    test "iss/aud/exp errors take precedence over :invalid_claims", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"iss" => "https://evil.example/", "sub" => :__drop__}))
      assert {:error, :invalid_issuer} = Token.verify(config, forged)
    end
  end

  describe "verify/3 principal" do
    test "an unknown principal_kind value fails with :invalid_principal", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"principal_kind" => "admin"}))
      assert {:error, :invalid_principal} = Token.verify(config, forged)
    end

    test "a sub/principal_kind namespace mismatch fails with :invalid_principal", %{config: config, pem: pem} do
      # principal_kind=user but an oc_ subject.
      user_with_oc_sub =
        forge(pem, %{
          "act" => "ac_7",
          "aud" => @audience,
          "exp" => unix_in(3600),
          "iat" => unix_now(),
          "iss" => @issuer,
          "jti" => "mismatch",
          "principal_kind" => "user",
          "scope" => "documents.read",
          "sid" => "sess_1",
          "sub" => "oc_abc",
          "token_version" => 0
        })

      assert {:error, :invalid_principal} = Token.verify(config, user_with_oc_sub)

      # Mirror: principal_kind=client with a usr_ subject.
      client_with_usr_sub = forge(pem, client_claims(%{"principal_kind" => "client", "sub" => "usr_abc"}))
      assert {:error, :invalid_principal} = Token.verify(config, client_with_usr_sub)
    end
  end

  describe "verify/3 typ" do
    test "a refresh token where access is expected fails with :unexpected_typ", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"typ" => "refresh"}))
      assert {:error, :unexpected_typ} = Token.verify(config, forged)
    end

    test "expected_typ selects which typ verify accepts", %{config: config, pem: pem} do
      access = forge(pem, client_claims(%{"typ" => "access"}))
      refresh = forge(pem, client_claims(%{"typ" => "refresh"}))

      assert {:error, :unexpected_typ} = Token.verify(config, access, expected_typ: "refresh")
      assert {:ok, claims} = Token.verify(config, refresh, expected_typ: "refresh")
      assert claims["typ"] == "refresh"
      assert {:ok, _} = Token.verify(config, access)
    end

    test "a garbage typ value fails with :invalid_typ", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"typ" => "bearer"}))
      assert {:error, :invalid_typ} = Token.verify(config, forged)
    end
  end

  describe "verify/3 DPoP binding matrix" do
    test "a DPoP-bound token verifies only with a matching :dpop_jkt", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: @valid_jkt
               )

      assert {:ok, claims} = Token.verify(config, jwt, dpop_jkt: @valid_jkt)
      assert claims["cnf"] == %{"jkt" => @valid_jkt}
    end

    test "a DPoP-bound token presented without :dpop_jkt fails with :dpop_proof_required", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: @valid_jkt
               )

      assert {:error, :dpop_proof_required} = Token.verify(config, jwt)
      assert {:error, :dpop_proof_required} = Token.verify(config, jwt, dpop_jkt: nil)
    end

    test "a malformed binding requirement cannot disable confirmation verification", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: @valid_jkt
               )

      for invalid <- [nil, "false", 0, {:error, :unavailable}] do
        assert_raise ArgumentError, ~r/:require_confirmation_binding must be true or false/, fn ->
          Token.verify(config, jwt, require_confirmation_binding: invalid)
        end
      end

      assert {:ok, _claims} = Token.verify(config, jwt, require_confirmation_binding: false)
    end

    test "a DPoP-bound token with a mismatched :dpop_jkt fails with :dpop_binding_mismatch", %{config: config} do
      other = "AAAAOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: @valid_jkt
               )

      assert {:error, :dpop_binding_mismatch} = Token.verify(config, jwt, dpop_jkt: other)
    end

    test "a plain bearer token presented with :dpop_jkt fails with :dpop_proof_unexpected", %{config: config} do
      jwt = mint_client!(config)
      assert {:error, :dpop_proof_unexpected} = Token.verify(config, jwt, dpop_jkt: @valid_jkt)
    end

    test "a DPoP-bound token with a cross :mtls_cert_thumbprint fails with :mtls_cert_unexpected", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: @valid_jkt
               )

      # Even with a matching dpop_jkt also present, the stray cross opt is rejected.
      assert {:error, :mtls_cert_unexpected} =
               Token.verify(config, jwt, dpop_jkt: @valid_jkt, mtls_cert_thumbprint: @valid_x5t)
    end
  end

  describe "verify/3 mTLS binding matrix" do
    test "an mTLS-bound token verifies only with a matching :mtls_cert_thumbprint", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: @valid_x5t
               )

      assert {:ok, claims} = Token.verify(config, jwt, mtls_cert_thumbprint: @valid_x5t)
      assert claims["cnf"] == %{"x5t#S256" => @valid_x5t}
    end

    test "an mTLS-bound token presented without :mtls_cert_thumbprint fails with :mtls_cert_required", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: @valid_x5t
               )

      assert {:error, :mtls_cert_required} = Token.verify(config, jwt)
      assert {:error, :mtls_cert_required} = Token.verify(config, jwt, mtls_cert_thumbprint: nil)
    end

    test "an mTLS-bound token with a mismatched :mtls_cert_thumbprint fails with :mtls_binding_mismatch", %{
      config: config
    } do
      other = "AAAAOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: @valid_x5t
               )

      assert {:error, :mtls_binding_mismatch} = Token.verify(config, jwt, mtls_cert_thumbprint: other)
    end

    test "a plain bearer token presented with :mtls_cert_thumbprint fails with :mtls_cert_unexpected", %{config: config} do
      jwt = mint_client!(config)
      assert {:error, :mtls_cert_unexpected} = Token.verify(config, jwt, mtls_cert_thumbprint: @valid_x5t)
    end

    test "an mTLS-bound token with a cross :dpop_jkt fails with :dpop_proof_unexpected", %{config: config} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: [], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: @valid_x5t
               )

      assert {:error, :dpop_proof_unexpected} =
               Token.verify(config, jwt, mtls_cert_thumbprint: @valid_x5t, dpop_jkt: @valid_jkt)
    end
  end

  describe "verify/3 unsupported confirmation shapes" do
    test "a cnf carrying both jkt and x5t#S256 fails with :unsupported_confirmation", %{config: config, pem: pem} do
      forged =
        forge(pem, client_claims(%{"cnf" => %{"jkt" => @valid_jkt, "x5t#S256" => @valid_x5t}}))

      assert {:error, :unsupported_confirmation} = Token.verify(config, forged)
    end

    test "a cnf with an extra member alongside the binding key fails with :unsupported_confirmation",
         %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"cnf" => %{"jkt" => @valid_jkt, "extra" => "x"}}))
      assert {:error, :unsupported_confirmation} = Token.verify(config, forged)
    end

    test "a cnf.jkt that is not a canonical thumbprint fails with :unsupported_confirmation",
         %{config: config, pem: pem} do
      malformed = [
        "tooshort",
        String.duplicate("a", 42),
        String.duplicate("a", 44),
        String.duplicate("a", 42) <> "+",
        String.duplicate("a", 42) <> "=",
        "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
        "",
        42,
        ["thumb"]
      ]

      for bad <- malformed do
        forged = forge(pem, client_claims(%{"cnf" => %{"jkt" => bad}}))

        assert {:error, :unsupported_confirmation} = Token.verify(config, forged),
               "expected :unsupported_confirmation for cnf.jkt=#{inspect(bad)}"
      end
    end

    test "a cnf that is not a map fails with :unsupported_confirmation", %{config: config, pem: pem} do
      forged = forge(pem, client_claims(%{"cnf" => @valid_jkt}))
      assert {:error, :unsupported_confirmation} = Token.verify(config, forged)
    end

    test "unsupported-confirmation rejection wins over downstream claim-shape failures",
         %{config: config, pem: pem} do
      forged =
        forge(pem, %{
          "aud" => @audience,
          "cnf" => %{"jkt" => @valid_jkt, "x5t#S256" => @valid_x5t},
          "exp" => unix_in(3600),
          "iss" => @issuer,
          "sub" => "oc_abc123"
          # intentionally missing jti/iat/scope/client_id
        })

      assert {:error, :unsupported_confirmation} = Token.verify(config, forged)
    end
  end

  describe "verify/3 kid-based key selection" do
    test "a token whose header kid names a key we do not hold fails with :invalid_signature",
         %{config: config, pem: pem} do
      forged = forge(pem, client_claims(), kid: "not-our-key")
      assert {:error, :invalid_signature} = Token.verify(config, forged)
    end

    test "a verifier holding two rotated keys selects by kid and accepts tokens from each" do
      pem_a = Factory.rsa_pem()
      pem_b = Factory.rsa_pem()

      # The active signing config (signing + verifying under key A only).
      config_a = Factory.config(pem_a)

      # A second issuer holding key B (distinct keystore module).
      config_b = Factory.foreign_config(pem_b)

      # A rotation verifier that trusts BOTH keys for verification while
      # signing under A. Configured directly on the Static keystore; the
      # Factory.config on_exit removes the whole Static env entry.
      Application.put_env(:attesto, Static, signing_pem: pem_a, verification_pems: [pem_a, pem_b])

      rotation_config =
        Attesto.Config.new(
          issuer: @issuer,
          audience: @audience,
          keystore: Static,
          principal_kinds: [
            Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
          ]
        )

      assert {:ok, %{access_token: jwt_a}} =
               Token.mint(config_a, %{kind: "client", sub: "oc_a", scopes: [], claims: %{"client_id" => "x"}})

      assert {:ok, %{access_token: jwt_b}} =
               Token.mint(config_b, %{kind: "client", sub: "oc_b", scopes: [], claims: %{"client_id" => "y"}})

      # kid for key A selects key A; kid for key B selects key B.
      assert {:ok, claims_a} = Token.verify(rotation_config, jwt_a)
      assert claims_a["sub"] == "oc_a"

      assert {:ok, claims_b} = Token.verify(rotation_config, jwt_b)
      assert claims_b["sub"] == "oc_b"
    end

    test "a malformed PEM candidate retains the keystore failure behavior" do
      pem = Factory.rsa_pem()
      keystore = RotationKeystore
      keystore.install(pem, [pem, "not a pem"])
      config = keystore.config()

      assert {:ok, %{access_token: jwt}} =
               Token.mint(config, %{kind: "client", sub: "oc_bad_key", scopes: [], claims: %{"client_id" => "x"}})

      assert_raise ArgumentError, fn -> Token.verify(config, jwt) end
    end
  end

  describe "peek_signed_claims/2" do
    test "returns claims for a validly-signed token (even when otherwise unverifiable)",
         %{config: config, pem: pem} do
      # Signed with our key but with a foreign issuer: verify/3 would
      # reject it, yet peek surfaces the claims for denial attribution.
      forged = forge(pem, client_claims(%{"iss" => "https://evil.example/", "sub" => "oc_abuser"}))

      assert {:error, :invalid_issuer} = Token.verify(config, forged)
      assert {:ok, claims} = Token.peek_signed_claims(config, forged)
      assert claims["sub"] == "oc_abuser"
    end

    test "returns an error for a forged-signature token", %{config: config} do
      foreign = Factory.foreign_config(Factory.rsa_pem())

      assert {:ok, %{access_token: jwt}} =
               Token.mint(foreign, %{kind: "client", sub: "oc_x", scopes: [], claims: %{"client_id" => "x"}})

      assert {:error, :invalid_signature} = Token.peek_signed_claims(config, jwt)
    end

    test "returns an error for garbage", %{config: config} do
      assert {:error, :invalid_token} = Token.peek_signed_claims(config, "not.a.jwt")
      assert {:error, :invalid_token} = Token.peek_signed_claims(config, 42)
    end
  end
end
