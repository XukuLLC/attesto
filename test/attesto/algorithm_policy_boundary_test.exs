defmodule Attesto.AlgorithmPolicyBoundaryTest do
  use ExUnit.Case, async: true

  alias Attesto.{AuthorizationRequest, ClientAssertion, IdentityAssertion, JWS, JwtVc, KeyAttestation}
  alias Attesto.CIBA.Request, as: CibaRequest
  alias Attesto.{RequestObject, SdJwt, SdJwtVc, StatusList, WalletAttestation}
  alias Attesto.RequestObject.Policy
  alias Attesto.Test.JWT

  @now 1_700_000_000
  @client "client-example"
  @issuer "https://issuer.example"
  @redirect "https://client.example/callback"
  @apis [
    :request_object,
    :client_assertion,
    :key_attestation,
    :wallet_attestation,
    :authorization_request,
    :ciba_request,
    :identity_assertion,
    :jwt_vc_json,
    :status_list,
    :sd_jwt,
    :sd_jwt_vc
  ]
  @fapi_apis [
    :request_object,
    :client_assertion,
    :key_attestation,
    :wallet_attestation,
    :authorization_request,
    :ciba_request,
    :sd_jwt,
    :sd_jwt_vc
  ]

  setup_all do
    ec = JOSE.JWK.generate_key({:ec, "P-256"})

    %{
      signer: ec,
      holder: ec,
      alg: "ES256",
      weak_rsa: JOSE.JWK.generate_key({:rsa, 1024}),
      strong_rsa: JOSE.JWK.generate_key({:rsa, 2048})
    }
  end

  for api <- @apis do
    test "#{api} rejects an explicit empty algorithm policy", context do
      api = unquote(api)
      assert {:ok, _verified} = verify_for(api, context, [])

      for enforcement <- [[], [enforce_fapi_alg_policy: false]] do
        assert {:error, _reason} = verify_for(api, context, [accepted_algs: []] ++ enforcement)
      end
    end
  end

  for api <- @fapi_apis do
    accepted = if api == :wallet_attestation, do: ["PS256", "ES256"], else: ["PS256"]

    test "#{api} preserves RSA strength when the FAPI allowlist is narrowed", context do
      api = unquote(api)
      weak = %{context | signer: context.weak_rsa, alg: "PS256"}
      strong = %{context | signer: context.strong_rsa, alg: "PS256"}

      # The attestation provider signs with RSA; its instance PoP uses ES256.
      accepted = unquote(accepted)

      assert {:error, _reason} = verify_for(api, weak, [])
      assert {:error, _reason} = verify_for(api, weak, accepted_algs: accepted)
      assert {:ok, _verified} = verify_for(api, strong, accepted_algs: accepted)

      assert {:ok, _verified} =
               verify_for(api, weak, accepted_algs: accepted, enforce_fapi_alg_policy: false)
    end
  end

  for api <- @fapi_apis do
    test "#{api} never weakens RSA strength through a mixed allowlist", context do
      api = unquote(api)
      weak = %{context | signer: context.weak_rsa, alg: "PS256"}
      strong = %{context | signer: context.strong_rsa, alg: "PS256"}
      accepted = ["PS256", "ES256", "ES384"]

      assert {:error, _reason} = verify_for(api, weak, accepted_algs: accepted)
      assert {:ok, _verified} = verify_for(api, strong, accepted_algs: accepted)

      assert {:ok, _verified} =
               verify_for(api, weak, accepted_algs: accepted, enforce_fapi_alg_policy: false)
    end
  end

  for api <- @apis do
    test "#{api} rejects an entire malformed algorithm allowlist", context do
      for policy <- [
            nil,
            "ES256",
            false,
            ["ES256", "ES256"],
            ["ES256", nil],
            ["ES256", :ES256],
            ["ES256", "ES25X"],
            ["ES256", %{}]
          ] do
        assert {:error, _reason} = verify_for(unquote(api), context, accepted_algs: policy)
      end
    end
  end

  for api <- @fapi_apis do
    test "#{api} requires explicit opt-out for a valid broader algorithm", context do
      key = JOSE.JWK.generate_key({:ec, "P-384"})
      broader = %{context | signer: key, alg: "ES384"}
      accepted = ["ES256", "ES384"]

      assert {:error, _reason} = verify_for(unquote(api), broader, accepted_algs: accepted)

      assert {:error, _reason} =
               verify_for(unquote(api), broader, accepted_algs: accepted, enforce_fapi_alg_policy: true)

      assert {:ok, _verified} =
               verify_for(unquote(api), broader, accepted_algs: accepted, enforce_fapi_alg_policy: false)
    end

    test "#{api} rejects malformed enforcement flags", context do
      for value <- [nil, "false", 0] do
        assert_raise ArgumentError, fn ->
          verify_for(unquote(api), context, enforce_fapi_alg_policy: value)
        end
      end
    end
  end

  test "low-level policy validation rejects malformed lists before candidate construction", context do
    public = trusted(context)
    jwt = signed(context.signer, "ES256", %{"ok" => true})
    candidates = JWS.verification_candidates(public)

    for policy <- [nil, "ES256", ["ES256", "ES256"], ["ES256", nil], ["ES256", "ES25X"], ["ES256", :ES256]] do
      assert [] = JWS.verification_candidates(public, accepted_algs: policy)
      assert {:error, :invalid_signature} = JWS.verify_strict(jwt, candidates, accepted_algs: policy)

      assert [] =
               JWS.verification_candidates(public,
                 accepted_algs: policy,
                 candidate_builder: fn _key -> flunk("malformed policy reached key construction") end
               )
    end

    for value <- [nil, "false", 0] do
      assert [] = JWS.verification_candidates(public, fapi?: value)
      assert {:error, :invalid_signature} = JWS.verify_strict(jwt, candidates, fapi?: value)
    end
  end

  test "low-level omitted JWS policy remains unrestricted but explicit empty policy denies", context do
    key = context.strong_rsa
    public = public_key(key, "RS256")
    jwt = signed(key, "RS256", %{"ok" => true})
    candidates = JWS.verification_candidates(public)

    assert [_candidate] = candidates
    assert {:ok, %{"ok" => true}} = JWS.verify_strict(jwt, candidates)
    assert [] = JWS.verification_candidates(public, accepted_algs: [])

    assert {:error, :invalid_signature} = JWS.verify_strict(jwt, candidates, accepted_algs: [])

    assert {:error, :denied} =
             JWS.verify_strict(jwt, candidates, accepted_algs: [], fapi?: false, terminal_error: :denied)

    assert {:ok, _claims} = JWS.verify_strict(jwt, candidates, accepted_algs: ["RS256"])
  end

  test "SD-JWT default rejects weak PS256 while a broader EC profile remains available", context do
    key = JOSE.JWK.generate_key({:ec, "P-384"})
    broader = %{context | signer: key, alg: "ES384"}

    assert {:error, :unsupported_alg} = verify_for(:sd_jwt, broader, [])
    assert {:error, :invalid_signature} = verify_for(:sd_jwt, broader, accepted_algs: ["ES384"])

    assert {:ok, _verified} =
             verify_for(:sd_jwt, broader, accepted_algs: ["ES384"], enforce_fapi_alg_policy: false)

    assert {:error, :invalid_signature} =
             verify_for(:sd_jwt, broader, accepted_algs: ["ES384"], enforce_fapi_alg_policy: true)
  end

  test "SD-JWT rejects malformed explicit policy options", context do
    for accepted <- [nil, "ES256", false] do
      assert {:error, :unsupported_alg} = verify_for(:sd_jwt, context, accepted_algs: accepted)
      assert [] = JWS.verification_candidates(trusted(context), accepted_algs: accepted)
    end

    for value <- [nil, "false", 0] do
      assert_raise ArgumentError, fn ->
        verify_for(:sd_jwt, context, enforce_fapi_alg_policy: value)
      end
    end
  end

  defp verify_for(:request_object, context, opts) do
    jwt = signed(context.signer, context.alg, request_claims())
    RequestObject.verify(jwt, trusted(context), [issuer: @client, audience: @issuer, now: @now] ++ opts)
  end

  defp verify_for(:client_assertion, context, opts) do
    claims = Map.merge(common_claims(), %{"iss" => @client, "sub" => @client, "aud" => @issuer})
    jwt = signed(context.signer, context.alg, claims)
    ClientAssertion.verify(jwt, @client, @issuer, trusted(context), [now: @now] ++ opts)
  end

  defp verify_for(:key_attestation, context, opts) do
    claims = Map.put(common_claims(), "attested_keys", [public_key(context.holder, "ES256")])
    jwt = signed(context.signer, context.alg, claims, "key-attestation+jwt")
    KeyAttestation.verify(jwt, [trusted_jwks: trusted(context), now: @now] ++ opts)
  end

  defp verify_for(:wallet_attestation, context, opts) do
    claims = Map.merge(common_claims(), %{"sub" => @client, "cnf" => %{"jwk" => public_key(context.holder, "ES256")}})
    attestation = signed(context.signer, context.alg, claims, "oauth-client-attestation+jwt")
    pop_claims = %{"aud" => @issuer, "iat" => @now, "jti" => "instance-proof"}
    pop = signed(context.holder, "ES256", pop_claims, "oauth-client-attestation-pop+jwt")

    WalletAttestation.verify(
      attestation,
      pop,
      [trusted_wallet_provider_jwks: trusted(context), audience: @issuer, now: @now] ++ opts
    )
  end

  defp verify_for(:authorization_request, context, opts) do
    now = System.system_time(:second)
    claims = Map.merge(request_claims(), %{"iat" => now, "nbf" => now, "exp" => now + 300})
    jwt = signed(context.signer, context.alg, claims)
    policy = struct!(Policy, opts)

    AuthorizationRequest.validate(
      %{
        "request" => jwt,
        "client_id" => @client,
        "redirect_uri" => @redirect,
        "code_challenge" => String.duplicate("A", 43),
        "code_challenge_method" => "S256"
      },
      registered_redirect_uris: [@redirect],
      request_object_jwks: trusted(context),
      request_object_audience: @issuer,
      request_object_policy: policy
    )
  end

  defp verify_for(:ciba_request, context, opts) do
    claims =
      Map.merge(common_claims(), %{
        "iss" => @client,
        "aud" => @issuer,
        "scope" => "openid",
        "login_hint" => "user@example.com"
      })

    jwt = signed(context.signer, context.alg, claims)
    client = %{client_id: @client, token_delivery_mode: :poll, jwks: trusted(context)}
    CibaRequest.validate(client, %{"request" => jwt}, [issuer: @issuer, now: @now] ++ opts)
  end

  defp verify_for(:identity_assertion, context, opts) do
    claims =
      Map.merge(common_claims(), %{
        "iss" => @issuer,
        "sub" => "subject-example",
        "aud" => @issuer,
        "client_id" => @client
      })

    jwt = signed(context.signer, context.alg, claims, "oauth-id-jag+jwt")

    IdentityAssertion.verify(
      jwt,
      trusted(context),
      [issuer: @issuer, audience: @issuer, client_id: @client, now: @now] ++ opts
    )
  end

  defp verify_for(:jwt_vc_json, context, opts) do
    claims =
      Map.merge(common_claims(), %{
        "iss" => @issuer,
        "sub" => "subject-example",
        "vc" => %{
          "@context" => ["https://www.w3.org/2018/credentials/v1"],
          "type" => ["VerifiableCredential"],
          "credentialSubject" => %{"given_name" => "Example"},
          "issuer" => @issuer
        }
      })

    jwt = signed(context.signer, context.alg, claims, "JWT")
    JwtVc.verify(jwt, trusted(context), [now: @now] ++ opts)
  end

  defp verify_for(:status_list, context, opts) do
    claims =
      Map.merge(common_claims(), %{
        "sub" => @issuer <> "/status",
        "status_list" => %{"bits" => 1, "lst" => JWS.encode64(:zlib.compress(<<0>>))}
      })

    jwt = signed(context.signer, context.alg, claims, "statuslist+jwt")
    StatusList.verify(jwt, trusted(context), [now: @now] ++ opts)
  end

  defp verify_for(format, context, opts) when format in [:sd_jwt, :sd_jwt_vc] do
    claims = Map.merge(common_claims(), %{"iss" => @issuer, "vct" => "https://issuer.example/type"})
    jwt = signed(context.signer, context.alg, claims, "dc+sd-jwt") <> "~"
    module = if format == :sd_jwt, do: SdJwt, else: SdJwtVc
    module.verify(jwt, trusted(context), [now: @now] ++ opts)
  end

  defp request_claims do
    Map.merge(common_claims(), %{
      "iss" => @client,
      "client_id" => @client,
      "aud" => @issuer,
      "response_type" => "code",
      "redirect_uri" => @redirect,
      "scope" => "openid",
      "code_challenge" => String.duplicate("A", 43),
      "code_challenge_method" => "S256"
    })
  end

  defp common_claims, do: %{"iat" => @now, "nbf" => @now, "exp" => @now + 300, "jti" => "policy-test"}

  defp trusted(context), do: %{"keys" => [public_key(context.signer, context.alg)]}

  defp public_key(key, alg) do
    key |> JOSE.JWK.to_public_map() |> elem(1) |> Map.put("alg", alg)
  end

  defp signed(key, alg, claims, typ \\ "oauth-authz-req+jwt") do
    JWT.sign_compact(key, %{"alg" => alg, "typ" => typ}, claims)
  end
end
