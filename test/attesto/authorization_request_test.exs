defmodule Attesto.AuthorizationRequestTest do
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationRequest
  alias Attesto.RequestObject.Policy

  @redirect_uri "https://client.example.com/cb"
  @registered [@redirect_uri]
  @issuer "https://issuer.example"

  # A syntactically valid S256 code_challenge: BASE64URL(SHA256(verifier)),
  # 43 chars, no padding (RFC 7636 §4.2). This is the RFC 7636 Appendix B
  # example challenge.
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  defp base_params(overrides \\ %{}) do
    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => "client-123",
        "redirect_uri" => @redirect_uri,
        "scope" => "openid profile",
        "state" => "xyz",
        "nonce" => "n-0S6_WzA2Mj",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256"
      },
      overrides
    )
  end

  defp validate(params) do
    AuthorizationRequest.validate(params, registered_redirect_uris: @registered)
  end

  defp validate_require_nonce(params) do
    AuthorizationRequest.validate(params,
      registered_redirect_uris: @registered,
      require_nonce: true
    )
  end

  defp unsigned_request_object(claims) do
    header = Base.url_encode64(JSON.encode!(%{"alg" => "none"}), padding: false)
    payload = Base.url_encode64(JSON.encode!(claims), padding: false)
    header <> "." <> payload <> "."
  end

  defp signed_request_object(claims, opts \\ []) do
    jwk = Keyword.get_lazy(opts, :jwk, fn -> JOSE.JWK.generate_key({:ec, "P-256"}) end)
    kid = Keyword.get(opts, :kid, "client-key-1")
    alg = Keyword.get(opts, :alg, "ES256")
    {_, public_map} = JOSE.JWK.to_public_map(jwk)
    client_jwk = Map.merge(public_map, %{"kid" => kid, "alg" => alg})
    header = Map.merge(%{"alg" => alg, "kid" => kid}, Keyword.get(opts, :header, %{}))
    {_, request} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    {request, client_jwk}
  end

  # A complete, valid signed-request-object claim set (the object params are
  # authoritative, so they must carry the whole request). nbf/exp default to a
  # fresh, FAPI-compliant window; overrides tweak individual claims.
  defp fapi_request_claims(overrides \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => "client-123",
        "aud" => @issuer,
        "client_id" => "client-123",
        "redirect_uri" => @redirect_uri,
        "response_type" => "code",
        "scope" => "openid",
        "code_challenge" => @code_challenge,
        "code_challenge_method" => "S256",
        "nbf" => now,
        "exp" => now + 300
      },
      overrides
    )
  end

  defp validate_request_object(request, client_jwk, opts) do
    # The outer params carry a registered redirect_uri so a request-object
    # verification failure is redirectable (RFC 6749 §4.1.2.1); on success the
    # signed object's params are authoritative and replace these.
    AuthorizationRequest.validate(
      %{"request" => request, "client_id" => "client-123", "redirect_uri" => @redirect_uri},
      [
        registered_redirect_uris: @registered,
        request_object_jwks: %{"keys" => [client_jwk]},
        request_object_audience: @issuer
      ] ++ opts
    )
  end

  describe "validate/2 success" do
    test "accepts a valid OIDC authorization-code request" do
      assert {:ok, req} = validate(base_params())

      assert %AuthorizationRequest{
               response_type: "code",
               client_id: "client-123",
               redirect_uri: @redirect_uri,
               scope: ["openid", "profile"],
               openid?: true,
               state: "xyz",
               nonce: "n-0S6_WzA2Mj",
               code_challenge: @code_challenge,
               code_challenge_method: "S256",
               claims: %{}
             } = req
    end

    test "reads dpop_jkt from the query on a plain (non-JAR) request (RFC 9449 §10)" do
      assert {:ok, req} = validate(base_params(%{"dpop_jkt" => "thumb-abc"}))
      assert req.dpop_jkt == "thumb-abc"
    end

    test "reads dpop_jkt from the signed request object, ignoring the outer query" do
      # RFC 9101 §6.3 / RFC 9449 §10: the signed object's params are
      # authoritative. An attacker-supplied outer dpop_jkt MUST NOT override the
      # value the client signed (nor bind the code when the client signed none).
      {request, client_jwk} =
        signed_request_object(fapi_request_claims(%{"dpop_jkt" => "signed-thumbprint"}))

      assert {:ok, req} =
               AuthorizationRequest.validate(
                 %{
                   "request" => request,
                   "client_id" => "client-123",
                   "redirect_uri" => @redirect_uri,
                   "dpop_jkt" => "attacker-thumbprint"
                 },
                 registered_redirect_uris: @registered,
                 request_object_jwks: %{"keys" => [client_jwk]},
                 request_object_audience: @issuer
               )

      assert req.dpop_jkt == "signed-thumbprint"
    end

    test "flags a plain OAuth (non-OIDC) request when the openid scope is absent" do
      assert {:ok, req} = validate(base_params(%{"scope" => "profile email"}))
      refute req.openid?
      assert req.scope == ["profile", "email"]
    end

    test "treats missing scope as empty and non-OIDC" do
      assert {:ok, req} = base_params() |> Map.delete("scope") |> validate()
      assert req.scope == []
      refute req.openid?
    end

    test "RFC 8707: binds a valid resource indicator to the request" do
      assert {:ok, req} = validate(base_params(%{"resource" => "https://api.example/mcp"}))
      assert req.resource == ["https://api.example/mcp"]
    end

    test "RFC 8707: binds multiple resource indicators (array form)" do
      assert {:ok, req} =
               validate(base_params(%{"resource" => ["https://a.example/api", "https://b.example/api"]}))

      assert req.resource == ["https://a.example/api", "https://b.example/api"]
    end

    test "RFC 8707: a missing resource is the empty set" do
      assert {:ok, req} = base_params() |> Map.delete("resource") |> validate()
      assert req.resource == []
    end

    test "RFC 8707: a malformed resource is a redirectable invalid_target error" do
      assert {:error, {:redirect, %{error: "invalid_target"}}} =
               validate(base_params(%{"resource" => "https://api.example/mcp#frag"}))
    end

    test "carries state and nonce through, nil when absent" do
      params = base_params() |> Map.drop(["state", "nonce"])
      assert {:ok, req} = validate(params)
      assert is_nil(req.state)
      assert is_nil(req.nonce)
    end

    test "parses optional prompt, max_age, and acr_values" do
      params =
        base_params(%{
          "prompt" => "login consent",
          "max_age" => "300",
          "acr_values" => "urn:mace:incommon:iap:silver phr"
        })

      assert {:ok, req} = validate(params)
      assert req.prompt == ["login", "consent"]
      assert req.max_age == 300
      assert req.acr_values == ["urn:mace:incommon:iap:silver", "phr"]
    end

    test "parses optional OIDC claims request object" do
      claims = %{
        "userinfo" => %{
          "name" => %{"essential" => true}
        }
      }

      assert {:ok, req} = validate(base_params(%{"claims" => JSON.encode!(claims)}))
      assert req.claims == claims
    end

    test "defaults optional params to empty / nil when absent" do
      assert {:ok, req} = validate(base_params())
      assert req.prompt == []
      assert req.acr_values == []
      assert is_nil(req.max_age)
      assert req.claims == %{}
    end

    test "response_mode is nil when absent (transport applies the default)" do
      assert {:ok, req} = validate(base_params())
      assert is_nil(req.response_mode)
    end

    test "carries a supported response_mode through (JARM §2.3)" do
      for mode <- AuthorizationRequest.supported_response_modes() do
        assert {:ok, req} = validate(base_params(%{"response_mode" => mode}))
        assert req.response_mode == mode
      end
    end
  end

  describe "validate/2 non-redirectable errors (OIDC Core §3.1.2.6)" do
    test "missing client_id does not redirect" do
      params = base_params() |> Map.delete("client_id")
      assert {:error, {:direct, :invalid_client_id}} = validate(params)
    end

    test "blank client_id does not redirect" do
      assert {:error, {:direct, :invalid_client_id}} = validate(base_params(%{"client_id" => ""}))
    end

    test "missing redirect_uri does not redirect" do
      params = base_params() |> Map.delete("redirect_uri")
      assert {:error, {:direct, :missing_redirect_uri}} = validate(params)
    end

    test "redirect_uri not in the registered set does not redirect" do
      params = base_params(%{"redirect_uri" => "https://attacker.example.com/cb"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "redirect_uri must match exactly, not by prefix" do
      params = base_params(%{"redirect_uri" => @redirect_uri <> "/extra"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "an empty registered set rejects every redirect_uri" do
      result = AuthorizationRequest.validate(base_params(), registered_redirect_uris: [])
      assert {:error, {:direct, :redirect_uri_not_registered}} = result
    end

    test "client_id and redirect_uri are checked before redirectable params" do
      # response_type is also bad, but the non-redirectable redirect_uri error
      # wins: an untrusted URI must never be redirected to (OIDC Core §3.1.2.6).
      params = base_params(%{"response_type" => "token", "redirect_uri" => "https://evil/cb"})
      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end
  end

  describe "validate/2 redirectable errors (RFC 6749 §4.1.2.1)" do
    test "missing response_type redirects with invalid_request" do
      params = base_params() |> Map.delete("response_type")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "unsupported response_type redirects with unsupported_response_type" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"response_type" => "token"}))
      assert err.error == "unsupported_response_type"
      assert err.redirect_uri == @redirect_uri
    end

    test "request_uri is explicitly rejected when unsupported" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"request_uri" => "https://rp.example/request.jwt"}))

      assert err.error == "request_uri_not_supported"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "request object is rejected when no trusted client keys are supplied" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"request" => "header.body.sig"}))

      assert err.error == "invalid_request_object"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "a request carrying no request object is rejected when the policy requires one" do
      # FAPI 2.0 Message Signing §5.3.1: the policy mandates a signed request
      # object, so plain parameters alone are rejected (redirectable).
      assert {:error, {:redirect, err}} =
               AuthorizationRequest.validate(base_params(),
                 registered_redirect_uris: @registered,
                 request_object_policy: Policy.fapi_message_signing()
               )

      assert err.error == "invalid_request"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "an unsupported response_mode redirects with invalid_request" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"response_mode" => "form_post"}))

      assert err.error == "invalid_request"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "the required-request-object error stays non-redirectable when client_id is untrusted" do
      # OIDC Core §3.1.2.6: even though the policy requires a signed request
      # object, a missing client_id is non-redirectable - the supplied
      # redirect_uri cannot be trusted, so this must NOT redirect.
      params = base_params() |> Map.delete("client_id")

      assert {:error, {:direct, :invalid_client_id}} =
               AuthorizationRequest.validate(params,
                 registered_redirect_uris: @registered,
                 request_object_policy: Policy.fapi_message_signing()
               )
    end

    test "a trusted redirectable error carries response_mode and client_id (JARM context)" do
      # The transport needs the requested response_mode and the audience to
      # return the error as a signed JWT (JARM §2.3); the core attaches them once
      # the client is trusted.
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"scope" => ~s(open"id), "response_mode" => "query.jwt"}))

      assert err.error == "invalid_scope"
      assert err.response_mode == "query.jwt"
      assert err.client_id == "client-123"
    end

    test "a request-object error carries response_mode and client_id once the client is trusted" do
      # The HIGH-severity gap: request-object failures are produced before
      # validate_redirectable, so they must attach the JARM context themselves.
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"request" => "bad.jwt.sig", "response_mode" => "query.jwt"}))

      assert err.error == "invalid_request_object"
      assert err.response_mode == "query.jwt"
      assert err.client_id == "client-123"
    end

    test "a request-object error with an untrusted client_id stays non-redirectable" do
      params = base_params(%{"request" => "bad.jwt.sig"}) |> Map.delete("client_id")

      assert {:error, {:direct, :invalid_client_id}} =
               validate(params)
    end

    test "unsigned request object is rejected as unsupported" do
      request =
        unsigned_request_object(%{
          "client_id" => "client-123",
          "redirect_uri" => @redirect_uri,
          "response_type" => "code",
          "scope" => "openid",
          "state" => "xyz",
          "nonce" => "n-0S6_WzA2Mj"
        })

      assert {:error, {:redirect, err}} =
               AuthorizationRequest.validate(base_params(%{"request" => request}),
                 registered_redirect_uris: @registered,
                 request_object_jwks: %{"keys" => []}
               )

      assert err.error == "request_not_supported"
      assert err.redirect_uri == @redirect_uri
      assert err.state == "xyz"
    end

    test "invalid request object with an untrusted redirect_uri does not redirect" do
      params =
        base_params(%{
          "request" => "header.body.sig",
          "redirect_uri" => "https://attacker.example/cb"
        })

      assert {:error, {:direct, :redirect_uri_not_registered}} = validate(params)
    end

    test "request object parameters are authoritative and query PKCE cannot supplement them" do
      {request, client_jwk} =
        signed_request_object(%{
          "iss" => "client-123",
          "aud" => "https://issuer.example",
          "client_id" => "client-123",
          "redirect_uri" => @redirect_uri,
          "response_type" => "code",
          "scope" => "openid profile",
          "state" => "signed-state"
        })

      attacker_verifier = String.duplicate("a", 64)
      attacker_challenge = Attesto.Thumbprint.of(attacker_verifier)

      params =
        %{
          "request" => request,
          "client_id" => "client-123",
          "redirect_uri" => @redirect_uri,
          "state" => "attacker-state",
          "scope" => "openid admin",
          "code_challenge" => attacker_challenge,
          "code_challenge_method" => "S256"
        }

      assert {:error, {:redirect, err}} =
               AuthorizationRequest.validate(params,
                 registered_redirect_uris: @registered,
                 request_object_jwks: %{"keys" => [client_jwk]},
                 request_object_audience: "https://issuer.example"
               )

      assert err.error == "invalid_request"
      assert err.error_description =~ "code_challenge"
      assert err.state == "signed-state"
    end

    test "request object validation requires an audience" do
      {request, client_jwk} =
        signed_request_object(%{
          "iss" => "client-123",
          "aud" => "https://issuer.example",
          "client_id" => "client-123",
          "redirect_uri" => @redirect_uri,
          "response_type" => "code",
          "scope" => "openid",
          "code_challenge" => @code_challenge,
          "code_challenge_method" => "S256"
        })

      assert {:error, {:redirect, err}} =
               AuthorizationRequest.validate(base_params(%{"request" => request}),
                 registered_redirect_uris: @registered,
                 request_object_jwks: %{"keys" => [client_jwk]}
               )

      assert err.error == "invalid_request_object"
    end

    test "request object validation requires query client_id to match object iss" do
      {request, client_jwk} =
        signed_request_object(%{
          "iss" => "client-A",
          "aud" => "https://issuer.example",
          "client_id" => "client-A",
          "redirect_uri" => @redirect_uri,
          "response_type" => "code",
          "scope" => "openid",
          "code_challenge" => @code_challenge,
          "code_challenge_method" => "S256"
        })

      params =
        base_params(%{
          "request" => request,
          "client_id" => "client-B"
        })

      assert {:error, {:redirect, err}} =
               AuthorizationRequest.validate(params,
                 registered_redirect_uris: @registered,
                 request_object_jwks: %{"keys" => [client_jwk]},
                 request_object_audience: "https://issuer.example"
               )

      assert err.error == "invalid_request_object"
    end

    test "an out-of-ABNF scope token redirects with invalid_scope" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"scope" => "open\"id"}))
      assert err.error == "invalid_scope"
    end

    test "missing code_challenge redirects with invalid_request" do
      params = base_params() |> Map.delete("code_challenge")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "code_challenge"
    end

    test "a syntactically invalid code_challenge redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"code_challenge" => "short"}))
      assert err.error == "invalid_request"
    end

    test "code_challenge_method=plain is rejected (RFC 7636 §4.4.1)" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"code_challenge_method" => "plain"}))

      assert err.error == "invalid_request"
      assert err.error_description =~ "plain"
    end

    test "missing code_challenge_method is rejected" do
      params = base_params() |> Map.delete("code_challenge_method")
      assert {:error, {:redirect, err}} = validate(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "S256"
    end

    test "an unknown code_challenge_method is rejected" do
      assert {:error, {:redirect, err}} =
               validate(base_params(%{"code_challenge_method" => "S512"}))

      assert err.error == "invalid_request"
    end

    test "a non-integer max_age redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"max_age" => "soon"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "max_age"
    end

    test "a negative max_age redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"max_age" => "-5"}))
      assert err.error == "invalid_request"
    end

    test "redirectable errors echo a nil state when state is absent" do
      params = base_params(%{"response_type" => "token"}) |> Map.delete("state")
      assert {:error, {:redirect, err}} = validate(params)
      assert is_nil(err.state)
    end

    test "an unknown prompt token redirects with invalid_request (OIDC Core §3.1.2.1)" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"prompt" => "login bogus"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "prompt"
    end

    test "malformed claims redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"claims" => "{not json"}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "claims"
    end

    test "non-object claims redirects with invalid_request" do
      assert {:error, {:redirect, err}} = validate(base_params(%{"claims" => ~s(["name"])}))
      assert err.error == "invalid_request"
      assert err.error_description =~ "claims"
    end
  end

  describe "validate/2 prompt parsing (OIDC Core §3.1.2.1)" do
    test "accepts each defined prompt value" do
      assert {:ok, req} = validate(base_params(%{"prompt" => "none"}))
      assert req.prompt == ["none"]

      assert {:ok, req} = validate(base_params(%{"prompt" => "login consent select_account"}))
      assert req.prompt == ["login", "consent", "select_account"]
    end

    test "absent prompt parses to an empty list" do
      params = base_params() |> Map.delete("prompt")
      assert {:ok, req} = validate(params)
      assert req.prompt == []
    end
  end

  describe "validate/2 require_nonce (OIDC Core §3.1.2.1)" do
    test "missing nonce with require_nonce: true redirects with invalid_request" do
      params = base_params() |> Map.delete("nonce")
      assert {:error, {:redirect, err}} = validate_require_nonce(params)
      assert err.error == "invalid_request"
      assert err.error_description =~ "nonce"
    end

    test "present nonce with require_nonce: true is ok" do
      assert {:ok, req} = validate_require_nonce(base_params(%{"nonce" => "n-0S6_WzA2Mj"}))
      assert req.nonce == "n-0S6_WzA2Mj"
    end

    test "nonce stays optional when require_nonce is off (default)" do
      params = base_params() |> Map.delete("nonce")
      assert {:ok, req} = validate(params)
      assert is_nil(req.nonce)
    end

    test "a non-OIDC request (no openid scope) is never nonce-constrained" do
      # OIDC Core §3.1.2.1: nonce only applies to OpenID Connect Authentication
      # Requests. A plain OAuth request without openid scope is accepted even
      # under require_nonce: true.
      params = base_params(%{"scope" => "profile"}) |> Map.delete("nonce")
      assert {:ok, req} = validate_require_nonce(params)
      assert is_nil(req.nonce)
    end

    test "a signed request object carrying openid scope cannot bypass require_nonce" do
      # The OUTER params carry no openid scope (no scope at all): the openid gate
      # MUST be judged on the merged request, or a direct JAR would slip past the
      # host's nonce policy.
      {request, client_jwk} = signed_request_object(Map.delete(fapi_request_claims(), "nonce"))

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, require_nonce: true)

      assert err.error == "invalid_request"
      assert err.error_description =~ "nonce"
    end

    test "a signed request object with openid scope and a nonce satisfies require_nonce" do
      {request, client_jwk} =
        signed_request_object(fapi_request_claims(%{"nonce" => "n-0S6_WzA2Mj"}))

      assert {:ok, req} = validate_request_object(request, client_jwk, require_nonce: true)
      assert req.nonce == "n-0S6_WzA2Mj"
      assert req.openid? == true
    end

    test "a signed request object without openid scope is not nonce-constrained" do
      claims = Map.delete(fapi_request_claims(%{"scope" => "profile"}), "nonce")
      {request, client_jwk} = signed_request_object(claims)

      assert {:ok, req} = validate_request_object(request, client_jwk, require_nonce: true)
      assert is_nil(req.nonce)
      assert req.openid? == false
    end
  end

  describe "validate/2 request_object_policy (FAPI Message Signing 2.0 §5.3.1)" do
    @oauth_authz_req_typ %{"typ" => "oauth-authz-req+jwt"}

    test "default policy accepts a signed request object without nbf/exp (generic OIDC §6.1)" do
      {request, client_jwk} =
        signed_request_object(Map.drop(fapi_request_claims(), ["nbf", "exp"]))

      assert {:ok, _req} = validate_request_object(request, client_jwk, [])
    end

    test "FAPI profile accepts a fully compliant request object" do
      {request, client_jwk} = signed_request_object(fapi_request_claims(), header: @oauth_authz_req_typ)

      assert {:ok, _req} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())
    end

    test "FAPI profile rejects a request object missing nbf" do
      {request, client_jwk} =
        signed_request_object(Map.delete(fapi_request_claims(), "nbf"), header: @oauth_authz_req_typ)

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())

      assert err.error == "invalid_request_object"
    end

    test "FAPI profile rejects a request object missing exp" do
      {request, client_jwk} =
        signed_request_object(Map.delete(fapi_request_claims(), "exp"), header: @oauth_authz_req_typ)

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())

      assert err.error == "invalid_request_object"
    end

    test "FAPI profile rejects an nbf more than 60 minutes in the past" do
      now = System.system_time(:second)

      {request, client_jwk} =
        signed_request_object(fapi_request_claims(%{"nbf" => now - 3700, "exp" => now + 300}),
          header: @oauth_authz_req_typ
        )

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())

      assert err.error == "invalid_request_object"
    end

    test "FAPI profile rejects a lifetime longer than 60 minutes" do
      now = System.system_time(:second)

      {request, client_jwk} =
        signed_request_object(fapi_request_claims(%{"nbf" => now, "exp" => now + 3700}),
          header: @oauth_authz_req_typ
        )

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())

      assert err.error == "invalid_request_object"
    end

    test "FAPI profile rejects a typ that is not oauth-authz-req+jwt" do
      # The default helper produces typ \"JWT\" (JOSE.JWT.sign injects it), which
      # the strict FAPI pin rejects.
      {request, client_jwk} = signed_request_object(fapi_request_claims())

      assert {:error, {:redirect, err}} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())

      assert err.error == "invalid_request_object"
    end

    test "an aud array containing the issuer is accepted (§5.3.1)" do
      {request, client_jwk} =
        signed_request_object(fapi_request_claims(%{"aud" => [@issuer, "https://other.example"]}),
          header: @oauth_authz_req_typ
        )

      assert {:ok, _req} =
               validate_request_object(request, client_jwk, request_object_policy: Policy.fapi_message_signing())
    end
  end
end
