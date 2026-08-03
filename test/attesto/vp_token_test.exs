defmodule Attesto.VpTokenTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{Cose, JWS, Mdoc, SdJwtVc, VpToken}

  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"

  defp keypair(spec \\ {:ec, "P-256"}) do
    jwk = JOSE.JWK.generate_key(spec)
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp kb_jwt(holder_pem, presentation, nonce, audience, now, sd_hash \\ nil) do
    sd_hash = sd_hash || hash(presentation)

    JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
      "nonce" => nonce,
      "aud" => audience,
      "iat" => now,
      "sd_hash" => sd_hash
    })
  end

  defp hash(value), do: :crypto.hash(:sha256, value) |> Base.url_encode64(padding: false)

  defp valid_context(opts \\ []) do
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, holder_jwk} = keypair()
    now = 1_700_000_000

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice", "family_name" => "Example"},
        cnf: %{"jwk" => holder_jwk},
        iat: now
      )

    presentation = vc <> kb_jwt(holder_pem, vc, "nonce-1", "client-1", now)

    Map.merge(
      %{
        issuer_jwk: issuer_jwk,
        issuer_pem: issuer_pem,
        holder_pem: holder_pem,
        holder_jwk: holder_jwk,
        vc: vc,
        presentation: presentation,
        now: now,
        nonce: "nonce-1",
        audience: "client-1"
      },
      Map.new(opts)
    )
  end

  test "verifies a single credential and returns only safe fields" do
    ctx = valid_context()

    assert {:ok, %{"id" => result}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert result.vct == "identity"
    assert result.iss == "https://issuer.example"
    assert result.claims["given_name"] == "Alice"
    assert result.claims["family_name"] == "Example"
    assert result.cnf == %{"jwk" => ctx.holder_jwk}
    refute Map.has_key?(result, :issuer_jwt)
    refute Map.has_key?(result, :key_binding_jwt)
  end

  test "supports static issuer keys and an issuer resolver" do
    ctx = valid_context()
    caller = self()

    assert {:ok, %{"id" => _}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert {:ok, %{"id" => _}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               resolve_issuer: fn iss ->
                 send(caller, {:resolved_issuer, iss})
                 {:ok, ctx.issuer_jwk}
               end,
               now: ctx.now
             )

    assert_receive {:resolved_issuer, "https://issuer.example"}
  end

  test "rejects a wrong nonce and audience" do
    ctx = valid_context()

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: "wrong",
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: "wrong",
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "requires a Key Binding JWT" do
    ctx = valid_context()
    [jwt | _] = String.split(ctx.vc, "~")

    assert {:error, {"id", :missing_key_binding}} =
             VpToken.verify(%{"id" => jwt <> "~"},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "requires a holder key in cnf" do
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, _holder_jwk} = keypair()
    now = 1_700_000_000

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice"},
        iat: now
      )

    presentation = vc <> kb_jwt(holder_pem, vc, "nonce-1", "client-1", now)

    assert {:error, {"id", :missing_holder_key}} =
             VpToken.verify(%{"id" => presentation},
               nonce: "nonce-1",
               audience: "client-1",
               issuer_jwks: issuer_jwk,
               now: now
             )
  end

  test "rejects a tampered signature and wrong issuer keys" do
    ctx = valid_context()
    tampered = tamper_signature(ctx.presentation)
    opts = [nonce: ctx.nonce, audience: ctx.audience, now: ctx.now]

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => tampered}, opts ++ [issuer_jwks: ctx.issuer_jwk])

    {_other_pem, wrong_jwk} = keypair()

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation}, opts ++ [issuer_jwks: wrong_jwk])
  end

  test "rejects an expired credential" do
    ctx = valid_context()

    expired_vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: ctx.issuer_pem],
        claims: %{"given_name" => "Alice"},
        cnf: %{"jwk" => ctx.holder_jwk},
        iat: ctx.now - 3600,
        exp: ctx.now - 3600
      )

    expired = expired_vc <> kb_jwt(ctx.holder_pem, expired_vc, ctx.nonce, ctx.audience, ctx.now)

    assert {:error, {"id", :expired}} =
             VpToken.verify(%{"id" => expired},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "preserves list-valued presentations" do
    ctx = valid_context()

    assert {:ok, %{"id" => results}} =
             VpToken.verify(%{"id" => [ctx.presentation, ctx.presentation]},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert is_list(results)
    assert length(results) == 2
    assert Enum.all?(results, &(&1.vct == "identity"))
  end

  test "checks expected query IDs before accepting the response" do
    ctx = valid_context()

    assert {:error, {:missing_credentials, ["missing"]}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               expected_query_ids: ["id", "missing"],
               now: ctx.now
             )
  end

  test "rejects a Key Binding JWT whose sd_hash covers another presentation" do
    ctx = valid_context()
    wrong_kb = kb_jwt(ctx.holder_pem, ctx.presentation, ctx.nonce, ctx.audience, ctx.now, hash("other"))
    presentation = ctx.vc <> wrong_kb

    assert {:error, {"id", :invalid_key_binding}} =
             VpToken.verify(%{"id" => presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  describe "programmer errors" do
    test "requires a map and valid presentation values" do
      opts = [nonce: "nonce", audience: "client", issuer_jwks: %{}]

      assert_raise ArgumentError, fn -> VpToken.verify([], opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => 123}, opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => []}, opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => [123]}, opts) end
    end

    test "requires the nonce and audience" do
      assert_raise ArgumentError, fn -> VpToken.verify(%{}, issuer_jwks: %{}, audience: "client") end
      assert_raise ArgumentError, fn -> VpToken.verify(%{}, issuer_jwks: %{}, nonce: "nonce") end
    end

    test "requires exactly one issuer trust source" do
      opts = [nonce: "nonce", audience: "client"]

      assert_raise ArgumentError, fn -> VpToken.verify(%{}, opts) end

      assert_raise ArgumentError, fn ->
        VpToken.verify(%{}, opts ++ [issuer_jwks: %{}, resolve_issuer: fn _iss -> {:ok, %{}} end])
      end
    end
  end

  describe "mso_mdoc presentations" do
    defp mdoc_keypair, do: keypair()

    defp mdoc_context(overrides \\ []) do
      %{
        client_id: "client-1",
        response_uri: "https://verifier.example.com/response",
        nonce: "nonce-1",
        now: 1_700_000_000
      }
      |> Map.merge(Map.new(overrides))
    end

    defp issue_mdoc(issuer_pem, holder_public, now, namespaces) do
      {:ok, issued} =
        Mdoc.issue(
          device_key: holder_public,
          doc_type: @doc_type,
          issuer_pem: issuer_pem,
          namespaces: namespaces,
          validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
        )

      {:ok, issuer_signed, ""} = issued |> Base.url_decode64!(padding: false) |> CBOR.decode()
      issuer_signed
    end

    defp mdoc_device_response(issuer_signed, holder_pem, ctx) do
      session_transcript = mdoc_session_transcript(ctx)
      device_namespaces_tagged = mdoc_tagged(%{})

      device_authentication_bytes =
        ["DeviceAuthentication", session_transcript, @doc_type, device_namespaces_tagged]
        |> mdoc_tagged()
        |> CBOR.encode()

      {:ok, device_auth_cose, ""} =
        holder_pem |> Cose.sign1_detached(device_authentication_bytes, []) |> CBOR.decode()

      document = %{
        "docType" => @doc_type,
        "issuerSigned" => issuer_signed,
        "deviceSigned" => %{
          "nameSpaces" => device_namespaces_tagged,
          "deviceAuth" => %{"deviceSignature" => device_auth_cose}
        }
      }

      %{"documents" => [document], "status" => 0, "version" => "1.0"}
      |> CBOR.encode()
      |> Base.url_encode64(padding: false)
    end

    defp mdoc_session_transcript(ctx) do
      handover_info_hash =
        [ctx.client_id, ctx.nonce, nil, ctx.response_uri]
        |> CBOR.encode()
        |> then(&:crypto.hash(:sha256, &1))
        |> mdoc_bytes()

      [nil, nil, ["OpenID4VPHandover", handover_info_hash]]
    end

    defp mdoc_tagged(value), do: %CBOR.Tag{tag: 24, value: mdoc_bytes(CBOR.encode(value))}
    defp mdoc_bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

    defp mdoc_valid_context(opts \\ []) do
      {issuer_pem, issuer_jwk} = mdoc_keypair()
      {holder_pem, holder_jwk} = mdoc_keypair()
      ctx = mdoc_context()

      namespaces = %{@mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}}
      issuer_signed = issue_mdoc(issuer_pem, holder_jwk, ctx.now, namespaces)
      device_response = mdoc_device_response(issuer_signed, holder_pem, ctx)

      Map.merge(
        %{
          issuer_jwk: issuer_jwk,
          device_response: device_response,
          audience: ctx.client_id,
          nonce: ctx.nonce,
          response_uri: ctx.response_uri,
          now: ctx.now
        },
        Map.new(opts)
      )
    end

    test "verifies a DCQL entry declared as mso_mdoc via :formats" do
      mctx = mdoc_valid_context()

      assert {:ok, %{"mdl" => result}} =
               VpToken.verify(%{"mdl" => mctx.device_response},
                 nonce: mctx.nonce,
                 audience: mctx.audience,
                 issuer_jwks: mctx.issuer_jwk,
                 response_uri: mctx.response_uri,
                 formats: %{"mdl" => "mso_mdoc"},
                 now: mctx.now
               )

      assert result.doc_type == @doc_type
      assert result.namespaces == %{@mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}}
      assert result.device_namespaces == %{}
    end

    test "detects mso_mdoc by shape when :formats is omitted" do
      mctx = mdoc_valid_context()

      assert {:ok, %{"mdl" => result}} =
               VpToken.verify(%{"mdl" => mctx.device_response},
                 nonce: mctx.nonce,
                 audience: mctx.audience,
                 issuer_jwks: mctx.issuer_jwk,
                 response_uri: mctx.response_uri,
                 now: mctx.now
               )

      assert result.doc_type == @doc_type
    end

    test "a mixed vp_token verifies both an SD-JWT VC and an mso_mdoc entry" do
      sd_jwt_ctx = valid_context()
      mctx = mdoc_valid_context()

      vp_token = %{"identity" => sd_jwt_ctx.presentation, "mdl" => mctx.device_response}

      assert {:ok, results} =
               VpToken.verify(vp_token,
                 nonce: sd_jwt_ctx.nonce,
                 audience: sd_jwt_ctx.audience,
                 issuer_jwks: [sd_jwt_ctx.issuer_jwk, mctx.issuer_jwk],
                 response_uri: mctx.response_uri,
                 now: sd_jwt_ctx.now
               )

      assert results["identity"].vct == "identity"
      assert results["mdl"].doc_type == @doc_type
    end

    test "rejects a wrong nonce, client_id, and response_uri" do
      mctx = mdoc_valid_context()
      base_opts = [issuer_jwks: mctx.issuer_jwk, response_uri: mctx.response_uri, now: mctx.now]

      assert {:error, {"mdl", _reason}} =
               VpToken.verify(
                 %{"mdl" => mctx.device_response},
                 [nonce: "wrong-nonce", audience: mctx.audience] ++ base_opts
               )

      assert {:error, {"mdl", _reason}} =
               VpToken.verify(
                 %{"mdl" => mctx.device_response},
                 [nonce: mctx.nonce, audience: "wrong-client"] ++ base_opts
               )

      assert {:error, {"mdl", _reason}} =
               VpToken.verify(%{"mdl" => mctx.device_response},
                 nonce: mctx.nonce,
                 audience: mctx.audience,
                 issuer_jwks: mctx.issuer_jwk,
                 response_uri: "https://attacker.example.com/response",
                 now: mctx.now
               )
    end

    test "missing :response_uri fails a DCQL entry that needs it" do
      mctx = mdoc_valid_context()

      assert {:error, {"mdl", :missing_response_uri}} =
               VpToken.verify(%{"mdl" => mctx.device_response},
                 nonce: mctx.nonce,
                 audience: mctx.audience,
                 issuer_jwks: mctx.issuer_jwk,
                 now: mctx.now
               )
    end

    test "supports an issuer resolver keyed on the unverified docType" do
      mctx = mdoc_valid_context()
      caller = self()

      assert {:ok, %{"mdl" => result}} =
               VpToken.verify(%{"mdl" => mctx.device_response},
                 nonce: mctx.nonce,
                 audience: mctx.audience,
                 response_uri: mctx.response_uri,
                 resolve_issuer: fn doc_type ->
                   send(caller, {:resolved_doc_type, doc_type})
                   {:ok, mctx.issuer_jwk}
                 end,
                 now: mctx.now
               )

      assert result.doc_type == @doc_type
      assert_receive {:resolved_doc_type, @doc_type}
    end

    test "programmer errors: :formats rejects unknown format strings" do
      mctx = mdoc_valid_context()

      assert_raise ArgumentError, fn ->
        VpToken.verify(%{"mdl" => mctx.device_response},
          nonce: mctx.nonce,
          audience: mctx.audience,
          issuer_jwks: mctx.issuer_jwk,
          response_uri: mctx.response_uri,
          formats: %{"mdl" => "not_a_format"},
          now: mctx.now
        )
      end
    end
  end

  defp tamper_signature(presentation) do
    [jwt | rest] = String.split(presentation, "~")
    [protected, payload, signature] = String.split(jwt, ".")
    replacement = if String.last(signature) == "A", do: "B", else: "A"
    tampered_jwt = Enum.join([protected, payload, String.slice(signature, 0..-2//1) <> replacement], ".")
    Enum.join([tampered_jwt | rest], "~")
  end
end
