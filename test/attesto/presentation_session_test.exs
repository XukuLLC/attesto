defmodule Attesto.PresentationSessionTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.{Cose, JWS, Mdoc, PresentationSession, SdJwtVc}
  alias Attesto.PresentationSessionStore.ETS, as: Store

  @audience "verifier-client-1"
  @query_id "identity"
  @mdoc_query_id "mdl"
  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"
  @response_uri "https://verifier.example.com/response"
  @racers 20

  setup do
    start_supervised!(Store)

    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, holder_jwk} = keypair()
    now = System.system_time(:second)

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice", "family_name" => "Example"},
        cnf: %{"jwk" => holder_jwk},
        iat: now
      )

    %{
      holder_pem: holder_pem,
      issuer_jwk: issuer_jwk,
      now: now,
      vc: vc
    }
  end

  test "create returns the state id and nonce and persists a pending session", ctx do
    assert {:ok, %{id: id, nonce: nonce}} = create_session(ctx)
    assert id != nonce

    assert {:ok, entry} = Store.get(id)
    assert entry.id == id
    assert entry.expires_at == ctx.now + 300
    assert entry.data.nonce == nonce
    assert entry.data.state == id
    assert entry.data.audience == @audience
    assert entry.data.expected_query_ids == [@query_id]
    assert entry.data.issuer_trust == {:issuer_jwks, ctx.issuer_jwk}
    assert entry.data.status == :pending
    refute Map.has_key?(entry.data, :result)
  end

  test "persists and serves an optional signed request object", ctx do
    assert {:ok, %{id: id}} = create_session(ctx, request_object: "eyJ.signed.jar")
    assert {:ok, "eyJ.signed.jar"} = PresentationSession.request_object(Store, id)

    # A session created without one has no request object to serve.
    assert {:ok, %{id: bare_id}} = create_session(ctx)
    assert :error = PresentationSession.request_object(Store, bare_id)
    assert :error = PresentationSession.request_object(Store, "unknown")
  end

  test "attach_request_object/3 sets the request object on a pending session", ctx do
    assert {:ok, %{id: id}} = create_session(ctx)
    assert :error = PresentationSession.request_object(Store, id)

    assert :ok = PresentationSession.attach_request_object(Store, id, "eyJ.attached.jar")
    assert {:ok, "eyJ.attached.jar"} = PresentationSession.request_object(Store, id)

    assert {:error, :unavailable} = PresentationSession.attach_request_object(Store, "unknown", "x.y.z")
  end

  test "attach_request_object/3 refuses a completed session", ctx do
    {:ok, session} = create_session(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)
    assert {:ok, _} = PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

    assert {:error, :unavailable} =
             PresentationSession.attach_request_object(Store, session.id, "x.y.z")
  end

  test "a valid response completes the session and makes its result readable", ctx do
    {:ok, session} = create_session(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)

    assert {:ok, %{@query_id => verified}} =
             PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

    assert verified.vct == "identity"
    assert verified.iss == "https://issuer.example"
    assert verified.claims["given_name"] == "Alice"

    assert {:ok, entry} = Store.get(session.id)
    assert entry.data.status == :completed
    assert entry.data.result == %{results: %{@query_id => verified}}

    assert {:ok, %{@query_id => ^verified}} =
             PresentationSession.result(Store, session.id)
  end

  test "an id correlation verifies the same state-keyed session", ctx do
    {:ok, session} = create_session(ctx)

    assert {:ok, %{@query_id => _verified}} =
             PresentationSession.verify_response(
               Store,
               {:id, session.id},
               valid_vp_token(ctx, session.nonce),
               now: ctx.now
             )
  end

  test "wrong nonce and audience responses fail without completing the session", ctx do
    {:ok, session} = create_session(ctx)

    assert {:error, {:invalid_presentation, {@query_id, _reason}}} =
             PresentationSession.verify_response(
               Store,
               {:state, session.id},
               valid_vp_token(ctx, "wrong-nonce"),
               now: ctx.now
             )

    assert_pending(session.id)
    assert :error = PresentationSession.result(Store, session.id)

    assert {:error, {:invalid_presentation, {@query_id, _reason}}} =
             PresentationSession.verify_response(
               Store,
               {:state, session.id},
               valid_vp_token(ctx, session.nonce, "wrong-audience"),
               now: ctx.now
             )

    assert_pending(session.id)
    assert :error = PresentationSession.result(Store, session.id)
  end

  test "unknown and expired sessions return distinct errors", ctx do
    assert {:error, :unknown_session} =
             PresentationSession.verify_response(Store, {:state, "unknown"}, %{}, now: ctx.now)

    :ok =
      Store.put(%{
        id: "expired",
        data: %{
          audience: @audience,
          expected_query_ids: [@query_id],
          issuer_trust: {:issuer_jwks, ctx.issuer_jwk},
          nonce: "expired-nonce",
          state: "expired",
          status: :pending
        },
        expires_at: ctx.now - 1
      })

    assert {:error, :expired} =
             PresentationSession.verify_response(Store, {:state, "expired"}, %{}, now: ctx.now)

    assert :error = Store.complete("expired", %{results: %{}})
  end

  test "a second valid submission cannot replay or overwrite the result", ctx do
    {:ok, session} = create_session(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)

    assert {:ok, results} =
             PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

    assert {:error, :already_completed} =
             PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

    # result/2 returns the SAME shape as verify_response/4 (the VpToken results).
    assert {:ok, ^results} = PresentationSession.result(Store, session.id)
  end

  test "exactly one simultaneous valid response completes a session", ctx do
    {:ok, session} = create_session(ctx)
    vp_token = valid_vp_token(ctx, session.nonce)

    results =
      1..@racers
      |> Enum.map(fn _ ->
        Task.async(fn ->
          PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)
        end)
      end)
      |> Task.await_many(10_000)

    assert Enum.count(results, &match?({:ok, _verified}, &1)) == 1
    assert Enum.count(results, &(&1 == {:error, :already_completed})) == @racers - 1
  end

  test "supports a function-based issuer resolver in the in-memory store", ctx do
    caller = self()

    {:ok, session} =
      create_session(ctx,
        issuer_trust:
          {:resolve_issuer,
           fn issuer ->
             send(caller, {:resolved_issuer, issuer})
             {:ok, ctx.issuer_jwk}
           end}
      )

    assert {:ok, %{@query_id => _verified}} =
             PresentationSession.verify_response(
               Store,
               {:state, session.id},
               valid_vp_token(ctx, session.nonce),
               now: ctx.now
             )

    assert_receive {:resolved_issuer, "https://issuer.example"}
  end

  test "the optional take atomically polls and clears only completed sessions", ctx do
    {:ok, pending} = create_session(ctx)
    assert :error = Store.take(pending.id)
    assert_pending(pending.id)

    assert {:ok, _results} =
             PresentationSession.verify_response(
               Store,
               {:state, pending.id},
               valid_vp_token(ctx, pending.nonce),
               now: ctx.now
             )

    assert {:ok, %{data: %{status: :completed}}} = Store.take(pending.id)
    assert :error = Store.take(pending.id)
    assert :error = Store.get(pending.id)
  end

  test "create rejects malformed verification context", ctx do
    valid = %{
      audience: @audience,
      expected_query_ids: [],
      issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
    }

    assert {:error, :invalid_attrs} = PresentationSession.create(Store, %{valid | audience: ""})

    assert {:error, :invalid_attrs} =
             PresentationSession.create(Store, %{valid | expected_query_ids: [""]})

    assert {:error, :invalid_attrs} =
             PresentationSession.create(Store, %{valid | issuer_trust: {:resolve_issuer, :not_a_function}})
  end

  describe "mso_mdoc round trip" do
    setup do
      {issuer_pem, issuer_jwk} = keypair()
      {holder_pem, holder_jwk} = keypair()
      now = System.system_time(:second)

      namespaces = %{@mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}}

      {:ok, issued} =
        Mdoc.issue(
          device_key: holder_jwk,
          doc_type: @doc_type,
          issuer_pem: issuer_pem,
          namespaces: namespaces,
          validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
        )

      {:ok, issuer_signed, ""} = issued |> Base.url_decode64!(padding: false) |> CBOR.decode()

      %{holder_pem: holder_pem, issuer_jwk: issuer_jwk, issuer_signed: issuer_signed, now: now}
    end

    defp mdoc_create_session(ctx, overrides \\ []) do
      attrs =
        Map.merge(
          %{
            audience: @audience,
            expected_query_ids: [@mdoc_query_id],
            issuer_trust: {:issuer_jwks, ctx.issuer_jwk},
            response_uri: @response_uri
          },
          Map.new(overrides)
        )

      PresentationSession.create(Store, attrs, now: ctx.now)
    end

    defp mdoc_vp_token(ctx, nonce, audience \\ @audience, response_uri \\ @response_uri) do
      session_transcript = mdoc_session_transcript(audience, nonce, response_uri)
      device_namespaces_tagged = mdoc_tagged(%{})

      device_authentication_bytes =
        ["DeviceAuthentication", session_transcript, @doc_type, device_namespaces_tagged]
        |> mdoc_tagged()
        |> CBOR.encode()

      {:ok, device_auth_cose, ""} =
        ctx.holder_pem |> Cose.sign1_detached(device_authentication_bytes, []) |> CBOR.decode()

      document = %{
        "docType" => @doc_type,
        "issuerSigned" => ctx.issuer_signed,
        "deviceSigned" => %{
          "nameSpaces" => device_namespaces_tagged,
          "deviceAuth" => %{"deviceSignature" => device_auth_cose}
        }
      }

      device_response =
        %{"documents" => [document], "status" => 0, "version" => "1.0"}
        |> CBOR.encode()
        |> Base.url_encode64(padding: false)

      %{@mdoc_query_id => device_response}
    end

    defp mdoc_session_transcript(client_id, nonce, response_uri) do
      handover_info_hash =
        [client_id, nonce, nil, response_uri]
        |> CBOR.encode()
        |> then(&:crypto.hash(:sha256, &1))
        |> mdoc_bytes()

      [nil, nil, ["OpenID4VPHandover", handover_info_hash]]
    end

    defp mdoc_tagged(value), do: %CBOR.Tag{tag: 24, value: mdoc_bytes(CBOR.encode(value))}
    defp mdoc_bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

    test "a session created with :response_uri verifies an mso_mdoc response end-to-end", ctx do
      {:ok, session} = mdoc_create_session(ctx)
      vp_token = mdoc_vp_token(ctx, session.nonce)

      assert {:ok, %{@mdoc_query_id => verified}} =
               PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

      assert verified.doc_type == @doc_type
      assert verified.namespaces == %{@mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}}
    end

    test "a wrong nonce, client_id, or response_uri fails without completing the session", ctx do
      {:ok, session} = mdoc_create_session(ctx)

      assert {:error, {:invalid_presentation, {@mdoc_query_id, _reason}}} =
               PresentationSession.verify_response(
                 Store,
                 {:state, session.id},
                 mdoc_vp_token(ctx, "wrong-nonce"),
                 now: ctx.now
               )

      assert_pending(session.id)

      assert {:error, {:invalid_presentation, {@mdoc_query_id, _reason}}} =
               PresentationSession.verify_response(
                 Store,
                 {:state, session.id},
                 mdoc_vp_token(ctx, session.nonce, "wrong-client"),
                 now: ctx.now
               )

      assert_pending(session.id)

      assert {:error, {:invalid_presentation, {@mdoc_query_id, _reason}}} =
               PresentationSession.verify_response(
                 Store,
                 {:state, session.id},
                 mdoc_vp_token(ctx, session.nonce, @audience, "https://attacker.example.com/response"),
                 now: ctx.now
               )

      assert_pending(session.id)
    end

    test "a session created without :response_uri cannot verify an mso_mdoc response", ctx do
      {:ok, session} = mdoc_create_session(ctx, response_uri: nil)
      vp_token = mdoc_vp_token(ctx, session.nonce)

      assert {:error, {:invalid_presentation, {@mdoc_query_id, :missing_response_uri}}} =
               PresentationSession.verify_response(Store, {:state, session.id}, vp_token, now: ctx.now)

      assert_pending(session.id)
    end
  end

  defp create_session(ctx, overrides \\ []) do
    attrs =
      Map.merge(
        %{
          audience: @audience,
          expected_query_ids: [@query_id],
          issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
        },
        Map.new(overrides)
      )

    PresentationSession.create(Store, attrs, now: ctx.now)
  end

  defp valid_vp_token(ctx, nonce, audience \\ @audience) do
    presentation = ctx.vc <> kb_jwt(ctx.holder_pem, ctx.vc, nonce, audience, ctx.now)
    %{@query_id => presentation}
  end

  defp assert_pending(id) do
    assert {:ok, %{data: data}} = Store.get(id)
    assert data.status == :pending
    refute Map.has_key?(data, :result)
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp kb_jwt(holder_pem, presentation, nonce, audience, now) do
    JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
      "nonce" => nonce,
      "aud" => audience,
      "iat" => now,
      "sd_hash" => hash(presentation)
    })
  end

  defp hash(value), do: :crypto.hash(:sha256, value) |> Base.url_encode64(padding: false)
end
