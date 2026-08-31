defmodule Attesto.PresentationSessionTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.{Cose, JWS, Mdoc, PresentationSession, SdJwtVc}
  alias Attesto.PresentationSessionStore.ETS
  alias Attesto.PresentationSessionStore.ETS, as: Store

  @audience "verifier-client-1"
  @query_id "identity"
  @mdoc_query_id "mdl"
  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"
  @response_uri "https://verifier.example.com/response"
  @racers 20

  defmodule ContractStore do
    @moduledoc false
    @behaviour Attesto.PresentationSessionStore

    @impl true
    def put(entry), do: dispatch(:put, fn -> ETS.put(entry) end)
    @impl true
    def get(id), do: dispatch(:get, fn -> ETS.get(id) end)
    @impl true
    def complete(id, result), do: dispatch(:complete, fn -> ETS.complete(id, result) end)
    @impl true
    def take(id), do: dispatch(:take, fn -> ETS.take(id) end)
    @impl true
    def attach_request_object(id, request_object),
      do: dispatch(:attach_request_object, fn -> ETS.attach_request_object(id, request_object) end)

    @impl true
    def attach_response_encryption_jwk(id, jwk),
      do: dispatch(:attach_response_encryption_jwk, fn -> ETS.attach_response_encryption_jwk(id, jwk) end)

    defp dispatch(operation, fallback) do
      case Process.get({__MODULE__, operation}) do
        nil -> fallback.()
        {:return, value} -> value
      end
    end
  end

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

  test "invalid lifetime is rejected before the store is called", ctx do
    attrs = %{
      audience: @audience,
      expected_query_ids: [@query_id],
      issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
    }

    Process.put({ContractStore, :put}, {:return, {:private, "store-was-called"}})

    for invalid <- [0, -1, 1.5, "300", nil] do
      assert_raise ArgumentError, ~r/:ttl must be a positive integer/, fn ->
        PresentationSession.create(ContractStore, attrs, ttl: invalid, now: ctx.now)
      end
    end
  end

  test "negative clocks are rejected before put or get and leave the session untouched", ctx do
    attrs = %{
      audience: @audience,
      expected_query_ids: [@query_id],
      issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
    }

    Process.put({ContractStore, :put}, {:return, {:private_put_sentinel, attrs}})

    for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
      assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
        PresentationSession.create(ContractStore, attrs, now: bad_now)
      end
    end

    Process.delete({ContractStore, :put})
    {:ok, session} = create_session(ctx)
    Process.put({ContractStore, :get}, {:return, {:private_get_sentinel, session.id}})

    for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
      assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
        PresentationSession.verify_response(
          ContractStore,
          {:state, session.id},
          %{},
          now: bad_now
        )
      end
    end

    Process.delete({ContractStore, :get})
    assert_pending(session.id)
  end

  test "persists and serves an optional signed request object", ctx do
    assert {:ok, %{id: id}} = create_session(ctx, request_object: "eyJ.signed.jar")
    assert {:ok, "eyJ.signed.jar"} = PresentationSession.request_object(Store, id)

    # A session created without one has no request object to serve.
    assert {:ok, %{id: bare_id}} = create_session(ctx)
    assert :error = PresentationSession.request_object(Store, bare_id)
    assert :error = PresentationSession.request_object(Store, "unknown")
  end

  test "request-object and response-key reads reject malformed store results without exposing them" do
    future = System.system_time(:second) + 100

    Process.put({ContractStore, :get}, {:return, {:unexpected, "presentation-get-private-sentinel"}})

    assert_contract_error("get/1", fn ->
      PresentationSession.request_object(ContractStore, "session-1")
    end)

    Process.put(
      {ContractStore, :get},
      {:return,
       {:ok,
        %{
          id: "session-1",
          expires_at: future,
          data: %{status: :pending, request_object: {:invalid, "request-object-private-sentinel"}}
        }}}
    )

    assert_contract_error("get/1", fn ->
      PresentationSession.request_object(ContractStore, "session-1")
    end)

    Process.put(
      {ContractStore, :get},
      {:return,
       {:ok,
        %{
          id: "session-1",
          expires_at: future,
          data: %{status: :pending, response_encryption_jwk: "response-key-private-sentinel"}
        }}}
    )

    assert_contract_error("get/1", fn ->
      PresentationSession.response_encryption_jwk(ContractStore, "session-1")
    end)
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

    # `get/1` exposes status but never the completed result payload (the PII):
    # that is read exactly once via `result/2` (which consumes through `take/1`).
    assert {:ok, entry} = Store.get(session.id)
    assert entry.data.status == :completed
    refute Map.has_key?(entry.data, :result)

    assert {:ok, %{@query_id => ^verified}} =
             PresentationSession.result(Store, session.id)

    # Single-use: a second read (e.g. a replayed response_code) gets nothing.
    assert :error = PresentationSession.result(Store, session.id)
  end

  test "a malformed or unexpected consuming result fails loudly without exposing store data" do
    Process.put({ContractStore, :take}, {:return, {:unexpected, "take-private-sentinel"}})
    assert_contract_error("take/1", fn -> PresentationSession.result(ContractStore, "session-1") end)

    Process.put(
      {ContractStore, :take},
      {:return,
       {:ok,
        %{
          id: "session-1",
          expires_at: System.system_time(:second) + 100,
          data: %{status: :completed, result: %{results: "result-private-sentinel"}}
        }}}
    )

    assert_contract_error("take/1", fn -> PresentationSession.result(ContractStore, "session-1") end)

    Process.put(
      {ContractStore, :take},
      {:return,
       {:ok,
        %{
          id: "session-expired",
          expires_at: System.system_time(:second) - 1,
          data: %{status: :completed, result: %{results: %{expired: true}}}
        }}}
    )

    assert :error = PresentationSession.result(ContractStore, "session-expired")
  end

  test "all presentation-store callback return contracts fail loudly with constant messages", ctx do
    Process.put({ContractStore, :put}, {:return, {:unexpected, "put-private-sentinel"}})

    assert_contract_error("put/1", fn ->
      create_session_with_store(ContractStore, ctx)
    end)

    Process.delete({ContractStore, :put})
    {:ok, session} = create_session(ctx)

    Process.put(
      {ContractStore, :attach_request_object},
      {:return, {:unexpected, "attach-request-private-sentinel"}}
    )

    assert_contract_error("attach_request_object/2", fn ->
      PresentationSession.attach_request_object(ContractStore, session.id, "x.y.z")
    end)

    Process.put(
      {ContractStore, :attach_response_encryption_jwk},
      {:return, {:unexpected, "attach-key-private-sentinel"}}
    )

    assert_contract_error("attach_response_encryption_jwk/2", fn ->
      PresentationSession.attach_response_encryption_jwk(ContractStore, session.id, %{"kty" => "EC"})
    end)

    Process.put({ContractStore, :get}, {:return, {:unexpected, "load-private-sentinel"}})

    assert_contract_error("get/1", fn ->
      PresentationSession.verify_response(
        ContractStore,
        {:state, session.id},
        valid_vp_token(ctx, session.nonce),
        now: ctx.now
      )
    end)

    Process.delete({ContractStore, :get})
    Process.put({ContractStore, :complete}, {:return, {:unexpected, "complete-private-sentinel"}})

    assert_contract_error("complete/2", fn ->
      PresentationSession.verify_response(
        ContractStore,
        {:state, session.id},
        valid_vp_token(ctx, session.nonce),
        now: ctx.now
      )
    end)
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

  test "take atomically polls and clears only completed sessions", ctx do
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
    create_session_with_store(Store, ctx, overrides)
  end

  defp create_session_with_store(store, ctx, overrides \\ []) do
    attrs =
      Map.merge(
        %{
          audience: @audience,
          expected_query_ids: [@query_id],
          issuer_trust: {:issuer_jwks, ctx.issuer_jwk}
        },
        Map.new(overrides)
      )

    PresentationSession.create(store, attrs, now: ctx.now)
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

  defp assert_contract_error(callback, fun) do
    error =
      assert_raise RuntimeError, "presentation session store #{callback} violated its contract", fun

    refute Exception.message(error) =~ "private-sentinel"
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
