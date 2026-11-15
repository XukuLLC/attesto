defmodule Attesto.StatusListCacheTest do
  use ExUnit.Case, async: false

  alias Attesto.{JWS, StatusList}
  alias Attesto.StatusList.Cache

  setup do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    uri = "https://issuer.example/status/#{System.unique_integer([:positive])}"
    %{jwk: jwk, public: jwk |> JOSE.JWK.to_public_map() |> elem(1), uri: uri, now: System.system_time(:second)}
  end

  defp token(ctx, opts \\ []) do
    claims = %{
      "sub" => ctx.uri,
      "iat" => ctx.now,
      "status_list" => StatusList.build([Keyword.get(opts, :status, 0)], bits: 2)
    }

    claims = Map.merge(claims, Map.new(Keyword.get(opts, :claims, [])))
    JWS.sign_compact_jwk(ctx.jwk, %{"alg" => "ES256", "typ" => "statuslist+jwt"}, claims)
  end

  defp check(ctx, resolver, extra \\ []) do
    StatusList.check_status(
      StatusList.reference(ctx.uri, 0),
      resolver,
      ctx.public,
      Keyword.merge([now: ctx.now, cache_status: true], extra)
    )
  end

  test "verified tokens are reused, while trust and signatures are checked on every use", ctx do
    caller = self()
    jwt = token(ctx)

    resolver = fn _, _ ->
      send(caller, :fetched)
      {:ok, jwt}
    end

    assert :ok = check(ctx, resolver)
    assert_received :fetched
    assert :ok = check(ctx, resolver)
    refute_received :fetched
    wrong = %{ctx | public: JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)}
    assert {:error, :invalid_status_list_signature} = check(wrong, resolver)
    assert_received :fetched
    assert {:ok, ^jwt} = Cache.get({ctx.uri, "application/statuslist+jwt"}, ctx.now)
    assert :ok = check(ctx, resolver)
    refute_received :fetched
  end

  test "bad signatures and subject mismatches never enter the cache", ctx do
    for jwt <- ["invalid.signature.token", token(ctx, claims: [{"sub", "https://elsewhere.example"}])] do
      assert {:error, _} = check(ctx, fn _, _ -> {:ok, jwt} end)
      assert :miss = Cache.get({ctx.uri, "application/statuslist+jwt"}, ctx.now)
    end
  end

  test "signed ttl, exp and the fixed maximum age each expire cached entries", ctx do
    for {claims, elapsed} <- [[{"ttl", 2}], [{"exp", ctx.now + 3}], []] |> Enum.zip([2, 3, 300]) do
      jwt = token(ctx, claims: claims)
      assert :ok = check(ctx, fn _, _ -> {:ok, jwt} end)
      assert {:error, :unreachable} = check(ctx, fn _, _ -> {:error, :unreachable} end, now: ctx.now + elapsed)
    end

    jwt = token(ctx, claims: [{"ttl", 0}])
    assert :ok = check(ctx, fn _, _ -> {:ok, jwt} end)
    assert :miss = Cache.get({ctx.uri, "application/statuslist+jwt"}, ctx.now)
  end

  test "media types are separate and memory and entry count stay bounded", ctx do
    assert :ok = check(ctx, fn _, _ -> {:ok, token(ctx)} end)
    assert :miss = Cache.get({ctx.uri, "application/statuslist+cwt"}, ctx.now)
    for index <- 1..80, do: Cache.put({ctx.uri <> "/#{index}", "application/statuslist+jwt"}, "token", %{}, ctx.now)
    state = :sys.get_state(Cache)
    assert map_size(state.entries) <= 64

    for index <- 1..20,
        do:
          Cache.put(
            {ctx.uri <> "/large/#{index}", "application/statuslist+jwt"},
            String.duplicate("x", 1_048_576),
            %{},
            ctx.now
          )

    state = :sys.get_state(Cache)
    assert state.bytes <= 16 * 1_048_576
    assert map_size(state.entries) <= 64
  end

  test "suspension and application statuses remain distinguishable from revocation", ctx do
    assert {:error, :credential_suspended} =
             check(ctx, fn _, _ -> {:ok, token(ctx, status: 2)} end, cache_status: false)

    assert {:error, {:credential_status, 3}} =
             check(ctx, fn _, _ -> {:ok, token(ctx, status: 3)} end, cache_status: false)
  end

  test "default core verification reuses a token admitted only after validation", ctx do
    jwt = token(ctx)
    assert :ok = check(ctx, fn _, _ -> {:ok, jwt} end)
    pem = ctx.jwk |> JOSE.JWK.to_pem() |> elem(1)

    vc =
      Attesto.SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
        iat: ctx.now,
        status: StatusList.reference(ctx.uri, 0)
      )

    assert {:ok, _} = Attesto.SdJwtVc.verify(vc, ctx.public, now: ctx.now)
  end

  test "CWT status and identifier list caching honours integer ttl and exp claims", ctx do
    pem = ctx.jwk |> JOSE.JWK.to_pem() |> elem(1)
    caller = self()

    for {status, accept, token} <- [
          {StatusList.reference(ctx.uri, 0), "application/statuslist+cwt",
           StatusList.issue_cwt(pem, ctx.uri, [0], now: ctx.now, ttl: 2, exp: ctx.now + 10)},
          {%{"identifier_list" => %{"uri" => ctx.uri, "id" => <<1>>}}, "application/identifierlist+cwt",
           StatusList.issue_identifier_list_cwt(pem, ctx.uri, [], now: ctx.now, ttl: 2, exp: ctx.now + 10)}
        ] do
      resolver = fn _, ^accept ->
        send(caller, :fetched)
        {:ok, token}
      end

      opts = [format: :cwt, cache_status: true, now: ctx.now]
      assert :ok = StatusList.check_status(status, resolver, ctx.public, opts)
      assert_received :fetched
      assert :ok = StatusList.check_status(status, resolver, ctx.public, opts)
      refute_received :fetched

      assert {:error, :unreachable} =
               StatusList.check_status(
                 status,
                 fn _, _ -> {:error, :unreachable} end,
                 ctx.public,
                 Keyword.put(opts, :now, ctx.now + 2)
               )
    end
  end
end
