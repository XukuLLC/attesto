defmodule Attesto.AuthorizationCodeBindingTest do
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore.ETS
  alias Attesto.RefreshStore.ETS, as: RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Secret

  @verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @jkt Base.url_encode64(:crypto.hash(:sha256, "key"), padding: false)
  @params %{client_id: "client", redirect_uri: "https://client.example/cb", code_verifier: @verifier, dpop_jkt: @jkt}
  @attrs %{
    client_id: "client",
    redirect_uri: "https://client.example/cb",
    code_challenge: @challenge,
    dpop_jkt: @jkt,
    subject: "subject",
    scope: [],
    resource: []
  }

  defmodule StalledStore do
    use Attesto.Test.CodeStoreDelegates

    def read(hash) do
      Process.put(:stalled_reads, Process.get(:stalled_reads, 0) + 1)
      super(hash)
    end

    def claim(_hash), do: :error
    def flag_replay(_hash), do: :error
  end

  defmodule DeletedClaimStore do
    use Attesto.Test.CodeStoreDelegates

    def finish(hash, redemption) do
      :sys.replace_state(ETS, fn state ->
        :ets.delete(ETS, hash)
        state
      end)

      super(hash, redemption)
    end

    def revoke_access_token_for_code(hash) do
      send(self(), {:revoked_missing_link, hash})
      super(hash)
    end
  end

  defmodule ObservedRefreshStore do
    @behaviour Attesto.RefreshStore

    def insert(record) do
      send(self(), {:issued_refresh, record})
      RefreshStore.insert(record)
    end

    defdelegate get(hash), to: RefreshStore
    defdelegate rotate(hash, child, successor, opts), to: RefreshStore
    defdelegate revoke_family(family), to: RefreshStore
  end

  setup do
    start_supervised!(ETS)
    start_supervised!(RefreshStore)
    :ok
  end

  for {field, value, reason} <- [
        {:client_id, "other", :client_mismatch},
        {:redirect_uri, "https://other.example/cb", :redirect_uri_mismatch},
        {:code_verifier, String.duplicate("x", 43), :pkce_failed},
        {:dpop_jkt, Base.url_encode64(:crypto.hash(:sha256, "other"), padding: false), :dpop_binding_mismatch}
      ] do
    test "a wrong #{field} leaves a live code redeemable" do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
      hash = Secret.hash(code)
      before = ETS.read(hash)

      assert {:error, unquote(reason)} =
               AuthorizationCode.redeem(ETS, code, Map.put(@params, unquote(field), unquote(value)))

      assert ETS.read(hash) == before
      assert {:ok, _} = AuthorizationCode.redeem(ETS, code, @params)
    end

    test "a wrong #{field} cannot contain a pending or finalized redemption" do
      for phase <- [:pending, :finalized] do
        {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
        {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
        hash = Secret.hash(code)
        jti = Secret.generate()
        :ok = ETS.record_access_token_for_code(hash, jti, System.system_time(:second) + 600)
        issued = if phase == :finalized, do: finalize(code, grant)
        before = ETS.read(hash)

        assert {:error, unquote(reason)} =
                 AuthorizationCode.redeem(ETS, code, Map.put(@params, unquote(field), unquote(value)))

        assert ETS.read(hash) == before
        assert {:ok, %{revoked: false}} = ETS.read(hash)
        issued = issued || finalize(code, grant)
        refute ETS.access_token_revoked?(jti)
        assert {:ok, _} = RefreshToken.rotate(RefreshStore, issued.token, client_id: "client")
      end
    end
  end

  test "a matching pending replay contains the family created at finalization" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
    hash = Secret.hash(code)
    :ok = ETS.record_access_token_for_code(hash, "matching-jti", System.system_time(:second) + 600)
    assert {:error, :invalid_grant} = AuthorizationCode.redeem(ETS, code, @params)
    issued = finalize(code, grant)
    assert ETS.access_token_revoked?("matching-jti")
    assert {:error, _} = RefreshToken.rotate(RefreshStore, issued.token, client_id: "client")
  end

  test "reads and failed claims do not flag a replay" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, _} = AuthorizationCode.redeem(ETS, code, @params)
    hash = Secret.hash(code)
    assert {:ok, %{state: :claimed, data: data, revoked: false}} = ETS.read(hash)
    assert Map.take(data, Map.keys(@attrs)) == @attrs
    assert :error = ETS.claim(hash)
    assert {:ok, %{revoked: false}} = ETS.read(hash)
  end

  test "a replay flag losing to finish rereads the redemption" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
    issued = finalize(code, grant)
    assert :error = ETS.flag_replay(Secret.hash(code))
    family = issued.family_id
    assert {:error, {:reuse, %{family_id: ^family}}} = AuthorizationCode.redeem(ETS, code, @params)
    assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, @params, now: System.system_time(:second) + 600)
  end

  test "an unchallenged consumed code compares client and redirect without a verifier" do
    {:ok, code} = AuthorizationCode.issue(ETS, %{@attrs | code_challenge: nil, dpop_jkt: nil})
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, Map.drop(@params, [:code_verifier, :dpop_jkt]))
    :ok = AuthorizationCode.finalize(ETS, code, grant)
    assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, Map.delete(@params, :code_verifier))
    assert {:error, :client_mismatch} = AuthorizationCode.redeem(ETS, code, %{@params | client_id: "other"})
  end

  test "racing presentations redeem once and a wrong client cannot win" do
    for second <- [@params, %{@params | client_id: "other"}] do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
      parent = self()

      tasks =
        for params <- [@params, second] do
          Task.async(fn ->
            send(parent, {:ready, self()})

            receive do
              :go -> AuthorizationCode.redeem(ETS, code, params)
            end
          end)
        end

      assert_receive {:ready, first}
      assert_receive {:ready, second_pid}
      send(first, :go)
      send(second_pid, :go)
      results = Task.await_many(tasks)
      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      if second.client_id == "other", do: assert(match?({:ok, _}, hd(results)))
    end
  end

  test "expiry refuses only live codes and failed comparisons remain non-writing after expiry" do
    now = System.system_time(:second)

    for phase <- [:live, :claimed, :redeemed] do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs, now: now, ttl: 1)

      if phase != :live do
        {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params, now: now)
        if phase == :redeemed, do: AuthorizationCode.finalize(ETS, code, grant)
      end

      hash = Secret.hash(code)
      before = ETS.read(hash)

      assert {:error, :client_mismatch} =
               AuthorizationCode.redeem(ETS, code, %{@params | client_id: "other"}, now: now + 2)

      assert ETS.read(hash) == before

      case phase do
        :live ->
          assert {:error, :expired} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
          assert ETS.read(hash) == before

        :claimed ->
          assert {:error, :invalid_grant} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
          assert {:ok, %{revoked: true}} = ETS.read(hash)

        :redeemed ->
          assert {:error, {:reuse, _}} = AuthorizationCode.redeem(ETS, code, @params, now: now + 2)
      end
    end
  end

  test "failed transitions stop after three rereads in live and claimed states" do
    for phase <- [:live, :claimed] do
      {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
      if phase == :claimed, do: :ok = ETS.claim(Secret.hash(code))
      Process.put(:stalled_reads, 0)

      assert_raise RuntimeError, ~r/contract/, fn ->
        AuthorizationCode.redeem(StalledStore, code, @params)
      end

      assert Process.get(:stalled_reads) == 4
    end
  end

  test "a deleted claim revokes the just-issued family and requests access-link revocation" do
    {:ok, code} = AuthorizationCode.issue(ETS, @attrs)
    {:ok, grant} = AuthorizationCode.redeem(ETS, code, @params)
    hash = Secret.hash(code)

    assert {:error, :invalid_grant} =
             AuthorizationCode.issue_refresh_and_finalize(
               DeletedClaimStore,
               code,
               grant,
               ObservedRefreshStore,
               %{client_id: "client", subject: "subject", scope: [], resource: []}
             )

    assert_received {:issued_refresh, record}
    assert :error = RefreshStore.get(record.token_hash)
    assert_received {:revoked_missing_link, ^hash}
    assert :error = ETS.read(hash)
  end

  test "a verifier on an unchallenged code fails without writing in every state" do
    for phase <- [:live, :claimed, :redeemed] do
      {:ok, code} = AuthorizationCode.issue(ETS, %{@attrs | code_challenge: nil})
      hash = Secret.hash(code)

      if phase != :live do
        {:ok, grant} = AuthorizationCode.redeem(ETS, code, Map.delete(@params, :code_verifier))
        if phase == :redeemed, do: AuthorizationCode.finalize(ETS, code, grant)
      end

      before = ETS.read(hash)
      assert {:error, :pkce_failed} = AuthorizationCode.redeem(ETS, code, @params)
      assert ETS.read(hash) == before
    end
  end

  defp finalize(code, grant) do
    assert {:ok, issued} =
             AuthorizationCode.issue_refresh_and_finalize(ETS, code, grant, RefreshStore, %{
               client_id: "client",
               subject: "subject",
               scope: [],
               resource: []
             })

    issued
  end
end
