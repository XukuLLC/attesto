defmodule Attesto.PreAuthorizedCodeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.PreAuthorizedCode
  alias Attesto.PreAuthorizedCodeStore.ETS
  alias Attesto.PreAuthorizedCodeStore.ETS, as: Store
  alias Attesto.Secret

  @now 1_000
  @racers 25

  defmodule ContractStore do
    @moduledoc false
    @behaviour Attesto.PreAuthorizedCodeStore

    @impl true
    def put(record), do: ETS.put(record)

    @impl true
    def take(code_hash) do
      result = ETS.take(code_hash)

      case Process.get({__MODULE__, :take}) do
        nil -> result
        {:return, value} -> value
        {:mutate_ok, mutator} -> mutate_ok(result, mutator)
      end
    end

    @impl true
    def get(code_hash), do: ETS.get(code_hash)

    defp mutate_ok({:ok, record}, mutator), do: {:ok, mutator.(record)}
    defp mutate_ok(other, _mutator), do: other
  end

  setup do
    start_supervised!(Store)
    :ok
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        subject: "usr_42",
        credential_configuration_ids: ["UniversityDegree_JWT"],
        authorized_scopes: ["openid"]
      },
      overrides
    )
  end

  defp race(fun) do
    1..@racers
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(5_000)
  end

  defp fault_take(mode) do
    Process.put({ContractStore, :take}, mode)
  end

  defp clear_take_fault do
    Process.delete({ContractStore, :take})
  end

  test "issue then redeem returns the bound grant context" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    assert {:ok, grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)

    assert grant == %{
             subject: "usr_42",
             credential_configuration_ids: ["UniversityDegree_JWT"],
             authorized_scopes: ["openid"]
           }
  end

  test "a code can be redeemed only once" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
    assert {:error, :invalid_grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "an expired code returns expired" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), ttl: 1, now: @now)

    assert {:error, :expired} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now + 1)
  end

  test "an invalid clock is rejected before a one-time code is consumed" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    for invalid_now <- [-1, 1.5, "now"] do
      assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
        PreAuthorizedCode.redeem(Store, code, %{}, now: invalid_now)
      end
    end

    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "invalid lifetime and malformed scope fail before storage" do
    for invalid_ttl <- [0, -1, 1.0, "60", nil] do
      assert_raise ArgumentError, ~r/:ttl must be a positive integer/, fn ->
        PreAuthorizedCode.issue(Store, attrs(), ttl: invalid_ttl, now: @now)
      end
    end

    for invalid_scopes <- [[""], ["openid profile"], ["openid", :profile]] do
      assert {:error, :invalid_attrs} =
               PreAuthorizedCode.issue(Store, attrs(%{authorized_scopes: invalid_scopes}), now: @now)
    end

    assert :ets.tab2list(Store) == []
  end

  test "a matching transaction code redeems successfully" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "a bound transaction code is required" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_required} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "a wrong transaction code mismatches" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_mismatch} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "4321"}, now: @now)
  end

  test "an unexpected transaction code is rejected" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    assert {:error, :tx_code_unexpected} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "the plaintext transaction code is never stored" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:ok, %{data: data}} = Store.get(Secret.hash(code))
    refute Map.has_key?(data, :tx_code)
    refute "1234" in Map.values(data)
    assert data.tx_code_hash == Secret.hash("1234")
  end

  test "an unknown code returns invalid grant" do
    assert {:error, :invalid_grant} = PreAuthorizedCode.redeem(Store, Secret.generate(), %{}, now: @now)
  end

  test "take rejects partial, malformed, and materially changed consumed records" do
    mutations = [
      fn record -> Map.delete(record, :code_hash) end,
      fn record -> Map.put(record, :code_hash, "private-hash-sentinel") end,
      fn record -> update_in(record.data, &Map.delete(&1, :subject)) end,
      fn record -> put_in(record, [:data, :subject], "") end,
      fn record -> put_in(record, [:data, :credential_configuration_ids], []) end,
      fn record -> put_in(record, [:data, :authorized_scopes], ["openid", 7]) end,
      fn record -> Map.put(record, :expires_at, "private-expiry-sentinel") end
    ]

    for mutate <- mutations do
      {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
      fault_take({:mutate_ok, mutate})

      error =
        assert_raise RuntimeError, "pre-authorized code store take/1 violated its contract", fn ->
          PreAuthorizedCode.redeem(ContractStore, code, %{}, now: @now)
        end

      refute Exception.message(error) =~ "private-"
      clear_take_fault()

      assert {:error, :invalid_grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
    end
  end

  test "take rejects a malformed transaction-code hash and an unexpected callback outcome" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)
    fault_take({:mutate_ok, fn record -> put_in(record, [:data, :tx_code_hash], {:private, code}) end})

    error =
      assert_raise RuntimeError, "pre-authorized code store take/1 violated its contract", fn ->
        PreAuthorizedCode.redeem(ContractStore, code, %{tx_code: "1234"}, now: @now)
      end

    refute Exception.message(error) =~ code
    clear_take_fault()

    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
    fault_take({:return, {:error, {:private_take_sentinel, code}}})

    error =
      assert_raise RuntimeError, "pre-authorized code store take/1 violated its contract", fn ->
        PreAuthorizedCode.redeem(ContractStore, code, %{}, now: @now)
      end

    refute Exception.message(error) =~ code
  end

  test "an empty authorized scope list remains valid" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{authorized_scopes: []}), now: @now)

    assert {:ok, %{authorized_scopes: []}} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "invalid attrs return invalid attrs" do
    assert {:error, :invalid_attrs} =
             PreAuthorizedCode.issue(Store, attrs() |> Map.delete(:subject), now: @now)

    assert {:error, :invalid_attrs} =
             PreAuthorizedCode.issue(Store, attrs(%{credential_configuration_ids: []}), now: @now)
  end

  test "a failed transaction-code check burns the code" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_mismatch} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "4321"}, now: @now)

    assert {:error, :invalid_grant} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "the underlying ETS table is :protected: only the owner process can write it" do
    assert :protected == :ets.info(Store, :protection)

    # A forged row inserted by any OTHER process (not the store's owner
    # GenServer) must fail outright - a co-resident process must not be able
    # to plant a redeemable pre-authorized-code grant.
    parent = self()

    spawn(fn ->
      result =
        try do
          :ets.insert(Store, {"forged", System.system_time(:second) + 60, %{forged: true}})
          :inserted
        rescue
          ArgumentError -> :rejected
        end

      send(parent, {:forged_insert, result})
    end)

    assert_receive {:forged_insert, :rejected}
    assert :error = Store.take(Secret.hash("forged-code"))

    # The store's own API still works: `put/1`/`take/1`/`reset/0` are routed
    # through the owner process, so they succeed despite the table being
    # :protected (reset via `:ets.delete_all_objects` from a foreign process
    # would raise on a :protected table — the `reset: :server` macro option).
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)

    {:ok, _} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
    assert :ok = Store.reset()
  end

  test "exactly one of 25 simultaneous redemptions wins" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    results = race(fn -> PreAuthorizedCode.redeem(Store, code, %{}, now: @now) end)

    winners = Enum.count(results, &match?({:ok, _}, &1))
    losers = Enum.count(results, &(&1 == {:error, :invalid_grant}))

    assert winners == 1
    assert losers == @racers - 1
  end
end
