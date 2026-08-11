defmodule Attesto.PreAuthorizedCodeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.PreAuthorizedCode
  alias Attesto.PreAuthorizedCodeStore.ETS, as: Store
  alias Attesto.Secret

  @now 1_000
  @racers 25

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
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), ttl: 0, now: @now)

    assert {:error, :expired} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
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
