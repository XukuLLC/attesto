defmodule Attesto.StatusListStoreTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.StatusList
  alias Attesto.StatusListStore
  alias Attesto.StatusListStore.ETS, as: Store

  @racers 50

  setup do
    start_supervised!(Store)
    :ok
  end

  test "declares and implements the status-list store behaviour" do
    behaviours =
      Store.module_info(:attributes)
      |> Keyword.get_values(:behaviour)
      |> List.flatten()

    assert StatusListStore in behaviours
    assert function_exported?(Store, :allocate, 1)
    assert function_exported?(Store, :set_status, 3)
    assert function_exported?(Store, :statuses, 1)
    assert function_exported?(Store, :get_status, 2)
  end

  test "allocate returns distinct monotonic indices per URI" do
    uri = "https://issuer.example/statuslists/monotonic"

    assert {:ok, 0} = Store.allocate(uri)
    assert {:ok, 1} = Store.allocate(uri)
    assert {:ok, 2} = Store.allocate(uri)
    assert {:ok, 0} = Store.allocate(uri <> "/other")
    assert Store.statuses(uri) == [0, 0, 0]
  end

  test "set_status and get_status reflect allocated indices" do
    uri = "https://issuer.example/statuslists/read-write"
    assert {:ok, 0} = Store.allocate(uri)
    assert {:ok, 1} = Store.allocate(uri)

    assert :ok = Store.set_status(uri, 1, 1)
    assert {:ok, 0} = Store.get_status(uri, 0)
    assert {:ok, 1} = Store.get_status(uri, 1)
    assert Store.statuses(uri) == [0, 1]
  end

  test "set_status rejects an index that was never allocated" do
    uri = "https://issuer.example/statuslists/unallocated"
    assert {:ok, 0} = Store.allocate(uri)

    assert :error = Store.set_status(uri, 1, 1)
    assert :error = Store.set_status(uri <> "/unknown", 0, 1)
    assert :error = Store.get_status(uri, 1)
    assert Store.statuses(uri) == [0]
  end

  test "statuses is dense and feeds StatusList pack and build" do
    uri = "https://issuer.example/statuslists/dense"

    for expected <- 0..4 do
      assert {:ok, ^expected} = Store.allocate(uri)
    end

    assert :ok = Store.set_status(uri, 2, 1)
    statuses = Store.statuses(uri)
    packed = StatusList.pack(statuses, 1)

    assert statuses == [0, 0, 1, 0, 0]
    assert StatusList.status_at(packed, 1, 0) == 0
    assert StatusList.status_at(packed, 1, 2) == 1
    assert StatusList.status_at(packed, 1, 4) == 0
    assert %{"bits" => 1, "lst" => encoded} = StatusList.build(statuses)
    assert is_binary(encoded) and encoded != ""
  end

  test "concurrent allocations for one URI return distinct indices" do
    uri = "https://issuer.example/statuslists/concurrent"

    indices =
      1..@racers
      |> Enum.map(fn _ -> Task.async(fn -> Store.allocate(uri) end) end)
      |> Task.await_many(5_000)
      |> Enum.map(fn {:ok, idx} -> idx end)

    assert Enum.sort(indices) == Enum.to_list(0..(@racers - 1))
    assert length(Enum.uniq(indices)) == @racers
    assert length(Store.statuses(uri)) == @racers
  end
end
