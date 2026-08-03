defmodule Attesto.CNonceStoreTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.CNonceStore
  alias Attesto.CNonceStore.ETS, as: Store

  setup do
    start_supervised!(Store)
    :ok
  end

  test "declares and implements the c_nonce store behaviour" do
    behaviours =
      Store.module_info(:attributes)
      |> Keyword.get_values(:behaviour)
      |> List.flatten()

    assert CNonceStore in behaviours
    assert function_exported?(Store, :issue, 1)
    assert function_exported?(Store, :valid?, 1)
  end

  test "issue returns a nonce that is valid" do
    nonce = Store.issue(60)

    assert is_binary(nonce)
    assert Store.valid?(nonce)
  end

  test "an unknown nonce is not valid" do
    refute Store.valid?("never-issued-by-this-store")
  end

  test "validating a nonce does not consume it" do
    nonce = Store.issue(60)

    assert Store.valid?(nonce)
    assert Store.valid?(nonce)
  end

  test "an expired nonce is not valid" do
    nonce = Store.issue(1)
    assert Store.valid?(nonce)

    issued_at = System.system_time(:second)
    wait_until_clock_passes(issued_at + 1)

    refute Store.valid?(nonce)
  end

  defp wait_until_clock_passes(target) do
    if System.system_time(:second) > target do
      :ok
    else
      wait_until_clock_passes(target)
    end
  end
end
