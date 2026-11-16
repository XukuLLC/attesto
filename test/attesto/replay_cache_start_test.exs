defmodule Attesto.DPoP.ReplayCacheStartTest do
  use ExUnit.Case, async: false

  alias Attesto.DPoP.ReplayCache

  test "an isolated node still requires an explicit single-node statement" do
    assert Node.list() == []

    for {opts, cause} <- [
          {[], "without single_node?: true"},
          {[single_node?: false], "without single_node?: true"},
          {[single_node?: nil], "without single_node?: true"},
          {[single_node?: "true"], "without single_node?: true"},
          {[multi_node_acknowledged?: true], "does not accept :multi_node_acknowledged?"},
          {[single_node?: true, multi_node_acknowledged?: true], "does not accept :multi_node_acknowledged?"}
        ] do
      assert {:error, {%ArgumentError{message: message}, _}} = GenServer.start(ReplayCache, opts)
      assert message =~ cause
      assert message =~ "single_node?: true"
      assert message =~ "AttestoPhoenix.Store.EctoReplayCheck"
      assert :ets.whereis(ReplayCache) == :undefined
    end
  end

  test "the explicit single-node cache rejects replay" do
    start_supervised!({ReplayCache, single_node?: true})
    assert :ok = ReplayCache.check_and_record("proof", 60)
    assert {:error, :replay} = ReplayCache.check_and_record("proof", 60)
  end
end
