defmodule Attesto.DPoPCapabilitiesTest do
  use ExUnit.Case, async: false

  alias Attesto.DPoP

  setup do
    :ok = DPoP.clear_allowed_algs_cache()
    DPoP.allowed_algs()

    on_exit(fn ->
      :erlang.trace_pattern({:jose_jwa, :supports, 0}, false, [:call_count])
      DPoP.clear_allowed_algs_cache()
    end)

    :ok
  end

  test "priming preserves the exact algorithm set and avoids repeated discovery" do
    expected = DPoP.allowed_algs()
    :erlang.trace_pattern({:jose_jwa, :supports, 0}, true, [:call_count])

    assert :ok = DPoP.prime_allowed_algs()
    for _ <- 1..100, do: assert(DPoP.allowed_algs() == expected)
    assert {:call_count, 1} = :erlang.trace_info({:jose_jwa, :supports, 0}, :call_count)
    refute Enum.any?(DPoP.allowed_algs(), &(&1 == "none" or String.starts_with?(&1, "HS")))
  end

  test "clearing resumes capability discovery rather than retaining the snapshot" do
    expected = DPoP.allowed_algs()
    assert :ok = DPoP.prime_allowed_algs()
    assert :ok = DPoP.clear_allowed_algs_cache()
    :erlang.trace_pattern({:jose_jwa, :supports, 0}, true, [:call_count])

    assert DPoP.allowed_algs() == expected
    assert DPoP.allowed_algs() == expected
    assert {:call_count, 2} = :erlang.trace_info({:jose_jwa, :supports, 0}, :call_count)
    assert :ok = DPoP.clear_allowed_algs_cache()
  end
end
