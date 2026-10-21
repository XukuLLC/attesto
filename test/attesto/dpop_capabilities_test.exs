defmodule Attesto.DPoPCapabilitiesTest do
  use ExUnit.Case, async: false

  alias Attesto.DPoP

  setup do
    previous_fallback = JOSE.crypto_fallback()
    previous_snapshot = :persistent_term.get({DPoP, :jws_capabilities, 1}, :uncached)
    :ok = DPoP.clear_allowed_algs_cache()
    DPoP.allowed_algs()

    on_exit(fn ->
      :erlang.trace_pattern({:jose_jwa, :supports, 0}, false, [:call_count])
      if JOSE.JWA in :meck.mocked(), do: :meck.unload(JOSE.JWA)
      JOSE.crypto_fallback(previous_fallback)
      DPoP.clear_allowed_algs_cache()

      if previous_snapshot != :uncached,
        do: :persistent_term.put({DPoP, :jws_capabilities, 1}, previous_snapshot)
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

  test "empty and symmetric-only discovery refuse an unprimed snapshot" do
    :ok = :meck.new(JOSE.JWA, [:passthrough, :no_link])

    for algorithms <- [[], ["HS256", "none"]] do
      :meck.expect(JOSE.JWA, :supports, fn -> [jws: {:alg, algorithms}] end)
      assert {:error, :no_supported_algorithms} = DPoP.prime_allowed_algs()
      assert :uncached = :persistent_term.get({DPoP, :jws_capabilities, 1}, :uncached)
      assert DPoP.allowed_algs() == []
    end
  end

  test "failed re-priming erases an existing snapshot" do
    :ok = :meck.new(JOSE.JWA, [:passthrough, :no_link])

    for failure <- [:empty, :symmetric, :malformed, :exception] do
      :meck.expect(JOSE.JWA, :supports, fn -> [jws: {:alg, ["ES256"]}] end)
      assert :ok = DPoP.prime_allowed_algs()
      assert DPoP.allowed_algs() == ["ES256"]

      :meck.expect(JOSE.JWA, :supports, fn ->
        case failure do
          :empty -> [jws: {:alg, []}]
          :symmetric -> [jws: {:alg, ["HS256", "none"]}]
          :malformed -> [jws: {:alg, :unavailable}]
          :exception -> :meck.exception(:error, :discovery_failed)
        end
      end)

      assert {:error, :no_supported_algorithms} = DPoP.prime_allowed_algs()
      assert :uncached = :persistent_term.get({DPoP, :jws_capabilities, 1}, :uncached)
      assert DPoP.allowed_algs() == []
    end
  end

  test "a primed snapshot survives a backend change until clearing and re-priming" do
    :ok = :meck.new(JOSE.JWA, [:passthrough, :no_link])

    :meck.expect(JOSE.JWA, :supports, fn ->
      algorithms = if JOSE.crypto_fallback(), do: ["RS256"], else: ["ES256"]
      [jws: {:alg, algorithms}]
    end)

    JOSE.crypto_fallback(false)
    assert :ok = DPoP.prime_allowed_algs()
    JOSE.crypto_fallback(true)
    assert DPoP.allowed_algs() == ["ES256"]
    assert :meck.num_calls(JOSE.JWA, :supports, []) == 1
    assert :ok = DPoP.clear_allowed_algs_cache()
    assert DPoP.allowed_algs() == ["RS256"]
    assert :ok = DPoP.prime_allowed_algs()
    assert ["RS256"] = :persistent_term.get({DPoP, :jws_capabilities, 1})
    assert DPoP.allowed_algs() == ["RS256"]
  end
end
