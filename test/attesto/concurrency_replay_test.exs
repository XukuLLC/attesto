defmodule Attesto.ConcurrencyReplayTest do
  @moduledoc false
  # Targeted races against the expiry boundary of the DPoP replay cache.
  #
  # `Attesto.ConcurrencySwarmTest` floods the *happy* CAS: a fresh jti seen
  # by N racers at once must admit exactly one winner. This suite drives the
  # harder, easily-overlooked branch in `ReplayCache.check_and_record/2`
  # (replay_cache.ex lines 114-125): the `:ets.insert_new/2` lost, the entry
  # already exists, AND it has just expired. There the cache *replaces* the
  # stale row and accepts (lines 118-121) instead of reporting :replay. That
  # replace-on-expiry path is the only way a previously-seen jti is ever
  # re-admitted, so its concurrency and its TTL semantics both need proof:
  #
  #   1. Expiry-boundary swap race - many racers hit a jti that expired
  #      mid-swarm. The branch is a read-then-write (lookup, then insert),
  #      NOT an atomic insert_new, so the invariant is weaker than the happy
  #      path: at most one racer may take the replace-and-accept path. We
  #      prove no two racers both replace-and-accept, i.e. an expired jti is
  #      never re-admitted more than once by a single contended swap.
  #
  #   2. TTL re-use after expiry - a jti recorded with ttl_seconds: 1, then
  #      flooded (all :replay within the window), is re-insertable once the
  #      TTL has actually elapsed. This is the user-visible contract the
  #      replay_cache contract encodes: a jti is forgotten after its TTL.
  #
  # The cache is a named ETS-backed GenServer singleton; starting it mutates
  # VM-global state and the table is shared, so this suite is async: false
  # and resets the table between tests.
  use ExUnit.Case, async: false

  alias Attesto.DPoP.ReplayCache

  @swarm 50
  @await_ms 5_000

  setup do
    start_supervised!({ReplayCache, multi_node_acknowledged?: true})
    # The table is a named singleton; clear any carryover so size/0 counts
    # only what this test inserts.
    ReplayCache.reset()
    :ok
  end

  defp swarm(n, fun) do
    1..n
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(@await_ms)
  end

  describe "expiry-boundary swap race: flooded re-record of a just-expired jti" do
    # Regression test for the expired-entry race: the cache used to look up
    # and then overwrite expired rows non-atomically, allowing multiple
    # concurrent re-admissions of the same just-expired jti.
    test "at most one racer replaces-and-accepts an expired jti; the rest see :replay" do
      jti = "expiry-swap-#{System.unique_integer([:positive])}"

      # Plant the jti with the smallest possible TTL, then let it lapse. The
      # row is still present (the 30s sweeper has not run), so every racer
      # below will lose insert_new/2 and contend for the expired-entry
      # replacement path.
      assert :ok = ReplayCache.check_and_record(jti, 1)
      Process.sleep(1_100)

      # Re-record the SAME, now-expired jti from a swarm. The contract we
      # hold the impl to: a single expired entry is re-admitted AT MOST once.
      # No two racers may both take the replace-and-accept path; the rest,
      # once any racer has refreshed the row to a future expiry, must report
      # :replay.
      results = swarm(@swarm, fn -> ReplayCache.check_and_record(jti, 60) end)

      assert length(results) == @swarm

      accepts = Enum.count(results, &(&1 == :ok))
      replays = Enum.count(results, &(&1 == {:error, :replay}))

      assert Enum.all?(results, &(&1 == :ok or &1 == {:error, :replay})),
             "every result must be :ok or {:error, :replay}; got #{inspect(results)}"

      assert accepts == 1,
             "an expired jti must be re-admitted exactly once under contention; got #{accepts} accepts"

      assert replays == @swarm - 1,
             "every other racer must see the refreshed entry as :replay; got #{replays} replays"

      # The jti is now live again on a 60s TTL. A further check_and_record
      # must be a plain :replay - the swap window has closed, so no second
      # replace-and-accept can occur.
      assert {:error, :replay} = ReplayCache.check_and_record(jti, 60),
             "a jti refreshed to a future expiry must reject immediately as :replay"

      # The swarm collided on one identity: exactly one row survives.
      assert ReplayCache.size() == 1
    end

    test "a jti still inside its TTL is never re-admitted by a concurrent swarm" do
      # Control for the test above: with the entry NOT expired, the lookup
      # branch's `prior_expires_ms < now_ms` guard is false for everyone, so
      # the replace-and-accept path is unreachable. The first racer wins via
      # insert_new/2; every other racer - whether it loses insert_new or
      # reads the live row - must report :replay. Zero swaps.
      jti = "live-no-swap-#{System.unique_integer([:positive])}"

      results = swarm(@swarm, fn -> ReplayCache.check_and_record(jti, 60) end)

      assert length(results) == @swarm

      accepts = Enum.count(results, &(&1 == :ok))

      assert accepts == 1,
             "a fresh jti admits exactly one winner; got #{accepts} accepts"

      assert Enum.count(results, &(&1 == {:error, :replay})) == @swarm - 1,
             "every loser on a live jti must be :replay; got #{inspect(results)}"

      assert ReplayCache.size() == 1
    end
  end

  describe "TTL boundary: re-use of a jti after its TTL elapses" do
    test "a jti flooded within ttl_seconds: 1 is all-replay, then re-insertable once expired" do
      jti = "ttl-reuse-#{System.unique_integer([:positive])}"

      # First record wins; the jti is now remembered for ~1 second.
      assert :ok = ReplayCache.check_and_record(jti, 1)

      # Flood the SAME jti while it is still well inside its 1s window. Every
      # racer must see it as already-seen: the entry is live, so neither the
      # insert_new winner nor the expiry-swap branch is reachable.
      within_window = swarm(@swarm, fn -> ReplayCache.check_and_record(jti, 1) end)

      assert Enum.all?(within_window, &(&1 == {:error, :replay})),
             "every re-record inside the TTL window must be :replay; got #{inspect(within_window)}"

      # Let the TTL fully elapse (1s ttl + margin for monotonic-clock skew
      # and scheduler latency). The entry is now logically expired; the row
      # may or may not have been swept, but either way the next record must
      # succeed - eviction-via-sweep OR replace-on-expiry both re-admit it.
      Process.sleep(1_200)

      assert :ok = ReplayCache.check_and_record(jti, 1),
             "a jti must be re-insertable once its TTL has elapsed"

      # And it is once again single-use: an immediate re-record is :replay
      # on the freshly-recorded entry.
      assert {:error, :replay} = ReplayCache.check_and_record(jti, 1),
             "the re-recorded jti must again reject as :replay within its new window"
    end
  end

  describe "live-entry retention under unique-identity floods" do
    test "a flood never evicts a still-live replay identity" do
      victim = "retained-victim-#{System.unique_integer([:positive])}"
      assert :ok = ReplayCache.check_and_record(victim, 60)

      for index <- 1..5_000 do
        assert :ok = ReplayCache.check_and_record("flood-#{index}-#{victim}", 60)
      end

      assert {:error, :replay} = ReplayCache.check_and_record(victim, 60)
      assert ReplayCache.size() == 5_001
    end
  end
end
