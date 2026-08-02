defmodule Attesto.ReplayCacheContract do
  @moduledoc false
  # Reusable conformance suite for any DPoP replay-check callback.
  #
  # Unlike `Attesto.CodeStoreContract` / `Attesto.RefreshStoreContract`,
  # the thing under test here is NOT a behaviour module with named
  # functions - it is a *callback value*. `Attesto.DPoP.verify_proof/2`
  # accepts `:replay_check` as any `(jti, ttl_seconds) -> :ok |
  # {:error, :replay}` fun (RFC 9449 §11.1 lets a deployment swap the
  # node-local `Attesto.DPoP.ReplayCache` ETS singleton for a shared store
  # - Postgres `INSERT ... ON CONFLICT DO NOTHING`, Redis `SET NX PX`, etc.
  # - so that replay rejection holds across the whole deployment, not just
  # per node). This contract pins the invariants every such replacement
  # must satisfy, so the ETS reference today and a SQL-backed store
  # tomorrow are held to the identical record-once / reject-replay /
  # expire-and-readmit guarantees that DPoP proof-replay defence rests on.
  #
  # ## Options
  #
  #   * `:check` (required) - a 0-arity fun returning the
  #     `(jti, ttl_seconds) -> :ok | {:error, :replay}` callback under
  #     test, freshly resolved inside each test (so it observes the state
  #     started by `:start`). For the ETS reference this is simply
  #     `fn -> &Attesto.DPoP.ReplayCache.check_and_record/2 end`.
  #   * `:start` (optional) - a 0-arity fun that starts whatever backing
  #     state the callback needs (a GenServer, a connection, a fresh table)
  #     and returns its pid (or anything; the return is ignored). When
  #     omitted, no setup is run - use this only for a stateless callback
  #     that needs none.
  #
  # The reference implementation is a named singleton GenServer over a
  # VM-global ETS table, so the host case MUST be
  # `use ExUnit.Case, async: false`.
  #
  #     defmodule MyReplayCheckContractTest do
  #       use ExUnit.Case, async: false
  #
  #       use Attesto.ReplayCacheContract,
  #         start: fn ->
  #           start_supervised!(
  #             {Attesto.DPoP.ReplayCache, multi_node_acknowledged?: true}
  #           )
  #         end,
  #         check: fn -> &Attesto.DPoP.ReplayCache.check_and_record/2 end
  #     end
  #
  # ## On the TTL-expiry test
  #
  # The expiry invariant (a `jti` whose TTL has elapsed is re-admittable)
  # is the gap this contract closes versus the pre-existing
  # `dpop_test.exs` coverage, which only exercised same-process replay
  # within the window. The expiry test passes `ttl_seconds: 1` and sleeps
  # past it in real time; `Attesto.DPoP.ReplayCache` keys expiry off
  # `System.monotonic_time/1`, so wall-clock sleeping advances it. It is
  # tagged `:slow` so a fast inner loop can exclude it; a backing store
  # whose smallest practical TTL is coarser than one second can also
  # exclude it and assert expiry by its own clock.

  defmacro __using__(opts) do
    check = Keyword.fetch!(opts, :check)
    start = Keyword.get(opts, :start)

    start_call =
      if start,
        do: quote(do: unquote(start).()),
        else: quote(do: :ok)

    quote do
      @contract_check unquote(check)

      setup do
        unquote(start_call)
        :ok
      end

      # A `jti` no other test will collide with. Replay defence keys on the
      # exact `jti` string, so uniqueness per test keeps the shared backing
      # store from leaking state between cases.
      defp contract_jti(label) do
        "contract-#{label}-#{System.unique_integer([:positive])}"
      end

      # The default TTL most tests use: long enough that nothing expires
      # mid-test, short enough that a leaked entry sweeps out promptly.
      @contract_ttl 60

      test "first record of a jti returns :ok" do
        check = @contract_check.()

        assert :ok = check.(contract_jti("first"), @contract_ttl)
      end

      test "a second record of the same jti within TTL is {:error, :replay}" do
        check = @contract_check.()
        jti = contract_jti("replay")

        assert :ok = check.(jti, @contract_ttl)
        assert {:error, :replay} = check.(jti, @contract_ttl)
      end

      test "a third record of the same jti stays {:error, :replay} (rejection is stable)" do
        check = @contract_check.()
        jti = contract_jti("stable")

        assert :ok = check.(jti, @contract_ttl)
        assert {:error, :replay} = check.(jti, @contract_ttl)
        assert {:error, :replay} = check.(jti, @contract_ttl)
      end

      test "distinct jtis are recorded independently and each first-seen returns :ok" do
        check = @contract_check.()
        a = contract_jti("indep-a")
        b = contract_jti("indep-b")
        c = contract_jti("indep-c")

        assert :ok = check.(a, @contract_ttl)
        assert :ok = check.(b, @contract_ttl)
        assert :ok = check.(c, @contract_ttl)

        # Recording one does not poison the others, and replay is per-jti.
        assert {:error, :replay} = check.(a, @contract_ttl)
        assert {:error, :replay} = check.(b, @contract_ttl)
        assert {:error, :replay} = check.(c, @contract_ttl)
      end

      test "a recorded jti does not cause a false positive for a different jti" do
        # A naive store that, say, recorded a prefix or a truncated hash
        # could collide distinct jtis. Two jtis sharing a long common
        # prefix must still be treated as distinct.
        check = @contract_check.()
        n = System.unique_integer([:positive])
        shared = "contract-prefix-#{n}-"

        assert :ok = check.(shared <> "left", @contract_ttl)
        assert :ok = check.(shared <> "right", @contract_ttl)
      end

      @tag :slow
      test "a jti whose TTL has elapsed is re-admittable (expire then re-insert returns :ok)" do
        # The RFC 9449 §11.1 invariant the older dpop_test.exs did not
        # cover: replay defence is bounded by the proof's freshness window,
        # not forever. Once a jti's TTL lapses the store MUST forget it, so
        # a fresh proof that happens to mint the same jti is admitted (and
        # immediately re-defended for its own window). An over-eager store
        # that never expires would reject legitimate later proofs.
        check = @contract_check.()
        jti = contract_jti("expiring")
        ttl_seconds = 1

        assert :ok = check.(jti, ttl_seconds)
        # Still within the window: the replay is rejected.
        assert {:error, :replay} = check.(jti, ttl_seconds)

        # Sleep past the TTL (plus margin for the sweep/lazy-expiry edge).
        Process.sleep(ttl_seconds * 1_000 + 250)

        # The window has closed: the same jti is admitted again...
        assert :ok = check.(jti, ttl_seconds)
        # ...and is once more defended within its renewed window.
        assert {:error, :replay} = check.(jti, ttl_seconds)
      end

      @tag :slow
      test "an expired jti does not cause a false :replay for an unrelated jti" do
        # Expiry must evict, not merely hide: after one jti's window closes,
        # an entirely different jti is still seen for the first time as :ok.
        check = @contract_check.()
        expiring = contract_jti("evict-expiring")
        fresh = contract_jti("evict-fresh")
        ttl_seconds = 1

        assert :ok = check.(expiring, ttl_seconds)
        Process.sleep(ttl_seconds * 1_000 + 250)

        assert :ok = check.(fresh, @contract_ttl)
        assert {:error, :replay} = check.(fresh, @contract_ttl)
      end
    end
  end
end
