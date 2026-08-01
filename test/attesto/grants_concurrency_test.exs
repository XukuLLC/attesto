defmodule Attesto.GrantsConcurrencyTest do
  @moduledoc false
  # Live concurrency tests: hammer the atomic single-use / claim primitives
  # with many simultaneous redemptions/rotations of the SAME credential and
  # assert the safety invariant - at most one winner - holds. These are the
  # tests that catch a non-atomic store (the class of bug that lets a
  # captured code/token be used twice).
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.CodeStore
  alias Attesto.GrantsConcurrencyTest.RecordingStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken

  @verifier "concurrency-verifier-unreserved.chars_aaaaaaaaaaaa~0"
  @racers 25

  setup do
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp race(fun) do
    1..@racers
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(5_000)
  end

  describe "authorization code single-use under concurrency" do
    test "exactly one of many simultaneous redemptions of one code wins", %{challenge: challenge} do
      {:ok, code} =
        AuthorizationCode.issue(CodeStore.ETS, %{
          client_id: "oc_app",
          redirect_uri: "https://app.example.com/cb",
          code_challenge: challenge,
          subject: "usr_42",
          scope: ["documents.read"]
        })

      params = %{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier, client_id: "oc_app"}

      results = race(fn -> AuthorizationCode.redeem(CodeStore.ETS, code, params) end)

      winners = Enum.count(results, &match?({:ok, _}, &1))
      losers = Enum.count(results, &(&1 == {:error, :invalid_grant}))

      assert winners == 1, "exactly one redemption may win; got #{winners}"
      assert losers == @racers - 1
    end
  end

  describe "refresh rotation claim under concurrency" do
    test "no two simultaneous rotations of one token both mint a successor" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", scope: ["documents.read"]})

      results = race(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      successors =
        results
        |> Enum.flat_map(fn
          {:ok, %{token: token}} -> [token]
          _other -> []
        end)
        |> Enum.uniq()

      # The atomic claim guarantees at most one distinct successor. With the
      # default retry grace window, losing racers may receive the same successor
      # through the idempotent retry path; that is safe. What must never happen
      # is a fork where two different successors are minted from one parent.
      #
      # A racer that passed the initial non-consuming `get` but whose
      # `consume` call arrives after `revoke_family` has already deleted the
      # token row from ETS will see `{:error, :invalid_grant}` (the store
      # returns `:error` for an absent row). Both `:reuse_detected` and
      # `:invalid_grant` are safe terminal outcomes: neither produces a
      # successor, and the family is revoked either way.
      assert length(successors) <= 1,
             "at most one distinct successor may be minted; got #{length(successors)}"

      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or r == {:error, :reuse_detected} or r == {:error, :invalid_grant}
             end)

      # Whichever way the race resolved, the family must not be left in a
      # FORKED state. That is the invariant; "the next rotation fails" is not,
      # and asserting it made this test load-dependent.
      #
      # Within `:rotation_grace_seconds` (10s by default) a matching retry of
      # an already-consumed parent is documented to return the SAME successor,
      # so whether this call fails depends on which way the racers resolved: if
      # a loser tripped reuse detection the family is revoked and the row is
      # gone (`:invalid_grant`), but if every loser landed on the idempotent
      # path there is nothing to revoke and the original successor is returned
      # again. Both are correct. Only a NEW successor would be a fork.
      case RefreshToken.rotate(RefreshStore.ETS, t0) do
        {:ok, %{token: token}} ->
          assert token in successors,
                 "a post-race rotation minted a successor no racer saw, forking the family"

        {:error, reason} ->
          assert reason in [:reuse_detected, :invalid_grant]
      end
    end

    # The test above can only see successors that were RETURNED to a caller. A
    # child written to storage and then not handed back is invisible to it, and
    # a child sitting in the store is a usable credential whether or not anyone
    # received it. This one watches the store instead.
    #
    # What it can and cannot catch, stated plainly because the difference is
    # not obvious:
    #
    #   * It CAN catch a successor that reaches storage without reaching a
    #     caller. `rotate/3` returns `{:ok, _}` unconditionally once `issue/3`
    #     has inserted and the `remember_successor/3` RESULT is discarded, so a
    #     store that merely returns an error there cannot strand a child - but
    #     one that RAISES leaves the child persisted while the caller gets an
    #     exception, and a host writes those stores.
    #
    #   * It does NOT prove `consume/2` is atomic, though it can catch some
    #     non-atomic implementations. A store whose `consume` only reads and
    #     reports success produces 25 distinct persisted successors, which the
    #     fork assertion rejects. A different break does not: rewiring
    #     `{:reuse, _}` to `{:ok, _}` yields ZERO successors instead of two,
    #     because the extra claimants revoke the family and the winner's own
    #     insert is then refused. Passing here means no fork was observed in
    #     this run, not that the claim is atomic - that is the store's
    #     contract, tested where the stores are.
    #
    # The vacuity guard below matters for the same reason: without it, "no
    # successors were persisted" would satisfy a fork assertion perfectly.
    test "no second successor is persisted, even one no caller received" do
      RecordingStore.reset()

      {:ok, %{token: t0}} =
        RefreshToken.issue(RecordingStore, %{subject: "usr_42", scope: ["documents.read"]})

      results = race(fn -> RefreshToken.rotate(RecordingStore, t0) end)

      # Generation 0 is the parent from `issue/3`; anything above it is a
      # successor that actually landed in storage.
      persisted =
        RecordingStore.persisted()
        |> Enum.filter(&(&1.generation >= 1))
        |> Enum.map(& &1.token_hash)
        |> Enum.uniq()

      assert length(persisted) <= 1,
             "the race persisted #{length(persisted)} distinct successors; one parent may father at most one child"

      # Guard against a vacuous pass: an empty store satisfies "at most one
      # successor" perfectly, so require evidence the race reached the claim at
      # all. Zero persisted successors is itself legitimate - a loser can
      # revoke the family in the window between the winner's `consume` and its
      # `insert`, so the winner's child is refused - which is why this asserts
      # that the claim was REACHED rather than that a child exists.
      assert Enum.any?(results, &(match?({:ok, _}, &1) or &1 == {:error, :reuse_detected})),
             "no racer won the claim or tripped reuse detection, so nothing was ruled out " <>
               "(outcomes: #{inspect(Enum.frequencies_by(results, fn
                 {:ok, _} -> :ok
                 {:error, r} -> r
               end))})"

      # Both inclusions, because either alone is satisfiable while the other
      # fails. Every successor handed out must be in the store (nobody holds a
      # credential the store does not know), AND every successor in the store
      # must have been handed out (nothing is stranded there unclaimed, which
      # is the case a `remember_successor/3` that raises would produce).
      returned = for({:ok, %{token: token}} <- results, do: Attesto.Secret.hash(token)) |> Enum.uniq()

      for hash <- returned do
        assert hash in persisted, "a racer was handed a successor that is not in the store"
      end

      for hash <- persisted do
        assert hash in returned,
               "a successor is in the store that no racer received; a stranded child is still a usable credential"
      end

      # Every outcome must be terminal-and-safe: a successor, or one of the
      # refusals that leaves no successor behind.
      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or r in [{:error, :reuse_detected}, {:error, :invalid_grant}]
             end)
    end
  end

  # Wraps the ETS reference store and records every successor insert that
  # actually landed, so a test can assert over what STORAGE holds rather than
  # only over what callers were handed back. Records after the delegate
  # returns `:ok`, so an insert the store refused (`:family_revoked`) is not
  # counted as persisted.
  defmodule RecordingStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @table :grants_concurrency_insert_log

    def reset do
      if :ets.whereis(@table) != :undefined, do: :ets.delete(@table)
      :ets.new(@table, [:duplicate_bag, :public, :named_table])
      :ok
    end

    def persisted, do: Enum.map(:ets.tab2list(@table), fn {:persisted, entry} -> entry end)

    @impl true
    def insert(entry) do
      case RefreshStore.ETS.insert(entry) do
        :ok ->
          :ets.insert(@table, {:persisted, entry})
          :ok

        other ->
          other
      end
    end

    @impl true
    def get(token_hash), do: RefreshStore.ETS.get(token_hash)

    @impl true
    def consume(token_hash, opts), do: RefreshStore.ETS.consume(token_hash, opts)

    @impl true
    def remember_successor(token_hash, successor, opts),
      do: RefreshStore.ETS.remember_successor(token_hash, successor, opts)

    @impl true
    def revoke_family(family_id), do: RefreshStore.ETS.revoke_family(family_id)
  end
end
