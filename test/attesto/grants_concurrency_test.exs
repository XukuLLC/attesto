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
      # The atomic store commits the parent, retry state, and child together,
      # so matching losers recover the same successor rather than observing a
      # partially rotated family.
      assert length(successors) <= 1,
             "at most one distinct successor may be minted; got #{length(successors)}"

      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or
                 r in [
                   {:error, :reuse_detected},
                   {:error, :grant_revoked},
                   {:error, :invalid_grant},
                   {:error, :temporarily_unavailable}
                 ]
             end)

      # Whichever way the race resolved, the family must not be left in a
      # FORKED state. That is the invariant; "the next rotation fails" is not,
      # and asserting it made this test load-dependent.
      #
      # A post-race retry either returns that same successor or a terminal
      # refusal; it must never mint a new child.
      case RefreshToken.rotate(RefreshStore.ETS, t0) do
        {:ok, %{token: token}} ->
          assert token in successors,
                 "a post-race rotation minted a successor no racer saw, forking the family"

        {:error, reason} ->
          assert reason in [:reuse_detected, :grant_revoked, :invalid_grant, :temporarily_unavailable]
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
    #   * It observes what the atomic rotate contract actually committed.
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
      # all.
      # that the claim was REACHED rather than that a child exists.
      assert Enum.any?(results, &(match?({:ok, _}, &1) or &1 in [{:error, :reuse_detected}, {:error, :grant_revoked}])),
             "no racer won the claim or tripped reuse detection, so nothing was ruled out " <>
               "(outcomes: #{inspect(Enum.frequencies_by(results, fn
                 {:ok, _} -> :ok
                 {:error, r} -> r
               end))})"

      # Every successor handed out must have landed in the store. Conversely,
      # every live successor must have been handed out.
      returned = for({:ok, %{token: token}} <- results, do: Attesto.Secret.hash(token)) |> Enum.uniq()

      for hash <- returned do
        assert hash in persisted, "a racer was handed a successor that is not in the store"
      end

      live_persisted = Enum.filter(persisted, &match?({:ok, _}, RefreshStore.ETS.get(&1)))

      for hash <- live_persisted do
        assert hash in returned,
               "a live successor is in the store that no racer received; a stranded child is still a usable credential"
      end

      # Every outcome must be terminal-and-safe: a successor, or one of the
      # refusals that leaves no successor behind.
      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or
                 r in [
                   {:error, :reuse_detected},
                   {:error, :grant_revoked},
                   {:error, :invalid_grant},
                   {:error, :temporarily_unavailable}
                 ]
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
    def rotate(parent_hash, child, successor, opts) do
      case RefreshStore.ETS.rotate(parent_hash, child, successor, opts) do
        {:ok, _parent, committed_child} = result ->
          :ets.insert(@table, {:persisted, committed_child})
          result

        other ->
          other
      end
    end

    @impl true
    def revoke_family(family_id), do: RefreshStore.ETS.revoke_family(family_id)
  end
end
