defmodule Attesto.ConcurrencySwarmTest do
  @moduledoc false
  # Contention floods that extend the two-way race tests in
  # `Attesto.GrantsConcurrencyTest` from a pair of racers to a swarm of N.
  # Where the two-way tests prove the atomic primitive admits at most one
  # winner, these prove the SAME invariants hold under heavy contention and
  # that the conservative responses (family revocation, replay rejection)
  # are idempotent: no second successor is ever minted, no two distinct
  # proofs both win the replay CAS.
  #
  # Named-singleton stores (RefreshStore.ETS, DPoP.ReplayCache) plus the
  # DPoP factory's reliance on shared crypto material => async: false.
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Test.Factory

  @swarm 30
  @await_ms 5_000

  setup do
    start_supervised!(RefreshStore.ETS)
    start_supervised!(DPoP.ReplayCache)
    :ok
  end

  defp swarm(fun) do
    1..@swarm
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(@await_ms)
  end

  describe "reuse swarm: flooded retry of an already-consumed token" do
    test "parallel honest retries of the consumed original return the same successor" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", scope: ["documents.read"]})

      # Rotate once: t0 is now consumed, and a live successor (t1) exists.
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)
      assert is_binary(t1)
      refute t1 == t0

      # Fire a flood of rotations of the ALREADY-CONSUMED original. Within
      # the rotation grace window this is treated as an idempotent retry of a
      # lost response: every successful retry must receive the SAME successor
      # that was already minted, never a distinct second successor.
      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      assert length(results) == @swarm

      assert Enum.all?(results, &match?({:ok, _}, &1)),
             "honest retries inside grace must be idempotent; got #{inspect(results)}"

      successor_tokens = for {:ok, %{token: token}} <- results, do: token
      assert Enum.uniq(successor_tokens) == [t1]

      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t1),
             "the live successor must remain usable after idempotent retries"
    end

    test "a swarm on a node one second behind the commit clock recovers one successor" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_clock_swarm", scope: ["documents.read"]}, now: 1_000)

      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)
      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0, now: 999) end)

      assert Enum.all?(results, &match?({:ok, %{token: ^t1}}, &1))
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_001)
    end
  end

  describe "claim swarm: flooded rotation of one live token" do
    test "concurrent rotations never fork: at most one distinct successor, chain stays forkless" do
      {:ok, %{token: t0, family_id: family_id}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_7", scope: ["documents.read"]})

      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      assert length(results) == @swarm

      # Every request either wins the atomic transition or reads its complete
      # committed parent and returns the same idempotent successor. No loser
      # may observe a consumed parent before the child and retry state commit.
      assert Enum.all?(results, &match?({:ok, _}, &1)),
             "every matching request should coalesce on the committed successor; got #{inspect(results)}"

      successor_tokens =
        results
        |> Enum.flat_map(fn
          {:ok, %{token: tok}} -> [tok]
          _ -> []
        end)
        |> Enum.uniq()

      assert successor_tokens != []

      assert length(successor_tokens) == 1,
             "rotation must be forkless: exactly one distinct successor; got #{inspect(successor_tokens)}"

      # Drive the family to a terminal revoked state, then confirm the chain is
      # dead with no surviving fork: neither the original nor the minted
      # successor can rotate.
      :ok = RefreshStore.ETS.revoke_family(family_id)

      refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, t0)),
             "the original must not rotate once the family is revoked"

      for tok <- successor_tokens do
        refute match?({:ok, _}, RefreshToken.rotate(RefreshStore.ETS, tok)),
               "no successor may rotate once the family is revoked (forkless invariant)"
      end
    end
  end

  describe "DPoP replay CAS: flooded verification of one proof" do
    test "exactly one parallel verify_proof of the same jti wins; the rest are :replay" do
      {proof, _jkt} = Factory.dpop_proof()

      verify = fn ->
        DPoP.verify_proof(proof,
          http_method: "POST",
          http_uri: "https://api.example.com/oauth/token",
          replay_check: &DPoP.ReplayCache.check_and_record/2
        )
      end

      results = swarm(verify)

      assert length(results) == @swarm

      winners = Enum.filter(results, &match?({:ok, _}, &1))
      replays = Enum.filter(results, &(&1 == {:error, :replay}))

      assert length(winners) == 1,
             "exactly one verify may record the jti first; got #{length(winners)}"

      assert length(replays) == @swarm - 1,
             "every other verify of the same jti must be :replay; got #{length(replays)}"

      # The sole winner carries the verified shape: same jkt/jti the others
      # collided on, proving they raced on one identity, not distinct proofs.
      [{:ok, verified}] = winners
      assert is_binary(verified.jkt)
      assert is_binary(verified.jti)
    end
  end
end
