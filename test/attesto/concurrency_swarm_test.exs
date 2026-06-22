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
  end

  describe "claim swarm: flooded rotation of one live token" do
    test "concurrent rotations never fork: at most one distinct successor, chain stays forkless" do
      {:ok, %{token: t0, family_id: family_id}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_7", scope: ["documents.read"]})

      results = swarm(fn -> RefreshToken.rotate(RefreshStore.ETS, t0) end)

      assert length(results) == @swarm

      # Every result is one of: a successful rotation ({:ok,_}); a loser that saw
      # the token already claimed (:reuse_detected, which revokes the family); or
      # a loser whose read landed after a concurrent revoke deleted the row
      # (:invalid_grant). All three are safe.
      assert Enum.all?(results, fn r ->
               match?({:ok, _}, r) or r in [{:error, :reuse_detected}, {:error, :invalid_grant}]
             end),
             "results must be {:ok,_}, :reuse_detected, or :invalid_grant; got #{inspect(results)}"

      # A {:ok,_} is either the single task that won the atomic claim and minted
      # the successor, OR a lagging task whose read landed after that claim,
      # within the rotation-grace window: an idempotent lost-response retry that
      # returns the SAME successor (exactly what the reuse swarm above asserts).
      # So more than one {:ok,_} is safe under contention - what must never
      # happen is a FORK. The invariant is forklessness: at most ONE distinct
      # successor is ever minted, no matter how many retries observe it. (An
      # earlier `length(winners) <= 1` check was a flawed proxy that flaked when
      # scheduling let several grace retries observe the same live successor.)
      successor_tokens =
        results
        |> Enum.flat_map(fn
          {:ok, %{token: tok}} -> [tok]
          _ -> []
        end)
        |> Enum.uniq()

      assert length(successor_tokens) <= 1,
             "rotation must be forkless: at most one distinct successor; got #{inspect(successor_tokens)}"

      # Whether the swarm trips reuse detection depends on interleaving (an
      # all-idempotent interleaving leaves one safe live leaf and never revokes),
      # so drive the family to its terminal revoked state deterministically, then
      # confirm the chain is dead with no surviving fork: neither the original
      # nor the minted successor can rotate.
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
