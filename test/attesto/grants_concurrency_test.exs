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
  end
end
