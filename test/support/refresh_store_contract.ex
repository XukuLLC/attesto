defmodule Attesto.RefreshStoreContract do
  @moduledoc false
  # Reusable conformance suite for any `Attesto.RefreshStore` implementation.
  #
  # `use` this module from a test case to inject the shared security
  # contract for refresh-token stores. The same tests run against any
  # store, so the ETS reference today and a SQL store tomorrow are held to
  # the identical atomic-rotation and family-revocation guarantees that
  # refresh-token reuse detection rests on.
  #
  # ## Options
  #
  #   * `:store` (required) - the module implementing `Attesto.RefreshStore`.
  #   * `:start` (optional) - a 0-arity fun that starts the store and
  #     returns its pid (or `{:ok, pid}`). When omitted, the suite calls
  #     `start_supervised!(store)`.
  #
  # The store under test is typically a named singleton GenServer, so the
  # host case MUST be `use ExUnit.Case, async: false`.
  #
  #     defmodule MyStoreContractTest do
  #       use ExUnit.Case, async: false
  #       use Attesto.RefreshStoreContract, store: My.RefreshStore
  #     end

  defmacro __using__(opts) do
    store = Keyword.fetch!(opts, :store)
    start = Keyword.get(opts, :start)

    start_call =
      if start,
        do: quote(do: unquote(start).()),
        else: quote(do: start_supervised!(unquote(store)))

    # A reusable ExUnit contract must inject the test definitions into each
    # adapter's case; splitting this quote would only scatter one contract.
    # credo:disable-for-next-line Credo.Check.Refactor.LongQuoteBlocks
    quote do
      @contract_store unquote(store)

      setup do
        unquote(start_call)
        :ok
      end

      # A plain map matching the documented `Attesto.RefreshStore.entry`
      # shape. Fresh, unconsumed, unexpired unless a test overrides it.
      defp contract_refresh_record(overrides \\ %{}) do
        token_suffix = 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
        family_suffix = 8 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

        %{
          token_hash: "token_hash_" <> token_suffix,
          family_id: "fam_" <> family_suffix,
          generation: 0,
          data: %{
            subject: "usr_example",
            scope: ["things.read"],
            resource: ["https://api.example.test"],
            acr: nil,
            auth_time: nil,
            client_id: "oc_example",
            dpop_jkt: nil,
            claims: %{}
          },
          expires_at: System.system_time(:second) + 3600,
          consumed: false,
          consumed_at: nil,
          successor: nil
        }
        |> Map.merge(overrides)
      end

      test "insert then get returns the record, still unconsumed" do
        record = contract_refresh_record()

        assert :ok = @contract_store.insert(record)
        assert {:ok, got} = @contract_store.get(record.token_hash)
        assert got == record
        assert got.consumed == false
      end

      test "get is non-consuming: get after get leaves the token unconsumed" do
        record = contract_refresh_record()
        :ok = @contract_store.insert(record)

        assert {:ok, first} = @contract_store.get(record.token_hash)
        assert first.consumed == false
        assert {:ok, second} = @contract_store.get(record.token_hash)
        assert second.consumed == false

        assert first == second
      end

      test "rotate atomically commits the consumed parent, exact successor, and child" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {child, successor} = contract_child_and_successor(record, now)

        assert {:ok, committed, committed_child} =
                 @contract_store.rotate(record.token_hash, child, successor, now: now)

        assert committed.consumed == true
        assert committed.consumed_at == now
        assert committed.successor == successor
        assert committed_child == child
        assert {:ok, ^committed} = @contract_store.get(record.token_hash)
        assert {:ok, ^child} = @contract_store.get(child.token_hash)
      end

      test "a losing rotate reads the committed winner and never stores its alternate child" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {winner_child, winner_successor} = contract_child_and_successor(record, now)
        {alternate_child, alternate_successor} = contract_child_and_successor(record, now, "alternate")

        assert {:ok, winner, winner_child_snapshot} =
                 @contract_store.rotate(record.token_hash, winner_child, winner_successor, now: now)

        assert {:reuse, reused} =
                 @contract_store.rotate(record.token_hash, alternate_child, alternate_successor, now: now)

        assert reused == winner
        assert winner_child_snapshot == winner_child
        assert {:ok, ^winner_child_snapshot} = @contract_store.get(winner_child.token_hash)
        assert :error = @contract_store.get(alternate_child.token_hash)
      end

      test "strict tombstone round-trips and cannot be reopened by a positive retry" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {child, _successor} = contract_child_and_successor(record, now)
        tombstone = %{retry_until: now, recoverable: false}

        assert {:ok, committed, committed_child} = @contract_store.rotate(record.token_hash, child, tombstone, now: now)
        assert committed.successor == tombstone
        assert committed_child == child
        {late_child, _late_successor} = contract_child_and_successor(record, now, "late")

        assert {:reuse, reused} =
                 @contract_store.rotate(
                   record.token_hash,
                   late_child,
                   %{token: "must-not-stick", generation: 1, context: child.data, retry_until: now + 60},
                   now: now
                 )

        assert reused == committed
        assert :error = @contract_store.get(late_child.token_hash)
      end

      test "absent, expired, and revoked parents leave a candidate child unstored" do
        now = System.system_time(:second)
        absent = contract_refresh_record(%{expires_at: now + 3_600})
        {absent_child, absent_successor} = contract_child_and_successor(absent, now)
        assert :error = @contract_store.rotate("token_hash_absent", absent_child, absent_successor, now: now)
        assert :error = @contract_store.get(absent_child.token_hash)

        expired = contract_refresh_record(%{expires_at: now - 1})
        :ok = @contract_store.insert(expired)
        {expired_child, expired_successor} = contract_child_and_successor(expired, now)

        assert {:error, :expired} =
                 @contract_store.rotate(expired.token_hash, expired_child, expired_successor, now: now)

        assert {:ok, ^expired} = @contract_store.get(expired.token_hash)
        assert :error = @contract_store.get(expired_child.token_hash)

        revoked = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(revoked)
        {revoked_child, revoked_successor} = contract_child_and_successor(revoked, now)
        :ok = @contract_store.revoke_family(revoked.family_id)

        assert {:error, :family_revoked} =
                 @contract_store.rotate(revoked.token_hash, revoked_child, revoked_successor, now: now)

        assert :error = @contract_store.get(revoked_child.token_hash)
      end

      test "malformed successor and token/generation collisions leave the parent unchanged" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {child, successor} = contract_child_and_successor(record, now)

        assert {:error, :invalid_rotation} =
                 @contract_store.rotate(record.token_hash, child, %{retry_until: now}, now: now)

        assert {:ok, ^record} = @contract_store.get(record.token_hash)
        assert :error = @contract_store.get(child.token_hash)

        strict_with_secret = %{
          retry_until: now,
          recoverable: false,
          token: "must-not-be-stored",
          context: child.data
        }

        assert {:error, :invalid_rotation} =
                 @contract_store.rotate(record.token_hash, child, strict_with_secret, now: now)

        assert {:ok, ^record} = @contract_store.get(record.token_hash)

        collision =
          contract_refresh_record(%{
            token_hash: child.token_hash,
            family_id: "other-family",
            generation: 9,
            expires_at: now + 3_600
          })

        :ok = @contract_store.insert(collision)
        assert {:error, :token_conflict} = @contract_store.rotate(record.token_hash, child, successor, now: now)
        assert {:ok, ^record} = @contract_store.get(record.token_hash)

        sibling =
          contract_refresh_record(%{
            family_id: record.family_id,
            generation: child.generation,
            expires_at: now + 3_600
          })

        :ok = @contract_store.insert(sibling)
        {generation_child, generation_successor} = contract_child_and_successor(record, now, "generation")

        assert {:error, :family_integrity_error} =
                 @contract_store.rotate(record.token_hash, generation_child, generation_successor, now: now)

        assert :error = @contract_store.get(record.token_hash)
        assert :error = @contract_store.get(sibling.token_hash)
        assert :error = @contract_store.get(generation_child.token_hash)
      end

      test "invalid child identity and retry-state bindings never mutate the parent" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {child, successor} = contract_child_and_successor(record, now)

        invalid_pairs = [
          {%{child | family_id: "wrong-family"}, successor},
          {%{child | generation: child.generation + 1}, successor},
          {%{child | data: %{child.data | scope: ["other"]}}, successor},
          {%{child | consumed: true}, successor},
          {%{child | consumed_at: now}, successor},
          {%{child | successor: %{retry_until: now, recoverable: false}}, successor},
          {%{child | expires_at: now}, successor},
          {child, %{successor | generation: successor.generation + 1}},
          {child, %{successor | context: %{successor.context | scope: ["other"]}}},
          {child, %{successor | retry_until: now - 1}},
          {child, %{successor | retry_until: child.expires_at}},
          {child, Map.put(successor, :extra, "not-contract-state")}
        ]

        for {invalid_child, invalid_successor} <- invalid_pairs do
          assert {:error, :invalid_rotation} =
                   @contract_store.rotate(record.token_hash, invalid_child, invalid_successor, now: now)

          assert {:ok, ^record} = @contract_store.get(record.token_hash)
          assert :error = @contract_store.get(invalid_child.token_hash)
        end
      end

      test "concurrent positive-grace rotations coalesce on one committed successor" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)

        tasks =
          for index <- 1..12 do
            Task.async(fn ->
              {child, successor} = contract_child_and_successor(record, now, "swarm-#{index}")
              {@contract_store.rotate(record.token_hash, child, successor, now: now), child}
            end)
          end

        results = Task.await_many(tasks)
        successful = Enum.filter(results, &match?({{:ok, _, _}, _}, &1))
        assert [{{:ok, winner, winner_child}, _winner_candidate}] = successful

        assert Enum.all?(results, fn
                 {{:ok, _, _}, _child} -> true
                 {{:reuse, reused}, _child} -> reused == winner
                 _ -> false
               end)

        children =
          results
          |> Enum.map(fn {_result, child} -> child.token_hash end)
          |> Enum.filter(fn hash -> @contract_store.get(hash) != :error end)

        assert children == [winner.successor |> Map.fetch!(:token) |> Attesto.Secret.hash()]
      end

      test "revoke_family removes exactly the matching family" do
        target_family = "fam_target"
        keep_family = "fam_keep"

        target_a = contract_refresh_record(%{family_id: target_family})
        target_b = contract_refresh_record(%{family_id: target_family, generation: 1})
        keep_a = contract_refresh_record(%{family_id: keep_family})
        keep_b = contract_refresh_record(%{family_id: keep_family, generation: 1})

        for record <- [target_a, target_b, keep_a, keep_b] do
          :ok = @contract_store.insert(record)
        end

        assert :ok = @contract_store.revoke_family(target_family)

        # The target family is gone from the read path.
        assert :error = @contract_store.get(target_a.token_hash)
        assert :error = @contract_store.get(target_b.token_hash)

        # The other family is untouched.
        assert {:ok, _} = @contract_store.get(keep_a.token_hash)
        assert {:ok, _} = @contract_store.get(keep_b.token_hash)
      end

      test "revoke_family is idempotent: revoking twice is fine" do
        record = contract_refresh_record(%{family_id: "fam_idem"})
        :ok = @contract_store.insert(record)

        assert :ok = @contract_store.revoke_family("fam_idem")
        assert :ok = @contract_store.revoke_family("fam_idem")
        # Revoking a family that was never present is also a no-op success.
        assert :ok = @contract_store.revoke_family("fam_never_existed")

        assert :error = @contract_store.get(record.token_hash)
      end

      test "a concurrent revocation leaves no live family member regardless of ordering" do
        now = System.system_time(:second)
        record = contract_refresh_record(%{expires_at: now + 3_600})
        :ok = @contract_store.insert(record)
        {child, successor} = contract_child_and_successor(record, now)

        rotate_task =
          Task.async(fn -> @contract_store.rotate(record.token_hash, child, successor, now: now) end)

        revoke_task = Task.async(fn -> @contract_store.revoke_family(record.family_id) end)

        rotate_result = Task.await(rotate_task)
        assert :ok = Task.await(revoke_task)

        assert match?({:ok, _, _}, rotate_result) or rotate_result == {:error, :family_revoked}
        assert :error = @contract_store.get(record.token_hash)
        assert :error = @contract_store.get(child.token_hash)

        late = contract_refresh_record(%{family_id: record.family_id})
        assert {:error, :family_revoked} = @contract_store.insert(late)
      end

      defp contract_child_and_successor(parent, now, suffix \\ "successor") do
        token = "#{suffix}-#{:erlang.unique_integer([:positive])}"
        context = parent.data

        child =
          contract_refresh_record(%{
            token_hash: Attesto.Secret.hash(token),
            family_id: parent.family_id,
            generation: parent.generation + 1,
            data: context,
            expires_at: now + 1_800
          })

        successor = %{
          token: token,
          generation: child.generation,
          context: context,
          retry_until: now + 60
        }

        {child, successor}
      end

      test "revocation is sticky: a later insert into a revoked family is refused" do
        # The concurrency guarantee reuse detection depends on: once a
        # family is revoked, a successor that arrives afterwards (e.g. a
        # rotation that won its claim but inserts after the revoke) MUST be
        # rejected, not stored, so the family cannot fork back to life.
        assert :ok = @contract_store.revoke_family("fam_sticky")

        late = contract_refresh_record(%{family_id: "fam_sticky"})
        assert {:error, :family_revoked} = @contract_store.insert(late)
        assert :error = @contract_store.get(late.token_hash)
      end
    end
  end
end
