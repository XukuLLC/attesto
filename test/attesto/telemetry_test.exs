defmodule Attesto.TelemetryTest do
  @moduledoc false
  # The event names and metadata keys asserted here are public API: a host
  # attaches to them and routes them to a pager or a SIEM. Renaming one, or
  # dropping a documented key, breaks that host silently at runtime - there is
  # no compile-time link between an emitter and a handler. These tests are the
  # link.
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore
  alias Attesto.RefreshStore.ETS
  alias Attesto.RefreshToken
  alias Attesto.Telemetry
  alias Attesto.Test.Factory
  alias Attesto.Token

  setup context do
    handler = "attesto-telemetry-test-#{inspect(context.test)}"
    test_pid = self()

    :ok =
      :telemetry.attach_many(
        handler,
        Telemetry.events(),
        fn event, measurements, metadata, _cfg ->
          send(test_pid, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    start_supervised!(RefreshStore.ETS)
    :ok
  end

  describe "events/0" do
    test "lists every event the library emits, for attach_many/4" do
      assert Telemetry.events() == [
               [:attesto, :refresh_token, :reuse_detected],
               [:attesto, :refresh_token, :rotation_state_failed],
               [:attesto, :introspection, :refresh_store_failed],
               [:attesto, :dpop, :replay_detected],
               [:attesto, :token, :sender_constraint_mismatch]
             ]
    end
  end

  describe "[:attesto, :refresh_token, :rotation_state_failed]" do
    defmodule RetryStateUnavailableStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def insert(entry), do: ETS.insert(entry)
      @impl true
      def get(token_hash), do: ETS.get(token_hash)
      @impl true
      def rotate(token_hash, child, successor, opts) do
        send(self(), {:atomic_rotate_called, successor})

        if Map.get(successor, :recoverable, true) == false do
          ETS.rotate(token_hash, child, successor, opts)
        else
          {:error, :retry_state_unavailable}
        end
      end

      @impl true
      def revoke_family(family_id), do: ETS.revoke_family(family_id)
    end

    defmodule InvalidRotationStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def insert(entry), do: ETS.insert(entry)

      @impl true
      def get(token_hash), do: ETS.get(token_hash)

      @impl true
      def rotate(_token_hash, _child, _successor, _opts), do: {:error, :invalid_rotation}

      @impl true
      def revoke_family(family_id), do: ETS.revoke_family(family_id)
    end

    defmodule ExceptionalRotateStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def insert(entry), do: ETS.insert(entry)
      @impl true
      def get(token_hash), do: ETS.get(token_hash)
      @impl true
      def rotate(token_hash, child, successor, opts) do
        case Process.get({__MODULE__, :rotate_failure}) do
          :raise ->
            _ = ETS.rotate(token_hash, child, successor, opts)
            raise "original rotate failure"

          :throw ->
            _ = ETS.rotate(token_hash, child, successor, opts)
            throw({:original_rotate_throw, "callback-private-value"})

          :exit ->
            _ = ETS.rotate(token_hash, child, successor, opts)
            exit({:original_rotate_exit, "callback-private-exit-value"})

          _ ->
            ETS.rotate(token_hash, child, successor, opts)
        end
      end

      @impl true
      def revoke_family(family_id) do
        send(self(), :exceptional_store_cleanup_attempted)

        if Process.get({__MODULE__, :cleanup_failure}) do
          raise "secondary cleanup failure"
        else
          ETS.revoke_family(family_id)
        end
      end
    end

    defmodule RevokeContractViolationStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def insert(entry), do: ETS.insert(entry)
      @impl true
      def get(token_hash), do: ETS.get(token_hash)
      @impl true
      def rotate(token_hash, child, successor, opts) do
        _ = ETS.rotate(token_hash, child, successor, opts)
        {:unexpected_return, "credential-sentinel-that-must-not-escape"}
      end

      @impl true
      def revoke_family(_family_id), do: {:unexpected_return, "credential-sentinel-that-must-not-escape"}
    end

    defmodule MutationFaultStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def insert(entry) do
        result = ETS.insert(entry)
        send(self(), {:mutation_store_inserted, entry.generation})
        after_mutation(:insert, result)
      end

      @impl true
      def get(token_hash) do
        result = ETS.get(token_hash)

        case Process.get({__MODULE__, :get_override}) do
          override when is_function(override, 2) -> override.(token_hash, result)
          _none -> result
        end
      end

      @impl true
      def rotate(token_hash, child, successor, opts) do
        result = ETS.rotate(token_hash, child, successor, opts)
        send(self(), :mutation_store_rotated)
        after_mutation(:rotate, result)
      end

      @impl true
      def revoke_family(family_id) do
        send(self(), :mutation_store_cleanup_attempted)

        case Process.get({__MODULE__, :revoke}) do
          nil -> ETS.revoke_family(family_id)
          {:return, value} -> value
          {:raise, message} -> raise message
          {:throw, value} -> throw(value)
          {:exit, value} -> exit(value)
        end
      end

      defp after_mutation(operation, result) do
        case Process.get({__MODULE__, operation}) do
          nil -> result
          {:return, value} -> value
          {:return_fun, fun} when is_function(fun, 1) -> fun.(result)
          {:raise, message} -> raise message
          {:throw, value} -> throw(value)
          {:exit, value} -> exit(value)
        end
      end
    end

    test "an initial store lookup exception is reported without replacing the original failure" do
      {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "initial-get-fault"})
      assert_received {:mutation_store_inserted, 0}

      Process.put({MutationFaultStore, :get_override}, fn _token_hash, _actual ->
        raise "original get failure"
      end)

      assert_raise RuntimeError, "original get failure", fn ->
        RefreshToken.rotate(MutationFaultStore, token, now: 1_000)
      end

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :lookup
      assert metadata.reason == :store_raised
      assert metadata.revocation == :not_attempted
      refute Map.has_key?(metadata, :family_id)
      refute inspect(metadata) =~ "original get failure"
      assert {:ok, %{consumed: false}} = ETS.get(Attesto.Secret.hash(token))
      Process.delete({MutationFaultStore, :get_override})
    end

    test "an initial lookup contract violation is reported without revoking an untrusted family" do
      {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "initial-get-contract"})
      assert_received {:mutation_store_inserted, 0}

      Process.put({MutationFaultStore, :get_override}, fn _token_hash, _actual ->
        {:unexpected, "credential-sentinel-that-must-not-escape"}
      end)

      assert_raise RuntimeError, "refresh store get/1 violated its contract", fn ->
        RefreshToken.rotate(MutationFaultStore, token, now: 1_000)
      end

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :lookup
      assert metadata.reason == :store_contract_violation
      assert metadata.revocation == :not_attempted
      refute Map.has_key?(metadata, :family_id)
      refute inspect(metadata) =~ "credential-sentinel"
      assert {:ok, %{consumed: false}} = ETS.get(Attesto.Secret.hash(token))
      Process.delete({MutationFaultStore, :get_override})
    end

    test "an initial store lookup throw or exit is reported and preserved" do
      for {failure, expected} <- [
            {{:throw, :original_get_throw}, :store_threw},
            {{:exit, :original_get_exit}, :store_exited}
          ] do
        {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "initial-get-signal"})
        assert_received {:mutation_store_inserted, 0}

        Process.put({MutationFaultStore, :get_override}, fn _token_hash, _actual ->
          case failure do
            {:throw, value} -> throw(value)
            {:exit, value} -> exit(value)
          end
        end)

        case failure do
          {:throw, value} -> assert catch_throw(RefreshToken.rotate(MutationFaultStore, token)) == value
          {:exit, value} -> assert catch_exit(RefreshToken.rotate(MutationFaultStore, token)) == value
        end

        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :lookup
        assert metadata.reason == expected
        assert metadata.revocation == :not_attempted
        Process.delete({MutationFaultStore, :get_override})
      end
    end

    test "a positive grace reports unavailable without consuming the parent when retry state cannot be stored" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RetryStateUnavailableStore, %{
          subject: "usr_rotation_state",
          client_id: "oc_rotation_state",
          scope: ["documents.read"]
        })

      assert {:error, :temporarily_unavailable} =
               RefreshToken.rotate(RetryStateUnavailableStore, t0,
                 client_id: "oc_rotation_state",
                 now: 1_000,
                 rotation_grace_seconds: 10
               )

      assert_received {:atomic_rotate_called, %{retry_until: 1_010}}

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], measurements, metadata}

      assert is_integer(measurements.system_time)
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :retry_state_unavailable
      assert metadata.client_id == "oc_rotation_state"
      assert metadata.subject == "usr_rotation_state"
      assert metadata.generation == 0
      assert metadata.revocation == :not_attempted
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}

      assert {:ok, %{consumed: false}} = RefreshStore.ETS.get(Attesto.Secret.hash(t0))
    end

    test "a documented invalid rotation reports unavailable without revoking the parent" do
      {:ok, %{token: t0}} = RefreshToken.issue(InvalidRotationStore, %{subject: "usr_invalid_rotation"}, now: 1_000)

      assert {:error, :temporarily_unavailable} =
               RefreshToken.rotate(InvalidRotationStore, t0, now: 1_000)

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _measurements, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :invalid_rotation
      assert metadata.revocation == :not_attempted
      assert {:ok, %{consumed: false}} = RefreshStore.ETS.get(Attesto.Secret.hash(t0))
    end

    test "a returned cleanup contract violation is reported without exposing its value" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RevokeContractViolationStore, %{subject: "usr_cleanup_contract"})

      error =
        assert_raise RuntimeError, "refresh store revoke_family/1 violated its contract", fn ->
          RefreshToken.rotate(RevokeContractViolationStore, t0, now: 1_000)
        end

      refute Exception.message(error) =~ "credential-sentinel"
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "credential-sentinel"
    end

    test "an invalid atomic rotate result after commit revokes the family" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_contract"})
      assert_received {:mutation_store_inserted, 0}
      Process.put({MutationFaultStore, :rotate}, {:return, {:unexpected, "sensitive-return-sentinel"}})

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)

      assert_received :mutation_store_rotated
      assert_received :mutation_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :store_contract_violation
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "sensitive-return-sentinel"
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      assert :error = ETS.get(Attesto.Secret.hash(t0))
    end

    test "a second raising atomic rotate after commit is cleaned up, reported, and preserved" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_raise"})
      Process.put({MutationFaultStore, :rotate}, {:raise, "original rotate failure"})

      assert_raise RuntimeError, "original rotate failure", fn ->
        RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)
      end

      assert_received :mutation_store_rotated
      assert_received :mutation_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :store_raised
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "original rotate failure"
      assert :error = ETS.get(Attesto.Secret.hash(t0))
    end

    test "an invalid atomic rotate result after commit revokes the entire family" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_contract_2"})
      assert_received {:mutation_store_inserted, 0}
      Process.put({MutationFaultStore, :rotate}, {:return, {:unexpected, "sensitive-rotate-sentinel"}})

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)

      assert_received :mutation_store_rotated
      assert_received :mutation_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :store_contract_violation
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "sensitive-rotate-sentinel"
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      assert :ets.tab2list(ETS) == []
    end

    test "a raising atomic rotate after commit is cleaned up, reported, and preserved" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_raise_2"})
      Process.put({MutationFaultStore, :rotate}, {:raise, "original rotate failure 2"})

      assert_raise RuntimeError, "original rotate failure 2", fn ->
        RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)
      end

      assert_received :mutation_store_rotated
      assert_received :mutation_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :store_raised
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "original rotate failure 2"
      assert :ets.tab2list(ETS) == []
    end

    test "a second atomic rotate throw and exit after commit preserve the original failure after cleanup" do
      for {fault, expected_reason} <- [
            {{:throw, {:rotate_throw, "private-throw-value"}}, :store_threw},
            {{:exit, {:rotate_exit, "private-exit-value"}}, :store_exited}
          ] do
        {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_signal"})
        Process.put({MutationFaultStore, :rotate}, fault)

        case fault do
          {:throw, expected} -> assert catch_throw(RefreshToken.rotate(MutationFaultStore, t0)) == expected
          {:exit, expected} -> assert catch_exit(RefreshToken.rotate(MutationFaultStore, t0)) == expected
        end

        assert_received :mutation_store_cleanup_attempted
        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :rotate_successor
        assert metadata.reason == expected_reason
        refute inspect(metadata) =~ "private-"
        Process.delete({MutationFaultStore, :rotate})
      end
    end

    test "atomic rotate throw and exit after commit preserve the original failure after cleanup" do
      for {fault, expected_reason} <- [
            {{:throw, {:rotate_throw_2, "private-throw-value"}}, :store_threw},
            {{:exit, {:rotate_exit_2, "private-exit-value"}}, :store_exited}
          ] do
        {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_rotate_signal_2"})
        Process.put({MutationFaultStore, :rotate}, fault)

        case fault do
          {:throw, expected} -> assert catch_throw(RefreshToken.rotate(MutationFaultStore, t0)) == expected
          {:exit, expected} -> assert catch_exit(RefreshToken.rotate(MutationFaultStore, t0)) == expected
        end

        assert_received :mutation_store_rotated
        assert_received :mutation_store_cleanup_attempted
        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :rotate_successor
        assert metadata.reason == expected_reason
        refute inspect(metadata) =~ "private-"
        Process.delete({MutationFaultStore, :rotate})
      end
    end

    test "cleanup faults never replace an original atomic rotate failure" do
      {:ok, %{token: rotate_token}} =
        RefreshToken.issue(MutationFaultStore, %{subject: "rotate-cleanup-fault"})

      Process.put({MutationFaultStore, :rotate}, {:throw, :original_rotate_throw})
      Process.put({MutationFaultStore, :revoke}, {:return, {:unexpected, "cleanup-return-sentinel"}})

      assert catch_throw(RefreshToken.rotate(MutationFaultStore, rotate_token)) == :original_rotate_throw
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, rotate_metadata}
      assert rotate_metadata.operation == :rotate_successor
      assert rotate_metadata.revocation == :failed
      refute inspect(rotate_metadata) =~ "cleanup-return-sentinel"

      Process.delete({MutationFaultStore, :rotate})
      Process.delete({MutationFaultStore, :revoke})

      {:ok, %{token: rotate_token_2}} =
        RefreshToken.issue(MutationFaultStore, %{subject: "rotate-cleanup-fault-2"})

      Process.put({MutationFaultStore, :rotate}, {:exit, :original_rotate_exit})
      Process.put({MutationFaultStore, :revoke}, {:raise, "secondary cleanup failure"})

      assert catch_exit(RefreshToken.rotate(MutationFaultStore, rotate_token_2)) == :original_rotate_exit
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, rotate_metadata_2}
      assert rotate_metadata_2.operation == :rotate_successor
      assert rotate_metadata_2.revocation == :failed
      refute inspect(rotate_metadata_2) =~ "secondary cleanup failure"
    end

    test "atomic rotate result must preserve every trusted pre-read invariant" do
      corruptions = [
        token_hash: "wrong-token-hash",
        family_id: "wrong-family",
        generation: 99,
        data: %{subject: "forged", scope: [], resource: []},
        expires_at: 1,
        consumed: true,
        consumed_at: 1_000,
        successor: %{token: "unexpected"}
      ]

      for {field, replacement} <- corruptions do
        {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "claim-invariants"})
        token_hash = Attesto.Secret.hash(token)
        assert {:ok, original} = ETS.get(token_hash)
        forged = Map.put(original, field, replacement)

        Process.put(
          {MutationFaultStore, :rotate},
          {:return_fun, fn {:ok, _committed, child} -> {:ok, forged, child} end}
        )

        assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, token, now: 1_000)
        assert_received :mutation_store_rotated
        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :rotate_successor
        assert metadata.reason == :store_contract_violation
        refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
        Process.delete({MutationFaultStore, :rotate})
      end
    end

    test "a malformed reuse record is an operational failure, not token-reuse evidence" do
      {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "reuse-invariants"})
      token_hash = Attesto.Secret.hash(token)
      assert {:ok, original} = ETS.get(token_hash)
      forged = %{original | consumed: true, consumed_at: nil}

      Process.put(
        {MutationFaultStore, :rotate},
        {:return_fun, fn {:ok, _committed, _child} -> {:reuse, forged} end}
      )

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, token, now: 1_000)
      assert_received :mutation_store_rotated
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :rotate_successor
      assert metadata.reason == :store_contract_violation
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
    end

    test "malformed consumed records loaded before strict retry handling are operational failures" do
      cases = [
        {nil, 0, :consumed_at_missing},
        {nil, 10, :consumed_at_missing},
        {-1, 0, :consumed_at_invalid},
        {1_001, 0, :clock_before_consumption}
      ]

      for {consumed_at, grace, reason} <- cases do
        {:ok, %{token: token}} =
          RefreshToken.issue(MutationFaultStore, %{subject: "stored-consumed-invariants"}, now: 1_000)

        assert {:ok, _successor} =
                 RefreshToken.rotate(MutationFaultStore, token,
                   now: 1_000,
                   rotation_grace_seconds: 10
                 )

        parent_hash = Attesto.Secret.hash(token)
        assert {:ok, parent} = ETS.get(parent_hash)
        forged_parent = %{parent | consumed_at: consumed_at}

        Process.put({MutationFaultStore, :get_override}, fn
          ^parent_hash, _actual -> {:ok, forged_parent}
          _other_hash, actual -> actual
        end)

        assert {:error, :grant_revoked} =
                 RefreshToken.rotate(MutationFaultStore, token,
                   now: 1_000,
                   rotation_grace_seconds: grace
                 )

        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :recover_successor
        assert metadata.reason == reason
        refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      end
    end

    test "a consumed record at its expiry is an operational state failure" do
      {:ok, %{token: token}} =
        RefreshToken.issue(MutationFaultStore, %{subject: "expired-consumption"}, ttl: 1, now: 1_000)

      assert {:ok, _successor} =
               RefreshToken.rotate(MutationFaultStore, token,
                 now: 1_000,
                 rotation_grace_seconds: 10
               )

      parent_hash = Attesto.Secret.hash(token)
      assert {:ok, parent} = ETS.get(parent_hash)
      forged_parent = %{parent | consumed_at: parent.expires_at}

      Process.put({MutationFaultStore, :get_override}, fn
        ^parent_hash, _actual -> {:ok, forged_parent}
        _other_hash, actual -> actual
      end)

      assert {:error, :grant_revoked} =
               RefreshToken.rotate(MutationFaultStore, token,
                 now: parent.expires_at,
                 rotation_grace_seconds: 60
               )

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :recover_successor
      assert metadata.reason == :consumed_at_after_expiry
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      Process.delete({MutationFaultStore, :get_override})
    end

    test "recovery rejects successor context that changes any security-relevant parent field" do
      variants = [
        subject: "other-subject",
        client_id: "other-client",
        dpop_jkt: Attesto.Secret.hash("other-proof-key"),
        acr: "urn:example:other-acr",
        auth_time: 1,
        claims: %{"role" => "elevated"}
      ]

      for {field, replacement} <- variants do
        context = %{subject: "original-subject", scope: ["read"], client_id: "client-1"}
        {:ok, %{token: parent_token}} = RefreshToken.issue(MutationFaultStore, context, now: 1_000)

        assert {:ok, _} =
                 RefreshToken.rotate(MutationFaultStore, parent_token, client_id: "client-1", now: 1_000)

        parent_hash = Attesto.Secret.hash(parent_token)
        assert {:ok, parent} = ETS.get(parent_hash)
        forged_context = Map.put(parent.successor.context, field, replacement)
        forged_parent = put_in(parent, [:successor, :context], forged_context)

        Process.put({MutationFaultStore, :get_override}, fn
          ^parent_hash, _actual -> {:ok, forged_parent}
          _other_hash, actual -> actual
        end)

        assert {:error, :grant_revoked} =
                 RefreshToken.rotate(MutationFaultStore, parent_token,
                   client_id: "client-1",
                   now: 1_001
                 )

        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :recover_successor
        assert metadata.reason == :successor_state_invalid
        refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
        Process.delete({MutationFaultStore, :get_override})
      end
    end

    test "recovery rejects a child with inconsistent identity or consumption state" do
      corruptions = [
        fn child -> %{child | token_hash: "wrong-token-hash"} end,
        fn child -> %{child | consumed: false, consumed_at: 1_000} end,
        fn child -> %{child | consumed: true, consumed_at: nil} end
      ]

      for corrupt <- corruptions do
        {:ok, %{token: parent_token}} =
          RefreshToken.issue(MutationFaultStore, %{subject: "child-check", scope: ["read"]}, now: 1_000)

        assert {:ok, rotated} = RefreshToken.rotate(MutationFaultStore, parent_token, now: 1_000)
        parent_hash = Attesto.Secret.hash(parent_token)
        child_hash = Attesto.Secret.hash(rotated.token)
        assert {:ok, child} = ETS.get(child_hash)
        forged_child = corrupt.(child)

        Process.put({MutationFaultStore, :get_override}, fn
          ^child_hash, _actual -> {:ok, forged_child}
          _other_hash, actual -> actual
        end)

        assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, parent_token, now: 1_001)

        assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
        assert metadata.operation == :recover_successor
        assert metadata.reason == :successor_invalid
        refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
        Process.delete({MutationFaultStore, :get_override})
        assert :error = ETS.get(parent_hash)
      end
    end

    test "recovery accepts a live child whose optional state keys are omitted" do
      {:ok, %{token: parent_token}} =
        RefreshToken.issue(MutationFaultStore, %{subject: "optional-child-state"}, now: 1_000)

      assert {:ok, rotated} = RefreshToken.rotate(MutationFaultStore, parent_token, now: 1_000)
      child_hash = Attesto.Secret.hash(rotated.token)
      assert {:ok, child} = ETS.get(child_hash)
      child_without_optional_keys = Map.drop(child, [:consumed_at, :successor])

      Process.put({MutationFaultStore, :get_override}, fn
        ^child_hash, _actual -> {:ok, child_without_optional_keys}
        _other_hash, actual -> actual
      end)

      assert {:ok, retried} = RefreshToken.rotate(MutationFaultStore, parent_token, now: 1_001)
      assert retried.token == rotated.token
      refute_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, _}
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      Process.delete({MutationFaultStore, :get_override})
    end

    test "a malformed stored client binding is rejected before atomic rotate" do
      {:ok, %{token: token}} = RefreshToken.issue(MutationFaultStore, %{subject: "stored-client"})
      token_hash = Attesto.Secret.hash(token)
      assert {:ok, record} = ETS.get(token_hash)
      malformed = put_in(record, [:data, :client_id], 123)

      Process.put({MutationFaultStore, :get_override}, fn
        ^token_hash, _actual -> {:ok, malformed}
        _other_hash, actual -> actual
      end)

      assert_raise RuntimeError, "refresh store get/1 violated its contract", fn ->
        RefreshToken.rotate(MutationFaultStore, token)
      end

      refute_received :mutation_store_rotated
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :lookup
      assert metadata.reason == :store_contract_violation
      assert metadata.revocation == :succeeded
      assert metadata.family_id == record.family_id
      assert :error = ETS.get(token_hash)
    end

    test "zero grace sends a non-recoverable tombstone instead of plaintext" do
      {:ok, %{token: t0}} = RefreshToken.issue(RetryStateUnavailableStore, %{subject: "usr_strict"})

      assert {:ok, %{token: t1}} =
               RefreshToken.rotate(RetryStateUnavailableStore, t0,
                 now: 1_000,
                 rotation_grace_seconds: 0
               )

      assert_received {:atomic_rotate_called, %{retry_until: 1_000, recoverable: false}}
      refute_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, _}
      assert {:ok, _} = RefreshStore.ETS.get(Attesto.Secret.hash(t1))
    end

    test "a raising retry-state store is cleaned up, reported, and re-raised unchanged" do
      Process.put({ExceptionalRotateStore, :rotate_failure}, :raise)
      {:ok, %{token: t0}} = RefreshToken.issue(ExceptionalRotateStore, %{subject: "usr_store_raise"})

      assert_raise RuntimeError, "original rotate failure", fn ->
        RefreshToken.rotate(ExceptionalRotateStore, t0, now: 1_000)
      end

      assert_received :exceptional_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.reason == :store_raised
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "original rotate failure"
      assert :error = ETS.get(Attesto.Secret.hash(t0))
    end

    test "a throwing retry-state store keeps the original throw even when cleanup raises" do
      Process.put({ExceptionalRotateStore, :rotate_failure}, :throw)
      Process.put({ExceptionalRotateStore, :cleanup_failure}, true)
      {:ok, %{token: t0}} = RefreshToken.issue(ExceptionalRotateStore, %{subject: "usr_store_throw"})

      assert catch_throw(RefreshToken.rotate(ExceptionalRotateStore, t0, now: 1_000)) ==
               {:original_rotate_throw, "callback-private-value"}

      assert_received :exceptional_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.reason == :store_threw
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "callback-private-value"
      refute inspect(metadata) =~ "secondary cleanup failure"
    end

    test "an exiting retry-state store is cleaned up, reported, and exits unchanged" do
      Process.put({ExceptionalRotateStore, :rotate_failure}, :exit)
      {:ok, %{token: t0}} = RefreshToken.issue(ExceptionalRotateStore, %{subject: "usr_store_exit"})

      assert catch_exit(RefreshToken.rotate(ExceptionalRotateStore, t0, now: 1_000)) ==
               {:original_rotate_exit, "callback-private-exit-value"}

      assert_received :exceptional_store_cleanup_attempted
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.reason == :store_exited
      assert metadata.revocation == :succeeded
      refute inspect(metadata) =~ "callback-private-exit-value"
      assert :error = ETS.get(Attesto.Secret.hash(t0))
    end

    test "missing recovery state is an operational failure, not alleged reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_missing_state"}, now: 1_000)
      token_hash = Attesto.Secret.hash(t0)
      assert {:ok, _} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)
      assert {:ok, parent} = ETS.get(token_hash)

      Process.put({MutationFaultStore, :get_override}, fn
        ^token_hash, _actual -> {:ok, %{parent | successor: nil}}
        _other_hash, actual -> actual
      end)

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_001)

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.operation == :recover_successor
      assert metadata.reason == :successor_state_missing
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      Process.delete({MutationFaultStore, :get_override})
    end

    test "a retry bundle whose successor row is absent is not alleged reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_missing_child"}, now: 1_000)
      token_hash = Attesto.Secret.hash(t0)
      assert {:ok, _} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)
      assert {:ok, consumed} = ETS.get(token_hash)
      forged = put_in(consumed, [:successor, :token], "absent-successor-token")

      Process.put({MutationFaultStore, :get_override}, fn
        ^token_hash, _actual -> {:ok, forged}
        _other_hash, actual -> actual
      end)

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_001)

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.reason == :successor_missing
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      Process.delete({MutationFaultStore, :get_override})
    end

    test "a backward clock skew within configured grace recovers without alleging reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_clock"}, now: 1_000)
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)

      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 995)
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      refute_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, _}
    end

    test "a retry deadline before consumption is invalid state, not alleged reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(MutationFaultStore, %{subject: "usr_bad_deadline"}, now: 1_000)
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)

      token_hash = Attesto.Secret.hash(t0)
      assert {:ok, consumed} = ETS.get(token_hash)
      forged = put_in(consumed, [:successor, :retry_until], 999)

      Process.put({MutationFaultStore, :get_override}, fn
        ^token_hash, _actual -> {:ok, forged}
        _other_hash, actual -> actual
      end)

      assert {:error, :grant_revoked} = RefreshToken.rotate(MutationFaultStore, t0, now: 1_000)

      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}
      assert metadata.reason == :retry_deadline_invalid
      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      Process.delete({MutationFaultStore, :get_override})
    end

    test "a replay after the fixed retry deadline is actual reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_short_child"}, now: 1_000)

      assert {:ok, _} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_000,
                 ttl: 1,
                 rotation_grace_seconds: 10
               )

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_002,
                 rotation_grace_seconds: 10
               )

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      refute_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, _}
    end

    test "event metadata contains neither parent nor successor credentials or hashes" do
      {:ok, %{token: t0}} = RefreshToken.issue(RetryStateUnavailableStore, %{subject: "usr_no_credentials"})
      assert {:error, :temporarily_unavailable} = RefreshToken.rotate(RetryStateUnavailableStore, t0, now: 1_000)

      assert_received {:atomic_rotate_called, %{token: successor}}
      assert_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, metadata}

      encoded = inspect(metadata)
      refute encoded =~ t0
      refute encoded =~ Attesto.Secret.hash(t0)
      refute encoded =~ successor
      refute encoded =~ Attesto.Secret.hash(successor)
    end
  end

  describe "[:attesto, :refresh_token, :reuse_detected]" do
    test "fires when a rotated token is presented again, carrying the revoked family" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{
          subject: "usr_77",
          client_id: "oc_client",
          scope: ["documents.read"]
        })

      # Rotation is fail-closed on the client binding: a token issued with a
      # `client_id` must present a matching one.
      {:ok, _successor} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_client")

      # Outside the idempotency window the reuse is a captured-token signal.
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_client", now: future())

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], measurements, metadata}

      assert is_integer(measurements.system_time)
      assert is_binary(metadata.family_id)
      assert metadata.client_id == "oc_client"
      assert metadata.subject == "usr_77"
      assert metadata.revocation == :succeeded
    end

    test "a reuse alert survives a returned cleanup contract violation" do
      store = Attesto.TelemetryTest.MutationFaultStore
      t0 = rotated_parent!(store, "usr_reuse_contract")

      Process.put(
        {store, :revoke},
        {:return, {:unexpected_return, "cleanup-contract-private-sentinel"}}
      )

      error =
        assert_raise RuntimeError, "refresh store revoke_family/1 violated its contract", fn ->
          RefreshToken.rotate(store, t0, now: 1_001, rotation_grace_seconds: 0)
        end

      refute Exception.message(error) =~ "private-sentinel"

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.subject == "usr_reuse_contract"
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "private-sentinel"
    end

    test "a reuse alert survives and preserves a raising cleanup callback" do
      store = Attesto.TelemetryTest.MutationFaultStore
      t0 = rotated_parent!(store, "usr_reuse_raise")
      Process.put({store, :revoke}, {:raise, "original cleanup failure"})

      assert_raise RuntimeError, "original cleanup failure", fn ->
        RefreshToken.rotate(store, t0, now: 1_001, rotation_grace_seconds: 0)
      end

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.subject == "usr_reuse_raise"
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "original cleanup failure"
    end

    test "a reuse alert survives and preserves a thrown cleanup callback" do
      store = Attesto.TelemetryTest.MutationFaultStore
      t0 = rotated_parent!(store, "usr_reuse_throw")
      Process.put({store, :revoke}, {:throw, {:original_cleanup_throw, "private-throw-sentinel"}})

      assert catch_throw(
               RefreshToken.rotate(store, t0,
                 now: 1_001,
                 rotation_grace_seconds: 0
               )
             ) == {:original_cleanup_throw, "private-throw-sentinel"}

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.subject == "usr_reuse_throw"
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "private-throw-sentinel"
    end

    test "a reuse alert survives and preserves an exiting cleanup callback" do
      store = Attesto.TelemetryTest.MutationFaultStore
      t0 = rotated_parent!(store, "usr_reuse_exit")
      Process.put({store, :revoke}, {:exit, {:original_cleanup_exit, "private-exit-sentinel"}})

      assert catch_exit(
               RefreshToken.rotate(store, t0,
                 now: 1_001,
                 rotation_grace_seconds: 0
               )
             ) == {:original_cleanup_exit, "private-exit-sentinel"}

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.subject == "usr_reuse_exit"
      assert metadata.revocation == :failed
      refute inspect(metadata) =~ "private-exit-sentinel"
    end

    test "an ordinary successful rotation emits nothing" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_78"})
      {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0)

      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
    end

    # Routine refusals must not be events, or the signal above drowns.
    test "an unknown token emits nothing" do
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, "no-such-token")

      refute_received {:telemetry, _event, _measurements, _metadata}
    end

    # A real race cannot deterministically force the loser branch, so this
    # store returns the atomic contract's `{:reuse, record}` result directly.
    defmodule ReuseOnRotateStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @entry %{
        token_hash: Attesto.Secret.hash("presented"),
        family_id: "fam_concurrent",
        generation: 0,
        data: %{
          subject: "usr_concurrent",
          client_id: "oc_racer",
          scope: [],
          resource: [],
          claims: %{},
          dpop_jkt: nil,
          acr: nil,
          auth_time: nil
        },
        expires_at: 4_102_444_800,
        consumed: false,
        consumed_at: nil,
        successor: nil
      }

      @child %{
        token_hash: Attesto.Secret.hash("successor"),
        family_id: "fam_concurrent",
        generation: 1,
        data: %{
          subject: "usr_concurrent",
          client_id: "oc_racer",
          scope: [],
          resource: [],
          claims: %{},
          dpop_jkt: nil,
          acr: nil,
          auth_time: nil
        },
        expires_at: 4_102_444_800,
        consumed: false,
        consumed_at: nil,
        successor: nil
      }

      @committed %{
        @entry
        | consumed: true,
          consumed_at: 1_000,
          successor: %{
            token: "successor",
            generation: 1,
            context: @child.data,
            retry_until: 1_000,
            recoverable: false
          }
      }

      def entry, do: @entry

      @impl true
      def get(hash) when hash == @entry.token_hash, do: {:ok, @entry}
      def get(hash) when hash == @child.token_hash, do: {:ok, @child}
      @impl true
      def rotate(_hash, _child, _successor, _opts), do: {:reuse, @committed}
      @impl true
      def revoke_family(_family_id), do: :ok
      @impl true
      def insert(_entry), do: :ok
    end

    defmodule FamilyRevokedStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @entry ReuseOnRotateStore.entry()

      @impl true
      def get(_hash), do: {:ok, @entry}
      @impl true
      def rotate(_hash, _child, _successor, _opts), do: {:error, :family_revoked}
      @impl true
      def revoke_family(_family_id), do: :ok
      @impl true
      def insert(_entry), do: :ok
    end

    test "a strict concurrent claim losing to atomic rotate emits" do
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(ReuseOnRotateStore, "presented",
                 client_id: "oc_racer",
                 rotation_grace_seconds: 0
               )

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.family_id == "fam_concurrent"
      assert metadata.subject == "usr_concurrent"
      assert metadata.client_id == "oc_racer"
    end

    # This double reproduces the RETURN value of a revoked family but not its
    # cause, and the cause is the whole question: `revoke_family/1` is also what
    # an ordinary RFC 7009 revocation or a logout calls, so a family can be
    # revoked mid-rotation by a token presented exactly once. The library cannot
    # tell the two apart from this branch, so it denies without accusing.
    test "winning the claim and then finding the family revoked denies WITHOUT alleging reuse" do
      # `:grant_revoked`, not `:reuse_detected`: the return says what is known
      # (the family is gone) rather than what is not (why).
      assert {:error, :grant_revoked} = RefreshToken.rotate(FamilyRevokedStore, "presented", client_id: "oc_racer")

      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _},
                      "a concurrent logout must not page someone about a stolen credential"
    end

    test "metadata carries no credential material" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_79"})
      {:ok, %{token: successor}} = RefreshToken.rotate(RefreshStore.ETS, t0)
      {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: future())

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}

      encoded = inspect(metadata)
      refute encoded =~ t0, "the presented refresh token must not appear in metadata"
      refute encoded =~ successor, "the successor token must not appear in metadata"
    end

    test "a consumed expected successor is actual reuse, not a recovery-state fault" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_advanced_chain"}, now: 1_000)
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_001)

      assert {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_002)

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
      refute_received {:telemetry, [:attesto, :refresh_token, :rotation_state_failed], _, _}
    end

    defp rotated_parent!(store, subject) do
      {:ok, %{token: token}} = RefreshToken.issue(store, %{subject: subject}, now: 1_000)
      assert {:ok, _successor} = RefreshToken.rotate(store, token, now: 1_000, rotation_grace_seconds: 0)
      token
    end
  end

  describe "[:attesto, :dpop, :replay_detected]" do
    test "fires when the replay check refuses a jti" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {proof, _jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: "https://api.example.com/x")

      assert {:error, :replay} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example.com/x",
                 replay_check: fn _jti, _ttl -> {:error, :replay} end
               )

      assert_received {:telemetry, [:attesto, :dpop, :replay_detected], measurements, metadata}
      assert is_integer(measurements.system_time)
      assert is_binary(metadata.jti)
    end

    test "a first-use proof emits nothing" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {proof, _jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: "https://api.example.com/x")

      assert {:ok, _} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example.com/x",
                 replay_check: fn _jti, _ttl -> :ok end
               )

      refute_received {:telemetry, [:attesto, :dpop, :replay_detected], _, _}
    end
  end

  describe "[:attesto, :token, :sender_constraint_mismatch]" do
    setup do
      {:ok, config: Factory.config(Factory.rsa_pem())}
    end

    test "fires when a DPoP-bound token is presented under the wrong key", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))

      {:ok, %{access_token: token}} =
        Token.mint(config, principal(), dpop_jkt: bound)

      assert {:error, :dpop_binding_mismatch} = Token.verify(config, token, dpop_jkt: other)

      assert_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _measurements, metadata}
      assert metadata.binding == :dpop
      assert metadata.reason == :dpop_binding_mismatch
      assert metadata.client_id == "oc_abc"
    end

    # The event is documented as evidence a token has left its holder, so it
    # must not be ringable by someone who merely holds ANY sender-bound token
    # from this issuer. Presenting one under a second key at a resource whose
    # audience policy would refuse it anyway must be refused on the audience,
    # silently - otherwise the alarm is free to ring, and repeatedly, since a
    # failed verification never claims the proof's `jti`.
    test "a token this resource would refuse on audience does not ring the alarm", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      elsewhere = "https://elsewhere.example/api"

      {:ok, %{access_token: token}} =
        Token.mint(config, principal(), dpop_jkt: bound, audience: elsewhere)

      # This resource trusts a different audience, and is presented the token
      # under the wrong key: both checks would fail.
      assert {:error, reason} =
               Token.verify(config, token,
                 dpop_jkt: other,
                 trusted_audiences: fn _claims -> ["https://this-resource.example/api"] end
               )

      assert reason == :invalid_audience,
             "audience must be decided before the binding check that reports"

      refute_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, _}
    end

    test "an unbound token verified normally emits nothing", %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, principal())

      assert {:ok, _claims} = Token.verify(config, token)

      refute_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, _}
    end

    test "metadata carries no token material", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))

      {:ok, %{access_token: token}} = Token.mint(config, principal(), dpop_jkt: bound)
      {:error, :dpop_binding_mismatch} = Token.verify(config, token, dpop_jkt: other)

      assert_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, metadata}
      refute inspect(metadata) =~ token
    end
  end

  # `:telemetry.execute/3` catches a raising handler, detaches it, and logs, so
  # the refusal is never taken down by a bad handler. Attesto adds no catch of
  # its own: one would also swallow a dispatcher failure, and silently losing an
  # event whose purpose is to say a credential may be stolen is worse than
  # failing loudly - a missing event leaves nothing to notice later.
  describe "a failing handler does not change the outcome" do
    test "reuse detection still returns :reuse_detected" do
      :telemetry.attach(
        "attesto-telemetry-raiser",
        [:attesto, :refresh_token, :reuse_detected],
        fn _e, _m, _md, _c -> raise "handler blew up" end,
        nil
      )

      on_exit(fn -> :telemetry.detach("attesto-telemetry-raiser") end)

      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_80"})
      {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: future())
    end
  end

  defp future, do: DateTime.add(DateTime.utc_now(), 3600, :second)

  defp principal do
    %{kind: "client", sub: "oc_abc", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc"}}
  end
end
