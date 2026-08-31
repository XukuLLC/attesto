defmodule Attesto.DeviceCodeTest do
  use ExUnit.Case, async: false

  alias Attesto.DeviceCode
  alias Attesto.DeviceCode.Grant
  alias Attesto.DeviceCodeStore.ETS
  alias Attesto.DeviceCodeStore.ETS, as: Store
  alias Attesto.Secret

  @now 1_700_000_000
  @max_exact_integer 9_007_199_254_740_991

  defmodule ContractStore do
    @moduledoc false
    @behaviour Attesto.DeviceCodeStore

    @impl true
    def put(record), do: fault(:put, ETS.put(record))
    @impl true
    def lookup_user_code(user_code), do: fault(:lookup_user_code, ETS.lookup_user_code(user_code))
    @impl true
    def get(hash) do
      result = ETS.get(hash)

      case Process.get({__MODULE__, :approve_after_get}) do
        {user_code, now} ->
          Process.delete({__MODULE__, :approve_after_get})
          {:ok, _record} = ETS.approve(String.replace(user_code, "-", ""), %{subject: "usr_1"}, %{now: now})

        nil ->
          :ok
      end

      fault(:get, result)
    end

    @impl true
    def approve(user_code, approval, opts), do: fault(:approve, ETS.approve(user_code, approval, opts))
    @impl true
    def deny(user_code, opts), do: fault(:deny, ETS.deny(user_code, opts))

    @impl true
    def poll(hash, opts), do: fault(:poll, ETS.poll(hash, opts))

    @impl true
    def consume(hash, opts), do: fault(:consume, ETS.consume(hash, opts))

    defp fault(callback, result) do
      case Process.get({__MODULE__, callback}) do
        nil -> result
        {:return, value} -> value
        {:mutate_ok, mutator} -> mutate_ok(result, mutator)
      end
    end

    defp mutate_ok({:ok, record}, mutator), do: {:ok, mutator.(record)}
    defp mutate_ok(other, _mutator), do: other
  end

  setup do
    start_supervised!(Store)
    Store.reset()
    :ok
  end

  defp issue(attrs \\ %{}, opts \\ []) do
    attrs = Map.merge(%{client_id: "cli-1", scope: ["read"]}, attrs)
    {:ok, issued} = DeviceCode.issue(Store, attrs, Keyword.put_new(opts, :now, @now))
    issued
  end

  defp fault(callback, mode) do
    Process.put({ContractStore, callback}, mode)
  end

  defp clear_fault(callback) do
    Process.delete({ContractStore, callback})
  end

  defp approve_after_get(user_code, now), do: Process.put({ContractStore, :approve_after_get}, {user_code, now})

  describe "issue/3" do
    test "returns a device code and a display-formatted user code" do
      %{device_code: dc, user_code: uc} = issue()
      assert is_binary(dc) and byte_size(dc) > 20
      # Display form: BCDF-GHJK (hyphenated groups of 4 from the base-20 alphabet).
      assert uc =~ ~r/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/
    end

    test "rejects a missing client_id" do
      assert {:error, :invalid_client_id} = DeviceCode.issue(Store, %{scope: ["read"]})
    end

    test "retries on a user_code collision and gives up after the bounded retries" do
      # A store that always reports the user_code as taken exhausts the retries.
      defmodule AlwaysTakenStore do
        def put(_record), do: {:error, :user_code_taken}
      end

      assert {:error, :user_code_unavailable} =
               DeviceCode.issue(AlwaysTakenStore, %{client_id: "cli-1"})
    end

    test "generated user codes are well-formed and varied (CSPRNG)" do
      codes = for _ <- 1..50, do: DeviceCode.generate_user_code()
      assert Enum.all?(codes, &(&1 =~ ~r/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/))
      # 50 draws from ~34.6 bits should be unique with overwhelming probability.
      assert length(Enum.uniq(codes)) == 50
    end

    test "rejects invalid TTL and user-code length before storage" do
      for ttl <- [0, -1, 1.5, "600", nil] do
        assert_raise ArgumentError, ":ttl must be a positive integer", fn ->
          DeviceCode.issue(ContractStore, %{client_id: "cli-1"}, ttl: ttl, now: @now)
        end
      end

      for length <- [0, 7, 65, 1.5, "8", nil] do
        assert_raise ArgumentError, ~r/:user_code_length must be an integer/, fn ->
          DeviceCode.issue(ContractStore, %{client_id: "cli-1"}, user_code_length: length, now: @now)
        end
      end
    end

    test "rejects negative clocks before put, get, approve, or deny and leaves storage untouched" do
      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:put, {:return, {:private_put_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          DeviceCode.issue(ContractStore, %{client_id: "cli-1"}, now: bad_now)
        end

        clear_fault(:put)
        assert :ets.tab2list(Store) == []
      end

      %{device_code: dc, user_code: uc} = issue()

      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:get, {:return, {:private_get_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: bad_now)
        end

        clear_fault(:get)
        assert {:ok, %{status: :pending}} = DeviceCode.lookup(Store, uc)

        fault(:lookup_user_code, {:return, {:private_lookup_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          DeviceCode.approve(ContractStore, uc, %{subject: "usr_1"}, now: bad_now)
        end

        clear_fault(:lookup_user_code)
        assert {:ok, %{status: :pending}} = DeviceCode.lookup(Store, uc)

        fault(:lookup_user_code, {:return, {:private_lookup_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          DeviceCode.deny(ContractStore, uc, now: bad_now)
        end

        clear_fault(:lookup_user_code)
        assert {:ok, %{status: :pending}} = DeviceCode.lookup(Store, uc)
      end
    end

    test "supports a configured user-code length end to end" do
      %{device_code: dc, user_code: uc} = issue(%{}, user_code_length: 12)

      assert String.length(String.replace(uc, "-", "")) == 12
      assert {:ok, %{user_code: normalized}} = DeviceCode.lookup(Store, uc, user_code_length: 12)
      assert normalized == String.replace(uc, "-", "")

      assert :ok =
               DeviceCode.approve(Store, uc, %{subject: "usr_1"},
                 now: @now,
                 user_code_length: 12
               )

      assert {:ok, %Grant{subject: "usr_1"}} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1, interval: 0)
    end

    test "approval rejects claims outside the portable JSON subset" do
      %{user_code: uc} = issue()

      for claims <- [
            %{role: "admin"},
            %{"nested" => %{role: "admin"}},
            %{"items" => [self()]},
            %{<<255>> => "bad"},
            %{"float" => 1.5},
            %{"float" => 1.0e100},
            %{"integer" => @max_exact_integer + 1},
            %{"integer" => -@max_exact_integer - 1}
          ] do
        assert {:error, :invalid_claims} =
                 DeviceCode.approve(Store, uc, %{subject: "usr_1", claims: claims}, now: @now + 1)

        assert {:ok, %{status: :pending}} = DeviceCode.lookup(Store, uc)
      end
    end
  end

  describe "user_code normalization (fail-closed)" do
    test "normalizes case + separators and validates the charset/length" do
      assert {:ok, "BCDFGHJK"} = DeviceCode.normalize_user_code("bcdf-ghjk")
      assert {:ok, "BCDFGHJK"} = DeviceCode.normalize_user_code("BCDF GHJK")
    end

    test "rejects out-of-alphabet, wrong-length, and ambiguous characters" do
      for bad <- ["BCDF-GHJ", "BCDFGHJKL", "AEIO-UEIO", "BCDF-GH0K", "BCDF-GH1K", ""] do
        assert {:error, :invalid_user_code} = DeviceCode.normalize_user_code(bad), "expected reject for #{inspect(bad)}"
      end
    end
  end

  describe "redeem/4 — RFC 8628 §3.5 state machine" do
    test "pending yields authorization_pending; approval then yields the grant; reuse is invalid_grant" do
      %{device_code: dc, user_code: uc} = issue()

      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1)

      assert :ok =
               DeviceCode.approve(
                 Store,
                 uc,
                 %{subject: "usr_1", scope: ["read"], claims: %{"acr" => "phr"}},
                 now: @now + 2
               )

      assert {:ok, %Grant{client_id: "cli-1", subject: "usr_1", scope: ["read"], claims: %{"acr" => "phr"}}} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 10)

      # Single-use: a second redemption of the consumed code is invalid_grant.
      assert {:error, :invalid_grant} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 20)
    end

    test "deny yields access_denied" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.deny(Store, uc, now: @now + 1)
      assert {:error, :access_denied} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 10)
    end

    test "an expired approved code cannot be consumed or minted (expiry wins)" do
      %{device_code: dc, user_code: uc} = issue(%{}, ttl: 600)
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)

      # The store guard is authoritative even if the core's earlier read saw
      # the approved record before the expiry boundary.
      hash = Secret.hash(dc)
      assert :error = Store.consume(hash, %{now: @now + 600})
      assert {:ok, %{status: :approved}} = Store.get(hash)

      assert {:error, :expired_token} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 600)
      assert {:ok, %{status: :approved}} = Store.get(hash)
    end

    test "polling faster than the interval yields slow_down" do
      %{device_code: dc} = issue()
      # First poll accepted (pending).
      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1, interval: 5)

      # Immediate re-poll within the interval.
      assert {:error, :slow_down} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 2, interval: 5)
      # After the interval, polling resumes.
      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 7, interval: 5)
    end

    test "approval wins a poll race even inside the interval" do
      %{device_code: dc, user_code: uc} = issue(%{}, interval: 100)

      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1, interval: 100)

      approve_after_get(uc, @now + 2)

      assert {:ok, %Grant{subject: "usr_1"}} =
               DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 3, interval: 100)
    end

    test "an unauthorized poll does not consume the client's throttle window" do
      %{device_code: dc} = issue()

      assert {:error, :invalid_grant} =
               DeviceCode.redeem(Store, dc, %{client_id: "wrong"}, now: @now + 1, interval: 5)

      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1, interval: 5)
    end

    test "a DPoP mismatch does not consume the client's throttle window" do
      bound = Secret.hash("bound-device-key")
      wrong = Secret.hash("wrong-device-key")
      %{device_code: dc} = issue(%{dpop_jkt: bound})

      assert {:error, :invalid_grant} =
               DeviceCode.redeem(
                 Store,
                 dc,
                 %{client_id: "cli-1", dpop_jkt: wrong},
                 now: @now + 1,
                 interval: 5
               )

      assert {:error, :authorization_pending} =
               DeviceCode.redeem(
                 Store,
                 dc,
                 %{client_id: "cli-1", dpop_jkt: bound},
                 now: @now + 1,
                 interval: 5
               )
    end

    test "rejects an invalid poll interval before reading storage" do
      for interval <- [-1, 1.5, "5", nil] do
        assert_raise ArgumentError, ":interval must be a non-negative integer", fn ->
          DeviceCode.redeem(ContractStore, "never-issued", %{client_id: "cli-1"},
            now: @now,
            interval: interval
          )
        end
      end
    end

    test "an unknown device code is invalid_grant" do
      assert {:error, :invalid_grant} = DeviceCode.redeem(Store, "never-issued", %{client_id: "cli-1"}, now: @now)
    end

    test "malformed and unexpected get results fail loudly without exposing adapter data" do
      %{device_code: dc} = issue()
      sentinel = "device-code-get-private-sentinel"

      fault(:get, {:mutate_ok, fn record -> put_in(record, [:data, :client_id], {sentinel}) end})

      error =
        assert_raise RuntimeError, "device code store get/1 violated its contract", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:get)

      fault(:get, {:return, {:error, {sentinel, dc}}})

      error =
        assert_raise RuntimeError, "device code store get/1 violated its contract", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ dc
    end

    test "a persisted device context with an extra key violates the store contract" do
      %{device_code: dc} = issue()
      sentinel = "device-code-context-private-sentinel"

      fault(:get, {:mutate_ok, fn record -> put_in(record, [:data, :unexpected], sentinel) end})

      error =
        assert_raise RuntimeError, "device code store get/1 violated its contract", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:get)
    end

    test "a poll result with an invalid stored status fails loudly without exposing it" do
      %{device_code: dc} = issue()
      sentinel = "device-code-store-private-sentinel"

      fault(
        :poll,
        {:mutate_ok, fn record -> Map.put(record, :status, {:invalid_status, sentinel}) end}
      )

      error =
        assert_raise RuntimeError, "device code store poll/2 violated its contract", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
    end

    test "an approved stored record cannot widen its granted scope" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)

      fault(:get, {:mutate_ok, fn record -> Map.put(record, :granted_scope, ["read", "admin"]) end})

      assert_raise RuntimeError, "device code store get/1 violated its contract", fn ->
        DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 2, interval: 0)
      end
    end

    test "consume rejects malformed or materially changed records after atomically burning the code" do
      mutations = [
        fn record -> Map.delete(record, :subject) end,
        fn record -> Map.put(record, :device_code_hash, "private-hash-sentinel") end,
        fn record -> put_in(record, [:data, :client_id], "private-client-sentinel") end,
        fn record -> Map.put(record, :granted_scope, ["private-scope-sentinel"]) end,
        fn record -> Map.put(record, :granted_claims, %{"nested" => %{role: :private_claims_sentinel}}) end,
        fn record -> Map.put(record, :expires_at, record.expires_at + 1) end,
        fn record -> Map.put(record, :status, :approved) end
      ]

      for mutate <- mutations do
        %{device_code: dc, user_code: uc} = issue()
        assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)
        fault(:consume, {:mutate_ok, mutate})

        error =
          assert_raise RuntimeError, "device code store consume/2 violated its contract", fn ->
            DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 10, interval: 0)
          end

        refute Exception.message(error) =~ "private-"
        clear_fault(:consume)

        assert {:error, :invalid_grant} =
                 DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 11, interval: 0)
      end
    end

    test "consume rejects an unexpected callback outcome without exposing it" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)
      fault(:consume, {:return, {:error, {:private_consume_sentinel, dc}}})

      error =
        assert_raise RuntimeError, "device code store consume/2 violated its contract", fn ->
          DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 10, interval: 0)
        end

      refute Exception.message(error) =~ dc
    end

    test "consume permits a concurrently advanced poll timestamp" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)
      fault(:consume, {:mutate_ok, fn record -> Map.put(record, :last_polled_at, @now + 11) end})

      assert {:ok, %Grant{subject: "usr_1"}} =
               DeviceCode.redeem(ContractStore, dc, %{client_id: "cli-1"}, now: @now + 10, interval: 0)
    end

    test "a client_id mismatch is invalid_grant and does not burn the code" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} = DeviceCode.redeem(Store, dc, %{client_id: "wrong"}, now: @now + 10, interval: 0)
      # The correct client still redeems (the mismatch did not consume it).
      assert {:ok, %Grant{}} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 11, interval: 0)
    end
  end

  describe "DPoP holder-of-key pre-binding (RFC 9449 §10)" do
    test "a code bound to a dpop_jkt redeems only with the matching proof key" do
      bound = Secret.hash("bound-device-key")
      wrong = Secret.hash("wrong-device-key")
      %{device_code: dc, user_code: uc} = issue(%{dpop_jkt: bound})
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1", dpop_jkt: wrong},
                 now: @now + 10,
                 interval: 0
               )

      assert {:ok, %Grant{dpop_jkt: ^bound}} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1", dpop_jkt: bound},
                 now: @now + 11,
                 interval: 0
               )
    end
  end

  describe "approve/deny guards" do
    test "approving a non-pending code is refused (decided once)" do
      %{user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"}, now: @now + 1)
      assert {:error, :already_decided} = DeviceCode.approve(Store, uc, %{subject: "usr_2"}, now: @now + 2)
      assert {:error, :already_decided} = DeviceCode.deny(Store, uc, now: @now + 2)
    end

    test "approve requires a subject" do
      %{user_code: uc} = issue()
      assert {:error, :invalid_subject} = DeviceCode.approve(Store, uc, %{}, now: @now + 1)
    end

    test "an unknown user_code is not_found; a malformed one is invalid_user_code" do
      assert {:error, :not_found} = DeviceCode.approve(Store, "BCDF-GHJK", %{subject: "usr_1"})
      assert {:error, :invalid_user_code} = DeviceCode.approve(Store, "nope", %{subject: "usr_1"})
    end

    test "unexpected approve and deny outcomes fail loudly without exposing adapter data" do
      %{user_code: approve_code} = issue()
      fault(:approve, {:return, {:error, {:private_decision_sentinel, approve_code}}})

      error =
        assert_raise RuntimeError, "device code store approve/3 violated its contract", fn ->
          DeviceCode.approve(ContractStore, approve_code, %{subject: "usr_1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ approve_code
      clear_fault(:approve)

      %{user_code: deny_code} = issue()
      fault(:deny, {:return, {:error, {:private_decision_sentinel, deny_code}}})

      error =
        assert_raise RuntimeError, "device code store deny/2 violated its contract", fn ->
          DeviceCode.deny(ContractStore, deny_code, now: @now + 1)
        end

      refute Exception.message(error) =~ deny_code
    end

    test "refuses decisions at the expiry boundary without mutating the code" do
      %{user_code: approve_code} = issue(%{}, ttl: 10)

      assert {:error, :expired} =
               DeviceCode.approve(Store, approve_code, %{subject: "usr_1"}, now: @now + 10)

      assert {:ok, %{status: :pending}} = Store.lookup_user_code(String.replace(approve_code, "-", ""))

      %{user_code: deny_code} = issue(%{}, ttl: 10)
      assert {:error, :expired} = DeviceCode.deny(Store, deny_code, now: @now + 10)
      assert {:ok, %{status: :pending}} = Store.lookup_user_code(String.replace(deny_code, "-", ""))
    end
  end

  describe "lookup/2 (verification page view)" do
    test "returns the pending view for the user to confirm" do
      %{user_code: uc} = issue(%{scope: ["read", "write"]})
      assert {:ok, view} = DeviceCode.lookup(Store, uc)
      assert view.client_id == "cli-1"
      assert view.scope == ["read", "write"]
      assert view.status == :pending
    end

    test "malformed input is rejected before the store lookup" do
      assert {:error, :invalid_user_code} = DeviceCode.lookup(Store, "bad")
    end

    test "malformed and unexpected store results fail loudly without exposing adapter data" do
      %{user_code: uc} = issue()
      sentinel = "private-lookup-sentinel"

      fault(
        :lookup_user_code,
        {:mutate_ok, fn record -> put_in(record, [:data, :client_id], {sentinel, uc}) end}
      )

      error =
        assert_raise RuntimeError, "device code store lookup_user_code/1 violated its contract", fn ->
          DeviceCode.lookup(ContractStore, uc)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:lookup_user_code)

      fault(:lookup_user_code, {:return, {:error, {sentinel, uc}}})

      error =
        assert_raise RuntimeError, "device code store lookup_user_code/1 violated its contract", fn ->
          DeviceCode.lookup(ContractStore, uc)
        end

      refute Exception.message(error) =~ uc
    end
  end
end
