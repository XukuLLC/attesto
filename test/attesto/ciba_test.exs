defmodule Attesto.CIBATest do
  use ExUnit.Case, async: false

  alias Attesto.CIBA
  alias Attesto.CIBA.Grant
  alias Attesto.CIBA.Request
  alias Attesto.CIBAStore.ETS
  alias Attesto.CIBAStore.ETS, as: Store
  alias Attesto.Secret

  @now 1_700_000_000
  @max_exact_integer 9_007_199_254_740_991
  @client_id "ciba-client-1"
  @notification_token "8d67dc78-7faa-4d41-aabd-67707b374255"

  defmodule ContractStore do
    @moduledoc false
    @behaviour Attesto.CIBAStore

    @impl true
    def put(record), do: fault(:put, ETS.put(record))

    @impl true
    def lookup(hash) do
      result = ETS.lookup(hash)

      case Process.get({__MODULE__, :approve_after_lookup}) do
        {approval_hash, now} when approval_hash == hash ->
          Process.delete({__MODULE__, :approve_after_lookup})

          {:ok, _record} =
            ETS.approve(
              hash,
              %{subject: "usr_1", acr: nil, auth_time: now, granted_scope: nil, granted_claims: %{}},
              %{now: now}
            )

        _other ->
          :ok
      end

      fault(:lookup, result)
    end

    @impl true
    def approve(hash, approval, opts), do: fault(:approve, ETS.approve(hash, approval, opts))
    @impl true
    def deny(hash, opts), do: fault(:deny, ETS.deny(hash, opts))
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

  defp request(overrides \\ %{}) do
    struct!(
      Request,
      Map.merge(
        %{
          client_id: @client_id,
          delivery_mode: :poll,
          hint: {:login_hint, "user@example.com"},
          scope: ["openid", "accounts.read"]
        },
        overrides
      )
    )
  end

  defp issue(request_overrides \\ %{}, attrs \\ %{}, opts \\ []) do
    attrs = Map.merge(%{subject: "usr_1"}, attrs)
    {:ok, issued} = CIBA.issue(Store, request(request_overrides), attrs, Keyword.put_new(opts, :now, @now))
    issued
  end

  defp fault(callback, mode) do
    Process.put({ContractStore, callback}, mode)
  end

  defp clear_fault(callback) do
    Process.delete({ContractStore, callback})
  end

  defp approve_after_lookup(auth_req_id, now),
    do: Process.put({ContractStore, :approve_after_lookup}, {Secret.hash(auth_req_id), now})

  describe "issue/4 (§7.3 acknowledgement)" do
    test "returns an auth_req_id in the §7.3 charset with >=160 bits of entropy, plus expires_in and interval" do
      %{auth_req_id: id, expires_in: expires_in, interval: interval} = issue()

      assert id =~ ~r/\A[A-Za-z0-9._-]+\z/
      # 32 CSPRNG bytes → 43 base64url chars; well above the 160-bit floor (27 chars).
      assert byte_size(id) == 43
      assert expires_in == 120
      assert interval == 5
    end

    test "issued ids are unique across draws (CSPRNG)" do
      ids = for _ <- 1..50, do: issue().auth_req_id
      assert length(Enum.uniq(ids)) == 50
    end

    test "requires a subject (the hint must already be resolved)" do
      assert {:error, :invalid_subject} = CIBA.issue(Store, request(), %{})
      assert {:error, :invalid_subject} = CIBA.issue(Store, request(), %{subject: ""})
    end

    test "honours requested_expiry under the cap" do
      assert %{expires_in: 30} = issue(%{requested_expiry: 30})
      assert %{expires_in: 600} = issue(%{requested_expiry: 86_400})
      assert %{expires_in: 200} = issue(%{requested_expiry: 86_400}, %{}, max_expires_in: 200)
    end

    test "a push-mode request has no interval (nothing to poll)" do
      assert %{interval: nil} =
               issue(%{delivery_mode: :push, client_notification_token: @notification_token})
    end

    test "rejects forged request structs before storage" do
      invalid_overrides = [
        %{scope: []},
        %{scope: ["accounts.read"]},
        %{hint: {:login_hint, ""}},
        %{hint: {:unknown, "user@example.com"}},
        %{delivery_mode: :poll, client_notification_token: @notification_token},
        %{delivery_mode: :ping, client_notification_token: nil},
        %{delivery_mode: :unknown},
        %{binding_message: ""},
        %{binding_message: "line\nbreak"},
        %{user_code: ""},
        %{requested_expiry: 0},
        %{signed?: true, request_jti: nil, request_exp: nil},
        %{signed?: false, request_jti: "replay-id", request_exp: @now + 60},
        %{signed?: true, request_jti: "replay-id", request_exp: @now}
      ]

      for overrides <- invalid_overrides do
        result = CIBA.issue(Store, request(overrides), %{subject: "usr_1"}, now: @now)
        assert result == {:error, :invalid_request}, "accepted forged request fields: #{inspect(overrides)}"
      end
    end

    test "accepts a still-live validated signed request struct" do
      signed = request(%{signed?: true, request_jti: "replay-id", request_exp: @now + 60})
      assert {:ok, %{auth_req_id: id}} = CIBA.issue(Store, signed, %{subject: "usr_1"}, now: @now)
      assert is_binary(id)
    end

    test "approval rejects claims outside the portable JSON subset" do
      %{auth_req_id: id} = issue()

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
                 CIBA.approve(Store, id, %{subject: "usr_1", claims: claims}, now: @now + 1)

        assert {:ok, _record} = Store.lookup(Secret.hash(id))
      end
    end

    test "rejects negative clocks before put and leaves storage untouched" do
      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:put, {:return, {:private_put_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          CIBA.issue(ContractStore, request(), %{subject: "usr_1"}, now: bad_now)
        end

        clear_fault(:put)
        assert :ets.tab2list(Store) == []
      end
    end
  end

  describe "redeem/4 — CIBA Core §10.1/§11 state machine" do
    test "pending yields authorization_pending; approval then yields the grant; reuse is invalid_grant" do
      %{auth_req_id: id} = issue()

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)

      assert {:ok, _decision} =
               CIBA.approve(Store, id, %{subject: "usr_1", scope: ["openid"], acr: "urn:mace:phr"}, now: @now + 5)

      assert {:ok, %Grant{} = grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
      assert grant.client_id == @client_id
      assert grant.subject == "usr_1"
      assert grant.scope == ["openid"]
      assert grant.acr == "urn:mace:phr"
      assert grant.auth_time == @now + 5

      # Single-use: a second redemption of the consumed request is invalid_grant.
      assert {:error, :invalid_grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 20)
    end

    test "denial yields access_denied" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.deny(Store, id, now: @now + 5)
      assert {:error, :access_denied} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
    end

    test "an expired auth_req_id yields expired_token, even after approval (expiry wins)" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 5)
      assert {:error, :expired_token} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 121)
    end

    test "polling faster than the issued interval yields slow_down (§11)" do
      %{auth_req_id: id, interval: 5} = issue()

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      # Immediate re-poll within the interval.
      assert {:error, :slow_down} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)
      # After the interval, polling resumes.
      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 7)
    end

    test "a ping-mode record enforces the interval too (§10.2: a polling ping client is a poll client)" do
      %{auth_req_id: id} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      assert {:error, :slow_down} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)
    end

    test "the first token request after issuance is never slow_down" do
      %{auth_req_id: id} = issue()
      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now)
    end

    test "approval wins a poll race even inside the interval" do
      %{auth_req_id: id} = issue(%{}, %{}, interval: 100)

      assert {:error, :authorization_pending} =
               CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)

      approve_after_lookup(id, @now + 2)

      assert {:ok, %Grant{subject: "usr_1"}} =
               CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 3)
    end

    test "rejects negative clocks before lookup, approve, or deny and leaves the request untouched" do
      %{auth_req_id: id} = issue()
      hash = Secret.hash(id)

      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:lookup, {:return, {:private_lookup_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: bad_now)
        end

        clear_fault(:lookup)
        assert {:ok, %{status: :pending}} = ETS.lookup(hash)

        fault(:lookup, {:return, {:private_lookup_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          CIBA.approve(ContractStore, id, %{subject: "usr_1"}, now: bad_now)
        end

        clear_fault(:lookup)
        assert {:ok, %{status: :pending}} = ETS.lookup(hash)

        fault(:lookup, {:return, {:private_lookup_sentinel, bad_now}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          CIBA.deny(ContractStore, id, now: bad_now)
        end

        clear_fault(:lookup)
        assert {:ok, %{status: :pending}} = ETS.lookup(hash)
      end
    end

    test "an unknown auth_req_id is invalid_grant" do
      unknown = String.duplicate("a", 43)
      assert {:error, :invalid_grant} = CIBA.redeem(Store, unknown, %{client_id: @client_id}, now: @now)
    end

    test "a lookup result with an invalid stored status fails loudly without exposing it" do
      %{auth_req_id: id} = issue()
      sentinel = "ciba-store-private-sentinel"

      fault(
        :lookup,
        {:mutate_ok, fn record -> Map.put(record, :status, {:invalid_status, sentinel}) end}
      )

      error =
        assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
    end

    test "an approved stored decision must retain the requested subject" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      fault(:lookup, {:mutate_ok, fn record -> Map.put(record, :subject, "different-user") end})

      assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
        CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 2)
      end
    end

    test "an approved stored decision retains a reported ACR when one was requested" do
      %{auth_req_id: id} = issue(%{acr_values: ["urn:mace:phr"]})

      assert {:ok, _decision} =
               CIBA.approve(Store, id, %{subject: "usr_1", acr: "urn:mace:phr"}, now: @now + 1)

      fault(:lookup, {:mutate_ok, fn record -> Map.put(record, :acr, nil) end})

      assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
        CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 2)
      end
    end

    test "an approved stored decision cannot report authentication in the future" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      fault(:lookup, {:mutate_ok, fn record -> Map.put(record, :auth_time, @now + 10) end})

      assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
        CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 2)
      end
    end

    test "one-second approval clock skew is safe for both poll and ping redemption" do
      for {request_overrides, label} <- [
            {%{}, :poll},
            {%{client_notification_token: @notification_token, delivery_mode: :ping}, :ping}
          ] do
        %{auth_req_id: id} = issue(request_overrides)
        assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

        assert {:ok, %Grant{auth_time: auth_time}} =
                 CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now)

        assert auth_time == @now + 1
        assert label in [:poll, :ping]
      end
    end

    test "poll rejects a changed issue-time context and unexpected outcomes" do
      %{auth_req_id: id} = issue()
      sentinel = "private-poll-sentinel"

      fault(:poll, {:mutate_ok, fn record -> put_in(record, [:data, :client_id], sentinel) end})

      error =
        assert_raise RuntimeError, "CIBA store poll/2 violated its contract", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:poll)

      %{auth_req_id: id} = issue()
      fault(:poll, {:return, {:error, {:private_poll_sentinel, id}}})

      error =
        assert_raise RuntimeError, "CIBA store poll/2 violated its contract", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 1)
        end

      refute Exception.message(error) =~ id
    end

    test "a persisted CIBA context with an extra key violates the store contract" do
      %{auth_req_id: id} = issue()
      sentinel = "private-ciba-context-sentinel"

      fault(:lookup, {:mutate_ok, fn record -> put_in(record, [:data, :unexpected], sentinel) end})

      error =
        assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:lookup)
    end

    test "consume rejects malformed or materially changed records after atomically burning the request" do
      mutations = [
        fn record -> Map.delete(record, :subject) end,
        fn record -> Map.put(record, :auth_req_id_hash, "private-hash-sentinel") end,
        fn record -> put_in(record, [:data, :client_id], "private-client-sentinel") end,
        fn record -> Map.put(record, :granted_scope, ["private-scope-sentinel"]) end,
        fn record -> Map.put(record, :granted_claims, %{"nested" => %{role: :private_claims_sentinel}}) end,
        fn record -> Map.put(record, :auth_time, record.auth_time + 1) end,
        fn record -> Map.put(record, :expires_at, record.expires_at + 1) end,
        fn record -> Map.put(record, :status, :approved) end
      ]

      for mutate <- mutations do
        %{auth_req_id: id} = issue()
        assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
        fault(:consume, {:mutate_ok, mutate})

        error =
          assert_raise RuntimeError, "CIBA store consume/2 violated its contract", fn ->
            CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 10)
          end

        refute Exception.message(error) =~ "private-"
        clear_fault(:consume)

        assert {:error, :invalid_grant} =
                 CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 11)
      end
    end

    test "consume rejects an unexpected callback outcome without exposing it" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
      fault(:consume, {:return, {:error, {:private_consume_sentinel, id}}})

      error =
        assert_raise RuntimeError, "CIBA store consume/2 violated its contract", fn ->
          CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 10)
        end

      refute Exception.message(error) =~ id
    end

    test "consume permits a concurrently advanced poll timestamp" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
      fault(:consume, {:mutate_ok, fn record -> Map.put(record, :last_polled_at, @now + 11) end})

      assert {:ok, %Grant{subject: "usr_1"}} =
               CIBA.redeem(ContractStore, id, %{client_id: @client_id}, now: @now + 10)
    end

    test "a malformed auth_req_id fails closed before any store lookup" do
      # Outside the §7.3 charset / length floor: never hashed, never looked up.
      for bad <- ["", "short", "has space in it padpadpad", "bang!bang!bang!bang!"] do
        assert {:error, :invalid_grant} = CIBA.redeem(Store, bad, %{client_id: @client_id}, now: @now),
               "expected reject for #{inspect(bad)}"
      end
    end

    test "a client_id mismatch is invalid_grant and does not burn the request (§11: issued to another Client)" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} = CIBA.redeem(Store, id, %{client_id: "wrong"}, now: @now + 10)
      # The correct client still redeems (the mismatch did not consume it).
      assert {:ok, %Grant{}} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 16)
    end
  end

  describe "redeem/4 — push mode is not a token-endpoint grant (§11)" do
    test "an approved push-mode request is unauthorized_client and stays unconsumed" do
      %{auth_req_id: id} =
        issue(%{delivery_mode: :push, client_notification_token: @notification_token})

      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      # §11: a push-mode client MUST NOT redeem at the token endpoint.
      assert {:error, :unauthorized_client} =
               CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)

      # The rejection did not burn the single-use request: it is still approved,
      # not consumed (a repeat redeem sees the same non-minting outcome).
      assert {:error, :unauthorized_client} =
               CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 3)

      assert {:ok, %{status: :approved}} = CIBA.lookup(Store, id)
    end
  end

  describe "redeem/4 — validation precedes poll-interval throttling (§11)" do
    # A large interval so that a second token request always lands "inside the
    # interval"; the point is that throttling must never mask these outcomes.
    test "a wrong client cannot mutate the legit client's throttle state" do
      %{auth_req_id: id} = issue(%{}, %{}, interval: 100)

      # Wrong client is rejected AND must not set last_polled_at.
      assert {:error, :invalid_grant} = CIBA.redeem(Store, id, %{client_id: "wrong"}, now: @now + 1)

      # The legit client's first poll one second later is therefore
      # authorization_pending, never slow_down.
      assert {:error, :authorization_pending} =
               CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)
    end

    test "an expired request yields expired_token even inside the poll interval" do
      %{auth_req_id: id} = issue(%{requested_expiry: 30}, %{}, interval: 100)

      # A pending poll sets last_polled_at.
      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)

      # Now expired, but still within the 100s interval of the last poll:
      # expiry wins over slow_down.
      assert {:error, :expired_token} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 31)
    end

    test "an approved request yields the grant even inside the poll interval" do
      %{auth_req_id: id} = issue(%{}, %{}, interval: 100)

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 2)

      # Approval inside the interval must mint, not slow_down.
      assert {:ok, %Grant{}} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 3)
    end

    test "a denied request yields access_denied even inside the poll interval" do
      %{auth_req_id: id} = issue(%{}, %{}, interval: 100)

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      assert {:ok, _decision} = CIBA.deny(Store, id, now: @now + 2)

      assert {:error, :access_denied} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 3)
    end
  end

  describe "DPoP holder-of-key pre-binding (RFC 9449 §10)" do
    test "a request bound to a dpop_jkt redeems only with the matching proof key" do
      bound = Secret.hash("bound-ciba-key")
      wrong = Secret.hash("wrong-ciba-key")
      %{auth_req_id: id} = issue(%{}, %{dpop_jkt: bound})
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} =
               CIBA.redeem(Store, id, %{client_id: @client_id, dpop_jkt: wrong}, now: @now + 10)

      assert {:ok, %Grant{dpop_jkt: ^bound}} =
               CIBA.redeem(Store, id, %{client_id: @client_id, dpop_jkt: bound}, now: @now + 16)
    end
  end

  describe "approve/4 and deny/3 guards" do
    test "a decision is taken exactly once" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
      assert {:error, :already_decided} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 2)
      assert {:error, :already_decided} = CIBA.deny(Store, id, now: @now + 2)
    end

    test "a decision on an expired request is refused" do
      %{auth_req_id: id} = issue()
      assert {:error, :expired} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 121)
      assert {:error, :expired} = CIBA.deny(Store, id, now: @now + 121)
    end

    test "approval requires a subject, and it must be the user the request was issued for" do
      %{auth_req_id: id} = issue()

      assert {:error, :invalid_subject} = CIBA.approve(Store, id, %{}, now: @now + 1)
      # Fail-closed: approving as a different user than the hint resolved to.
      assert {:error, :subject_mismatch} = CIBA.approve(Store, id, %{subject: "usr_2"}, now: @now + 1)
      # The mismatch left the request pending for the right user.
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 2)
    end

    test "a requested ACR requires the host to report the achieved ACR" do
      %{auth_req_id: id} = issue(%{acr_values: ["urn:mace:phr"]})

      assert {:error, :invalid_acr} =
               CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:ok, _decision} =
               CIBA.approve(Store, id, %{subject: "usr_1", acr: "urn:mace:phr"}, now: @now + 2)
    end

    test "rejects future auth_time without mutating the pending request" do
      %{auth_req_id: id} = issue()

      assert {:error, :invalid_auth_time} =
               CIBA.approve(Store, id, %{subject: "usr_1", auth_time: @now + 2}, now: @now + 1)

      assert {:ok, _decision} =
               CIBA.approve(Store, id, %{subject: "usr_1", auth_time: @now}, now: @now + 2)
    end

    test "an unknown id is not_found; a malformed one is invalid_auth_req_id" do
      unknown = String.duplicate("a", 43)
      assert {:error, :not_found} = CIBA.approve(Store, unknown, %{subject: "usr_1"}, now: @now)
      assert {:error, :not_found} = CIBA.deny(Store, unknown, now: @now)
      assert {:error, :invalid_auth_req_id} = CIBA.approve(Store, "nope!", %{subject: "usr_1"}, now: @now)
      assert {:error, :invalid_auth_req_id} = CIBA.deny(Store, "nope!", now: @now)
    end

    test "both decisions return the ping-notification data (§10.2 fires on approval and denial)" do
      %{auth_req_id: approved} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:ok, decision} = CIBA.approve(Store, approved, %{subject: "usr_1"}, now: @now + 1)
      assert decision.delivery_mode == :ping
      assert decision.client_id == @client_id
      assert decision.client_notification_token == @notification_token

      %{auth_req_id: denied} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:ok, decision} = CIBA.deny(Store, denied, now: @now + 1)
      assert decision.client_notification_token == @notification_token
    end

    test "a poll-mode decision carries no notification token" do
      %{auth_req_id: id} = issue()

      assert {:ok, %{client_notification_token: nil, delivery_mode: :poll}} =
               CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
    end

    test "approve rejects changed transition records and unknown error reasons" do
      %{auth_req_id: id} = issue()
      sentinel = "private-approve-sentinel"
      fault(:approve, {:mutate_ok, fn record -> put_in(record, [:data, :client_id], sentinel) end})

      error =
        assert_raise RuntimeError, "CIBA store approve/3 violated its contract", fn ->
          CIBA.approve(ContractStore, id, %{subject: "usr_1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:approve)

      %{auth_req_id: id} = issue()
      fault(:approve, {:return, {:error, {:private_approve_sentinel, id}}})

      error =
        assert_raise RuntimeError, "CIBA store approve/3 violated its contract", fn ->
          CIBA.approve(ContractStore, id, %{subject: "usr_1"}, now: @now + 1)
        end

      refute Exception.message(error) =~ id
    end

    test "deny rejects malformed transition records and unknown error reasons" do
      %{auth_req_id: id} = issue()
      sentinel = "private-deny-sentinel"
      fault(:deny, {:mutate_ok, fn record -> Map.put(record, :status, {sentinel, :denied}) end})

      error =
        assert_raise RuntimeError, "CIBA store deny/2 violated its contract", fn ->
          CIBA.deny(ContractStore, id, now: @now + 1)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:deny)

      %{auth_req_id: id} = issue()
      fault(:deny, {:return, {:error, {:private_deny_sentinel, id}}})

      error =
        assert_raise RuntimeError, "CIBA store deny/2 violated its contract", fn ->
          CIBA.deny(ContractStore, id, now: @now + 1)
        end

      refute Exception.message(error) =~ id
    end
  end

  describe "lookup/2 (authentication-device view)" do
    test "returns the pending view for the approval UI" do
      %{auth_req_id: id} = issue(%{acr_values: ["urn:mace:phr"], binding_message: "S24R"})

      assert {:ok, view} = CIBA.lookup(Store, id)
      assert view.client_id == @client_id
      assert view.scope == ["openid", "accounts.read"]
      assert view.binding_message == "S24R"
      assert view.acr_values == ["urn:mace:phr"]
      assert view.subject == "usr_1"
      assert view.status == :pending
      assert view.delivery_mode == :poll
    end

    test "malformed input is rejected before the store lookup; unknown is :error" do
      assert {:error, :invalid_auth_req_id} = CIBA.lookup(Store, "bad id")
      assert :error = CIBA.lookup(Store, String.duplicate("a", 43))
    end

    test "malformed and unexpected store results fail loudly without exposing adapter data" do
      %{auth_req_id: id} = issue()
      sentinel = "private-lookup-sentinel"
      fault(:lookup, {:mutate_ok, fn record -> put_in(record, [:data, :scope], [sentinel, 7]) end})

      error =
        assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
          CIBA.lookup(ContractStore, id)
        end

      refute Exception.message(error) =~ sentinel
      clear_fault(:lookup)

      fault(:lookup, {:return, {:error, {sentinel, id}}})

      error =
        assert_raise RuntimeError, "CIBA store lookup/1 violated its contract", fn ->
          CIBA.lookup(ContractStore, id)
        end

      refute Exception.message(error) =~ id
    end
  end

  describe "grant context" do
    test "carries resource (RFC 8707) and falls back to the requested scope when approval grants none" do
      %{auth_req_id: id} = issue(%{}, %{resource: ["https://api.example.com"]})
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:ok, %Grant{} = grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
      assert grant.resource == ["https://api.example.com"]
      assert grant.scope == ["openid", "accounts.read"]
    end
  end

  describe "grant_type/0 and error_status/1" do
    test "exposes the CIBA grant type URN" do
      assert CIBA.grant_type() == "urn:openid:params:grant-type:ciba"
    end

    test "maps the §13 backchannel authentication endpoint statuses" do
      assert CIBA.error_status(:invalid_client) == 401
      assert CIBA.error_status(:access_denied) == 403

      for error <- [
            :invalid_request,
            :invalid_scope,
            :expired_login_hint_token,
            :unknown_user_id,
            :unauthorized_client,
            :missing_user_code,
            :invalid_user_code,
            :invalid_binding_message
          ] do
        assert CIBA.error_status(error) == 400
      end
    end
  end
end
