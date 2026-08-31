defmodule Attesto.AuthorizationCodeRefreshBindingTest do
  @moduledoc false
  # The code store tracks replay metadata while the refresh store exercises the
  # family that was actually issued. Both reference stores are named
  # singletons, so this case is intentionally synchronous.
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore.ETS, as: CodeETS
  alias Attesto.PKCE
  alias Attesto.RefreshStore.ETS, as: RefreshETS
  alias Attesto.Secret

  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @redirect_uri "https://app.example.com/cb"
  @client_id "oc_app"

  defmodule TrackingStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def start_link, do: Agent.start_link(fn -> %{codes: %{}, consumed: %{}} end)
    def put_agent(pid), do: Process.put(__MODULE__, pid)
    defp agent, do: Process.get(__MODULE__)

    @impl Attesto.CodeStore
    def put(%{code_hash: code_hash} = record) do
      Agent.update(agent(), fn state -> %{state | codes: Map.put(state.codes, code_hash, record)} end)
    end

    @impl Attesto.CodeStore
    def take(code_hash) do
      Agent.get_and_update(agent(), fn state ->
        cond do
          Map.has_key?(state.consumed, code_hash) ->
            {{:error, :consumed, Map.fetch!(state.consumed, code_hash)}, state}

          Map.has_key?(state.codes, code_hash) ->
            {record, codes} = Map.pop(state.codes, code_hash)
            {{:ok, record}, %{state | codes: codes}}

          true ->
            {:error, state}
        end
      end)
    end

    @impl Attesto.CodeStore
    def mark_consumed(code_hash, meta) do
      case Process.get({__MODULE__, :mark_failure}) do
        {:return, value} ->
          value

        {:raise, reason} ->
          raise reason

        nil ->
          Agent.update(agent(), fn state -> %{state | consumed: Map.put(state.consumed, code_hash, meta)} end)
      end
    end
  end

  defmodule FailingRefreshStore do
    @moduledoc false

    def insert(_record), do: {:error, :family_revoked}
  end

  defmodule InvalidRefreshStore do
    @moduledoc false

    def insert(_record), do: {:unexpected, "refresh-store-contract-sentinel"}
  end

  setup do
    start_supervised!(CodeETS)
    start_supervised!(RefreshETS)
    {:ok, tracking_pid} = TrackingStore.start_link()
    TrackingStore.put_agent(tracking_pid)

    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  test "issue_refresh_and_finalize binds replay containment to the family it issues", %{
    challenge: challenge
  } do
    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42",
        scope: ["documents.read"],
        resource: ["https://api.example"],
        family_id: "authorization-request-provenance"
      })

    assert {:ok, %Grant{family_id: "authorization-request-provenance"} = grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    refresh_context = %{
      subject: grant.subject,
      scope: grant.scope,
      resource: grant.resource,
      client_id: grant.client_id,
      dpop_jkt: grant.dpop_jkt,
      claims: grant.claims
    }

    assert_raise ArgumentError, fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        Map.put(refresh_context, :family_id, "wrong-family"),
        now: 1_000
      )
    end

    assert_raise ArgumentError, "refresh context :subject must match the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{refresh_context | subject: "different-subject"},
        now: 1_000
      )
    end

    assert_raise ArgumentError, "refresh context :client_id must match the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{refresh_context | client_id: "different-client"},
        now: 1_000
      )
    end

    assert_raise ArgumentError, "refresh context :client_id must match the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        Map.delete(refresh_context, :client_id),
        now: 1_000
      )
    end

    assert_raise ArgumentError, "refresh context :scope must be a subset of the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{refresh_context | scope: grant.scope ++ ["admin.write"]},
        now: 1_000
      )
    end

    assert_raise ArgumentError, "refresh context :resource must be a subset of the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{refresh_context | resource: grant.resource ++ ["https://other.example"]},
        now: 1_000
      )
    end

    # The token-endpoint proof can bind the refresh credential to a key that
    # differs from an authorization-request DPoP binding.
    exchange_context = %{refresh_context | dpop_jkt: Secret.hash("token-endpoint-key")}

    assert {:ok, %{token: refresh_token, family_id: issued_family_id, generation: 0}} =
             AuthorizationCode.issue_refresh_and_finalize(
               TrackingStore,
               code,
               grant,
               RefreshETS,
               exchange_context,
               now: 1_000
             )

    refute issued_family_id == grant.family_id

    assert {:error, {:reuse, %{family_id: ^issued_family_id, subject: "usr_42"}}} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    assert :ok = RefreshETS.revoke_family(issued_family_id)
    assert :error = RefreshETS.get(Secret.hash(refresh_token))
  end

  test "refresh issuance failure leaves the spent code unfinalized", %{challenge: challenge} do
    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42"
      })

    assert {:ok, grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    assert {:error, :family_revoked} =
             AuthorizationCode.issue_refresh_and_finalize(
               TrackingStore,
               code,
               grant,
               FailingRefreshStore,
               %{subject: grant.subject, client_id: grant.client_id},
               now: 1_000
             )

    assert {:error, :invalid_grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })
  end

  test "a DPoP-bound grant permits confidential or bound public refresh tokens", %{challenge: challenge} do
    bound_jkt = Secret.hash("authorization-request-key")

    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42",
        dpop_jkt: bound_jkt
      })

    assert {:ok, %Grant{dpop_jkt: ^bound_jkt} = grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier,
               dpop_jkt: bound_jkt
             })

    refresh_context = %{subject: grant.subject, client_id: grant.client_id, dpop_jkt: bound_jkt}

    assert_raise ArgumentError, "refresh context :dpop_jkt must match the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{refresh_context | dpop_jkt: Secret.hash("different-key")},
        now: 1_000
      )
    end

    assert {:ok, %{family_id: confidential_family_id}} =
             AuthorizationCode.issue_refresh_and_finalize(
               TrackingStore,
               code,
               grant,
               RefreshETS,
               Map.delete(refresh_context, :dpop_jkt),
               now: 1_000
             )

    assert {:error, {:reuse, %{family_id: ^confidential_family_id}}} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier,
               dpop_jkt: bound_jkt
             })

    {:ok, public_code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42",
        dpop_jkt: bound_jkt
      })

    assert {:ok, %Grant{dpop_jkt: ^bound_jkt} = public_grant} =
             AuthorizationCode.redeem(TrackingStore, public_code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier,
               dpop_jkt: bound_jkt
             })

    assert {:ok, %{family_id: public_family_id}} =
             AuthorizationCode.issue_refresh_and_finalize(
               TrackingStore,
               public_code,
               public_grant,
               RefreshETS,
               %{subject: public_grant.subject, client_id: public_grant.client_id, dpop_jkt: bound_jkt},
               now: 1_000
             )

    assert {:error, {:reuse, %{family_id: ^public_family_id}}} =
             AuthorizationCode.redeem(TrackingStore, public_code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier,
               dpop_jkt: bound_jkt
             })
  end

  test "a DPoP-bound grant rejects a different refresh binding", %{challenge: challenge} do
    bound_jkt = Secret.hash("authorization-request-key")

    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42",
        dpop_jkt: bound_jkt
      })

    assert {:ok, %Grant{dpop_jkt: ^bound_jkt} = grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier,
               dpop_jkt: bound_jkt
             })

    assert_raise ArgumentError, "refresh context :dpop_jkt must match the redeemed grant", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{subject: grant.subject, client_id: grant.client_id, dpop_jkt: Secret.hash("different-key")},
        now: 1_000
      )
    end
  end

  test "refresh-store contract errors do not finalize the code", %{challenge: challenge} do
    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42"
      })

    assert {:ok, grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    error =
      assert_raise RuntimeError, "refresh store insert/1 violated its contract", fn ->
        AuthorizationCode.issue_refresh_and_finalize(
          TrackingStore,
          code,
          grant,
          InvalidRefreshStore,
          %{subject: grant.subject, client_id: grant.client_id},
          now: 1_000
        )
      end

    assert Exception.message(error) == "refresh store insert/1 violated its contract"

    assert {:error, :invalid_grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })
  end

  test "finalization contract errors never report successful issuance", %{challenge: challenge} do
    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42"
      })

    assert {:ok, grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    Process.put({TrackingStore, :mark_failure}, {:return, {:unexpected, "mark-sentinel"}})

    error =
      assert_raise RuntimeError, "authorization code store mark_consumed/2 violated its contract", fn ->
        AuthorizationCode.issue_refresh_and_finalize(
          TrackingStore,
          code,
          grant,
          RefreshETS,
          %{subject: grant.subject, client_id: grant.client_id},
          now: 1_000
        )
      end

    assert Exception.message(error) == "authorization code store mark_consumed/2 violated its contract"
    refute Exception.message(error) =~ "mark-sentinel"

    assert {:error, :invalid_grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    Process.delete({TrackingStore, :mark_failure})
  end

  test "finalization exceptions never report successful issuance", %{challenge: challenge} do
    {:ok, code} =
      AuthorizationCode.issue(TrackingStore, %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        subject: "usr_42"
      })

    assert {:ok, grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    Process.put({TrackingStore, :mark_failure}, {:raise, %RuntimeError{message: "mark callback failed"}})

    assert_raise RuntimeError, "mark callback failed", fn ->
      AuthorizationCode.issue_refresh_and_finalize(
        TrackingStore,
        code,
        grant,
        RefreshETS,
        %{subject: grant.subject, client_id: grant.client_id},
        now: 1_000
      )
    end

    assert {:error, :invalid_grant} =
             AuthorizationCode.redeem(TrackingStore, code, %{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               code_verifier: @verifier
             })

    Process.delete({TrackingStore, :mark_failure})
  end
end
