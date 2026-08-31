defmodule Attesto.AuthorizationCodeReuseTest do
  @moduledoc false
  # Code-reuse detection and the `:family_id` link (OAuth 2.0 Security BCP
  # §4.13 / RFC 6749 §4.1.2). Exercises issue/3 carrying a family_id onto
  # the redeemed Grant, and redeem/4 surfacing {:error, {:reuse, meta}}
  # when the store implements the optional reuse-tracking callbacks.
  #
  # async: true - each test uses its own in-process Agent-backed store
  # (started per test), so there is no shared singleton to serialize on.
  use ExUnit.Case, async: true

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.PKCE
  alias Attesto.Secret

  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @redirect_uri "https://app.example.com/cb"
  @client_id "oc_app"
  @subject "usr_42"
  @scope ["documents.read"]
  @family_id "fam_abc123"

  # --- A reuse-tracking CodeStore backed by a per-test Agent. ---
  #
  # Implements the OPTIONAL reuse-tracking pair: take/1 returns
  # {:error, :consumed, meta} for a hash already marked, and mark_consumed/2
  # records the meta. This is the store-side half code-reuse detection needs;
  # the ETS reference store deliberately does NOT implement it, so both paths
  # are covered (ETS in authorization_code_test.exs, this here).
  defmodule TrackingStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def start_link, do: Agent.start_link(fn -> %{codes: %{}, consumed: %{}} end)

    @impl Attesto.CodeStore
    def put(%{code_hash: code_hash} = record) do
      Agent.update(agent(), fn s -> %{s | codes: Map.put(s.codes, code_hash, record)} end)
    end

    @impl Attesto.CodeStore
    def take(code_hash) do
      Agent.get_and_update(agent(), fn s ->
        cond do
          Map.has_key?(s.consumed, code_hash) ->
            {{:error, :consumed, Map.fetch!(s.consumed, code_hash)}, s}

          Map.has_key?(s.codes, code_hash) ->
            {record, codes} = Map.pop(s.codes, code_hash)
            {{:ok, record}, %{s | codes: codes}}

          true ->
            {:error, s}
        end
      end)
    end

    @impl Attesto.CodeStore
    def mark_consumed(code_hash, meta) do
      Agent.update(agent(), fn s -> %{s | consumed: Map.put(s.consumed, code_hash, meta)} end)
    end

    # The agent pid is stashed in the process dictionary by the test setup so
    # the behaviour's arity-fixed callbacks (no store-state arg) can reach it.
    def put_agent(pid), do: Process.put(__MODULE__, pid)
    defp agent, do: Process.get(__MODULE__)
  end

  setup do
    {:ok, pid} = TrackingStore.start_link()
    TrackingStore.put_agent(pid)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp code_attrs(challenge, overrides \\ %{}) do
    Map.merge(
      %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        scope: @scope,
        subject: @subject
      },
      overrides
    )
  end

  defp redeem_params(overrides \\ %{}) do
    Map.merge(%{redirect_uri: @redirect_uri, code_verifier: @verifier, client_id: @client_id}, overrides)
  end

  describe "issue/3 family_id" do
    test "a family_id rides onto the redeemed Grant", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: @family_id}))

      assert {:ok, %Grant{family_id: @family_id}} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end

    test "family_id defaults to nil when omitted", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge))
      assert {:ok, %Grant{family_id: nil}} = AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end

    test "an empty family_id is invalid_family_id", %{challenge: challenge} do
      assert {:error, :invalid_family_id} =
               AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: ""}))
    end

    test "a non-binary family_id is invalid_family_id", %{challenge: challenge} do
      assert {:error, :invalid_family_id} =
               AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: 123}))
    end
  end

  describe "redeem/4 code-reuse detection (tracking store)" do
    test "a no-refresh finalize marker never carries authorization provenance as a family", %{
      challenge: challenge
    } do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: @family_id}))

      assert {:ok, %Grant{family_id: @family_id} = grant} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params())

      # The reuse marker is recorded by finalize/3 (the caller runs it only after
      # the full token response is built), not by redeem/4. Only then is a replay
      # a reuse attack.
      assert :ok = AuthorizationCode.finalize(TrackingStore, code, grant)

      assert {:error, {:reuse, %{family_id: nil, subject: @subject}}} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end

    test "reuse meta carries a nil family_id when the code had none", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge))
      assert {:ok, %Grant{} = grant} = AuthorizationCode.redeem(TrackingStore, code, redeem_params())
      assert :ok = AuthorizationCode.finalize(TrackingStore, code, grant)

      assert {:error, {:reuse, %{family_id: nil, subject: @subject}}} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end

    test "a redeem that validated but was never finalized is invalid_grant, not reuse", %{
      challenge: challenge
    } do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: @family_id}))

      # Redemption fully validates - but the caller's downstream issuance then
      # fails, so finalize/3 is NEVER called (the atomicity contract). The code
      # is single-use-spent, but a re-presentation (e.g. the client retrying a
      # transient failure) must be a clean invalid_grant, NOT a reuse attack that
      # would wrongly revoke the family.
      assert {:ok, %Grant{family_id: @family_id}} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params())

      assert {:error, :invalid_grant} = AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end

    test "a never-issued code is still invalid_grant, not reuse", %{challenge: _challenge} do
      assert {:error, :invalid_grant} =
               AuthorizationCode.redeem(TrackingStore, Secret.generate(), redeem_params())
    end

    test "a failed redeem does not mark consumed: the re-presentation is invalid_grant", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(TrackingStore, code_attrs(challenge, %{family_id: @family_id}))

      # First attempt fails PKCE. take/1 still spent the code (single use),
      # but no successful redemption means no consumed marker was written.
      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(TrackingStore, code, redeem_params(%{code_verifier: String.duplicate("z", 50)}))

      # So the second presentation finds the code absent and unmarked:
      # invalid_grant, NOT reuse. (We never validated a family to revoke.)
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(TrackingStore, code, redeem_params())
    end
  end
end
