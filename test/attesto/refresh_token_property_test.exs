defmodule Attesto.RefreshTokenPropertyTest do
  @moduledoc false
  # Refresh-token lifecycle properties over the ETS reference store.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Secret

  @scopes ~w(openid profile email documents.read documents.write reports.read offline_access)

  setup do
    start_supervised!(RefreshStore.ETS)
    RefreshStore.ETS.reset()
    :ok
  end

  describe "rotation lifecycle" do
    property "successive rotations stay in one family and advance generation by one" do
      check all(
              subject_suffix <- suffix_generator(),
              scopes <- list_of(member_of(@scopes), min_length: 1, max_length: 8),
              chain_length <- integer(1..5),
              max_runs: 60
            ) do
        :ok = RefreshStore.ETS.reset()
        scope = Enum.uniq(scopes)

        assert {:ok, issued} =
                 RefreshToken.issue(RefreshStore.ETS, %{
                   subject: "usr_" <> subject_suffix,
                   scope: scope,
                   claims: %{"tenant" => "t-" <> subject_suffix}
                 })

        final =
          Enum.reduce(1..chain_length, issued, fn expected_generation, current ->
            assert {:ok, rotated} = RefreshToken.rotate(RefreshStore.ETS, current.token)
            assert rotated.family_id == issued.family_id
            assert rotated.generation == expected_generation
            assert rotated.context.subject == "usr_" <> subject_suffix
            assert rotated.context.scope == scope
            assert rotated.context.claims == %{"tenant" => "t-" <> subject_suffix}
            refute rotated.token == current.token
            rotated
          end)

        assert final.family_id == issued.family_id
        assert final.generation == chain_length
      end
    end

    property "scope requests can only narrow the original grant" do
      check all(
              granted_input <- list_of(member_of(@scopes), min_length: 1, max_length: 10),
              requested <- list_of(member_of(@scopes), max_length: 6),
              max_runs: 80
            ) do
        :ok = RefreshStore.ETS.reset()
        granted = Enum.uniq(granted_input)
        assert {:ok, %{token: token}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_scope", scope: granted})

        expected_requested = Enum.uniq(requested)

        if Enum.all?(expected_requested, &(&1 in granted)) do
          assert {:ok, rotated} = RefreshToken.rotate(RefreshStore.ETS, token, scope: requested)
          assert rotated.context.scope == expected_requested
        else
          assert {:error, :invalid_scope} = RefreshToken.rotate(RefreshStore.ETS, token, scope: requested)
          assert {:ok, _rotated} = RefreshToken.rotate(RefreshStore.ETS, token, scope: granted)
        end
      end
    end

    property "recoverable validation failures do not consume the token" do
      check all(
              failure <- member_of([:client_missing, :client_wrong, :dpop_missing, :dpop_wrong, :scope_widen]),
              max_runs: 80
            ) do
        :ok = RefreshStore.ETS.reset()
        bound_jkt = Secret.hash("bound-key")

        context = %{
          subject: "usr_recoverable",
          scope: ["documents.read"],
          client_id: "oc_client",
          dpop_jkt: bound_jkt
        }

        good_opts = [client_id: "oc_client", dpop_jkt: bound_jkt]

        {bad_opts, expected_error} =
          case failure do
            :client_missing -> {[dpop_jkt: bound_jkt], :client_required}
            :client_wrong -> {[client_id: "oc_other", dpop_jkt: bound_jkt], :client_mismatch}
            :dpop_missing -> {[client_id: "oc_client"], :dpop_proof_required}
            :dpop_wrong -> {[client_id: "oc_client", dpop_jkt: Secret.hash("wrong-key")], :dpop_binding_mismatch}
            :scope_widen -> {[client_id: "oc_client", dpop_jkt: bound_jkt, scope: ["documents.write"]], :invalid_scope}
          end

        assert {:ok, %{token: token}} = RefreshToken.issue(RefreshStore.ETS, context)
        assert {:error, ^expected_error} = RefreshToken.rotate(RefreshStore.ETS, token, bad_opts)
        assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, token, good_opts)
      end
    end

    property "replaying any consumed generation after grace revokes the live family" do
      check all(chain_length <- integer(1..5), replay_index <- integer(0..4), max_runs: 60) do
        :ok = RefreshStore.ETS.reset()
        assert {:ok, issued} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_reuse", scope: ["openid"]})

        tokens =
          Enum.reduce(1..chain_length, [issued], fn _step, acc ->
            current = List.last(acc)
            assert {:ok, rotated} = RefreshToken.rotate(RefreshStore.ETS, current.token)
            acc ++ [rotated]
          end)

        consumed_count = length(tokens) - 1
        stale = Enum.at(tokens, rem(replay_index, consumed_count))
        live = List.last(tokens)

        assert {:error, :reuse_detected} =
                 RefreshToken.rotate(RefreshStore.ETS, stale.token, rotation_grace_seconds: 0)

        assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, live.token)
      end
    end

    property "a consumed parent expiry caps every persisted retry deadline" do
      check all(
              issued_grace <- integer(1..60),
              parent_ttl <- integer(1..issued_grace),
              max_runs: 80
            ) do
        :ok = RefreshStore.ETS.reset()
        now = 1_000

        assert {:ok, %{token: parent_token}} =
                 RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_expiry", scope: ["openid"]},
                   ttl: parent_ttl,
                   now: now
                 )

        # Make the child live well beyond both candidate deadlines, ensuring
        # the persisted retry deadline is later than the parent expiry.
        assert {:ok, %{token: child_token}} =
                 RefreshToken.rotate(RefreshStore.ETS, parent_token,
                   now: now,
                   ttl: issued_grace + 2,
                   rotation_grace_seconds: issued_grace
                 )

        assert {:ok, parent} = RefreshStore.ETS.get(Secret.hash(parent_token))
        assert parent.successor.retry_until >= parent.expires_at

        # A later, larger configured grace cannot make the consumed parent
        # retryable at its exact (strict) expiry boundary.
        assert {:error, :reuse_detected} =
                 RefreshToken.rotate(RefreshStore.ETS, parent_token,
                   now: parent.expires_at,
                   rotation_grace_seconds: issued_grace + 60
                 )

        assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, child_token)
      end
    end
  end

  defp suffix_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?a..?z, ?0..?9])), min_length: 1, max_length: 14)) do
      List.to_string(chars)
    end
  end
end
