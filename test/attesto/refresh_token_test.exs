defmodule Attesto.RefreshTokenTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore
  alias Attesto.RefreshStore.ETS
  alias Attesto.RefreshToken
  alias Attesto.Secret

  @issuer "https://issuer.example/tenant-a"
  @other_issuer "https://issuer.example/tenant-b"
  @issuer_claim_key "urn:attesto:refresh-token:issuer"

  defmodule AtomicStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record), do: ETS.insert(record)

    @impl true
    def get(token_hash), do: ETS.get(token_hash)

    @impl true
    def rotate(parent_hash, child, successor, opts), do: ETS.rotate(parent_hash, child, successor, opts)

    @impl true
    def revoke_family(family_id), do: ETS.revoke_family(family_id)
  end

  defmodule TokenConflictStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record), do: ETS.insert(record)

    @impl true
    def get(token_hash), do: ETS.get(token_hash)

    @impl true
    def rotate(_parent_hash, _child, _successor, _opts) do
      send(self(), :token_conflict_rotation_attempt)
      {:error, :token_conflict}
    end

    @impl true
    def revoke_family(family_id), do: ETS.revoke_family(family_id)
  end

  defmodule FamilyIntegrityStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record), do: ETS.insert(record)

    @impl true
    def get(token_hash), do: ETS.get(token_hash)

    @impl true
    def rotate(parent_hash, _child, _successor, _opts) do
      {:ok, parent} = ETS.get(parent_hash)
      :ok = ETS.revoke_family(parent.family_id)
      {:error, :family_integrity_error}
    end

    @impl true
    def revoke_family(family_id), do: ETS.revoke_family(family_id)
  end

  defmodule SnapshotAdvancingStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    alias Attesto.RefreshToken

    @impl true
    def insert(record), do: ETS.insert(record)

    @impl true
    def get(token_hash), do: ETS.get(token_hash)

    @impl true
    def rotate(parent_hash, child, successor, opts) do
      result = ETS.rotate(parent_hash, child, successor, opts)

      if match?({:ok, _, _}, result) and Process.get(:snapshot_child_advanced) != true do
        Process.put(:snapshot_child_advanced, true)

        try do
          case RefreshToken.rotate(__MODULE__, successor.token, opts) do
            {:ok, _} -> :ok
            other -> raise "child advance failed: #{inspect(other)}"
          end
        after
          Process.delete(:snapshot_child_advanced)
        end
      end

      result
    end

    @impl true
    def revoke_family(family_id), do: ETS.revoke_family(family_id)
  end

  defmodule MalformedContextStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record), do: ETS.insert(record)

    @impl true
    def get(token_hash) do
      result = ETS.get(token_hash)

      case {result, Process.get({__MODULE__, :mutator})} do
        {{:ok, record}, mutator} when is_function(mutator, 1) -> {:ok, mutator.(record)}
        _ -> result
      end
    end

    @impl true
    def rotate(parent_hash, child, successor, opts), do: ETS.rotate(parent_hash, child, successor, opts)

    @impl true
    def revoke_family(family_id), do: ETS.revoke_family(family_id)
  end

  setup do
    start_supervised!(RefreshStore.ETS)
    :ok
  end

  # A valid DPoP key thumbprint: Secret.hash/1 yields the canonical
  # 43-char base64url SHA-256 digest that Thumbprint.valid?/1 accepts.
  defp jkt(seed), do: Secret.hash(seed)

  # No client_id by default, so tokens are unbound and rotation needs no
  # presenting client (client binding is fail-closed and exercised on its
  # own in grants_client_scope_test). Tests that care add :client_id.
  defp context(overrides \\ %{}) do
    Map.merge(%{subject: "usr_42", scope: ["documents.read"]}, overrides)
  end

  test "issuer binding survives serialized claims, rotation, and retry without entering host claims" do
    host_claims = %{"tenant" => "a"}

    assert {:ok, initial} =
             RefreshToken.issue(ETS, context(%{issuer: @issuer, claims: host_claims}), now: 1_000)

    assert {:ok, stored} = ETS.get(Secret.hash(initial.token))
    assert stored.data.claims[@issuer_claim_key] == @issuer
    assert stored.data.claims["tenant"] == "a"

    # The reserved string key survives the JSON round trip used by persistent
    # stores for the established claims column.
    assert stored.data.claims == stored.data.claims |> Jason.encode!() |> Jason.decode!()

    assert {:error, :issuer_mismatch} =
             RefreshToken.rotate(ETS, initial.token, issuer: @other_issuer, now: 1_001)

    assert {:ok, %{consumed: false}} = ETS.get(Secret.hash(initial.token))

    assert {:ok, first} = RefreshToken.rotate(ETS, initial.token, issuer: @issuer, now: 1_001)
    assert first.context.issuer == @issuer
    assert first.context.claims == host_claims
    refute Map.has_key?(first.context.claims, @issuer_claim_key)

    assert {:ok, child_record} = ETS.get(Secret.hash(first.token))
    assert child_record.data.claims[@issuer_claim_key] == @issuer

    assert {:ok, retry} = RefreshToken.rotate(ETS, initial.token, issuer: @issuer, now: 1_002)
    assert retry == first

    # An issuer mismatch on a consumed parent is a policy rejection, not reuse:
    # it must not revoke the correctly bound live child.
    assert {:error, :issuer_mismatch} =
             RefreshToken.rotate(ETS, initial.token, issuer: @other_issuer, now: 1_002)

    assert {:ok, second} = RefreshToken.rotate(ETS, first.token, issuer: @issuer, now: 1_003)
    assert second.context.issuer == @issuer
    assert second.context.claims == host_claims
  end

  test "issuer checks fail closed for legacy tokens but omission remains compatible" do
    assert {:ok, legacy} = RefreshToken.issue(ETS, context(), now: 1_000)

    assert {:error, :issuer_mismatch} =
             RefreshToken.rotate(ETS, legacy.token, issuer: @issuer, now: 1_001)

    assert {:ok, %{consumed: false}} = ETS.get(Secret.hash(legacy.token))
    assert {:ok, legacy_child} = RefreshToken.rotate(ETS, legacy.token, now: 1_001)
    refute Map.has_key?(legacy_child.context, :issuer)

    assert {:ok, bound} = RefreshToken.issue(ETS, context(%{issuer: @issuer}), now: 1_000)
    assert {:ok, bound_child} = RefreshToken.rotate(ETS, bound.token, now: 1_001)
    assert bound_child.context.issuer == @issuer
  end

  test "attested refresh binding is independent of DPoP and survives capped retries" do
    instance = jkt("client-instance")
    dpop = jkt("independent-dpop")

    assert {:ok, initial} =
             RefreshToken.issue(ETS, context(%{attestation_jkt: instance, dpop_jkt: dpop}),
               now: 1_000,
               ttl: 100,
               family_ttl: 150
             )

    assert {:error, :attestation_proof_required} = RefreshToken.rotate(ETS, initial.token, dpop_jkt: dpop, now: 1_010)

    assert {:error, :attestation_binding_mismatch} =
             RefreshToken.rotate(ETS, initial.token, attestation_jkt: jkt("other-instance"), dpop_jkt: dpop, now: 1_010)

    assert {:ok, %{consumed: false}} = ETS.get(Secret.hash(initial.token))

    opts = [attestation_jkt: instance, dpop_jkt: dpop, now: 1_010, ttl: 1_000]
    assert {:ok, child} = RefreshToken.rotate(ETS, initial.token, opts)
    assert child.context.attestation_jkt == instance
    assert child.context.dpop_jkt == dpop
    assert child.context.family_expires_at == 1_150
    assert child.expires_at == 1_150
    assert {:ok, ^child} = RefreshToken.rotate(ETS, initial.token, Keyword.put(opts, :now, 1_011))

    assert {:error, :reuse_detected} =
             RefreshToken.rotate(ETS, initial.token, Keyword.put(opts, :attestation_jkt, jkt("other-instance")))

    assert {:error, :invalid_grant} = RefreshToken.rotate(ETS, child.token, opts)
  end

  test "attestation binding validates canonical thumbprints without widening legacy families" do
    assert {:error, :invalid_attestation_jkt} = RefreshToken.issue(ETS, context(%{attestation_jkt: "bad"}))
    assert {:ok, legacy} = RefreshToken.issue(ETS, context(), now: 1_000)
    assert {:ok, stored} = ETS.get(Secret.hash(legacy.token))
    refute Map.has_key?(stored.data, :attestation_jkt)

    assert {:error, :attestation_proof_unexpected} =
             RefreshToken.rotate(ETS, legacy.token, attestation_jkt: jkt("instance"), now: 1_001)

    assert {:ok, _} = RefreshToken.rotate(ETS, legacy.token, now: 1_001)
  end

  test "cached successor attestation binding cannot be erased or replaced" do
    instance = jkt("instance")

    for mutate <- [&Map.delete(&1, :attestation_jkt), &Map.put(&1, :attestation_jkt, jkt("other-instance"))] do
      :ok = ETS.reset()
      assert {:ok, initial} = RefreshToken.issue(ETS, context(%{attestation_jkt: instance}), now: 1_000)
      opts = [attestation_jkt: instance, now: 1_001]
      assert {:ok, child} = RefreshToken.rotate(ETS, initial.token, opts)

      Process.put({MalformedContextStore, :mutator}, fn record ->
        Map.update!(record, :successor, fn successor -> Map.update!(successor, :context, mutate) end)
      end)

      try do
        assert {:error, :grant_revoked} = RefreshToken.rotate(MalformedContextStore, initial.token, opts)
      after
        Process.delete({MalformedContextStore, :mutator})
      end

      assert :error = ETS.get(Secret.hash(child.token))
    end
  end

  test "cached successor issuer binding cannot be erased or replaced" do
    mutations = [
      &Map.delete(&1, @issuer_claim_key),
      &Map.put(&1, @issuer_claim_key, @other_issuer)
    ]

    for mutate <- mutations do
      :ok = ETS.reset()
      assert {:ok, initial} = RefreshToken.issue(ETS, context(%{issuer: @issuer}), now: 1_000)
      assert {:ok, child} = RefreshToken.rotate(ETS, initial.token, issuer: @issuer, now: 1_001)

      Process.put({MalformedContextStore, :mutator}, fn record ->
        Map.update!(record, :successor, fn successor ->
          Map.update!(successor, :context, fn successor_context ->
            Map.update!(successor_context, :claims, mutate)
          end)
        end)
      end)

      try do
        assert {:error, :grant_revoked} =
                 RefreshToken.rotate(MalformedContextStore, initial.token, issuer: @issuer, now: 1_002)
      after
        Process.delete({MalformedContextStore, :mutator})
      end

      assert :error = ETS.get(Secret.hash(child.token))
    end
  end

  @max_exact_integer 9_007_199_254_740_991

  describe "issue/3" do
    test "a fixed family lifetime caps issuance and every rotation" do
      assert {:ok, initial} = RefreshToken.issue(ETS, context(), now: 1_000, ttl: 100, family_ttl: 150)
      assert initial.expires_at == 1_100

      assert {:ok, first} = RefreshToken.rotate(ETS, initial.token, now: 1_090, ttl: 100)
      assert first.expires_at == 1_150
      assert first.context.family_expires_at == 1_150

      assert {:ok, last} = RefreshToken.rotate(ETS, first.token, now: 1_149, ttl: 10_000)
      assert last.expires_at == 1_150
      assert last.context.family_expires_at == 1_150

      assert {:ok, retry} = RefreshToken.rotate(ETS, first.token, now: 1_149, ttl: 20_000)
      assert retry == last
      assert {:error, :expired} = RefreshToken.rotate(ETS, last.token, now: 1_150)
      assert {:ok, %{consumed: false}} = ETS.get(Secret.hash(last.token))
    end

    test "a short family lifetime caps the first token and validates its option" do
      assert {:ok, %{expires_at: 1_010}} = RefreshToken.issue(ETS, context(), now: 1_000, ttl: 100, family_ttl: 10)

      for invalid <- [0, -1, 1.5, "60", false] do
        assert_raise ArgumentError, ~r/:family_ttl must be a positive integer or nil/, fn ->
          RefreshToken.issue(ETS, context(), family_ttl: invalid)
        end
      end
    end

    test "success returns a token, a family_id, and generation 0" do
      assert {:ok, %{token: token, family_id: family_id, generation: 0}} =
               RefreshToken.issue(RefreshStore.ETS, context())

      assert is_binary(token) and token != ""
      assert is_binary(family_id) and family_id != ""
    end

    test "a missing or empty subject is rejected as invalid_subject" do
      assert {:error, :invalid_subject} =
               RefreshToken.issue(RefreshStore.ETS, %{scope: ["documents.read"]})

      assert {:error, :invalid_subject} =
               RefreshToken.issue(RefreshStore.ETS, %{subject: ""})
    end

    test "a non-string-list scope is rejected as invalid_scope" do
      assert {:error, :invalid_scope} =
               RefreshToken.issue(RefreshStore.ETS, context(%{scope: ["documents.read", :nope]}))

      assert {:error, :invalid_scope} =
               RefreshToken.issue(RefreshStore.ETS, context(%{scope: "documents.read"}))
    end

    test "a malformed client binding is rejected before storage" do
      for client_id <- ["", 123, :client, []] do
        assert {:error, :invalid_client_id} =
                 RefreshToken.issue(RefreshStore.ETS, context(%{client_id: client_id}))
      end

      assert :ets.tab2list(RefreshStore.ETS) == []
    end

    test "issuer bindings are bounded HTTPS identifiers and reserve their claims marker" do
      too_long = "https://issuer.example/" <> String.duplicate("a", 2_048)

      for invalid <- [
            nil,
            "",
            "http://issuer.example/",
            "https:///missing-host",
            "https://issuer.example/?query=1",
            "https://issuer.example/#fragment",
            " https://issuer.example/",
            <<"https://issuer.example/", 255>>,
            too_long
          ] do
        assert {:error, :invalid_issuer} = RefreshToken.issue(ETS, context(%{issuer: invalid}))
      end

      for claims <- [
            %{@issuer_claim_key => @issuer},
            %{@issuer_claim_key => @other_issuer, "tenant" => "a"}
          ] do
        assert {:error, :invalid_claims} = RefreshToken.issue(ETS, context(%{claims: claims}))

        assert {:error, :invalid_claims} =
                 RefreshToken.issue(ETS, context(%{issuer: @issuer, claims: claims}))
      end

      assert :ets.tab2list(ETS) == []

      prefix = "https://issuer.example/"
      at_limit = prefix <> String.duplicate("a", 2_048 - byte_size(prefix))
      assert byte_size(at_limit) == 2_048
      assert {:ok, _issued} = RefreshToken.issue(ETS, context(%{issuer: at_limit}))
    end

    test "a malformed dpop_jkt is rejected as invalid_dpop_jkt" do
      assert {:error, :invalid_dpop_jkt} =
               RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: "not-a-valid-thumbprint"}))
    end

    test "a non-map :claims is rejected as invalid_claims" do
      # :claims is JSON host context; a non-map (here a list) is rejected at
      # the issue boundary.
      assert {:error, :invalid_claims} =
               RefreshToken.issue(RefreshStore.ETS, context(%{claims: [:not, :a, :map]}))
    end

    test "claims must be in the portable JSON subset with string keys" do
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
        assert {:error, :invalid_claims} = RefreshToken.issue(RefreshStore.ETS, context(%{claims: claims}))
      end
    end

    test "invalid lifetime and continuation options fail before insertion" do
      for invalid_ttl <- [0, -1, 1.0, "60", nil] do
        assert_raise ArgumentError, ~r/:ttl must be a positive integer/, fn ->
          RefreshToken.issue(RefreshStore.ETS, context(), ttl: invalid_ttl)
        end
      end

      for invalid_family <- ["", nil, 123] do
        assert_raise ArgumentError, ~r/:family_id and :generation are internal rotation state/, fn ->
          RefreshToken.issue(RefreshStore.ETS, context(), family_id: invalid_family)
        end
      end

      for invalid_generation <- [-1, 1.0, "1", nil] do
        assert_raise ArgumentError, ~r/:family_id and :generation are internal rotation state/, fn ->
          RefreshToken.issue(RefreshStore.ETS, context(), generation: invalid_generation)
        end
      end

      assert :ets.tab2list(RefreshStore.ETS) == []
    end

    test "a fresh issue starts a NEW family (distinct family_id across two issues)" do
      {:ok, %{family_id: fam_a, generation: 0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{family_id: fam_b, generation: 0}} = RefreshToken.issue(RefreshStore.ETS, context())

      refute fam_a == fam_b
    end

    test "ttl and now are honored: a token issued in the past is already expired at rotate" do
      {:ok, %{token: token}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 100, now: 1_000)

      # now (2_000) is past expires_at (1_000 + 100 = 1_100).
      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, token, now: 2_000)
    end

    test "ttl and now: a token is still live just before its expiry boundary" do
      {:ok, %{token: token}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 100, now: 1_000)

      # expires_at = 1_100; check is strict (expires_at > now), so 1_099 is live.
      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, token, now: 1_099)
    end

    test "backward clock skew up to the configured grace recovers, but larger skew revokes" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(), now: 1_000)
      assert {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)

      assert {:ok, %{token: ^t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 995)
      assert {:error, :grant_revoked} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 989)
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_000)
    end

    test "canonical persisted context requires every field before rotation" do
      missing_fields = [:subject, :scope, :resource, :client_id, :dpop_jkt, :acr, :auth_time, :claims]

      for field <- missing_fields do
        :ok = ETS.reset()
        {:ok, %{token: token}} = RefreshToken.issue(ETS, context(), now: 1_000)

        Process.put({MalformedContextStore, :mutator}, fn record ->
          Map.update!(record, :data, &Map.delete(&1, field))
        end)

        error =
          assert_raise RuntimeError, "refresh store get/1 violated its contract", fn ->
            RefreshToken.rotate(MalformedContextStore, token, now: 1_001)
          end

        Process.delete({MalformedContextStore, :mutator})
        assert Exception.message(error) == "refresh store get/1 violated its contract"
        assert :error = ETS.get(Secret.hash(token))
        assert Enum.empty?(:ets.tab2list(ETS))
      end
    end

    test "malformed persisted context values fail closed without issuing a child" do
      invalid_values = [
        {:subject, {:private_subject_sentinel}},
        {:scope, ["read", :private_scope_sentinel]},
        {:resource, {:private_resource_sentinel}},
        {:client_id, ""},
        {:dpop_jkt, "private-jkt-sentinel"},
        {:attestation_jkt, nil},
        {:attestation_jkt, "private-attestation-sentinel"},
        {:acr, ""},
        {:auth_time, -1},
        {:claims, [:private_claims_sentinel]},
        {:claims, %{"nested" => %{role: :private_claims_sentinel}}},
        {:claims, %{@issuer_claim_key => "http://private-issuer-sentinel.example"}}
      ]

      for {field, value} <- invalid_values do
        :ok = ETS.reset()
        {:ok, %{token: token}} = RefreshToken.issue(ETS, context(), now: 1_000)

        Process.put({MalformedContextStore, :mutator}, fn record ->
          Map.update!(record, :data, &Map.put(&1, field, value))
        end)

        error =
          assert_raise RuntimeError, "refresh store get/1 violated its contract", fn ->
            RefreshToken.rotate(MalformedContextStore, token, now: 1_001)
          end

        Process.delete({MalformedContextStore, :mutator})
        assert Exception.message(error) == "refresh store get/1 violated its contract"
        refute Exception.message(error) =~ "private_"
        assert :error = ETS.get(Secret.hash(token))
        assert Enum.empty?(:ets.tab2list(ETS))
      end
    end

    test "an extra persisted context key fails closed without issuing a child" do
      :ok = ETS.reset()
      {:ok, %{token: token}} = RefreshToken.issue(ETS, context(), now: 1_000)

      Process.put({MalformedContextStore, :mutator}, fn record ->
        Map.update!(record, :data, &Map.put(&1, :unexpected, :private_context_sentinel))
      end)

      error =
        assert_raise RuntimeError, "refresh store get/1 violated its contract", fn ->
          RefreshToken.rotate(MalformedContextStore, token, now: 1_001)
        end

      Process.delete({MalformedContextStore, :mutator})
      refute Exception.message(error) =~ "private_context_sentinel"
      assert :error = ETS.get(Secret.hash(token))
      assert Enum.empty?(:ets.tab2list(ETS))
    end
  end

  describe "rotate/3 success and chaining" do
    test "rotate consumes the old token and returns a generation+1 successor in the SAME family with the round-tripped context" do
      {:ok, %{token: t0, family_id: fam, generation: 0}} =
        RefreshToken.issue(RefreshStore.ETS, context(%{client_id: "oc_app"}))

      assert {:ok, %{token: t1, family_id: ^fam, generation: 1, context: ctx}} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_app")

      refute t1 == t0
      assert ctx.subject == "usr_42"
      assert ctx.scope == ["documents.read"]
      assert ctx.client_id == "oc_app"
    end

    test "an atomic store returns committed parent and child snapshots" do
      {:ok, %{token: t0, family_id: family_id}} =
        RefreshToken.issue(AtomicStore, context(), now: 1_000)

      assert {:ok, %{token: t1, family_id: ^family_id, generation: 1}} =
               RefreshToken.rotate(AtomicStore, t0, now: 1_001)

      assert {:ok, %{token: ^t1}} = RefreshToken.rotate(AtomicStore, t0, now: 1_002)
    end

    test "the winner snapshot remains valid if the child advances before rotate returns" do
      {:ok, %{token: t0}} = RefreshToken.issue(SnapshotAdvancingStore, context(), now: 1_000)

      assert {:ok, %{token: t1}} = RefreshToken.rotate(SnapshotAdvancingStore, t0, now: 1_000)
      assert {:ok, %{token: t2}} = RefreshToken.rotate(SnapshotAdvancingStore, t1, now: 1_000)
      assert {:ok, %{token: t3, generation: 3}} = RefreshToken.rotate(SnapshotAdvancingStore, t2, now: 1_001)
      assert {:ok, %{generation: 4}} = RefreshToken.rotate(SnapshotAdvancingStore, t3, now: 1_001)
    end

    test "an immediate honest retry of the old token returns the same successor" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, first} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:ok, retry} = RefreshToken.rotate(RefreshStore.ETS, t0)
      assert retry.token == first.token
      assert retry.family_id == first.family_id
      assert retry.generation == first.generation
      assert retry.context == first.context
    end

    test "the grace fixed at issuance cannot be enlarged by a later retry" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(), now: 1_000)

      assert {:ok, _} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_000,
                 rotation_grace_seconds: 2
               )

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_003,
                 rotation_grace_seconds: 10
               )
    end

    test "a consumed parent cannot retry after its expiry even while its persisted deadline is live" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 5, now: 1_000)

      assert {:ok, %{token: t1}} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_000,
                 ttl: 100,
                 rotation_grace_seconds: 10
               )

      assert {:ok, parent} = RefreshStore.ETS.get(Secret.hash(t0))
      assert parent.expires_at == 1_005
      assert parent.successor.retry_until == 1_010

      # The persisted retry deadline is still live, and a larger current grace
      # must not bypass the parent's strict expiry boundary.
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: parent.expires_at,
                 rotation_grace_seconds: 60
               )

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end

    test "rotation grace is capped so an expired successor cannot remain recoverable" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(), now: 1_000)

      assert {:ok, %{token: t1}} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 now: 1_000,
                 ttl: 2,
                 rotation_grace_seconds: 10
               )

      assert {:ok, parent} = RefreshStore.ETS.get(Secret.hash(t0))
      assert parent.successor.retry_until == 1_001

      assert {:ok, %{token: ^t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_001)
      assert {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_002)
    end

    test "rotation grace must be a non-negative integer before storage is touched" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())

      for invalid <- [-1, 1.0, "10", nil] do
        assert_raise ArgumentError, ~r/:rotation_grace_seconds must be a non-negative integer/, fn ->
          RefreshToken.rotate(RefreshStore.ETS, t0, rotation_grace_seconds: invalid)
        end
      end

      assert {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0, rotation_grace_seconds: 0)
    end

    test "an invalid successor lifetime does not consume the parent" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())

      for invalid_ttl <- [0, -1, 1.0, "60", nil] do
        assert_raise ArgumentError, ~r/:ttl must be a positive integer/, fn ->
          RefreshToken.rotate(RefreshStore.ETS, t0, ttl: invalid_ttl)
        end
      end

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, ttl: 60)
    end

    test "an unknown token is invalid_grant" do
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, "no-such-token")
    end

    test "an expired token is rejected as expired" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 1, now: 1_000)

      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)
    end

    test "a multi-generation chain rotates 1 -> 2 -> 3 in the same family" do
      {:ok, %{token: t0, family_id: fam, generation: 0}} =
        RefreshToken.issue(RefreshStore.ETS, context())

      assert {:ok, %{token: t1, family_id: ^fam, generation: 1}} =
               RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:ok, %{token: t2, family_id: ^fam, generation: 2}} =
               RefreshToken.rotate(RefreshStore.ETS, t1)

      assert {:ok, %{token: t3, family_id: ^fam, generation: 3}} =
               RefreshToken.rotate(RefreshStore.ETS, t2)

      refute t3 in [t0, t1, t2]
    end
  end

  describe "atomic rotation failure branches" do
    test "a token collision retries boundedly and leaves the parent usable" do
      {:ok, %{token: t0}} = RefreshToken.issue(TokenConflictStore, context(), now: 1_000)

      assert {:error, :temporarily_unavailable} =
               RefreshToken.rotate(TokenConflictStore, t0, now: 1_000)

      assert_received :token_conflict_rotation_attempt
      assert_received :token_conflict_rotation_attempt
      assert_received :token_conflict_rotation_attempt
      assert {:ok, %{consumed: false}} = ETS.get(Secret.hash(t0))
    end

    test "a generation-integrity conflict returns grant_revoked after the store revokes the family" do
      {:ok, %{token: t0, family_id: family_id}} =
        RefreshToken.issue(FamilyIntegrityStore, context(), now: 1_000)

      assert {:error, :grant_revoked} = RefreshToken.rotate(FamilyIntegrityStore, t0, now: 1_000)
      assert :error = ETS.get(Secret.hash(t0))
      assert :ok = ETS.revoke_family(family_id)
    end
  end

  describe "rotate/3 reuse detection and family revocation" do
    test "strict mode keeps immediate replay as reuse detection" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, rotation_grace_seconds: 0)

      # The whole family was revoked, so the live successor no longer exists.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end

    test "after the grace window, replaying an old generation revokes the whole family" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)
      {:ok, %{token: t2}} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_001)
      {:ok, %{token: t3}} = RefreshToken.rotate(RefreshStore.ETS, t2, now: 1_002)

      # Replay a stale mid-chain token (t1, already consumed by the t1->t2 rotation).
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_100)

      # Every token in the family is now gone, including the live leaf t3
      # and the already-consumed earlier generations.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t3)
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t2)
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "replaying the parent WITHIN grace after its successor was rotated revokes the family" do
      # A -> B -> C: the parent A's cached successor B is consumed by the B -> C
      # rotation. A within-grace replay of A must NOT idempotently re-issue the
      # now-stale B (the lost-response retry only applies while B is unused); the
      # chain has advanced, so this is a genuine reuse and the family is revoked.
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(), now: 1_000)
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_000)
      {:ok, %{token: t2}} = RefreshToken.rotate(RefreshStore.ETS, t1, now: 1_001)

      # now=1_002 is inside the default 10s grace (A consumed at 1_000), yet A's
      # successor B (t1) is already consumed: reuse, not an idempotent retry.
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, now: 1_002)

      # The family is torn down: the live leaf t2 no longer rotates.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t2)
    end

    test "a consumed-token retry with a different client revokes the family" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{client_id: "client-a"}))
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "client-a")

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "client-b")

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1, client_id: "client-a")
    end

    test "a consumed-token retry with a different requested scope revokes the family" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(%{scope: ["documents.read", "documents.write"]}))

      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.read"])

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.write"])

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end

    test "an equivalent reordered retry returns the originally issued successor" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(
          RefreshStore.ETS,
          context(%{
            scope: ["documents.read", "documents.write"],
            resource: ["https://api.example/a", "https://api.example/b"]
          })
        )

      assert {:ok, first} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 scope: ["documents.write", "documents.read", "documents.write"],
                 resource: ["https://api.example/b", "https://api.example/a", "https://api.example/b"]
               )

      assert {:ok, retry} =
               RefreshToken.rotate(RefreshStore.ETS, t0,
                 scope: ["documents.read", "documents.write"],
                 resource: ["https://api.example/a", "https://api.example/b"]
               )

      assert retry.token == first.token
      assert retry.context == first.context
      assert retry.context.scope == ["documents.write", "documents.read"]
      assert retry.context.resource == ["https://api.example/b", "https://api.example/a"]
    end

    test "a consumed-token retry with a different requested resource revokes the family" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(
          RefreshStore.ETS,
          context(%{resource: ["https://api.example/a", "https://api.example/b"]})
        )

      {:ok, %{token: t1}} =
        RefreshToken.rotate(RefreshStore.ETS, t0, resource: ["https://api.example/a"])

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, resource: ["https://api.example/b"])

      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end
  end

  describe "rotate/3 DPoP binding matrix" do
    test "unbound token + no presented jkt is OK" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "unbound token + a presented jkt -> :dpop_proof_unexpected" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context())

      assert {:error, :dpop_proof_unexpected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("presented-key"))
    end

    test "bound token + no presented jkt -> :dpop_proof_required" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_proof_required} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "bound token + matching jkt is OK" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "bound token + a different jkt -> :dpop_binding_mismatch" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_binding_mismatch} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("other-key"))
    end
  end

  describe "rotate/3 does not burn a token on a recoverable failure" do
    # Recoverable validation (expiry, DPoP) runs on a non-consuming read
    # BEFORE the token is claimed, so a transient client error does not
    # spend the token or trip reuse detection. A corrected retry succeeds.
    test "a recoverable :dpop_proof_required leaves the token intact; the corrected retry succeeds" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      # Client forgets the proof: recoverable validation error.
      assert {:error, :dpop_proof_required} = RefreshToken.rotate(RefreshStore.ETS, t0)

      # Client retries the SAME token with the correct proof and rotates
      # cleanly: the token was never consumed, so this is not reuse.
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "a recoverable :dpop_binding_mismatch leaves the token intact; the corrected retry succeeds" do
      bound = jkt("bound-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, context(%{dpop_jkt: bound}))

      assert {:error, :dpop_binding_mismatch} =
               RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt("wrong-key"))

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: bound)
    end

    test "a recoverable :expired keeps reporting :expired, never reuse" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, context(), ttl: 1, now: 1_000)

      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)

      # Re-presenting the same token still reads as :expired, not :reuse_detected,
      # because the failed rotation never consumed it.
      assert {:error, :expired} = RefreshToken.rotate(RefreshStore.ETS, t0, now: 5_000)
    end
  end
end
