defmodule Attesto.AuthorizationCodeTest do
  @moduledoc false
  # issue/3 and redeem/4 over the named ETS code store. The store is a
  # singleton (named ETS table + name: __MODULE__), so this case is
  # async: false and starts the store fresh per test.
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore
  alias Attesto.CodeStore.ETS
  alias Attesto.PKCE
  alias Attesto.Secret

  # A well-formed RFC 7636 §4.1 verifier (43..128 unreserved chars).
  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @redirect_uri "https://app.example.com/cb"
  @client_id "oc_app"
  @subject "usr_42"
  @scope ["documents.read"]
  @max_exact_integer 9_007_199_254_740_991

  defmodule ContractGetStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    def put(_entry), do: :ok
    @impl true
    def take(_hash), do: :error
    @impl true
    def get(hash) do
      case Process.get({__MODULE__, :return}) do
        :error -> :error
        {:bound, jkt} -> {:ok, %{code_hash: hash, data: %{dpop_jkt: jkt}, expires_at: 2_000_000_000}}
        {:unbound} -> {:ok, %{code_hash: hash, data: %{}, expires_at: 2_000_000_000}}
        value -> value
      end
    end
  end

  defmodule ContractStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    def put(entry), do: fault(:put, ETS.put(entry))

    @impl true
    def take(code_hash), do: fault(:take, ETS.take(code_hash))

    @impl true
    def get(code_hash), do: ETS.get(code_hash)

    @impl true
    def mark_consumed(_code_hash, _meta), do: fault(:mark_consumed, :ok)

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
    start_supervised!(CodeStore.ETS)
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
    # Client binding is fail-closed by default, so the realistic redemption
    # presents the issuing client. Tests that exercise the binding override
    # :client_id (or delete it).
    Map.merge(%{redirect_uri: @redirect_uri, code_verifier: @verifier, client_id: @client_id}, overrides)
  end

  # A canonical 43-char base64url thumbprint that is a real DPoP key id.
  defp valid_jkt(seed \\ "some-dpop-key"), do: Secret.hash(seed)

  defp fault(callback, mode) do
    Process.put({ContractStore, callback}, mode)
  end

  defp clear_fault(callback) do
    Process.delete({ContractStore, callback})
  end

  describe "issue/3 success" do
    test "returns a plaintext code string", %{challenge: challenge} do
      assert {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert is_binary(code)
      assert code != ""
    end

    test "the minted code redeems back to the issued grant context", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, %Grant{} = grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
      assert grant.client_id == @client_id
      assert grant.redirect_uri == @redirect_uri
      assert grant.subject == @subject
      assert grant.scope == @scope
    end

    test "scope defaults to [] when omitted", %{challenge: challenge} do
      attrs = code_attrs(challenge) |> Map.delete(:scope)
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, attrs)
      assert {:ok, %Grant{scope: []}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "JSON claims round-trip unchanged through issue and redeem", %{challenge: challenge} do
      claims = %{"tenant" => "acme", "nonce" => "n-1", "amr" => ["pwd"]}
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{claims: claims}))
      assert {:ok, %Grant{claims: ^claims}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "claims default to %{} when omitted", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, %Grant{claims: %{}}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "an explicit code_challenge_method of S256 is accepted", %{challenge: challenge} do
      attrs = code_attrs(challenge, %{code_challenge_method: "S256"})
      assert {:ok, _code} = AuthorizationCode.issue(CodeStore.ETS, attrs)
    end

    test "a DPoP jkt round-trips onto the redeemed grant", %{challenge: challenge} do
      jkt = valid_jkt()
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))

      assert {:ok, %Grant{dpop_jkt: ^jkt}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{dpop_jkt: jkt}))
    end

    test "an unexpected store put result fails with a constant error", %{challenge: challenge} do
      sentinel = "authorization-code-put-private-sentinel"
      fault(:put, {:return, {:error, {sentinel, code_attrs(challenge)}}})

      error =
        assert_raise RuntimeError, "authorization code store put/1 violated its contract", fn ->
          AuthorizationCode.issue(ContractStore, code_attrs(challenge))
        end

      refute Exception.message(error) =~ sentinel
    end
  end

  describe "dpop_bound?/2 store contract" do
    test "keeps ordinary absence and bound/unbound records unchanged" do
      Process.put({ContractGetStore, :return}, :error)
      refute AuthorizationCode.dpop_bound?(ContractGetStore, "unknown")

      Process.put({ContractGetStore, :return}, {:unbound})
      refute AuthorizationCode.dpop_bound?(ContractGetStore, "unbound")

      Process.put({ContractGetStore, :return}, {:bound, valid_jkt()})
      assert AuthorizationCode.dpop_bound?(ContractGetStore, "bound")
    end

    test "rejects unexpected and malformed get results with a constant error" do
      Process.put(
        {ContractGetStore, :return},
        {:unexpected, "authorization-code-store-private-sentinel"}
      )

      error =
        assert_raise RuntimeError, "authorization code store get/1 violated its contract", fn ->
          AuthorizationCode.dpop_bound?(ContractGetStore, "code")
        end

      refute Exception.message(error) =~ "private-sentinel"

      hash = Secret.hash("code")

      Process.put(
        {ContractGetStore, :return},
        {:ok,
         %{
           code_hash: hash,
           data: %{dpop_jkt: {:invalid, "authorization-code-data-private-sentinel"}},
           expires_at: 2_000_000_000
         }}
      )

      error =
        assert_raise RuntimeError, "authorization code store get/1 violated its contract", fn ->
          AuthorizationCode.dpop_bound?(ContractGetStore, "code")
        end

      refute Exception.message(error) =~ "private-sentinel"
    end
  end

  describe "issue/3 validation errors" do
    test "invalid_client_id when client_id is missing", %{challenge: challenge} do
      attrs = code_attrs(challenge) |> Map.delete(:client_id)
      assert {:error, :invalid_client_id} = AuthorizationCode.issue(CodeStore.ETS, attrs)
    end

    test "invalid_client_id when client_id is empty", %{challenge: challenge} do
      assert {:error, :invalid_client_id} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{client_id: ""}))
    end

    test "invalid_redirect_uri when redirect_uri is empty", %{challenge: challenge} do
      assert {:error, :invalid_redirect_uri} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{redirect_uri: ""}))
    end

    test "invalid_code_challenge for a non-S256-shaped challenge", %{challenge: _challenge} do
      assert {:error, :invalid_code_challenge} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs("not-a-valid-challenge"))
    end

    test "invalid_code_challenge for a 43-char but non-canonical challenge", %{challenge: _challenge} do
      # 43 chars, base64url alphabet, but the trailing char carries non-zero
      # low bits so it could never have come from a SHA-256 digest.
      noncanonical = String.duplicate("A", 42) <> "B"
      assert byte_size(noncanonical) == 43

      assert {:error, :invalid_code_challenge} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(noncanonical))
    end

    test "unsupported_code_challenge_method when method is not S256", %{challenge: challenge} do
      assert {:error, :unsupported_code_challenge_method} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{code_challenge_method: "plain"}))
    end

    test "invalid_subject when subject is missing", %{challenge: challenge} do
      attrs = code_attrs(challenge) |> Map.delete(:subject)
      assert {:error, :invalid_subject} = AuthorizationCode.issue(CodeStore.ETS, attrs)
    end

    test "invalid_subject when subject is empty", %{challenge: challenge} do
      assert {:error, :invalid_subject} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{subject: ""}))
    end

    test "invalid_claims when claims is not a map", %{challenge: challenge} do
      # :claims is JSON host context, so a non-map (here a list) is rejected at
      # the issue boundary rather than silently stored.
      assert {:error, :invalid_claims} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{claims: [:not, :a, :map]}))
    end

    test "invalid_claims when claims are outside the portable JSON subset", %{challenge: challenge} do
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
                 AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{claims: claims}))
      end
    end

    test "invalid_scope when scope is not a list", %{challenge: challenge} do
      assert {:error, :invalid_scope} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{scope: "documents.read"}))
    end

    test "invalid_scope when scope is a list with a non-binary element", %{challenge: challenge} do
      assert {:error, :invalid_scope} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{scope: ["documents.read", :write]}))
    end

    test "invalid_dpop_jkt for a malformed jkt", %{challenge: challenge} do
      assert {:error, :invalid_dpop_jkt} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: "not-a-thumbprint"}))
    end

    test "method is validated before attrs: bad method wins over a bad challenge", %{challenge: _challenge} do
      # validate_method/1 runs first in the with-chain, so a non-S256 method
      # is reported even when the challenge is also malformed.
      attrs = code_attrs("not-a-valid-challenge", %{code_challenge_method: "plain"})
      assert {:error, :unsupported_code_challenge_method} = AuthorizationCode.issue(CodeStore.ETS, attrs)
    end
  end

  describe "issue/3 ttl and now options" do
    test "ttl and now set an absolute expiry honored by redeem", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 30, now: 1_000)

      # 1_029 < 1_030 expiry -> still valid.
      assert {:ok, %Grant{}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 1_029)
    end

    test "now accepts a DateTime override", %{challenge: challenge} do
      issued_at = DateTime.from_unix!(2_000)
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 60, now: issued_at)

      assert {:ok, %Grant{}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: DateTime.from_unix!(2_030))
    end

    test "rejects invalid TTLs before generating or persisting a code", %{challenge: challenge} do
      for ttl <- [0, -1, 1.5, "60", nil] do
        fault(:put, {:return, {:error, :put_must_not_run}})

        assert_raise ArgumentError, ":ttl must be a positive integer", fn ->
          AuthorizationCode.issue(ContractStore, code_attrs(challenge), ttl: ttl, now: 1_000)
        end

        clear_fault(:put)
      end
    end

    test "rejects negative clocks before put or take and leaves storage untouched", %{challenge: challenge} do
      attrs = code_attrs(challenge)

      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:put, {:return, {:private_put_sentinel, attrs}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          AuthorizationCode.issue(ContractStore, attrs, now: bad_now)
        end

        clear_fault(:put)
        assert :ets.tab2list(ETS) == []
      end

      {:ok, code} = AuthorizationCode.issue(ETS, attrs, now: 1_000)

      for bad_now <- [-1, DateTime.from_unix!(-1, :second)] do
        fault(:take, {:return, {:private_take_sentinel, code}})

        assert_raise ArgumentError, ":now must be a non-negative NumericDate", fn ->
          AuthorizationCode.redeem(ContractStore, code, redeem_params(), now: bad_now)
        end

        clear_fault(:take)
        assert {:ok, _record} = ETS.get(Secret.hash(code))
      end
    end
  end

  describe "redeem/4 success returns a Grant" do
    test "Grant carries client_id, redirect_uri, subject, scope, dpop_jkt, and claims", %{challenge: challenge} do
      jkt = valid_jkt()
      claims = %{"tenant" => "acme"}

      {:ok, code} =
        AuthorizationCode.issue(
          CodeStore.ETS,
          code_attrs(challenge, %{dpop_jkt: jkt, claims: claims})
        )

      assert {:ok, grant} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{dpop_jkt: jkt}))

      assert %Grant{
               client_id: @client_id,
               redirect_uri: @redirect_uri,
               subject: @subject,
               scope: @scope,
               dpop_jkt: ^jkt,
               claims: ^claims
             } = grant
    end
  end

  describe "redeem/4 single-use and consume-on-failure" do
    test "a second redeem of a consumed code is invalid_grant", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, %Grant{}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "rejects an invalid clock before consuming the code", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), now: 1_000)

      assert_raise ArgumentError, fn ->
        AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: "not-a-clock")
      end

      assert {:ok, %Grant{}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 1_001)
    end

    test "a failed redeem still spends the code (consume-before-validate)", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      # First attempt fails on PKCE, but the code is taken before validation.
      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{code_verifier: String.duplicate("z", 50)}))

      # A subsequent fully-correct redeem now finds nothing -> invalid_grant.
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "a redirect-uri-mismatch failure also spends the code", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :redirect_uri_mismatch} =
               AuthorizationCode.redeem(
                 CodeStore.ETS,
                 code,
                 redeem_params(%{redirect_uri: "https://evil.example.com/cb"})
               )

      assert {:error, :invalid_grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "an unknown code is invalid_grant", %{challenge: _challenge} do
      assert {:error, :invalid_grant} =
               AuthorizationCode.redeem(CodeStore.ETS, Secret.generate(), redeem_params())
    end

    test "take rejects partial and malformed records after atomically burning the code", %{challenge: challenge} do
      mutations = [
        fn record -> Map.delete(record, :code_hash) end,
        fn record -> Map.put(record, :code_hash, "private-hash-sentinel") end,
        fn record -> update_in(record.data, &Map.delete(&1, :subject)) end,
        fn record -> update_in(record.data, &Map.delete(&1, :family_id)) end,
        fn record -> update_in(record.data, &Map.put(&1, :unexpected, :private_context_sentinel)) end,
        fn record -> put_in(record, [:data, :code_challenge], "private-challenge-sentinel") end,
        fn record -> put_in(record, [:data, :dpop_jkt], {:private, "jkt-sentinel"}) end,
        fn record -> put_in(record, [:data, :scope], ["documents.read", 7]) end,
        fn record -> put_in(record, [:data, :resource], ["https://api.example", 7]) end,
        fn record -> put_in(record, [:data, :claims], ["private-claims-sentinel"]) end,
        fn record -> put_in(record, [:data, :claims], %{"nested" => %{role: :private_claims_sentinel}}) end,
        fn record -> Map.put(record, :expires_at, "private-expiry-sentinel") end
      ]

      for mutate <- mutations do
        {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
        fault(:take, {:mutate_ok, mutate})

        error =
          assert_raise RuntimeError, "authorization code store take/1 violated its contract", fn ->
            AuthorizationCode.redeem(ContractStore, code, redeem_params())
          end

        refute Exception.message(error) =~ "private-"
        clear_fault(:take)

        assert {:error, :invalid_grant} =
                 AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
      end
    end

    test "take rejects unexpected outcomes and malformed reuse metadata without exposing them", %{
      challenge: challenge
    } do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      fault(:take, {:return, {:error, {:private_take_sentinel, code}}})

      error =
        assert_raise RuntimeError, "authorization code store take/1 violated its contract", fn ->
          AuthorizationCode.redeem(ContractStore, code, redeem_params())
        end

      refute Exception.message(error) =~ code
      clear_fault(:take)

      fault(:take, {:return, {:error, :consumed, {:private_meta_sentinel, code}}})

      error =
        assert_raise RuntimeError, "authorization code store take/1 violated its contract", fn ->
          AuthorizationCode.redeem(ContractStore, code, redeem_params())
        end

      refute Exception.message(error) =~ code
    end
  end

  describe "finalize/3 store contract" do
    test "an unexpected mark_consumed result fails with a constant error", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      {:ok, grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
      sentinel = "authorization-code-finalize-private-sentinel"
      fault(:mark_consumed, {:return, {:error, {sentinel, code}}})

      error =
        assert_raise RuntimeError, "authorization code store mark_consumed/2 violated its contract", fn ->
          AuthorizationCode.finalize(ContractStore, code, grant)
        end

      refute Exception.message(error) =~ sentinel
      refute Exception.message(error) =~ code
    end
  end

  describe "redeem/4 redirect_uri exact match" do
    test "a trailing-slash variant of the registered URI mismatches", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :redirect_uri_mismatch} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{redirect_uri: @redirect_uri <> "/"}))
    end

    test "a missing redirect_uri param mismatches", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      params = %{code_verifier: @verifier, client_id: @client_id}
      assert {:error, :redirect_uri_mismatch} = AuthorizationCode.redeem(CodeStore.ETS, code, params)
    end
  end

  describe "redeem/4 PKCE failures" do
    test "a wrong verifier collapses to pkce_failed", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{code_verifier: String.duplicate("q", 50)}))
    end

    test "an empty verifier collapses to pkce_failed", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{code_verifier: ""}))
    end

    test "a malformed (too-short) verifier collapses to pkce_failed", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{code_verifier: "short"}))
    end

    test "a missing verifier param fails as pkce_failed", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      params = %{redirect_uri: @redirect_uri, client_id: @client_id}
      assert {:error, :pkce_failed} = AuthorizationCode.redeem(CodeStore.ETS, code, params)
    end
  end

  describe "redeem/4 expiry" do
    test "an expired code is rejected", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 1, now: 1_000)
      assert {:error, :expired} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 2_000)
    end

    test "expiry boundary: redeem at exactly expires_at is expired", %{challenge: challenge} do
      # check_expiry uses strict >, so expires_at == now is treated as expired.
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 60, now: 1_000)
      assert {:error, :expired} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 1_060)
    end

    test "expiry boundary: one second before expires_at still redeems", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 60, now: 1_000)
      assert {:ok, %Grant{}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 1_059)
    end
  end

  describe "redeem/4 DPoP binding matrix" do
    test "unbound code with no presented jkt redeems", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, %Grant{dpop_jkt: nil}} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "unbound code with a presented jkt redeems", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:ok, %Grant{dpop_jkt: nil}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{dpop_jkt: valid_jkt()}))
    end

    test "bound code with no presented jkt is dpop_proof_required", %{challenge: challenge} do
      jkt = valid_jkt()
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))
      assert {:error, :dpop_proof_required} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "bound code with the matching jkt redeems", %{challenge: challenge} do
      jkt = valid_jkt()
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))

      assert {:ok, %Grant{dpop_jkt: ^jkt}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{dpop_jkt: jkt}))
    end

    test "bound code with a different jkt is dpop_binding_mismatch", %{challenge: challenge} do
      jkt = valid_jkt("key-a")
      other = valid_jkt("key-b")
      refute jkt == other

      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))

      assert {:error, :dpop_binding_mismatch} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{dpop_jkt: other}))
    end
  end
end
