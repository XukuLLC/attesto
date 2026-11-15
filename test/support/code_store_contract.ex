defmodule Attesto.CodeStoreContract do
  @moduledoc false

  defmacro __using__(opts) do
    store = Keyword.fetch!(opts, :store)
    start = Keyword.get(opts, :start)
    start_call = if start, do: quote(do: unquote(start).()), else: quote(do: start_supervised!(unquote(store)))

    quote do
      @contract_store unquote(store)
      setup do
        unquote(start_call)
        :ok
      end

      defp contract_code_record(overrides \\ %{}) do
        %{
          code_hash: Attesto.Secret.generate(),
          data: %{
            client_id: "contract-client",
            redirect_uri: "https://client.example/cb",
            subject: "contract-subject",
            scope: [],
            resource: [],
            code_challenge: nil,
            dpop_jkt: nil,
            family_id: "provenance",
            claims: %{"sid" => "contract-session"}
          },
          expires_at: System.system_time(:second) + 600
        }
        |> Map.merge(overrides)
      end

      defp contract_redemption,
        do: %{family_id: "contract-family", subject: "contract-subject", replay_retain_until: nil}

      unquote(lifecycle_tests())
      unquote(cutoff_tests())
      unquote(linkage_tests())
    end
  end

  defp lifecycle_tests do
    quote do
      test "all required callbacks are implemented" do
        assert :ok = Attesto.CodeStore.validate!(@contract_store)
        assert Attesto.CodeStore.behaviour_info(:optional_callbacks) == []
      end

      test "read is non-writing in every state and bindings remain immutable" do
        entry = contract_code_record()
        assert :error = @contract_store.read(entry.code_hash)
        assert :ok = @contract_store.put(entry)
        assert {:ok, live} = @contract_store.read(entry.code_hash)
        assert live == Map.merge(entry, %{state: :live, redemption: nil, revoked: false})
        assert @contract_store.read(entry.code_hash) == {:ok, live}
        assert :error = @contract_store.finish(entry.code_hash, contract_redemption())
        assert :error = @contract_store.flag_replay(entry.code_hash)
        assert :ok = @contract_store.claim(entry.code_hash)
        assert :error = @contract_store.claim(entry.code_hash)
        assert {:ok, claimed} = @contract_store.read(entry.code_hash)
        assert claimed == %{live | state: :claimed}
        assert @contract_store.read(entry.code_hash) == {:ok, claimed}

        assert {:ok, false} =
                 @contract_store.finish(entry.code_hash, contract_redemption())

        assert {:ok, redeemed} = @contract_store.read(entry.code_hash)
        assert redeemed == %{claimed | state: :redeemed, redemption: contract_redemption()}
        assert :error = @contract_store.flag_replay(entry.code_hash)
        assert :error = @contract_store.claim(entry.code_hash)
        assert :error = @contract_store.finish(entry.code_hash, contract_redemption())
        assert @contract_store.read(entry.code_hash) == {:ok, redeemed}
      end

      test "missing transitions do not create records" do
        hash = Attesto.Secret.generate()
        assert :error = @contract_store.claim(hash)
        assert :error = @contract_store.flag_replay(hash)
        assert :error = @contract_store.finish(hash, contract_redemption())
        assert :ok = @contract_store.revoke_access_token_for_code(hash)
        assert :error = @contract_store.read(hash)
      end

      test "claim does not make protocol expiry decisions" do
        entry = contract_code_record(%{expires_at: System.system_time(:second) - 60})
        :ok = @contract_store.put(entry)
        assert :ok = @contract_store.claim(entry.code_hash)
      end

      test "linkage before claim is refused" do
        entry = contract_code_record()
        :ok = @contract_store.put(entry)

        assert_raise ArgumentError, fn ->
          @contract_store.record_access_token_for_code(entry.code_hash, "premature", entry.expires_at)
        end

        assert {:ok, %{state: :live}} = @contract_store.read(entry.code_hash)
      end
    end
  end

  defp cutoff_tests do
    quote do
      test "finish reports replay and grant cut-off atomically" do
        entry = contract_code_record()
        :ok = @contract_store.put(entry)
        :ok = @contract_store.claim(entry.code_hash)
        :ok = @contract_store.record_access_token_for_code(entry.code_hash, entry.code_hash, entry.expires_at)
        assert :ok = @contract_store.flag_replay(entry.code_hash)
        assert :ok = @contract_store.flag_replay(entry.code_hash)
        assert {:ok, 0} = @contract_store.delete_unclaimed(subject: entry.data.subject)

        assert {:ok, true} =
                 @contract_store.finish(entry.code_hash, contract_redemption())

        assert :ok = @contract_store.revoke_access_token_for_code(entry.code_hash)
        assert @contract_store.access_token_revoked?(entry.code_hash)
      end

      test "bulk cut-off deletes only matching live codes and flags only matching claimed codes" do
        [live, claimed, redeemed, other] = for _ <- 1..4, do: contract_code_record()
        other = put_in(other.data.client_id, "another-client")
        for entry <- [live, claimed, redeemed, other], do: :ok = @contract_store.put(entry)
        :ok = @contract_store.claim(claimed.code_hash)
        :ok = @contract_store.claim(redeemed.code_hash)
        {:ok, _} = @contract_store.finish(redeemed.code_hash, contract_redemption())
        assert {:ok, 1} = @contract_store.delete_unclaimed(client_id: "contract-client", sid: "contract-session")
        assert :error = @contract_store.read(live.code_hash)
        assert {:ok, %{state: :claimed, revoked: true}} = @contract_store.read(claimed.code_hash)
        assert {:ok, %{state: :redeemed, revoked: false}} = @contract_store.read(redeemed.code_hash)
        assert {:ok, %{state: :live}} = @contract_store.read(other.code_hash)
        assert_raise ArgumentError, fn -> @contract_store.delete_unclaimed(%{}) end
      end
    end
  end

  defp linkage_tests do
    quote do
      test "access-token revocation survives late linkage and respects expiry" do
        entry = contract_code_record()
        :ok = @contract_store.put(entry)
        :ok = @contract_store.claim(entry.code_hash)
        :ok = @contract_store.revoke_access_token_for_code(entry.code_hash)
        :ok = @contract_store.record_access_token_for_code(entry.code_hash, entry.code_hash, entry.expires_at)
        assert @contract_store.access_token_revoked?(entry.code_hash)
        refute @contract_store.access_token_revoked?("unknown-token")
        expired = contract_code_record()
        :ok = @contract_store.put(expired)
        :ok = @contract_store.claim(expired.code_hash)

        :ok =
          @contract_store.record_access_token_for_code(
            expired.code_hash,
            expired.code_hash,
            System.system_time(:second) - 1
          )

        :ok = @contract_store.revoke_access_token_for_code(expired.code_hash)
        refute @contract_store.access_token_revoked?(expired.code_hash)
      end

      test "family revocation follows redemption family and never authorization provenance" do
        entry = contract_code_record()
        :ok = @contract_store.put(entry)
        :ok = @contract_store.claim(entry.code_hash)
        :ok = @contract_store.record_access_token_for_code(entry.code_hash, entry.code_hash, entry.expires_at)
        {:ok, _} = @contract_store.finish(entry.code_hash, contract_redemption())
        :ok = @contract_store.revoke_family_access_tokens("provenance")
        refute @contract_store.access_token_revoked?(entry.code_hash)
        :ok = @contract_store.revoke_family_access_tokens("contract-family")
        assert @contract_store.access_token_revoked?(entry.code_hash)
      end
    end
  end
end
