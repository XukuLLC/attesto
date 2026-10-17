defmodule Attesto.CodeStoreETSContractTest do
  @moduledoc false
  # Runs the shared `Attesto.CodeStore` contract against the ETS reference
  # implementation. async: false because `Attesto.CodeStore.ETS` is a named
  # singleton GenServer; the contract `setup` starts it via
  # start_supervised!.
  use ExUnit.Case, async: false
  use Attesto.CodeStoreContract, store: Attesto.CodeStore.ETS

  alias Attesto.CodeStore.ETS

  test "prevents non-owner processes from mutating its tables directly" do
    assert_raise ArgumentError, fn ->
      :ets.insert(ETS, {"injected", 9_999_999_999, %{code_hash: "injected"}})
    end

    assert_raise ArgumentError, fn ->
      :ets.insert(ETS.Consumed, {"injected", :infinity, %{family_id: "family"}})
    end

    assert_raise ArgumentError, fn ->
      :ets.insert(ETS.AccessTokens, {"injected", 9_999_999_999, "jti", nil})
    end

    assert_raise ArgumentError, fn ->
      :ets.insert(ETS.RevokedAccessTokens, {"jti", 9_999_999_999})
    end
  end

  test "tracks finalized consumption and retains unbounded family markers" do
    record = contract_code_record()
    :ok = ETS.put(record)
    assert {:ok, ^record} = ETS.take(record.code_hash)

    meta = %{family_id: "family-1", subject: "user-1", replay_retain_until: nil}
    assert :ok = ETS.mark_consumed(record.code_hash, meta)
    assert {:error, :consumed, ^meta} = ETS.take(record.code_hash)

    send(ETS, :sweep)
    :sys.get_state(ETS)
    assert {:error, :consumed, ^meta} = ETS.take(record.code_hash)
  end

  test "sweeps a bounded consumed marker after its family deadline" do
    record = contract_code_record()
    meta = %{family_id: "family-2", subject: "user-2", replay_retain_until: 1}
    :ok = ETS.mark_consumed(record.code_hash, meta)
    assert {:error, :consumed, ^meta} = ETS.take(record.code_hash)

    send(ETS, :sweep)
    :sys.get_state(ETS)
    assert :error = ETS.take(record.code_hash)
  end

  test "supports the Phoenix 4.1 no-refresh replay-containment sequence" do
    record = contract_code_record()
    expires_at = System.system_time(:second) + 600
    jti = "access-token-jti"
    meta = %{family_id: nil, subject: "user-1"}

    assert function_exported?(ETS, :record_access_token_for_code, 3)
    assert function_exported?(ETS, :revoke_access_token_for_code, 1)

    assert :ok = ETS.put(record)
    assert {:ok, ^record} = ETS.take(record.code_hash)
    assert :ok = ETS.record_access_token_for_code(record.code_hash, jti, expires_at)
    refute ETS.access_token_revoked?(jti)
    assert :ok = ETS.mark_consumed(record.code_hash, meta)
    assert {:error, :consumed, ^meta} = ETS.take(record.code_hash)
    assert :ok = ETS.revoke_access_token_for_code(record.code_hash)
    assert ETS.access_token_revoked?(jti)
  end

  test "binds the code-linked access token to the finalized refresh family" do
    record = contract_code_record()
    expires_at = System.system_time(:second) + 600
    jti = "refresh-access-token-jti"
    meta = %{family_id: "family-issued", subject: "user-1", replay_retain_until: expires_at + 600}

    assert :ok = ETS.put(record)
    assert {:ok, ^record} = ETS.take(record.code_hash)
    assert :ok = ETS.record_access_token_for_code(record.code_hash, jti, expires_at)
    assert :ok = ETS.mark_consumed(record.code_hash, meta)
    assert :ok = ETS.revoke_family_access_tokens(meta.family_id)
    assert ETS.access_token_revoked?(jti)
  end

  test "keeps access-token linkage and revocation markers bounded by token expiry" do
    code_hash = "expired-code-link"
    jti = "expired-access-token-jti"

    assert :ok = ETS.record_access_token_for_code(code_hash, jti, 1)
    assert :ok = ETS.revoke_access_token_for_code(code_hash)
    refute ETS.access_token_revoked?(jti)

    send(ETS, :sweep)
    :sys.get_state(ETS)

    assert [] = :ets.lookup(ETS.AccessTokens, code_hash)
    assert [] = :ets.lookup(ETS.RevokedAccessTokens, jti)
  end

  test "revoking one code does not revoke another code's access token" do
    expires_at = System.system_time(:second) + 600

    assert :ok = ETS.record_access_token_for_code("code-a", "jti-a", expires_at)
    assert :ok = ETS.record_access_token_for_code("code-b", "jti-b", expires_at)
    assert :ok = ETS.revoke_access_token_for_code("code-a")

    assert ETS.access_token_revoked?("jti-a")
    refute ETS.access_token_revoked?("jti-b")
  end
end
