defmodule Attesto.CodeStore.ETSTest do
  @moduledoc false
  # Contract tests for the single-node ETS implementation of
  # `Attesto.CodeStore`. The named-singleton store forces async: false.
  use ExUnit.Case, async: false

  alias Attesto.CodeStore.ETS

  setup do
    start_supervised!(ETS)
    :ok
  end

  defp record(code_hash, opts \\ []) do
    %{
      code_hash: code_hash,
      data: Keyword.get(opts, :data, %{client_id: "oc_app", subject: "usr_42"}),
      expires_at: Keyword.get(opts, :expires_at, System.system_time(:second) + 60)
    }
  end

  test "put then claim returns {:ok, record}" do
    rec = record("hash-roundtrip")
    assert :ok = ETS.put(rec)
    assert :ok = ETS.claim("hash-roundtrip")
  end

  test "claim removes the record so a second claim of the same hash is :error (single use)" do
    rec = record("hash-single-use")
    assert :ok = ETS.put(rec)

    assert :ok = ETS.claim("hash-single-use")
    assert :error = ETS.claim("hash-single-use")
  end

  test "claim of an absent hash returns :error" do
    assert :error = ETS.claim("hash-never-stored")
  end

  test "prevents non-owner processes from mutating its tables directly" do
    for table <- [ETS, ETS.Tokens] do
      assert :ets.info(table, :protection) == :protected
      assert_raise ArgumentError, fn -> :ets.insert(table, {"injected", true}) end
    end
  end

  test "revocation reads the token index while the owner is suspended" do
    now = System.system_time(:second)
    :ok = ETS.put(record("indexed"))
    :ok = ETS.claim("indexed")
    :ok = ETS.record_access_token_for_code("indexed", "jti", now + 600)
    :ok = ETS.revoke_access_token_for_code("indexed")
    :sys.suspend(ETS)

    try do
      assert ETS.access_token_revoked?("jti")
      refute ETS.access_token_revoked?("absent")
    after
      :sys.resume(ETS)
    end
  end

  test "abandoned claims expire after their fixed reservation only when code and token expire" do
    now = System.system_time(:second)

    for {hash, expiry, token_expiry} <- [
          {"reserved", now - 1, nil},
          {"abandoned", now - 1, nil},
          {"code-live", now + 600, nil},
          {"token-live", now - 1, now + 600}
        ] do
      :ok = ETS.put(record(hash, expires_at: expiry))
      :ok = ETS.claim(hash)
      if token_expiry, do: ETS.record_access_token_for_code(hash, hash, token_expiry)

      if hash != "reserved" do
        :sys.replace_state(ETS, fn state ->
          [{^hash, row, token, revoked}] = :ets.lookup(ETS, hash)
          :ets.insert(ETS, {hash, %{row | claim_retain_until: now}, token, revoked})
          state
        end)
      end
    end

    send(Process.whereis(ETS), :sweep)
    assert :error = ETS.read("abandoned")
    for hash <- ["reserved", "code-live", "token-live"], do: assert({:ok, _} = ETS.read(hash))
    assert :error = ETS.finish("abandoned", %{subject: "subject", family_id: nil, replay_retain_until: nil})
  end

  describe "delete_unclaimed/1" do
    defp grant(subject, client_id, sid), do: %{subject: subject, client_id: client_id, claims: %{"sid" => sid}}

    setup do
      :ok = ETS.put(record("u1-a-s1", data: grant("usr_1", "client_a", "s1")))
      :ok = ETS.put(record("u1-b-s2", data: grant("usr_1", "client_b", "s2")))
      :ok = ETS.put(record("u2-a-s3", data: grant("usr_2", "client_a", "s3")))
      :ok
    end

    test "deletes the matching unredeemed codes and reports the count" do
      assert {:ok, 2} = ETS.delete_unclaimed(subject: "usr_1")

      assert :error = ETS.claim("u1-a-s1")
      assert :error = ETS.claim("u1-b-s2")
      assert :ok = ETS.claim("u2-a-s3")
    end

    test "criteria are ANDed, and sid matches the recorded session" do
      assert {:ok, 1} = ETS.delete_unclaimed(subject: "usr_1", client_id: "client_a")
      assert {:ok, 1} = ETS.delete_unclaimed(sid: "s3")
      assert {:ok, 0} = ETS.delete_unclaimed(sid: "s1")
      assert :ok = ETS.claim("u1-b-s2")
    end

    test "a redeemed code keeps its reuse marker" do
      assert :ok = ETS.claim("u1-a-s1")
      assert {:ok, _} = ETS.finish("u1-a-s1", %{family_id: "fam-1", subject: "usr_1", replay_retain_until: nil})

      assert {:ok, 1} = ETS.delete_unclaimed(subject: "usr_1")
      assert {:ok, %{state: :redeemed, redemption: %{family_id: "fam-1"}}} = ETS.read("u1-a-s1")
    end

    test "empty criteria are refused, so a bug cannot clear the store" do
      assert_raise ArgumentError, fn -> ETS.delete_unclaimed([]) end
      assert :ok = ETS.claim("u1-a-s1")
    end
  end

  test "reset clears all stored records" do
    assert :ok = ETS.put(record("hash-a"))
    assert :ok = ETS.put(record("hash-b"))

    assert :ok = ETS.reset()

    assert :error = ETS.claim("hash-a")
    assert :error = ETS.claim("hash-b")
  end

  test "a record whose expires_at is in the past is still returned by claim" do
    # The store does not gate on expiry; `Attesto.AuthorizationCode`
    # re-checks expiry after claim. The store's only job is the atomic
    # claim, so an expired-but-present row must still come back.
    past = System.system_time(:second) - 3600
    rec = record("hash-expired", expires_at: past)
    assert :ok = ETS.put(rec)

    assert :ok = ETS.claim("hash-expired")
    # Still single use even when expired.
    assert :error = ETS.claim("hash-expired")
  end
end
