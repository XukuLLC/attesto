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

  test "put then take returns {:ok, record}" do
    rec = record("hash-roundtrip")
    assert :ok = ETS.put(rec)
    assert {:ok, ^rec} = ETS.take("hash-roundtrip")
  end

  test "take removes the record so a second take of the same hash is :error (single use)" do
    rec = record("hash-single-use")
    assert :ok = ETS.put(rec)

    assert {:ok, ^rec} = ETS.take("hash-single-use")
    assert :error = ETS.take("hash-single-use")
  end

  test "take of an absent hash returns :error" do
    assert :error = ETS.take("hash-never-stored")
  end

  describe "delete_unconsumed/1" do
    defp grant(subject, client_id, sid), do: %{subject: subject, client_id: client_id, claims: %{"sid" => sid}}

    setup do
      :ok = ETS.put(record("u1-a-s1", data: grant("usr_1", "client_a", "s1")))
      :ok = ETS.put(record("u1-b-s2", data: grant("usr_1", "client_b", "s2")))
      :ok = ETS.put(record("u2-a-s3", data: grant("usr_2", "client_a", "s3")))
      :ok
    end

    test "deletes the matching unredeemed codes and reports the count" do
      assert {:ok, 2} = ETS.delete_unconsumed(subject: "usr_1")

      assert :error = ETS.take("u1-a-s1")
      assert :error = ETS.take("u1-b-s2")
      assert {:ok, _} = ETS.take("u2-a-s3")
    end

    test "criteria are ANDed, and sid matches the recorded session" do
      assert {:ok, 1} = ETS.delete_unconsumed(subject: "usr_1", client_id: "client_a")
      assert {:ok, 1} = ETS.delete_unconsumed(sid: "s3")
      assert {:ok, 0} = ETS.delete_unconsumed(sid: "s1")
      assert {:ok, _} = ETS.take("u1-b-s2")
    end

    test "a redeemed code keeps its reuse marker" do
      assert {:ok, _} = ETS.take("u1-a-s1")
      assert :ok = ETS.mark_consumed("u1-a-s1", %{family_id: "fam-1", subject: "usr_1", replay_retain_until: nil})

      assert {:ok, 1} = ETS.delete_unconsumed(subject: "usr_1")
      assert {:error, :consumed, %{family_id: "fam-1"}} = ETS.take("u1-a-s1")
    end

    test "empty criteria are refused, so a bug cannot clear the store" do
      assert_raise ArgumentError, fn -> ETS.delete_unconsumed([]) end
      assert {:ok, _} = ETS.take("u1-a-s1")
    end
  end

  test "reset clears all stored records" do
    assert :ok = ETS.put(record("hash-a"))
    assert :ok = ETS.put(record("hash-b"))

    assert :ok = ETS.reset()

    assert :error = ETS.take("hash-a")
    assert :error = ETS.take("hash-b")
  end

  test "a record whose expires_at is in the past is still returned by take" do
    # The store does not gate on expiry; `Attesto.AuthorizationCode`
    # re-checks expiry after take. The store's only job is the atomic
    # get-and-delete, so an expired-but-present row must still come back.
    past = System.system_time(:second) - 3600
    rec = record("hash-expired", expires_at: past)
    assert :ok = ETS.put(rec)

    assert {:ok, ^rec} = ETS.take("hash-expired")
    # Still single use even when expired.
    assert :error = ETS.take("hash-expired")
  end
end
