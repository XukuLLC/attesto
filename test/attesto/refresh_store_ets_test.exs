defmodule Attesto.RefreshStore.ETSTest do
  @moduledoc false
  # Contract tests for the single-node ETS implementation of
  # `Attesto.RefreshStore`, focused on the atomic rotation transition and
  # family revocation. The named-singleton store forces
  # async: false.
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore.ETS
  alias Attesto.Secret

  setup do
    start_supervised!(ETS)
    :ok
  end

  defp record(token_hash, opts \\ []) do
    %{
      token_hash: token_hash,
      family_id: Keyword.get(opts, :family_id, "fam-default"),
      generation: Keyword.get(opts, :generation, 0),
      data: Keyword.get(opts, :data, %{subject: "usr_42", scope: ["documents.read"]}),
      expires_at: Keyword.get(opts, :expires_at, System.system_time(:second) + 1_209_600),
      consumed: Keyword.get(opts, :consumed, false)
    }
  end

  defp child(token, opts \\ []) do
    record(Secret.hash(token),
      family_id: Keyword.get(opts, :family_id, "fam-default"),
      generation: Keyword.get(opts, :generation, 1),
      data: Keyword.get(opts, :data, %{subject: "usr_42", scope: ["documents.read"]}),
      expires_at: Keyword.get(opts, :expires_at, 4_102_444_800)
    )
  end

  defp successor(token, child, opts \\ []) do
    (Keyword.get(opts, :strict, false) &&
       %{retry_until: Keyword.get(opts, :now, 1_000), recoverable: false}) ||
      %{
        token: token,
        generation: child.generation,
        context: child.data,
        retry_until: Keyword.get(opts, :retry_until, 1_010)
      }
  end

  test "rotate returns committed parent and child snapshots" do
    rec = record("tok-rotate-once")
    assert :ok = ETS.insert(rec)

    child = child("tok-child-once")

    assert {:ok, returned_parent, returned_child} =
             ETS.rotate(rec.token_hash, child, successor("tok-child-once", child), now: 1_000)

    assert returned_parent.token_hash == rec.token_hash
    assert returned_parent.consumed == true
    assert returned_parent.consumed_at == 1_000
    assert returned_parent.successor.token == "tok-child-once"
    assert returned_child == child
  end

  test "a second rotate returns the complete committed parent" do
    rec = record("tok-reuse")
    assert :ok = ETS.insert(rec)
    child = child("tok-reuse-child")
    retry = successor("tok-reuse-child", child)

    assert {:ok, _, _} = ETS.rotate(rec.token_hash, child, retry, now: 1_000)
    candidate = child("tok-reuse-other")
    assert {:reuse, reused} = ETS.rotate(rec.token_hash, candidate, successor("tok-reuse-other", candidate), now: 1_001)
    assert reused.token_hash == "tok-reuse"
    assert reused.family_id == "fam-default"
    assert reused.consumed == true
    assert reused.successor == retry
  end

  test "rotate of an absent hash returns :error" do
    candidate = child("tok-never-inserted-child")

    assert :error =
             ETS.rotate("tok-never-inserted", candidate, successor("tok-never-inserted-child", candidate), now: 1_000)
  end

  test "invalid direct rotation options do not stop or mutate the store" do
    refute function_exported?(ETS, :rotate, 3)

    rec = record("tok-invalid-direct")
    assert :ok = ETS.insert(rec)
    pid = Process.whereis(ETS)
    candidate = child("tok-invalid-direct-child")
    retry = successor("tok-invalid-direct-child", candidate)

    for opts <- [[], [now: -1], [now: "not-a-clock"], [now: 1.0], [{:now, 1, 2}]] do
      assert {:error, :invalid_rotation} = ETS.rotate(rec.token_hash, candidate, retry, opts)
      assert Process.whereis(ETS) == pid
      assert Process.alive?(pid)
      assert {:ok, ^rec} = ETS.get(rec.token_hash)
    end

    assert {:ok, _parent, ^candidate} = ETS.rotate(rec.token_hash, candidate, retry, now: 1_000)
    assert Process.whereis(ETS) == pid
    assert Process.alive?(pid)
  end

  test "revoke_family removes every record sharing a family_id, leaving others" do
    assert :ok = ETS.insert(record("tok-fam1-a", family_id: "fam-1", generation: 0))
    assert :ok = ETS.insert(record("tok-fam1-b", family_id: "fam-1", generation: 1))
    assert :ok = ETS.insert(record("tok-fam1-c", family_id: "fam-1", generation: 2))
    assert :ok = ETS.insert(record("tok-fam2-a", family_id: "fam-2", generation: 0))

    assert :ok = ETS.revoke_family("fam-1")

    # Every fam-1 token is gone.
    assert :error = ETS.get("tok-fam1-a")
    assert :error = ETS.get("tok-fam1-b")
    assert :error = ETS.get("tok-fam1-c")

    # The token in the untouched family survives and is still rotatable.
    survivor_child = child("tok-fam2-b", family_id: "fam-2")

    assert {:ok, survivor, _} =
             ETS.rotate("tok-fam2-a", survivor_child, successor("tok-fam2-b", survivor_child), now: 1_000)

    assert survivor.family_id == "fam-2"
  end

  test "reset clears all stored records" do
    assert :ok = ETS.insert(record("tok-r1", family_id: "fam-x"))
    assert :ok = ETS.insert(record("tok-r2", family_id: "fam-y"))

    assert :ok = ETS.reset()

    assert :error = ETS.get("tok-r1")
    assert :error = ETS.get("tok-r2")
  end
end
