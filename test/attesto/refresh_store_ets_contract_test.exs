defmodule Attesto.RefreshStoreETSContractTest do
  @moduledoc false
  # Runs the shared `Attesto.RefreshStore` contract against the ETS
  # reference implementation. async: false because
  # `Attesto.RefreshStore.ETS` is a named singleton GenServer; the contract
  # `setup` starts it via start_supervised!.
  use ExUnit.Case, async: false
  use Attesto.RefreshStoreContract, store: Attesto.RefreshStore.ETS

  alias Attesto.RefreshStore.ETS
  alias Attesto.Secret

  defp rotate_fixture(record, now, retry_until) do
    token = "sweeper-successor-#{:erlang.unique_integer([:positive])}"

    child =
      contract_refresh_record(%{
        token_hash: Secret.hash(token),
        family_id: record.family_id,
        generation: record.generation + 1,
        data: record.data,
        expires_at: now + 3_600
      })

    successor = %{
      token: token,
      generation: child.generation,
      context: child.data,
      retry_until: retry_until
    }

    {child, successor}
  end

  test "the sweeper redacts plaintext successor state after retry_until" do
    now = System.system_time(:second)
    rotation_now = now - 100
    record = contract_refresh_record(%{expires_at: rotation_now + 3_600})
    :ok = ETS.insert(record)
    retry_until = rotation_now + 1
    {child, successor} = rotate_fixture(record, rotation_now, retry_until)

    assert {:ok, _parent, ^child} = ETS.rotate(record.token_hash, child, successor, now: rotation_now)

    send(ETS, :sweep)
    :sys.get_state(ETS)

    assert {:ok, stored} = ETS.get(record.token_hash)
    assert stored.successor == %{retry_until: retry_until, recoverable: false}
    refute inspect(stored.successor) =~ successor.token
  end

  test "the sweeper retains an expired parent until its live retry deadline" do
    now = System.system_time(:second)
    rotation_now = now - 100
    record = contract_refresh_record(%{expires_at: now - 1})
    :ok = ETS.insert(record)
    {child, successor} = rotate_fixture(record, rotation_now, now + 60)
    assert {:ok, _parent, ^child} = ETS.rotate(record.token_hash, child, successor, now: rotation_now)

    send(ETS, :sweep)
    :sys.get_state(ETS)

    assert {:ok, %{successor: %{token: token}}} = ETS.get(record.token_hash)
    assert token == successor.token
  end

  test "the sweeper removes an expired parent after its retry deadline" do
    now = System.system_time(:second)
    rotation_now = now - 100
    record = contract_refresh_record(%{expires_at: now - 2})
    :ok = ETS.insert(record)
    {child, successor} = rotate_fixture(record, rotation_now, now - 1)
    assert {:ok, _parent, ^child} = ETS.rotate(record.token_hash, child, successor, now: rotation_now)

    send(ETS, :sweep)
    :sys.get_state(ETS)

    assert :error = ETS.get(record.token_hash)
  end

  test "revocation remains sticky past the legacy 30-day horizon for a long-lived imported family" do
    now = System.system_time(:second)
    family_id = "imported-long-lived-family"
    record = contract_refresh_record(%{family_id: family_id, expires_at: now + 365 * 24 * 60 * 60})
    :ok = ETS.insert(record)
    :ok = ETS.revoke_family(family_id)

    revoked_table = :"#{ETS}.Revoked"
    assert [{^family_id, :infinity}] = :ets.lookup(revoked_table, family_id)

    send(ETS, :sweep)
    :sys.get_state(ETS)
    assert [{^family_id, :infinity}] = :ets.lookup(revoked_table, family_id)

    late_record = contract_refresh_record(%{family_id: family_id, generation: 1, expires_at: now + 365 * 24 * 60 * 60})
    assert {:error, :family_revoked} = ETS.insert(late_record)
  end
end
