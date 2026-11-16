defmodule Attesto.CodeStoreETSContractTest do
  use ExUnit.Case, async: false
  use Attesto.Test.CodeStoreContract, store: Attesto.CodeStore.ETS

  alias Attesto.CodeStore.ETS

  test "cleanup retains in-flight issuance and both token and family lifetimes" do
    now = System.system_time(:second)

    for hash <- ["claimed", "unbounded", "bounded", "token", "expired"] do
      :ok = ETS.put(%{code_hash: hash, data: %{}, expires_at: now - 60})
      :ok = ETS.claim(hash)
    end

    for {hash, family, deadline} <- [
          {"unbounded", "family", nil},
          {"bounded", "family", now + 600},
          {"token", nil, nil},
          {"expired", nil, nil}
        ] do
      {:ok, _} = ETS.finish(hash, %{family_id: family, subject: "subject", replay_retain_until: deadline})
    end

    :ok = ETS.record_access_token_for_code("token", "retained-token", now + 600)
    send(Process.whereis(ETS), :sweep)
    for hash <- ["claimed", "unbounded", "bounded", "token"], do: assert({:ok, _} = ETS.read(hash))
    assert :error = ETS.read("expired")
  end

  test "duplicate inserts cannot reopen live, claimed or redeemed codes" do
    for phase <- [:live, :claimed, :redeemed] do
      hash = Atom.to_string(phase)
      entry = %{code_hash: hash, data: %{}, expires_at: System.system_time(:second) + 600}
      :ok = ETS.put(entry)
      if phase != :live, do: :ok = ETS.claim(hash)

      if phase == :redeemed,
        do: {:ok, _} = ETS.finish(hash, %{family_id: nil, subject: "subject", replay_retain_until: nil})

      before = ETS.read(hash)
      assert_raise ArgumentError, "authorization code hash already exists", fn -> ETS.put(entry) end
      assert ETS.read(hash) == before
    end
  end
end
