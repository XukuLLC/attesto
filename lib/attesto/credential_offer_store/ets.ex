defmodule Attesto.CredentialOfferStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CredentialOfferStore`.

  Credential offers live in a `:protected` ETS table owned by a `GenServer`
  that sweeps expired rows on a fixed interval. Writes (`put/1`, sweeping) run
  in the owner process; `fetch/1` reads directly, is non-consuming, and returns
  an offer only while its expiry is strictly in the future.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CredentialOfferStore` with a shared store. Like the other ETS
  stores it refuses to boot on a clustered BEAM unless
  `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CredentialOfferStore

  # `:protected`, not the shared default `:public`. An offer row carries a
  # redeemable `pre-authorized_code`, so a co-resident BEAM process must not be
  # able to `:ets.insert/2` a forged offer or overwrite a live one. Both writes
  # here (`put/1` and expiry sweeping) run inside the owner process; `fetch/1`
  # reads directly and is unaffected. A co-resident process can still read the
  # table - in-VM code execution is out of scope, as elsewhere.
  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    reset: :server,
    table_options: [:set, :protected, :named_table, read_concurrency: true, write_concurrency: true]

  @table __MODULE__

  @impl Attesto.CredentialOfferStore
  def put(%{id: id, offer: offer, expires_at: expires_at} = entry)
      when is_binary(id) and is_map(offer) and is_integer(expires_at) do
    GenServer.call(__MODULE__, {:put, entry})
  end

  @impl Attesto.CredentialOfferStore
  def fetch(id) when is_binary(id) do
    now = System.system_time(:second)

    # Return only live rows. Expired rows are left for the owner's sweep rather
    # than deleted here, so `fetch/1` performs no write (the table is
    # `:protected`; only the owner writes).
    case :ets.lookup(@table, id) do
      [{^id, expires_at, offer}] when expires_at > now -> {:ok, offer}
      _other -> :error
    end
  end

  @impl GenServer
  def handle_call({:put, %{id: id, offer: offer, expires_at: expires_at}}, _from, state) do
    true = :ets.insert(@table, {id, expires_at, offer})
    {:reply, :ok, state}
  end

  defp delete_expired(now) do
    # Delete every row whose expiry is strictly in the past.
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
  end
end
