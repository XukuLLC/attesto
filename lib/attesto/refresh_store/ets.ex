defmodule Attesto.RefreshStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.RefreshStore`.

  Tokens live in an ETS table owned by a `GenServer`. The security-
  critical `consume/1` (check-unconsumed-and-mark-consumed) is serialised
  through the owning process: routing it as a `GenServer.call/2` makes the
  read-modify-write atomic without an ETS compare-and-set dance, which is
  the simplest correct primitive for a reference store. `insert/1` and
  `revoke_family/1` go through the same process so all mutations are
  ordered.

  This is a per-node store. A multi-node deployment MUST back
  `Attesto.RefreshStore` with a shared store whose `consume/1` is atomic
  across nodes (e.g. Postgres `UPDATE ... WHERE consumed = false
  RETURNING`), or reuse detection only holds per node.

  Start options: `:sweep_interval_ms` (default `60_000`). The sweeper
  deletes tokens past their expiry; consumed-but-unexpired tokens are
  retained so reuse within the TTL window is still detected.

      children = [Attesto.RefreshStore.ETS]
  """

  @behaviour Attesto.RefreshStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 60_000,
    table_options: [:set, :named_table, read_concurrency: true],
    extra_tables: [{__MODULE__.Revoked, [:set, :named_table, read_concurrency: true]}],
    reset: :server

  @table __MODULE__
  @revoked :"#{__MODULE__}.Revoked"
  # How long a revoked-family marker is retained: long enough to outlive
  # any in-flight successor insert racing a concurrent revocation (and any
  # token that could still be presented). Generous; the sweeper prunes it.
  @revoked_retention_seconds 30 * 24 * 60 * 60

  @impl Attesto.RefreshStore
  def insert(
        %{
          token_hash: token_hash,
          family_id: family_id,
          generation: generation,
          data: data,
          expires_at: expires_at,
          consumed: consumed
        } = record
      )
      when is_binary(token_hash) and is_binary(family_id) and is_integer(generation) and is_map(data) and
             is_integer(expires_at) and is_boolean(consumed), do: GenServer.call(__MODULE__, {:insert, record})

  @impl Attesto.RefreshStore
  def get(token_hash) when is_binary(token_hash) do
    case :ets.lookup(@table, token_hash) do
      [{^token_hash, _family, _exp, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @impl Attesto.RefreshStore
  def consume(token_hash, opts \\ []) when is_binary(token_hash) and is_list(opts),
    do: GenServer.call(__MODULE__, {:consume, token_hash, opts})

  @impl Attesto.RefreshStore
  def remember_successor(token_hash, successor, opts \\ [])
      when is_binary(token_hash) and is_map(successor) and is_list(opts),
      do: GenServer.call(__MODULE__, {:remember_successor, token_hash, successor, opts})

  @impl Attesto.RefreshStore
  def revoke_family(family_id) when is_binary(family_id), do: GenServer.call(__MODULE__, {:revoke_family, family_id})

  @impl GenServer
  def handle_call({:insert, record}, _from, state) do
    if family_revoked?(record.family_id) do
      # Sticky revocation: refuse a successor insert into a revoked family,
      # even one that won its claim before the revocation landed.
      {:reply, {:error, :family_revoked}, state}
    else
      row = {record.token_hash, record.family_id, record.expires_at, record}
      true = :ets.insert(@table, row)
      {:reply, :ok, state}
    end
  end

  def handle_call({:consume, token_hash, opts}, _from, state) do
    now = Keyword.get(opts, :now, System.system_time(:second))

    reply =
      case :ets.lookup(@table, token_hash) do
        [] ->
          :error

        [{^token_hash, _family, _exp, %{consumed: true} = record}] ->
          {:reuse, record}

        [{^token_hash, family, exp, %{consumed: false} = record}] ->
          consumed =
            record
            |> Map.put(:consumed, true)
            |> Map.put(:consumed_at, now)

          true = :ets.insert(@table, {token_hash, family, exp, consumed})
          {:ok, record}
      end

    {:reply, reply, state}
  end

  def handle_call({:remember_successor, token_hash, successor, _opts}, _from, state) do
    reply =
      case :ets.lookup(@table, token_hash) do
        [{^token_hash, family, exp, %{consumed: true} = record}] ->
          true = :ets.insert(@table, {token_hash, family, exp, Map.put(record, :successor, successor)})
          :ok

        _ ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call({:revoke_family, family_id}, _from, state) do
    # Mark the family revoked (sticky) BEFORE deleting its rows, so a
    # concurrent insert serialized after this call sees the marker.
    true = :ets.insert(@revoked, {family_id, System.system_time(:second) + @revoked_retention_seconds})
    :ets.match_delete(@table, {:_, family_id, :_, :_})
    {:reply, :ok, state}
  end

  defp delete_expired(now) do
    :ets.select_delete(@table, [{{:_, :_, :"$1", :_}, [{:<, :"$1", now}], [true]}])
    :ets.select_delete(@revoked, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
  end

  defp family_revoked?(family_id) do
    case :ets.lookup(@revoked, family_id) do
      [{^family_id, expiry}] -> expiry > System.system_time(:second)
      [] -> false
    end
  end
end
