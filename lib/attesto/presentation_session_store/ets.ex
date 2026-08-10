defmodule Attesto.PresentationSessionStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.PresentationSessionStore`.

  Presentation sessions live in a `:protected` named ETS table owned by a
  `GenServer`. Every write runs inside that owner process, so `complete/2`
  atomically guards the `pending` to `completed` transition on status and
  expiry and concurrent submissions have exactly one possible winner on this
  node; no other process can write the table directly.

  This is a per-node store. A multi-node deployment MUST use a shared store,
  or explicitly acknowledge the limitation with
  `multi_node_acknowledged?: true`.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired entries are
      deleted.
    * `:multi_node_acknowledged?` (default `false`) - permit this per-node store
      to start on a clustered BEAM.

  ## Wiring

      children = [Attesto.PresentationSessionStore.ETS]
  """

  @behaviour Attesto.PresentationSessionStore

  # `:protected`, not the shared default `:public`: every write here already runs
  # inside the owner process (`put`/`complete`/`take`/`attach_*` are
  # `GenServer.call`s), so no other process needs write access. Dropping `:public`
  # stops a co-resident BEAM process from calling `:ets.insert/2` directly to
  # overwrite a verified result or bypass the atomic pending -> completed guard.
  # Reads (`get/1`) stay direct and are unaffected. The rows still hold plaintext
  # session data, so a co-resident process can read them; treat in-VM code
  # execution as out of scope, as everywhere else.
  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    reset: :server,
    table_options: [:set, :protected, :named_table, read_concurrency: true, write_concurrency: true]

  @table __MODULE__

  @impl Attesto.PresentationSessionStore
  def put(%{id: id, data: data, expires_at: expires_at} = entry)
      when is_binary(id) and is_map(data) and is_integer(expires_at) do
    GenServer.call(__MODULE__, {:put, entry})
  end

  @impl Attesto.PresentationSessionStore
  def get(id) when is_binary(id) do
    case :ets.lookup(@table, id) do
      [{^id, _expires_at, entry}] -> {:ok, drop_result(entry)}
      [] -> :error
    end
  end

  # `get/1` must never expose a completed session's verified result (the
  # presented PII): that is read exactly once via `take/1`. Strip it here so a
  # host that reads a completed session with `get/1` (against the contract)
  # still cannot re-read the claims. Status, expiry, request object, and
  # response-encryption key — everything `get/1` legitimately serves — remain.
  defp drop_result(%{data: %{result: _} = data} = entry), do: %{entry | data: Map.delete(data, :result)}

  defp drop_result(entry), do: entry

  @impl Attesto.PresentationSessionStore
  def complete(id, result) when is_binary(id) and is_map(result) do
    GenServer.call(__MODULE__, {:complete, id, result})
  end

  @impl Attesto.PresentationSessionStore
  def take(id) when is_binary(id) do
    GenServer.call(__MODULE__, {:take, id})
  end

  @impl Attesto.PresentationSessionStore
  def attach_request_object(id, request_object) when is_binary(id) and is_binary(request_object) do
    GenServer.call(__MODULE__, {:attach_request_object, id, request_object})
  end

  @impl Attesto.PresentationSessionStore
  def attach_response_encryption_jwk(id, jwk) when is_binary(id) and is_map(jwk) do
    GenServer.call(__MODULE__, {:attach_response_encryption_jwk, id, jwk})
  end

  @impl GenServer
  def handle_call({:put, entry}, _from, state) do
    true = :ets.insert_new(@table, {entry.id, entry.expires_at, entry})
    {:reply, :ok, state}
  end

  def handle_call({:complete, id, result}, _from, state) do
    now = System.system_time(:second)

    reply =
      case :ets.lookup(@table, id) do
        [{^id, expires_at, %{data: %{status: :pending} = data} = entry}] when expires_at > now ->
          completed_data = data |> Map.put(:status, :completed) |> Map.put(:result, result)
          completed = Map.put(entry, :data, completed_data)
          true = :ets.insert(@table, {id, expires_at, completed})
          :ok

        _other ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call({:attach_request_object, id, request_object}, _from, state) do
    now = System.system_time(:second)

    reply =
      case :ets.lookup(@table, id) do
        [{^id, expires_at, %{data: %{status: :pending} = data} = entry}] when expires_at > now ->
          updated = Map.put(entry, :data, Map.put(data, :request_object, request_object))
          true = :ets.insert(@table, {id, expires_at, updated})
          :ok

        _other ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call({:attach_response_encryption_jwk, id, jwk}, _from, state) do
    now = System.system_time(:second)

    reply =
      case :ets.lookup(@table, id) do
        [{^id, expires_at, %{data: %{status: :pending} = data} = entry}] when expires_at > now ->
          updated = Map.put(entry, :data, Map.put(data, :response_encryption_jwk, jwk))
          true = :ets.insert(@table, {id, expires_at, updated})
          :ok

        _other ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call({:take, id}, _from, state) do
    now = System.system_time(:second)

    reply =
      case :ets.lookup(@table, id) do
        [{^id, expires_at, %{data: %{status: :completed}}}] when expires_at > now ->
          case :ets.take(@table, id) do
            [{^id, ^expires_at, entry}] -> {:ok, entry}
            [] -> :error
          end

        _other ->
          :error
      end

    {:reply, reply, state}
  end

  defp delete_expired(now) do
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
  end
end
