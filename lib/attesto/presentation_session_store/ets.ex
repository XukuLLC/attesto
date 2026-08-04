defmodule Attesto.PresentationSessionStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.PresentationSessionStore`.

  Presentation sessions live in a public named ETS table owned by a
  `GenServer`. `complete/2` runs inside the owner process and atomically guards
  the `pending` to `completed` transition on status and expiry. Concurrent
  submissions therefore have exactly one possible winner on this node.

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

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000, reset: :server

  @table __MODULE__

  @impl Attesto.PresentationSessionStore
  def put(%{id: id, data: data, expires_at: expires_at} = entry)
      when is_binary(id) and is_map(data) and is_integer(expires_at) do
    GenServer.call(__MODULE__, {:put, entry})
  end

  @impl Attesto.PresentationSessionStore
  def get(id) when is_binary(id) do
    case :ets.lookup(@table, id) do
      [{^id, _expires_at, entry}] -> {:ok, entry}
      [] -> :error
    end
  end

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
