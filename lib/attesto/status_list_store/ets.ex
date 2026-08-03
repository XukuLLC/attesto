defmodule Attesto.StatusListStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.StatusListStore`.

  Allocation and status updates are serialized through the owning `GenServer`,
  making concurrent allocations for one URI atomic. Each URI is stored as one
  ETS row containing its next index and current status overrides.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.StatusListStore` with a shared store. Like the other ETS stores it
  refuses to boot on a clustered BEAM unless `multi_node_acknowledged?: true`.

  Start option: `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.StatusListStore

  use GenServer

  alias Attesto.StatusListStore

  @table __MODULE__

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
  end

  @impl StatusListStore
  def allocate(uri) when is_binary(uri) and uri != "" do
    GenServer.call(__MODULE__, {:allocate, uri})
  end

  def allocate(_uri), do: {:error, :invalid_uri}

  @impl StatusListStore
  def set_status(uri, idx, status)
      when is_binary(uri) and uri != "" and is_integer(idx) and idx >= 0 and is_integer(status) and status >= 0 do
    GenServer.call(__MODULE__, {:set_status, uri, idx, status})
  end

  def set_status(_uri, _idx, _status), do: :error

  @impl StatusListStore
  def statuses(uri) when is_binary(uri) and uri != "" do
    case :ets.lookup(@table, uri) do
      [{^uri, next_index, status_by_index}] ->
        Enum.map(0..(next_index - 1), &Map.get(status_by_index, &1, 0))

      [] ->
        []
    end
  end

  def statuses(_uri), do: []

  @impl StatusListStore
  def get_status(uri, idx) when is_binary(uri) and uri != "" and is_integer(idx) and idx >= 0 do
    case :ets.lookup(@table, uri) do
      [{^uri, next_index, status_by_index}] when idx < next_index ->
        {:ok, Map.get(status_by_index, idx, 0)}

      _other ->
        :error
    end
  end

  def get_status(_uri, _idx), do: :error

  @doc "Clear every status list. Test-facing."
  @spec reset() :: :ok
  def reset, do: GenServer.call(__MODULE__, :reset)

  @impl GenServer
  def init(opts) do
    Attesto.ClusterGuard.assert_single_node!(
      __MODULE__,
      Keyword.get(opts, :multi_node_acknowledged?, false)
    )

    :ets.new(@table, [:set, :protected, :named_table, read_concurrency: true])
    {:ok, %{}}
  end

  @impl GenServer
  def handle_call({:allocate, uri}, _from, state) do
    index =
      case :ets.lookup(@table, uri) do
        [{^uri, next_index, status_by_index}] ->
          true = :ets.insert(@table, {uri, next_index + 1, status_by_index})
          next_index

        [] ->
          true = :ets.insert(@table, {uri, 1, %{}})
          0
      end

    {:reply, {:ok, index}, state}
  end

  def handle_call({:set_status, uri, idx, status}, _from, state) do
    reply =
      case :ets.lookup(@table, uri) do
        [{^uri, next_index, status_by_index}] when idx < next_index ->
          true = :ets.insert(@table, {uri, next_index, Map.put(status_by_index, idx, status)})
          :ok

        _other ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call(:reset, _from, state) do
    true = :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end
end
