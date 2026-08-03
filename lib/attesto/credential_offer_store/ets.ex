defmodule Attesto.CredentialOfferStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CredentialOfferStore`.

  Credential offers live in a public ETS table owned by a `GenServer` that
  sweeps expired rows on a fixed interval. `fetch/1` is non-consuming and
  returns an offer only while its expiry is strictly in the future.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CredentialOfferStore` with a shared store. Like the other ETS
  stores it refuses to boot on a clustered BEAM unless
  `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CredentialOfferStore

  use GenServer

  @table __MODULE__
  @default_sweep_interval_ms 30_000

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
  end

  @impl Attesto.CredentialOfferStore
  def put(%{id: id, offer: offer, expires_at: expires_at})
      when is_binary(id) and is_map(offer) and is_integer(expires_at) do
    true = :ets.insert(@table, {id, expires_at, offer})
    :ok
  end

  @impl Attesto.CredentialOfferStore
  def fetch(id) when is_binary(id) do
    now = System.system_time(:second)

    case :ets.lookup(@table, id) do
      [{^id, expires_at, offer}] when expires_at > now ->
        {:ok, offer}

      [{^id, _expires_at, _offer}] ->
        :ets.delete(@table, id)
        :error

      [] ->
        :error
    end
  end

  @doc "Clear every entry. Test-facing."
  @spec reset() :: :ok
  def reset do
    if :ets.whereis(@table) != :undefined, do: :ets.delete_all_objects(@table)
    :ok
  end

  @impl GenServer
  def init(opts) do
    Attesto.ClusterGuard.assert_single_node!(
      __MODULE__,
      Keyword.get(opts, :multi_node_acknowledged?, false)
    )

    sweep_interval_ms = Keyword.get(opts, :sweep_interval_ms, @default_sweep_interval_ms)

    :ets.new(@table, [:set, :public, :named_table, read_concurrency: true, write_concurrency: true])

    schedule_sweep(sweep_interval_ms)
    {:ok, %{sweep_interval_ms: sweep_interval_ms}}
  end

  @impl GenServer
  def handle_info(:sweep, state) do
    now = System.system_time(:second)
    # Delete every row whose expiry is strictly in the past.
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])

    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
end
