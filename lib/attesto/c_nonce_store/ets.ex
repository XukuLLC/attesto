defmodule Attesto.CNonceStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CNonceStore`.

  Nonces are random 128-bit base64url strings held in a public ETS table
  owned by a `GenServer` that sweeps expired entries. Validation is
  non-consuming, so a c_nonce may be used by several proofs in one batch.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CNonceStore` with a shared store. Like the other ETS stores it
  refuses to boot on a clustered BEAM unless `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CNonceStore

  use GenServer

  alias Attesto.CNonceStore
  alias Attesto.Secret

  @table __MODULE__
  @default_ttl_seconds 300
  @default_sweep_interval_ms 30_000
  @nonce_bytes 16

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
  end

  @impl CNonceStore
  def issue(ttl_seconds \\ @default_ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    nonce = Secret.generate(@nonce_bytes)
    true = :ets.insert(@table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  @impl CNonceStore
  def valid?(nonce) when is_binary(nonce) do
    case :ets.lookup(@table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid?(_), do: false

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
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
end
