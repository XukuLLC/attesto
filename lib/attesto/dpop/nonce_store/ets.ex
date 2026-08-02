defmodule Attesto.DPoP.NonceStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.DPoP.NonceStore`.

  Nonces are random 128-bit base64url strings held in a public ETS table
  owned by a `GenServer` that sweeps expired entries. `validate/1` is the
  shape `Attesto.DPoP.verify_proof/2` expects for its `:nonce_check`:

      Attesto.DPoP.verify_proof(proof,
        http_method: "GET",
        http_uri: uri,
        nonce_check: &Attesto.DPoP.NonceStore.ETS.validate/1
      )

  and the server returns a fresh nonce on the challenge / on rotation with
  `issue/1`.

  This is a per-node store; a nonce issued on one node is unknown to
  another, so a multi-node deployment MUST back `Attesto.DPoP.NonceStore`
  with a shared store. Like the other ETS stores it refuses to boot on a
  clustered BEAM unless `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.DPoP.NonceStore

  use GenServer

  alias Attesto.DPoP.NonceStore
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

  @impl NonceStore
  def issue(ttl_seconds \\ @default_ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    nonce = Secret.generate(@nonce_bytes)
    true = :ets.insert(@table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  @impl NonceStore
  def valid?(nonce) when is_binary(nonce) do
    case :ets.lookup(@table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid?(_), do: false

  @doc """
  The `:nonce_check` callback for `Attesto.DPoP.verify_proof/2`: returns
  `:ok` for a live issued nonce, or `{:error, :use_dpop_nonce}` for a
  missing (nil), unknown, or expired one.
  """
  @spec validate(String.t() | nil) :: :ok | {:error, :use_dpop_nonce}
  def validate(nonce) do
    if is_binary(nonce) and valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
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
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
end
