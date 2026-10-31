defmodule Attesto.DeviceCodeStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.DeviceCodeStore`.

  Device-code records live in an ETS table owned by a `GenServer`. The
  state-changing callbacks (`approve/3`, `deny/2`, `poll/2`, `consume/2`) run
  inside `GenServer.call/2`, so they are serialized through the owner process —
  that is how this reference store gets the atomic, single-winner state
  transitions `Attesto.DeviceCodeStore` requires (a production multi-node
  deployment uses the Ecto store, whose transitions are single conditional
  `UPDATE ... RETURNING` statements). Reads that do not transition state
  (`lookup_user_code/1`, `get/1`) hit the table directly.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired rows are
      bulk-deleted. Correctness does not depend on sweeping (`redeem/4`
      re-checks expiry); the sweeper only bounds table size.

  ## Wiring

      children = [Attesto.DeviceCodeStore.ETS]
  """

  @behaviour Attesto.DeviceCodeStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    table_options: [:named_table, :protected, :set, read_concurrency: true],
    extra_tables: [{__MODULE__.UserIndex, [:named_table, :protected, :set, read_concurrency: true]}],
    cluster_guard?: false,
    interval_before_tables?: false,
    reset: :server,
    reset_doc: false,
    reset_spec?: false

  alias Attesto.PollingGrant.ETSTable

  @table __MODULE__
  @user_index __MODULE__.UserIndex

  @impl Attesto.DeviceCodeStore
  def put(%{device_code_hash: hash, user_code: user_code} = record) when is_binary(hash) and is_binary(user_code) do
    GenServer.call(__MODULE__, {:put, record})
  end

  @impl Attesto.DeviceCodeStore
  def lookup_user_code(user_code) when is_binary(user_code) do
    case :ets.lookup(@user_index, user_code) do
      [{^user_code, hash}] -> ETSTable.lookup(@table, hash)
      [] -> :error
    end
  end

  @impl Attesto.DeviceCodeStore
  def get(hash) when is_binary(hash), do: ETSTable.lookup(@table, hash)

  @impl Attesto.DeviceCodeStore
  def approve(user_code, approval, opts) when is_binary(user_code) and is_map(approval) and is_map(opts) do
    GenServer.call(__MODULE__, {:decide, user_code, :approved, approval, opts})
  end

  @impl Attesto.DeviceCodeStore
  def deny(user_code, opts) when is_binary(user_code) and is_map(opts) do
    GenServer.call(__MODULE__, {:decide, user_code, :denied, %{}, opts})
  end

  @impl Attesto.DeviceCodeStore
  def poll(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:poll, hash, opts})
  end

  @impl Attesto.DeviceCodeStore
  def consume(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:consume, hash, opts})
  end

  # ----- server -----

  @impl GenServer
  def handle_call({:put, record}, _from, state) do
    # Reject a colliding user_code so the caller retries with a fresh one,
    # rather than orphaning the existing flow by remapping the index.
    if :ets.member(@user_index, record.user_code) do
      {:reply, {:error, :user_code_taken}, state}
    else
      :ets.insert(@table, {record.device_code_hash, record.expires_at, record})
      :ets.insert(@user_index, {record.user_code, record.device_code_hash})
      {:reply, :ok, state}
    end
  end

  def handle_call({:decide, user_code, new_status, approval, opts}, _from, state) do
    now = Map.get(opts, :now, System.system_time(:second))

    reply =
      with {:ok, hash, record} <- fetch_by_user_code(user_code) do
        ETSTable.decide(@table, hash, record, now, new_status, approval_fields(new_status, approval))
      end

    {:reply, reply, state}
  end

  # RFC 8628 §3.5: the minimum poll interval is the one the core passes in.
  def handle_call({:poll, hash, opts}, _from, state) do
    {:reply, ETSTable.poll(@table, hash, opts.now, fn _record -> opts.interval end), state}
  end

  def handle_call({:consume, hash, opts}, _from, state) do
    {:reply, ETSTable.consume(@table, hash, Map.get(opts, :now, System.system_time(:second))), state}
  end

  defp delete_expired(now) do
    expired = :ets.select(@table, ETSTable.expired_match_spec(now, :record))
    Enum.each(expired, fn record -> drop(record.device_code_hash, record.user_code) end)
  end

  # ----- helpers -----

  defp fetch_by_user_code(user_code) do
    case :ets.lookup(@user_index, user_code) do
      [{^user_code, hash}] ->
        case ETSTable.lookup(@table, hash) do
          {:ok, record} -> {:ok, hash, record}
          :error -> {:error, :not_found}
        end

      [] ->
        {:error, :not_found}
    end
  end

  defp approval_fields(:approved, approval) do
    %{
      subject: Map.get(approval, :subject),
      granted_scope: Map.get(approval, :granted_scope, []),
      granted_claims: Map.get(approval, :granted_claims, %{})
    }
  end

  defp approval_fields(_status, _approval), do: %{}

  defp drop(hash, user_code) do
    :ets.delete(@table, hash)
    :ets.delete(@user_index, user_code)
  end
end
