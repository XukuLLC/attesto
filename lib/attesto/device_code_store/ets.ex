defmodule Attesto.DeviceCodeStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.DeviceCodeStore`.

  Device-code records live in an ETS table owned by a `GenServer`. The
  state-changing callbacks (`approve/2`, `deny/2`, `poll/2`, `consume/2`) run
  inside `GenServer.call/2`, so they are serialized through the owner process —
  that is how this reference store gets the atomic, single-winner state
  transitions `Attesto.DeviceCodeStore` requires (a production multi-node
  deployment uses the Ecto store, whose transitions are single conditional
  `UPDATE ... RETURNING` statements). Reads that do not transition state
  (`lookup_user_code/1`) hit the table directly.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired rows are
      bulk-deleted. Correctness does not depend on sweeping (`redeem/4`
      re-checks expiry); the sweeper only bounds table size.

  ## Wiring

      children = [Attesto.DeviceCodeStore.ETS]
  """

  @behaviour Attesto.DeviceCodeStore

  use GenServer

  @table __MODULE__
  @user_index __MODULE__.UserIndex
  @default_sweep_interval_ms 30_000

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
  end

  @impl Attesto.DeviceCodeStore
  def put(%{device_code_hash: hash, user_code: user_code} = record) when is_binary(hash) and is_binary(user_code) do
    GenServer.call(__MODULE__, {:put, record})
  end

  @impl Attesto.DeviceCodeStore
  def lookup_user_code(user_code) when is_binary(user_code) do
    case :ets.lookup(@user_index, user_code) do
      [{^user_code, hash}] ->
        case :ets.lookup(@table, hash) do
          [{^hash, _expires_at, record}] -> {:ok, pending_view(record)}
          [] -> :error
        end

      [] ->
        :error
    end
  end

  @impl Attesto.DeviceCodeStore
  def approve(user_code, approval) when is_binary(user_code) and is_map(approval) do
    GenServer.call(__MODULE__, {:decide, user_code, :approved, approval})
  end

  @impl Attesto.DeviceCodeStore
  def deny(user_code) when is_binary(user_code) do
    GenServer.call(__MODULE__, {:decide, user_code, :denied, %{}})
  end

  @impl Attesto.DeviceCodeStore
  def poll(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:poll, hash, opts})
  end

  @impl Attesto.DeviceCodeStore
  def consume(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:consume, hash, opts})
  end

  @doc false
  def reset, do: GenServer.call(__MODULE__, :reset)

  # ----- server -----

  @impl GenServer
  def init(opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    :ets.new(@user_index, [:named_table, :public, :set, read_concurrency: true])
    interval = Keyword.get(opts, :sweep_interval_ms, @default_sweep_interval_ms)
    schedule_sweep(interval)
    {:ok, %{sweep_interval_ms: interval}}
  end

  @impl GenServer
  def handle_call({:put, record}, _from, state) do
    :ets.insert(@table, {record.device_code_hash, record.expires_at, record})
    :ets.insert(@user_index, {record.user_code, record.device_code_hash})
    {:reply, :ok, state}
  end

  def handle_call({:decide, user_code, new_status, approval}, _from, state) do
    reply =
      with {:ok, hash, record} <- fetch_by_user_code(user_code),
           :ok <- require_pending(record) do
        updated =
          record
          |> Map.put(:status, new_status)
          |> Map.merge(approval_fields(new_status, approval))

        :ets.insert(@table, {hash, record.expires_at, updated})
        :ok
      end

    {:reply, reply, state}
  end

  def handle_call({:poll, hash, opts}, _from, state) do
    reply =
      case :ets.lookup(@table, hash) do
        [{^hash, _expires_at, record}] ->
          if poll_allowed?(record, opts) do
            updated = Map.put(record, :last_polled_at, opts.now)
            :ets.insert(@table, {hash, record.expires_at, updated})
            {:ok, updated}
          else
            {:error, :slow_down}
          end

        [] ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call({:consume, hash, _opts}, _from, state) do
    reply =
      case :ets.lookup(@table, hash) do
        [{^hash, _expires_at, %{status: :approved} = record}] ->
          consumed = Map.put(record, :status, :consumed)
          :ets.insert(@table, {hash, record.expires_at, consumed})
          {:ok, consumed}

        _ ->
          :error
      end

    {:reply, reply, state}
  end

  def handle_call(:reset, _from, state) do
    :ets.delete_all_objects(@table)
    :ets.delete_all_objects(@user_index)
    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_info(:sweep, state) do
    now = System.system_time(:second)
    expired = :ets.select(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [:"$3"]}])
    Enum.each(expired, fn record -> drop(record.device_code_hash, record.user_code) end)
    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  # ----- helpers -----

  defp fetch_by_user_code(user_code) do
    case :ets.lookup(@user_index, user_code) do
      [{^user_code, hash}] ->
        case :ets.lookup(@table, hash) do
          [{^hash, _expires_at, record}] -> {:ok, hash, record}
          [] -> {:error, :not_found}
        end

      [] ->
        {:error, :not_found}
    end
  end

  defp require_pending(%{status: :pending}), do: :ok
  defp require_pending(_record), do: {:error, :already_decided}

  defp approval_fields(:approved, approval) do
    %{
      subject: Map.get(approval, :subject),
      granted_scope: Map.get(approval, :granted_scope, []),
      granted_claims: Map.get(approval, :granted_claims, %{})
    }
  end

  defp approval_fields(_status, _approval), do: %{}

  # RFC 8628 §3.5: enforce the minimum poll interval. The first poll
  # (last_polled_at nil) is always allowed.
  defp poll_allowed?(%{last_polled_at: nil}, _opts), do: true
  defp poll_allowed?(%{last_polled_at: last}, %{now: now, interval: interval}), do: last <= now - interval

  defp pending_view(record) do
    data = Map.get(record, :data, %{})

    %{
      user_code: record.user_code,
      client_id: Map.get(data, :client_id),
      scope: Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      status: record.status,
      expires_at: record.expires_at
    }
  end

  defp drop(hash, user_code) do
    :ets.delete(@table, hash)
    :ets.delete(@user_index, user_code)
  end

  defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
end
