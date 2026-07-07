defmodule Attesto.CIBAStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CIBAStore`.

  Authentication-request records live in an ETS table owned by a `GenServer`.
  The state-changing callbacks (`approve/3`, `deny/2`, `poll/2`, `consume/2`)
  run inside `GenServer.call/2`, so they are serialized through the owner
  process - that is how this reference store gets the atomic, single-winner
  state transitions `Attesto.CIBAStore` requires (a production multi-node
  deployment uses an Ecto store, whose transitions are single conditional
  `UPDATE ... RETURNING` statements). Reads that do not transition state
  (`lookup/1`) hit the table directly.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired rows are
      bulk-deleted. Correctness does not depend on sweeping (`redeem/4`
      re-checks expiry); the sweeper only bounds table size.

  ## Wiring

      children = [Attesto.CIBAStore.ETS]
  """

  @behaviour Attesto.CIBAStore

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

  @impl Attesto.CIBAStore
  def put(%{auth_req_id_hash: hash} = record) when is_binary(hash) do
    GenServer.call(__MODULE__, {:put, record})
  end

  @impl Attesto.CIBAStore
  def lookup(hash) when is_binary(hash) do
    case :ets.lookup(@table, hash) do
      [{^hash, _expires_at, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @impl Attesto.CIBAStore
  def approve(hash, approval, opts) when is_binary(hash) and is_map(approval) and is_map(opts) do
    GenServer.call(__MODULE__, {:decide, hash, :approved, approval, opts})
  end

  @impl Attesto.CIBAStore
  def deny(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:decide, hash, :denied, %{}, opts})
  end

  @impl Attesto.CIBAStore
  def poll(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:poll, hash, opts})
  end

  @impl Attesto.CIBAStore
  def consume(hash, opts) when is_binary(hash) and is_map(opts) do
    GenServer.call(__MODULE__, {:consume, hash, opts})
  end

  @doc false
  def reset, do: GenServer.call(__MODULE__, :reset)

  # ----- server -----

  @impl GenServer
  def init(opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    interval = Keyword.get(opts, :sweep_interval_ms, @default_sweep_interval_ms)
    schedule_sweep(interval)
    {:ok, %{sweep_interval_ms: interval}}
  end

  @impl GenServer
  def handle_call({:put, record}, _from, state) do
    :ets.insert(@table, {record.auth_req_id_hash, record.expires_at, record})
    {:reply, :ok, state}
  end

  def handle_call({:decide, hash, new_status, approval, opts}, _from, state) do
    now = Map.get(opts, :now, System.system_time(:second))

    reply =
      case :ets.lookup(@table, hash) do
        # Guard the decision on BOTH pendingness and unexpiry: a decision on an
        # expired request must not land (its poll outcome is expired_token).
        [{^hash, expires_at, %{status: :pending} = record}] when expires_at > now ->
          updated =
            record
            |> Map.put(:status, new_status)
            |> Map.merge(approval_fields(new_status, approval))

          :ets.insert(@table, {hash, record.expires_at, updated})
          {:ok, updated}

        [{^hash, _expires_at, %{status: :pending}}] ->
          {:error, :expired}

        [{^hash, _expires_at, _record}] ->
          {:error, :already_decided}

        [] ->
          {:error, :not_found}
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

  def handle_call({:consume, hash, opts}, _from, state) do
    now = Map.get(opts, :now, System.system_time(:second))

    reply =
      case :ets.lookup(@table, hash) do
        # Guard the consume on BOTH approval and unexpiry, so a request that
        # expires between the core's poll-time check and this transition
        # cannot mint.
        [{^hash, expires_at, %{status: :approved} = record}] when expires_at > now ->
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
    {:reply, :ok, state}
  end

  @impl GenServer
  def handle_info(:sweep, state) do
    now = System.system_time(:second)
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  # ----- helpers -----

  defp approval_fields(:approved, approval) do
    %{
      acr: Map.get(approval, :acr),
      auth_time: Map.get(approval, :auth_time),
      granted_claims: Map.get(approval, :granted_claims, %{}),
      granted_scope: Map.get(approval, :granted_scope),
      subject: Map.get(approval, :subject)
    }
  end

  defp approval_fields(_status, _approval), do: %{}

  # CIBA Core §7.3: enforce the record's minimum token-request interval. The
  # first poll (last_polled_at nil) is always allowed; interval 0 disables
  # enforcement.
  defp poll_allowed?(%{last_polled_at: nil}, _opts), do: true
  defp poll_allowed?(%{interval: 0}, _opts), do: true
  defp poll_allowed?(%{interval: interval, last_polled_at: last}, %{now: now}), do: last <= now - interval

  defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
end
