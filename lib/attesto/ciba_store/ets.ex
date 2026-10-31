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

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    table_options: [:named_table, :protected, :set, read_concurrency: true],
    cluster_guard?: false,
    interval_before_tables?: false,
    reset: :server,
    reset_doc: false,
    reset_spec?: false

  alias Attesto.PollingGrant.ETSTable

  @table __MODULE__

  @impl Attesto.CIBAStore
  def put(%{auth_req_id_hash: hash} = record) when is_binary(hash) do
    GenServer.call(__MODULE__, {:put, record})
  end

  @impl Attesto.CIBAStore
  def lookup(hash) when is_binary(hash), do: ETSTable.lookup(@table, hash)

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

  # ----- server -----

  @impl GenServer
  def handle_call({:put, record}, _from, state) do
    :ets.insert(@table, {record.auth_req_id_hash, record.expires_at, record})
    {:reply, :ok, state}
  end

  def handle_call({:decide, hash, new_status, approval, opts}, _from, state) do
    now = Map.get(opts, :now, System.system_time(:second))

    reply =
      case ETSTable.lookup(@table, hash) do
        {:ok, record} -> ETSTable.decide(@table, hash, record, now, new_status, approval_fields(new_status, approval))
        :error -> {:error, :not_found}
      end

    {:reply, reply, state}
  end

  def handle_call({:poll, hash, opts}, _from, state) do
    {:reply, ETSTable.poll(@table, hash, opts.now, &poll_interval/1), state}
  end

  def handle_call({:consume, hash, opts}, _from, state) do
    {:reply, ETSTable.consume(@table, hash, Map.get(opts, :now, System.system_time(:second))), state}
  end

  defp delete_expired(now), do: :ets.select_delete(@table, ETSTable.expired_match_spec(now, :key))

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

  # CIBA Core §7.3: the minimum token-request interval is the record's own
  # (the value the client was told at issue); interval 0 disables enforcement.
  defp poll_interval(%{interval: 0}), do: :disabled
  defp poll_interval(%{interval: interval}), do: interval
end
