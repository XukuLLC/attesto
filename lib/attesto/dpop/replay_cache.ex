defmodule Attesto.DPoP.ReplayCache do
  @moduledoc """
  In-memory, TTL-bounded cache of seen DPoP proof `jti` values.

  RFC 9449 §11.1 requires the resource server to refuse a DPoP proof
  whose `jti` it has previously processed. A captured-and-replayed proof
  would otherwise be reusable for the full `iat` acceptance window
  (default 60 seconds).

  This module is a ready-made implementation for the `:replay_check`
  option of `Attesto.DPoP.verify_proof/2`. It stores `jti` values in a
  public ETS table owned by a `GenServer` that sweeps expired entries on
  a fixed interval; lookups are O(1) and lock-free via
  `:ets.insert_new/2`.

  ## Single-node deployment invariant (load-bearing)

  This implementation is a per-node ETS singleton. RFC 9449 §11.1 replay
  rejection only holds *across the deployment* if every request for a
  given access token reaches the same node - otherwise a captured proof
  is replayable once per node behind a load balancer. On a multi-node
  deployment you MUST swap the verifier's `:replay_check` callback for a
  shared-store implementation and set `:multi_node_acknowledged?: true` to
  silence the boot-time guard.

  **`AttestoPhoenix.Store.EctoReplayCheck` is that implementation** if you
  run `attesto_phoenix`: one relational table whose unique constraint on
  `jti` makes the record-and-check atomic across every node, with a
  matching schema and expiry sweeper. Reach for it before writing your own.
  Any other shared store (Redis, or another database using
  `INSERT ... ON CONFLICT DO NOTHING`) works too - the `:replay_check`
  shape (`(jti, ttl_seconds) -> :ok | {:error, :replay}`) lets any
  replacement plug in without changes to `Attesto.DPoP`. The verifier's `:replay_check` shape
  (`(jti, ttl_seconds) -> :ok | {:error, :replay}`) lets any such
  replacement plug in without changes to `Attesto.DPoP`. The verifier
  passes its own `:max_age_seconds` as `ttl_seconds`, so a shared store
  can size each `jti`'s retention to the proof's freshness window.

  The boot-time guard **raises** on startup if `Node.list/0` is non-empty
  and `:multi_node_acknowledged?` is not set - a clustered BEAM with a
  node-local replay cache is a silently-broken security boundary (a
  captured proof becomes replayable once per node) that this guard
  refuses to enter. Failing the supervised start surfaces the
  misconfiguration loudly rather than emitting a log nobody reads.

  ## Configuration (start options)

    * `:ttl_seconds` (default `60`) - how long each `jti` is remembered.
      SHOULD match (or modestly exceed) the verifier's `:max_age_seconds`
      so a proof whose `iat` window has already closed is rejected by
      freshness OR by replay, never just by eviction race.
    * `:sweep_interval_ms` (default `30_000`) - how often expired entries
      are deleted in bulk. The cache is correct without sweeping (lookups
      re-validate expiry); the sweeper just bounds table size.
    * `:multi_node_acknowledged?` (default `false`) - set to `true` after
      wiring a shared-store `:replay_check` so the boot-time guard does
      not fire on a clustered BEAM.

  ## Wiring

      children = [
        {Attesto.DPoP.ReplayCache, ttl_seconds: 60}
      ]

  then, at the verifier:

      Attesto.DPoP.verify_proof(proof,
        http_method: "GET",
        http_uri: uri,
        replay_check: &Attesto.DPoP.ReplayCache.check_and_record/2
      )
  """

  use GenServer

  @table __MODULE__
  @default_ttl_seconds 60
  @default_sweep_interval_ms 30_000

  @doc """
  Start the cache. Registered under `__MODULE__`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  def child_spec(opts) do
    %{
      id: __MODULE__,
      restart: :permanent,
      shutdown: 5_000,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  @doc """
  Record `jti` and report whether it has already been seen within the TTL
  window.

  Returns `:ok` if the `jti` was not present (and has now been recorded),
  or `{:error, :replay}` if it was. The two-argument form
  (`check_and_record/2`) takes the `jti` and the TTL to remember it for,
  which is the shape `Attesto.DPoP.verify_proof/2` passes its
  `:replay_check` callback (the verifier derives the TTL from its own
  acceptance window). Pass `&check_and_record/2` directly. The TTL
  argument defaults to #{@default_ttl_seconds} seconds when called as
  `check_and_record/1`.
  """
  @spec check_and_record(String.t(), pos_integer()) :: :ok | {:error, :replay}
  def check_and_record(jti, ttl_seconds \\ @default_ttl_seconds)
      when is_binary(jti) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    expires_at_ms = monotonic_ms() + ttl_seconds * 1_000

    case :ets.insert_new(@table, {jti, expires_at_ms}) do
      true ->
        :ok

      false ->
        now_ms = monotonic_ms()

        replace_expired(jti, now_ms, expires_at_ms)
    end
  end

  defp replace_expired(jti, now_ms, expires_at_ms) do
    case :ets.select_delete(@table, [{{jti, :"$1"}, [{:<, :"$1", now_ms}], [true]}]) do
      1 ->
        case :ets.insert_new(@table, {jti, expires_at_ms}) do
          true -> :ok
          false -> {:error, :replay}
        end

      0 ->
        {:error, :replay}
    end
  end

  @doc """
  Clear every entry from the cache. Test-facing.
  """
  @spec reset() :: :ok
  def reset do
    if :ets.whereis(@table) != :undefined do
      :ets.delete_all_objects(@table)
    end

    :ok
  end

  @doc """
  Return the number of entries currently held. Test/diagnostic-facing.
  """
  @spec size() :: non_neg_integer()
  def size do
    case :ets.whereis(@table) do
      :undefined -> 0
      _ -> :ets.info(@table, :size)
    end
  end

  @impl true
  def init(opts) do
    Attesto.ClusterGuard.assert_single_node!(
      __MODULE__,
      Keyword.get(opts, :multi_node_acknowledged?, false)
    )

    sweep_interval_ms = Keyword.get(opts, :sweep_interval_ms, @default_sweep_interval_ms)

    table =
      :ets.new(@table, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    schedule_sweep(sweep_interval_ms)
    {:ok, %{sweep_interval_ms: sweep_interval_ms, table: table}}
  end

  @impl true
  def handle_info(:sweep, state) do
    now_ms = monotonic_ms()
    # Delete every entry whose expiry is strictly in the past.
    :ets.select_delete(state.table, [{{:"$1", :"$2"}, [{:<, :"$2", now_ms}], [true]}])
    schedule_sweep(state.sweep_interval_ms)
    {:noreply, state}
  end

  defp schedule_sweep(interval_ms) do
    Process.send_after(self(), :sweep, interval_ms)
  end

  defp monotonic_ms, do: System.monotonic_time(:millisecond)
end
