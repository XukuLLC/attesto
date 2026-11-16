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

  This implementation is a per-node ETS singleton. Start it only with
  `single_node?: true`, an explicit statement that the deployment runs one
  node. Separate nodes behind a load balancer cannot be detected by BEAM
  clustering. On multiple nodes configure a shared `:replay_check` instead
  and do not start this cache.

  **`AttestoPhoenix.Store.EctoReplayCheck` is that implementation** if you
  run `attesto_phoenix`: one relational table whose unique constraint on
  `jti` makes the record-and-check atomic across every node, with a
  matching schema and expiry sweeper. Reach for it before writing your own.
  Any other shared store (Redis, or another database using
  `INSERT ... ON CONFLICT DO NOTHING`) works too - the `:replay_check`
  shape (`(jti, ttl_seconds) -> :ok | {:error, :replay}`) lets any
  replacement plug in without changes to `Attesto.DPoP`. The verifier
  passes its whole acceptance window as `ttl_seconds` - `:max_age_seconds`
  plus the future-skew allowance it also tolerates, plus a one-second
  integer-boundary margin, not `:max_age_seconds` alone - so a shared store
  sized by that value cannot forget an identity while a proof carrying it would
  still be accepted. (The identity the verifier passes is the `jti` namespaced
  by the proof-key thumbprint; the `jti`/`ttl_seconds` argument names are
  historical.)

  Startup refuses a missing or false `:single_node?` statement, even with
  no connected peers. Connected BEAM peers also cause startup to fail.
  This statement cannot prove deployment topology: the operator must keep it
  true for the lifetime of the cache. The former `:multi_node_acknowledged?`
  option is no longer accepted by this cache.

  ## Retention is per entry, not per cache

  How long a `jti` is remembered is decided by the caller, not by this
  process: `check_and_record/2` takes the TTL as an argument and stamps it
  onto the entry. `Attesto.DPoP.verify_proof/2` passes its whole acceptance
  window, so retention tracks the verifier's freshness policy automatically
  and a `jti` cannot be forgotten while a proof carrying it would still be
  accepted.

  There is deliberately no `:ttl_seconds` start option. One would be a
  cache-wide value that `check_and_record/2` has no way to consult - it is
  a plain function, not a call into this GenServer - so it could only ever
  disagree with the TTL the verifier actually supplies.

  `check_and_record/1` exists for a caller with no verifier to take the
  window from, and falls back to 60 seconds. Prefer
  the two-arity form: a caller that defers the claim itself (as
  `Attesto.Plug.Authenticate` does) should pass the `replay_ttl` that
  `verify_proof/2` returned, so the two agree by construction.

  ## Configuration (start options)

    * `:sweep_interval_ms` (default `30_000`) - how often expired entries
      are deleted in bulk. The cache is correct without sweeping (lookups
      re-validate expiry); the sweeper just bounds table size.
    * `:single_node?` (required) - must be `true`, asserting that the
      deployment runs one node.

  ## Wiring

      children = [
        {Attesto.DPoP.ReplayCache, single_node?: true}
      ]

  then, at the verifier:

      Attesto.DPoP.verify_proof(proof,
        http_method: "GET",
        http_uri: uri,
        replay_check: &Attesto.DPoP.ReplayCache.check_and_record/2
      )
  """

  use Attesto.Store.ETS,
    cluster_guard?: false,
    default_sweep_interval_ms: 30_000,
    sweep_time: :monotonic_ms,
    reset_doc: "Clear every entry from the cache. Test-facing."

  alias Attesto.Store.ETS

  @start_choices "Start it with single_node?: true when the deployment runs one node. " <>
                   "For more than one node, configure a shared :replay_check such as " <>
                   "AttestoPhoenix.Store.EctoReplayCheck and do not supervise this cache."

  @impl GenServer
  def init(opts) do
    cond do
      Keyword.has_key?(opts, :multi_node_acknowledged?) ->
        raise ArgumentError,
              "Attesto.DPoP.ReplayCache does not accept :multi_node_acknowledged?. " <> @start_choices

      Keyword.get(opts, :single_node?) != true ->
        raise ArgumentError, "Attesto.DPoP.ReplayCache was started without single_node?: true. " <> @start_choices

      Node.list() != [] ->
        raise ArgumentError,
              "Attesto.DPoP.ReplayCache was started with single_node?: true on a node that is " <>
                "connected to other BEAM nodes. " <> @start_choices

      true ->
        super(opts)
    end
  end

  @table __MODULE__
  @default_ttl_seconds 60

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
    ETS.check_and_record(@table, jti, ttl_seconds)
  end

  @doc """
  Return the number of entries currently held. Test/diagnostic-facing.
  """
  @spec size() :: non_neg_integer()
  def size, do: ETS.size(@table)

  defp delete_expired(now_ms) do
    ETS.delete_expired_entries(@table, now_ms)
  end
end
