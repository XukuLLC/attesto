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
  replacement plug in without changes to `Attesto.DPoP`. The verifier
  passes its whole acceptance window as `ttl_seconds` - `:max_age_seconds`
  plus the future-skew allowance it also tolerates, plus a one-second
  integer-boundary margin, not `:max_age_seconds` alone - so a shared store
  sized by that value cannot forget an identity while a proof carrying it would
  still be accepted. (The identity the verifier passes is the `jti` namespaced
  by the proof-key thumbprint; the `jti`/`ttl_seconds` argument names are
  historical.)

  The boot-time guard **raises** on startup if `Node.list/0` is non-empty
  and `:multi_node_acknowledged?` is not set - a clustered BEAM with a
  node-local replay cache is a silently-broken security boundary (a
  captured proof becomes replayable once per node) that this guard
  refuses to enter. Failing the supervised start surfaces the
  misconfiguration loudly rather than emitting a log nobody reads.

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
    * `:multi_node_acknowledged?` (default `false`) - set to `true` after
      wiring a shared-store `:replay_check` so the boot-time guard does
      not fire on a clustered BEAM.

  ## Wiring

      children = [
        Attesto.DPoP.ReplayCache
      ]

  then, at the verifier:

      Attesto.DPoP.verify_proof(proof,
        http_method: "GET",
        http_uri: uri,
        replay_check: &Attesto.DPoP.ReplayCache.check_and_record/2
      )
  """

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    sweep_time: :monotonic_ms,
    reset_doc: "Clear every entry from the cache. Test-facing."

  alias Attesto.Store.ETS

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
