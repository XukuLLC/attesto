defmodule Attesto.CNonceStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CNonceStore`.

  Nonces are random 128-bit base64url strings held in a public ETS table
  owned by a `GenServer` that sweeps expired entries. Validation (`valid?/1`) is
  non-consuming, so a c_nonce may be used by several proofs in one batch;
  `consume/1` atomically single-uses it (via `:ets.take/2`) once per request.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CNonceStore` with a shared store. Like the other ETS stores it
  refuses to boot on a clustered BEAM unless `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CNonceStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    nonce_store: [
      behaviour: Attesto.CNonceStore,
      default_ttl_seconds: 300,
      nonce_bytes: 16,
      max_entries: 1_000_000,
      consume?: true
    ]
end
