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

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    nonce_store: [
      behaviour: Attesto.DPoP.NonceStore,
      default_ttl_seconds: 300,
      nonce_bytes: 16,
      max_entries: 1_000_000,
      consume?: false
    ]

  @doc """
  The `:nonce_check` callback for `Attesto.DPoP.verify_proof/2`: returns
  `:ok` for a live issued nonce, or `{:error, :use_dpop_nonce}` for a
  missing (nil), unknown, or expired one.
  """
  @spec validate(String.t() | nil) :: :ok | {:error, :use_dpop_nonce}
  def validate(nonce) do
    if is_binary(nonce) and valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
  end
end
