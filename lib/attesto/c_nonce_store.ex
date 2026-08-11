defmodule Attesto.CNonceStore do
  @moduledoc """
  Storage seam for server-issued OID4VCI c_nonces.

  A server issues an opaque, time-limited c_nonce from the nonce endpoint and
  requires the wallet to echo it in the proof sent to the credential endpoint.
  This behaviour is where those nonces live: `issue/1` mints one, `valid?/1`
  reports whether a presented nonce is still live (non-consuming, so every proof
  in one OID4VCI `proofs` batch can validate against the shared nonce), and
  `consume/1` atomically single-uses it (called once per credential request,
  after the whole batch verifies, so a captured proof + nonce cannot be replayed
  for another credential).

  `Attesto.CNonceStore.ETS` is a ready single-node implementation. A
  multi-node deployment implements this over a shared store so a nonce issued
  by one node is honoured by another.
  """

  @doc "Mint and store a fresh nonce valid for `ttl_seconds`."
  @callback issue(ttl_seconds :: pos_integer()) :: String.t()

  @doc "Returns true iff `nonce` was issued by this store and has not expired."
  @callback valid?(nonce :: String.t()) :: boolean()

  @doc """
  Atomically consume `nonce` so it cannot be used again.

  Returns `:ok` to the single caller that wins the consume, and an `{:error, _}`
  to everyone else so single-use is enforced (that is what stops a captured proof
  from being replayed to mint duplicate credentials; a store that cannot
  implement this MUST NOT be used for issuance). The precise error is
  best-effort and implementation-dependent: a store that deletes the row on
  consume (like `Attesto.CNonceStore.ETS`) reports `{:error, :unknown}` for an
  already-consumed nonce because it is indistinguishable from one never issued;
  a store that records a `used_at` marker instead can distinguish `{:error,
  :used}` from `{:error, :expired}`/`{:error, :unknown}`. Callers MUST treat any
  `{:error, _}` as "not consumable" and fail closed.
  """
  @callback consume(nonce :: String.t()) :: :ok | {:error, :used | :expired | :unknown}
end
