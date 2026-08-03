defmodule Attesto.CNonceStore do
  @moduledoc """
  Storage seam for server-issued OID4VCI c_nonces.

  A server issues an opaque, time-limited c_nonce from the nonce endpoint and
  requires the wallet to echo it in the proof sent to the credential endpoint.
  This behaviour is where those nonces live: `issue/1` mints one, and
  `valid?/1` reports whether a presented nonce is still live.

  `Attesto.CNonceStore.ETS` is a ready single-node implementation. A
  multi-node deployment implements this over a shared store so a nonce issued
  by one node is honoured by another.
  """

  @doc "Mint and store a fresh nonce valid for `ttl_seconds`."
  @callback issue(ttl_seconds :: pos_integer()) :: String.t()

  @doc "Returns true iff `nonce` was issued by this store and has not expired."
  @callback valid?(nonce :: String.t()) :: boolean()
end
