defmodule Attesto.CNonceStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CNonceStore`.

  Nonces are random 128-bit base64url strings held in a public ETS table
  owned by a `GenServer` that sweeps expired entries. Validation is
  non-consuming, so a c_nonce may be used by several proofs in one batch.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CNonceStore` with a shared store. Like the other ETS stores it
  refuses to boot on a clustered BEAM unless `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CNonceStore

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000

  alias Attesto.CNonceStore
  alias Attesto.Secret

  @table __MODULE__
  @default_ttl_seconds 300
  @nonce_bytes 16

  @impl CNonceStore
  def issue(ttl_seconds \\ @default_ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    nonce = Secret.generate(@nonce_bytes)
    true = :ets.insert(@table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  @impl CNonceStore
  def valid?(nonce) when is_binary(nonce) do
    case :ets.lookup(@table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid?(_), do: false

  defp delete_expired(now) do
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
  end
end
