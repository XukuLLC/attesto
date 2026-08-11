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

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000

  alias Attesto.DPoP.NonceStore
  alias Attesto.Secret

  @table __MODULE__
  @default_ttl_seconds 300
  @nonce_bytes 16

  # Ceiling on stored nonces; a DPoP-nonce challenge is reachable pre-auth, so
  # bound table growth under a flood. Tiny rows: 1M ~= 40 MB.
  @max_entries 1_000_000

  @impl NonceStore
  def issue(ttl_seconds \\ @default_ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    evict_one_if_full()
    nonce = Secret.generate(@nonce_bytes)
    true = :ets.insert(@table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  # O(1) best-effort bound: at the ceiling, drop one arbitrary entry to make
  # room, so a flood cannot grow the table without limit. Deliberately not
  # serialized through the owner (no `GenServer.call` per mint); concurrent
  # issuers may transiently overshoot by the in-flight count (negligible at 1M),
  # steady state ~cap. TTL + sweep do the ordinary draining.
  defp evict_one_if_full do
    if :ets.info(@table, :size) >= @max_entries do
      case :ets.first(@table) do
        :"$end_of_table" -> :ok
        key -> :ets.delete(@table, key)
      end
    end
  end

  @impl NonceStore
  def valid?(nonce) when is_binary(nonce) do
    case :ets.lookup(@table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid?(_), do: false

  @doc """
  The `:nonce_check` callback for `Attesto.DPoP.verify_proof/2`: returns
  `:ok` for a live issued nonce, or `{:error, :use_dpop_nonce}` for a
  missing (nil), unknown, or expired one.
  """
  @spec validate(String.t() | nil) :: :ok | {:error, :use_dpop_nonce}
  def validate(nonce) do
    if is_binary(nonce) and valid?(nonce), do: :ok, else: {:error, :use_dpop_nonce}
  end

  defp delete_expired(now) do
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
  end
end
