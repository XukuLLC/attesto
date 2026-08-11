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

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000

  alias Attesto.CNonceStore
  alias Attesto.Secret

  @table __MODULE__
  @default_ttl_seconds 300
  @nonce_bytes 16

  # Ceiling on stored nonces. The nonce endpoint is unauthenticated, so a flood
  # would otherwise grow the table to rate x TTL. Tiny rows: 1M ~= 40 MB.
  @max_entries 1_000_000

  @impl CNonceStore
  def issue(ttl_seconds \\ @default_ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    evict_one_if_full()
    nonce = Secret.generate(@nonce_bytes)
    true = :ets.insert(@table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  # O(1) best-effort bound: when at the ceiling, drop one arbitrary entry to make
  # room, so a flood on the unauthenticated endpoint cannot grow the table
  # without limit. The check/evict/insert is deliberately NOT serialized through
  # the owner - that would put a `GenServer.call` on every mint. Concurrent
  # issuers can therefore transiently overshoot the ceiling by up to the in-flight
  # request count (negligible against a 1M ceiling); steady state stays at ~cap.
  # (`:ets.first/1` + `:ets.delete/2` are O(1); the periodic sweep + TTL do the
  # ordinary draining.)
  defp evict_one_if_full do
    if :ets.info(@table, :size) >= @max_entries do
      case :ets.first(@table) do
        :"$end_of_table" -> :ok
        key -> :ets.delete(@table, key)
      end
    end
  end

  @impl CNonceStore
  def valid?(nonce) when is_binary(nonce) do
    case :ets.lookup(@table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid?(_), do: false

  @impl CNonceStore
  def consume(nonce) when is_binary(nonce) do
    now = System.system_time(:second)

    # `:ets.take/2` is atomic: of two concurrent consumers exactly one gets the
    # row, so the nonce is single-use across requests.
    case :ets.take(@table, nonce) do
      [{^nonce, expires_at}] when expires_at > now -> :ok
      [{^nonce, _expired}] -> {:error, :expired}
      [] -> {:error, :unknown}
    end
  end

  def consume(_nonce), do: {:error, :unknown}

  defp delete_expired(now) do
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
  end
end
