defmodule Attesto.PreAuthorizedCodeStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.PreAuthorizedCodeStore`.

  Pre-authorized codes live in a public ETS table owned by a `GenServer` that
  sweeps expired rows on a fixed interval. `take/1` uses `:ets.take/2`, which
  fetches and deletes a row in one atomic step, so the single-use guarantee
  holds against concurrent redemptions on a node. This is a per-node store: a
  multi-node deployment MUST back `Attesto.PreAuthorizedCodeStore` with a
  shared store so a code issued on one node can be redeemed once on another.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired rows are
      bulk-deleted. Correctness does not depend on sweeping;
      `Attesto.PreAuthorizedCode` re-checks expiry after `take/1`.

  ## Wiring

      children = [Attesto.PreAuthorizedCodeStore.ETS]

  then pass the module as the store:

      Attesto.PreAuthorizedCode.issue(Attesto.PreAuthorizedCodeStore.ETS, attrs)
  """

  @behaviour Attesto.PreAuthorizedCodeStore

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000

  @table __MODULE__

  @impl Attesto.PreAuthorizedCodeStore
  def put(%{code_hash: code_hash, expires_at: expires_at} = record)
      when is_binary(code_hash) and is_integer(expires_at) do
    # expires_at is hoisted into its own tuple element so the sweep
    # match spec is a plain guard, never a map pattern.
    true = :ets.insert(@table, {code_hash, expires_at, record})
    :ok
  end

  @impl Attesto.PreAuthorizedCodeStore
  def take(code_hash) when is_binary(code_hash) do
    case :ets.take(@table, code_hash) do
      [{^code_hash, _expires_at, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @impl Attesto.PreAuthorizedCodeStore
  def get(code_hash) when is_binary(code_hash) do
    case :ets.lookup(@table, code_hash) do
      [{^code_hash, _expires_at, record}] -> {:ok, record}
      [] -> :error
    end
  end

  defp delete_expired(now) do
    # Delete every row whose expiry is strictly in the past.
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
  end
end
