defmodule Attesto.CredentialOfferStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CredentialOfferStore`.

  Credential offers live in a public ETS table owned by a `GenServer` that
  sweeps expired rows on a fixed interval. `fetch/1` is non-consuming and
  returns an offer only while its expiry is strictly in the future.

  This is a per-node store; a multi-node deployment MUST back
  `Attesto.CredentialOfferStore` with a shared store. Like the other ETS
  stores it refuses to boot on a clustered BEAM unless
  `multi_node_acknowledged?: true`.

  Start options: `:sweep_interval_ms` (default `30_000`),
  `:multi_node_acknowledged?` (default `false`).
  """

  @behaviour Attesto.CredentialOfferStore

  use Attesto.Store.ETS, default_sweep_interval_ms: 30_000

  @table __MODULE__

  @impl Attesto.CredentialOfferStore
  def put(%{id: id, offer: offer, expires_at: expires_at})
      when is_binary(id) and is_map(offer) and is_integer(expires_at) do
    true = :ets.insert(@table, {id, expires_at, offer})
    :ok
  end

  @impl Attesto.CredentialOfferStore
  def fetch(id) when is_binary(id) do
    now = System.system_time(:second)

    case :ets.lookup(@table, id) do
      [{^id, expires_at, offer}] when expires_at > now ->
        {:ok, offer}

      [{^id, _expires_at, _offer}] ->
        :ets.delete(@table, id)
        :error

      [] ->
        :error
    end
  end

  defp delete_expired(now) do
    # Delete every row whose expiry is strictly in the past.
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
  end
end
