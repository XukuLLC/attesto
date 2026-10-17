defmodule Attesto.CodeStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.CodeStore`.

  Codes live in an ETS table owned by a `GenServer` that sweeps expired rows
  on a fixed interval. `take/1` uses `:ets.take/2`, which
  fetches and deletes a row in one atomic step, so the single-use
  guarantee holds against concurrent redemptions on a node. This is a
  per-node store: a multi-node deployment MUST back `Attesto.CodeStore`
  with a shared store (e.g. Postgres `DELETE ... RETURNING`) so a code
  issued on one node can be redeemed (once) on another.

  Successful redemptions support the optional `mark_consumed/2` reuse
  contract. Markers for bounded refresh families live through their family
  deadline; unbounded refresh-family markers remain sticky for the store's
  lifetime. A no-refresh marker is retained for 24 hours, bounding memory
  while covering the normal access-token replay-response window.

  The store also indexes the JTI of an access token minted from a redeemed
  code. On a later code replay, callers can revoke that token by code hash or
  by the finalized refresh-family ID and query the revocation by JTI. Both the
  linkage and revocation marker expire with the access token.

  ## Start options

    * `:sweep_interval_ms` (default `30_000`) - how often expired rows are
      bulk-deleted. Correctness does not depend on sweeping (`take/1`
      returns the row and `Attesto.AuthorizationCode` re-checks expiry);
      the sweeper only bounds table size.

  ## Wiring

      children = [Attesto.CodeStore.ETS]

  then pass the module as the store:

      Attesto.AuthorizationCode.issue(Attesto.CodeStore.ETS, attrs)
  """

  @behaviour Attesto.CodeStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    table_options: [:set, :protected, :named_table, read_concurrency: true],
    extra_tables: [
      {__MODULE__.Consumed, [:set, :protected, :named_table, read_concurrency: true]},
      {__MODULE__.AccessTokens, [:set, :protected, :named_table, read_concurrency: true]},
      {__MODULE__.RevokedAccessTokens, [:set, :protected, :named_table, read_concurrency: true]}
    ],
    reset: :server

  @table __MODULE__
  @consumed :"#{__MODULE__}.Consumed"
  @access_tokens :"#{__MODULE__}.AccessTokens"
  @revoked_access_tokens :"#{__MODULE__}.RevokedAccessTokens"
  @no_refresh_retention_seconds 24 * 60 * 60

  @impl Attesto.CodeStore
  def put(%{code_hash: code_hash, expires_at: expires_at} = record)
      when is_binary(code_hash) and is_integer(expires_at) do
    GenServer.call(__MODULE__, {:put, record})
  end

  @impl Attesto.CodeStore
  def take(code_hash) when is_binary(code_hash) do
    GenServer.call(__MODULE__, {:take, code_hash})
  end

  @impl Attesto.CodeStore
  def mark_consumed(code_hash, meta) when is_binary(code_hash) and is_map(meta) do
    GenServer.call(__MODULE__, {:mark_consumed, code_hash, meta})
  end

  @doc "Link a minted access-token JTI to its redeemed code until token expiry."
  @spec record_access_token_for_code(String.t(), String.t(), integer()) :: :ok
  def record_access_token_for_code(code_hash, jti, expires_at)
      when is_binary(code_hash) and code_hash != "" and is_binary(jti) and jti != "" and is_integer(expires_at) do
    GenServer.call(__MODULE__, {:record_access_token_for_code, code_hash, jti, expires_at})
  end

  @doc "Revoke the unexpired access token linked to a code hash."
  @spec revoke_access_token_for_code(String.t()) :: :ok
  def revoke_access_token_for_code(code_hash) when is_binary(code_hash) and code_hash != "" do
    GenServer.call(__MODULE__, {:revoke_access_token_for_code, code_hash})
  end

  @doc "Revoke unexpired access tokens linked to a finalized refresh family."
  @spec revoke_family_access_tokens(String.t()) :: :ok
  def revoke_family_access_tokens(family_id) when is_binary(family_id) and family_id != "" do
    GenServer.call(__MODULE__, {:revoke_family_access_tokens, family_id})
  end

  @doc "Return whether a linked, unexpired access-token JTI has been revoked."
  @spec access_token_revoked?(String.t()) :: boolean()
  def access_token_revoked?(jti) when is_binary(jti) and jti != "" do
    case :ets.lookup(@revoked_access_tokens, jti) do
      [{^jti, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  @impl Attesto.CodeStore
  def get(code_hash) when is_binary(code_hash) do
    case :ets.lookup(@table, code_hash) do
      [{^code_hash, _expires_at, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @impl GenServer
  def handle_call({:put, record}, _from, state) do
    # expires_at is hoisted into its own tuple element so the sweep
    # match spec is a plain guard, never a map pattern.
    true = :ets.insert(@table, {record.code_hash, record.expires_at, record})
    {:reply, :ok, state}
  end

  def handle_call({:take, code_hash}, _from, state) do
    result =
      case :ets.take(@table, code_hash) do
        [{^code_hash, _expires_at, record}] -> {:ok, record}
        [] -> consumed_result(code_hash)
      end

    {:reply, result, state}
  end

  def handle_call({:mark_consumed, code_hash, meta}, _from, state) do
    retain_until = consumed_retain_until(meta)
    true = :ets.insert(@consumed, {code_hash, retain_until, meta})
    bind_access_token_to_family(code_hash, consumed_family_id(meta))
    {:reply, :ok, state}
  end

  def handle_call({:record_access_token_for_code, code_hash, jti, expires_at}, _from, state) do
    family_id = consumed_family_id_for_code(code_hash)
    true = :ets.insert(@access_tokens, {code_hash, expires_at, jti, family_id})
    {:reply, :ok, state}
  end

  def handle_call({:revoke_access_token_for_code, code_hash}, _from, state) do
    case :ets.lookup(@access_tokens, code_hash) do
      [{^code_hash, expires_at, jti, _family_id}] -> revoke_jti(jti, expires_at)
      [] -> :ok
    end

    {:reply, :ok, state}
  end

  def handle_call({:revoke_family_access_tokens, family_id}, _from, state) do
    @access_tokens
    |> :ets.match_object({:_, :_, :_, family_id})
    |> Enum.each(fn {_code_hash, expires_at, jti, ^family_id} -> revoke_jti(jti, expires_at) end)

    {:reply, :ok, state}
  end

  defp delete_expired(now) do
    # Delete every row whose expiry is strictly in the past.
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}])
    :ets.select_delete(@consumed, [{{:"$1", :"$2", :"$3"}, [{:is_integer, :"$2"}, {:<, :"$2", now}], [true]}])

    :ets.select_delete(@access_tokens, [
      {{:"$1", :"$2", :"$3", :"$4"}, [{:<, :"$2", now}], [true]}
    ])

    :ets.select_delete(@revoked_access_tokens, [
      {{:"$1", :"$2"}, [{:<, :"$2", now}], [true]}
    ])
  end

  defp consumed_result(code_hash) do
    case :ets.lookup(@consumed, code_hash) do
      [{^code_hash, _retain_until, meta}] -> {:error, :consumed, meta}
      [] -> :error
    end
  end

  defp consumed_retain_until(%{family_id: family_id, replay_retain_until: nil})
       when is_binary(family_id) and family_id != "", do: :infinity

  defp consumed_retain_until(%{replay_retain_until: deadline}) when is_integer(deadline) and deadline >= 0, do: deadline

  defp consumed_retain_until(_meta), do: System.system_time(:second) + @no_refresh_retention_seconds

  defp consumed_family_id(%{family_id: family_id}) when is_binary(family_id) and family_id != "", do: family_id
  defp consumed_family_id(_meta), do: nil

  defp consumed_family_id_for_code(code_hash) do
    case :ets.lookup(@consumed, code_hash) do
      [{^code_hash, _retain_until, meta}] -> consumed_family_id(meta)
      [] -> nil
    end
  end

  defp bind_access_token_to_family(code_hash, family_id) do
    case :ets.lookup(@access_tokens, code_hash) do
      [{^code_hash, expires_at, jti, _old_family_id}] ->
        true = :ets.insert(@access_tokens, {code_hash, expires_at, jti, family_id})
        :ok

      [] ->
        :ok
    end
  end

  defp revoke_jti(jti, expires_at) do
    retained_until =
      case :ets.lookup(@revoked_access_tokens, jti) do
        [{^jti, existing_expires_at}] -> max(existing_expires_at, expires_at)
        [] -> expires_at
      end

    true = :ets.insert(@revoked_access_tokens, {jti, retained_until})
    :ok
  end
end
