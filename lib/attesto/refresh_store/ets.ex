defmodule Attesto.RefreshStore.ETS do
  @moduledoc """
  Single-node ETS implementation of `Attesto.RefreshStore`.

  Tokens live in an ETS table owned by a `GenServer`. The security-
  critical `rotate/4` transition is serialised through the owning process.
  It validates the parent/child pair and performs one list-form ETS insert of
  the post-parent and child, so direct readers cannot observe an intermediate
  state. `insert/1` and `revoke_family/1` go through the same process, so all
  family mutations are ordered.

  This is a per-node store. A multi-node deployment MUST back
  `Attesto.RefreshStore` with a shared store whose complete `rotate/4`
  transaction is atomic across nodes and serialized against family
  revocation, or reuse detection only holds per node.

  Start options: `:sweep_interval_ms` (default `60_000`). The sweeper
  deletes tokens past their expiry; consumed-but-unexpired tokens are
  retained so reuse within the TTL window is still detected. Plaintext
  successor retry data is redacted after its `:retry_until` deadline.
  Revoked-family markers are retained for the lifetime of the store, as
  required by the sticky-revocation contract, including after all token rows
  have expired.

      children = [Attesto.RefreshStore.ETS]
  """

  @behaviour Attesto.RefreshStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 60_000,
    table_options: [:set, :named_table, read_concurrency: true],
    extra_tables: [
      {__MODULE__.Revoked, [:set, :named_table, read_concurrency: true]},
      {__MODULE__.Generations, [:set, :named_table, read_concurrency: true]}
    ],
    reset: :server

  @table __MODULE__
  @revoked :"#{__MODULE__}.Revoked"
  @generations :"#{__MODULE__}.Generations"
  @impl Attesto.RefreshStore
  def insert(
        %{
          token_hash: token_hash,
          family_id: family_id,
          generation: generation,
          data: data,
          expires_at: expires_at,
          consumed: consumed
        } = record
      )
      when is_binary(token_hash) and is_binary(family_id) and is_integer(generation) and is_map(data) and
             is_integer(expires_at) and is_boolean(consumed), do: GenServer.call(__MODULE__, {:insert, record})

  @impl Attesto.RefreshStore
  def get(token_hash) when is_binary(token_hash) do
    case :ets.lookup(@table, token_hash) do
      [{^token_hash, _family, _exp, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @impl Attesto.RefreshStore
  def rotate(parent_hash, child, successor, opts \\ [])
      when is_binary(parent_hash) and is_map(child) and is_map(successor) and is_list(opts),
      do: GenServer.call(__MODULE__, {:rotate, parent_hash, child, successor, opts})

  @impl Attesto.RefreshStore
  def revoke_family(family_id) when is_binary(family_id), do: GenServer.call(__MODULE__, {:revoke_family, family_id})

  @impl GenServer
  def handle_call({:insert, record}, _from, state) do
    reply =
      cond do
        family_revoked?(record.family_id) ->
          {:error, :family_revoked}

        :ets.member(@table, record.token_hash) or
            generation_taken?(record.family_id, record.generation) ->
          {:error, :conflict}

        true ->
          row = {record.token_hash, record.family_id, record.expires_at, record}
          true = :ets.insert(@table, row)
          true = :ets.insert(@generations, {{record.family_id, record.generation}, record.token_hash})
          :ok
      end

    {:reply, reply, state}
  end

  def handle_call({:rotate, parent_hash, child, successor, opts}, _from, state) do
    now = Keyword.fetch!(opts, :now)
    reply = rotate_result(:ets.lookup(@table, parent_hash), parent_hash, child, successor, now)

    {:reply, reply, state}
  end

  def handle_call({:revoke_family, family_id}, _from, state) do
    revoke_family_rows(family_id)
    {:reply, :ok, state}
  end

  defp rotate_result([], _parent_hash, child, _successor, _now) do
    case Map.get(child, :family_id) do
      family when is_binary(family) ->
        if family_revoked?(family), do: {:error, :family_revoked}, else: :error

      _invalid_family ->
        :error
    end
  end

  defp rotate_result(
         [{parent_hash, _family, _expires_at, %{consumed: true} = parent}],
         parent_hash,
         _child,
         _successor,
         _now
       ), do: {:reuse, parent}

  defp rotate_result(
         [{parent_hash, family, parent_exp, %{consumed: false} = parent}],
         parent_hash,
         child,
         successor,
         now
       ) do
    rotate_unconsumed(parent_hash, family, parent_exp, parent, child, successor, now)
  end

  defp rotate_unconsumed(parent_hash, family, parent_exp, parent, child, successor, now) do
    cond do
      family_revoked?(family) ->
        {:error, :family_revoked}

      not valid_rotation_time?(parent_exp, now) ->
        {:error, :expired}

      not valid_rotation_pair?(parent, child, successor, now) ->
        {:error, :invalid_rotation}

      :ets.member(@table, Map.fetch!(child, :token_hash)) ->
        {:error, :token_conflict}

      generation_taken?(family, Map.fetch!(child, :generation)) ->
        revoke_family_rows(family)
        {:error, :family_integrity_error}

      true ->
        commit_rotation(parent_hash, family, parent_exp, parent, child, successor, now)
    end
  end

  defp valid_rotation_time?(parent_exp, now), do: is_integer(now) and now >= 0 and parent_exp > now

  defp commit_rotation(parent_hash, family, parent_exp, parent, child, successor, now) do
    consumed_parent =
      parent
      |> Map.put(:consumed, true)
      |> Map.put(:consumed_at, now)
      |> Map.put(:successor, successor)

    # List-form insert is one ETS operation: direct get/1 readers see either
    # the complete pre-state or both committed rows.
    true =
      :ets.insert(@table, [
        {parent_hash, family, parent_exp, consumed_parent},
        child_row(child)
      ])

    true =
      :ets.insert(
        @generations,
        {{Map.fetch!(child, :family_id), Map.fetch!(child, :generation)}, Map.fetch!(child, :token_hash)}
      )

    {:ok, consumed_parent, child}
  end

  defp child_row(child) do
    {Map.fetch!(child, :token_hash), Map.fetch!(child, :family_id), Map.fetch!(child, :expires_at), child}
  end

  defp revoke_family_rows(family_id) do
    # Mark the family revoked (sticky) BEFORE deleting its rows, so a
    # concurrent insert serialized after this call sees the marker.
    # The refresh-store contract makes this marker permanent for the lifetime
    # of the store. An expiry would let an imported or long-lived family be
    # resurrected after the marker disappeared.
    true = :ets.insert(@revoked, {family_id, :infinity})
    :ets.match_delete(@table, {:_, family_id, :_, :_})
    :ets.match_delete(@generations, {{family_id, :_}, :_})
    :ok
  end

  defp delete_expired(now) do
    sweep_refresh_records(now)
    # Revoked-family markers are intentionally not swept: revocation is
    # sticky, including after every token row has expired or been deleted.
    :ok
  end

  defp sweep_refresh_records(now) do
    :ets.foldl(
      fn
        {token_hash, family, expires_at, %{generation: generation, successor: %{retry_until: retry_until}}}, :ok
        when expires_at < now and is_integer(retry_until) and retry_until < now ->
          delete_record(token_hash, family, generation)
          :ok

        {_token_hash, _family, expires_at, %{successor: %{retry_until: retry_until}}}, :ok
        when expires_at < now and is_integer(retry_until) and retry_until >= now ->
          # The parent credential is expired, but its lost-response recovery
          # window is not. Retain it until the absolute retry deadline.
          :ok

        {token_hash, family, expires_at, %{generation: generation}}, :ok when expires_at < now ->
          delete_record(token_hash, family, generation)
          :ok

        {token_hash, family, expires_at, %{successor: %{retry_until: retry_until} = successor} = record}, :ok
        when is_integer(retry_until) and retry_until < now and not is_map_key(successor, :recoverable) ->
          # Retain only the non-secret fixed deadline. A later request can then
          # distinguish an expired retry window from malformed/missing state
          # without keeping the credential or its context in memory.
          tombstone = %{retry_until: retry_until, recoverable: false}
          true = :ets.insert(@table, {token_hash, family, expires_at, Map.put(record, :successor, tombstone)})
          :ok

        _row, :ok ->
          :ok
      end,
      :ok,
      @table
    )
  end

  defp delete_record(token_hash, family_id, generation) do
    true = :ets.delete(@table, token_hash)
    true = :ets.delete(@generations, {family_id, generation})
    :ok
  end

  defp family_revoked?(family_id) do
    case :ets.lookup(@revoked, family_id) do
      [{^family_id, _marker}] -> true
      [] -> false
    end
  end

  defp valid_rotation_pair?(parent, child, successor, now) do
    valid_child_identity?(parent, child) and
      valid_child_state?(child) and
      valid_child_lifetime?(child, now) and
      valid_child_context?(child, successor) and
      valid_successor_state?(successor, child, now)
  end

  defp valid_child_identity?(parent, child) do
    child_hash = Map.get(child, :token_hash)
    child_generation = Map.get(child, :generation)

    is_binary(child_hash) and child_hash != "" and child_hash != Map.get(parent, :token_hash) and
      Map.get(child, :family_id) == Map.get(parent, :family_id) and
      is_integer(child_generation) and child_generation == Map.get(parent, :generation) + 1
  end

  defp valid_child_state?(child) do
    Map.get(child, :consumed) == false and is_nil(Map.get(child, :consumed_at)) and
      is_nil(Map.get(child, :successor))
  end

  defp valid_child_lifetime?(child, now) do
    child_expiry = Map.get(child, :expires_at)
    is_integer(now) and now >= 0 and is_integer(child_expiry) and child_expiry > now
  end

  defp valid_child_context?(child, successor) do
    child_data = Map.get(child, :data)
    is_map(child_data) and child_data == successor_context(successor, child_data)
  end

  defp successor_context(%{context: context}, _default), do: context
  defp successor_context(%{recoverable: false}, default), do: default
  defp successor_context(_successor, _default), do: :invalid

  defp valid_successor_state?(
         %{token: token, generation: generation, context: context, retry_until: retry_until} = successor,
         child,
         now
       )
       when map_size(successor) == 4 do
    is_binary(token) and token != "" and generation == child.generation and
      Attesto.Secret.hash(token) == child.token_hash and context == child.data and
      is_integer(retry_until) and retry_until >= now and
      retry_until < child.expires_at
  end

  defp valid_successor_state?(%{retry_until: now, recoverable: false} = successor, _child, now)
       when map_size(successor) == 2, do: true

  defp valid_successor_state?(_successor, _child, _now), do: false

  defp generation_taken?(family_id, generation) do
    :ets.member(@generations, {family_id, generation})
  end
end
