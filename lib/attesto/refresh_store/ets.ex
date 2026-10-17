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

  Start options: `:sweep_interval_ms` (default `60_000`). The sweeper retains
  expired consumed generations only through their successor retry deadline,
  then removes them even while a later generation remains live. This bounds a
  continuously rotated family's retained history without forcing a live
  family to reauthenticate after an arbitrary number of rotations. A
  family-keyed membership index keeps revocation proportional to that family's
  retained size instead of scanning the complete token table.
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
      {__MODULE__.Generations, [:set, :named_table, read_concurrency: true]},
      {__MODULE__.Families, [:bag, :named_table, read_concurrency: true]}
    ],
    reset: :server

  @table __MODULE__
  @revoked :"#{__MODULE__}.Revoked"
  @generations :"#{__MODULE__}.Generations"
  @families :"#{__MODULE__}.Families"
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
  def rotate(parent_hash, child, successor, opts)
      when is_binary(parent_hash) and is_map(child) and is_map(successor) and is_list(opts),
      do: rotate_with_validated_now(parent_hash, child, successor, opts)

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
          true = :ets.insert(@families, {record.family_id, record.token_hash})
          :ok
      end

    {:reply, reply, state}
  end

  def handle_call({:rotate, parent_hash, child, successor, now}, _from, state) when is_integer(now) and now >= 0 do
    reply = rotate_result(:ets.lookup(@table, parent_hash), parent_hash, child, successor, now)

    {:reply, reply, state}
  end

  def handle_call({:revoke_family, family_id}, _from, state) do
    revoke_family_rows(family_id)
    {:reply, :ok, state}
  end

  defp rotate_with_validated_now(parent_hash, child, successor, opts) do
    with true <- Keyword.keyword?(opts),
         {:ok, now} <- Keyword.fetch(opts, :now),
         true <- is_integer(now) and now >= 0 do
      GenServer.call(__MODULE__, {:rotate, parent_hash, child, successor, now})
    else
      _invalid_now -> {:error, :invalid_rotation}
    end
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

  # `handle_call/3` admits rotation messages only with a validated,
  # non-negative integer clock value.
  defp valid_rotation_time?(parent_exp, now), do: parent_exp > now

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

    true = :ets.insert(@families, {Map.fetch!(child, :family_id), Map.fetch!(child, :token_hash)})

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

    for {^family_id, token_hash} <- :ets.lookup(@families, family_id) do
      case :ets.lookup(@table, token_hash) do
        [{^token_hash, ^family_id, _expires_at, %{generation: generation}}] ->
          true = :ets.delete(@generations, {family_id, generation})

        _missing_or_invalid_row ->
          :ok
      end

      true = :ets.delete(@table, token_hash)
    end

    true = :ets.delete(@families, family_id)
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
      fn row, :ok ->
        sweep_refresh_record(row, now)
      end,
      :ok,
      @table
    )
  end

  defp sweep_refresh_record(
         {token_hash, family, expires_at,
          %{generation: generation, consumed: true, successor: %{retry_until: retry_until}}},
         now
       )
       when expires_at < now and is_integer(retry_until) and retry_until < now,
       do: delete_record(token_hash, family, generation)

  defp sweep_refresh_record({token_hash, family, expires_at, %{generation: generation, consumed: false}}, now)
       when expires_at < now, do: delete_record(token_hash, family, generation)

  defp sweep_refresh_record(row, now), do: redact_successor_after_retry(row, now)

  defp redact_successor_after_retry(
         {token_hash, family, expires_at, %{successor: %{retry_until: retry_until} = successor} = record},
         now
       )
       when is_integer(retry_until) and retry_until < now and not is_map_key(successor, :recoverable) do
    # Retain only the non-secret fixed deadline. An expired consumed record is
    # still replay evidence while a descendant is live, but it no longer needs
    # the plaintext successor credential or its context after this deadline.
    tombstone = %{retry_until: retry_until, recoverable: false}
    true = :ets.insert(@table, {token_hash, family, expires_at, Map.put(record, :successor, tombstone)})
    :ok
  end

  defp redact_successor_after_retry(_row, _now), do: :ok

  defp delete_record(token_hash, family_id, generation) do
    true = :ets.delete(@table, token_hash)
    true = :ets.delete(@generations, {family_id, generation})
    true = :ets.delete_object(@families, {family_id, token_hash})
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
      valid_attestation_binding?(parent, child) and
      valid_family_deadline?(parent, child) and
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
    is_integer(child_expiry) and child_expiry > now
  end

  defp valid_child_context?(child, successor) do
    child_data = Map.get(child, :data)
    is_map(child_data) and child_data == successor_context(successor, child_data)
  end

  defp valid_family_deadline?(parent, child) do
    parent_data = Map.get(parent, :data, %{})
    child_data = Map.get(child, :data, %{})

    is_map(parent_data) and
      Map.fetch(parent_data, :family_expires_at) == Map.fetch(child_data, :family_expires_at) and
      case Map.fetch(child_data, :family_expires_at) do
        :error -> true
        {:ok, deadline} -> is_integer(deadline) and child.expires_at <= deadline
      end
  end

  defp valid_attestation_binding?(parent, child) do
    parent_data = Map.get(parent, :data, %{})
    child_data = Map.get(child, :data, %{})

    is_map(parent_data) and
      Map.fetch(parent_data, :attestation_jkt) == Map.fetch(child_data, :attestation_jkt) and
      case Map.fetch(child_data, :attestation_jkt) do
        :error -> true
        {:ok, thumbprint} -> Attesto.Thumbprint.valid?(thumbprint)
      end
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
      Attesto.SecureCompare.equal?(Attesto.Secret.hash(token), child.token_hash) and context == child.data and
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
