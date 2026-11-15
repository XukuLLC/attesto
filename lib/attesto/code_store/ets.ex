defmodule Attesto.CodeStore.ETS do
  @moduledoc """
  Single-node implementation of `Attesto.CodeStore`.

  A GenServer serializes every transition over a protected ETS table. Reads
  also use that process so a bulk cut-off is observed atomically. All states
  retain immutable grant bindings. Claims have a fixed 300-second reservation;
  cleanup then requires code and linked access-token expiry. Redeemed records
  live through their recorded refresh-family and access-token lifetimes.
  An unbounded refresh-family record stays for the store's lifetime.

  Supervise this module and pass it to `Attesto.AuthorizationCode`. Multiple
  nodes require a shared store. `:sweep_interval_ms` defaults to 30,000; cleanup
  is only for retention, and core always checks authorization-code expiry.
  """
  @behaviour Attesto.CodeStore

  use Attesto.Store.ETS,
    default_sweep_interval_ms: 30_000,
    table_options: [:set, :protected, :named_table, read_concurrency: true],
    extra_tables: [{__MODULE__.Tokens, [:set, :protected, :named_table, read_concurrency: true]}],
    reset: :server

  @impl Attesto.CodeStore
  def put(entry) do
    case GenServer.call(__MODULE__, {:put, entry}) do
      :ok -> :ok
      :error -> raise ArgumentError, "authorization code hash already exists"
    end
  end

  @impl Attesto.CodeStore
  def read(hash), do: GenServer.call(__MODULE__, {:read, hash})
  @impl Attesto.CodeStore
  def claim(hash), do: GenServer.call(__MODULE__, {:claim, hash})
  @impl Attesto.CodeStore
  def finish(hash, redemption) do
    Attesto.CodeStore.validate_redemption!(redemption)
    GenServer.call(__MODULE__, {:finish, hash, redemption})
  end

  @impl Attesto.CodeStore
  def flag_replay(hash), do: GenServer.call(__MODULE__, {:flag_replay, hash})
  @impl Attesto.CodeStore
  def delete_unclaimed(criteria),
    do: GenServer.call(__MODULE__, {:delete_unclaimed, Attesto.RevocationCriteria.new!(criteria)})

  @impl Attesto.CodeStore
  def record_access_token_for_code(hash, jti, expiry) do
    case GenServer.call(__MODULE__, {:link, hash, jti, expiry}) do
      :ok -> :ok
      :error -> raise ArgumentError, "access-token linkage requires a claimed or redeemed code without a token"
    end
  end

  @impl Attesto.CodeStore
  def revoke_access_token_for_code(hash), do: GenServer.call(__MODULE__, {:revoke, hash})
  @impl Attesto.CodeStore
  def revoke_family_access_tokens(family), do: GenServer.call(__MODULE__, {:revoke_family, family})
  @impl Attesto.CodeStore
  def access_token_revoked?(jti) do
    case :ets.lookup(__MODULE__.Tokens, jti) do
      [{^jti, expiry, true}] -> expiry > System.system_time(:second)
      _ -> false
    end
  end

  @impl GenServer
  def handle_call({:put, entry}, _from, state) do
    record = Map.merge(entry, %{state: :live, redemption: nil, revoked: false})
    result = :ets.insert_new(__MODULE__, {entry.code_hash, record, nil, false})
    {:reply, if(result, do: :ok, else: :error), state}
  end

  def handle_call({:read, hash}, _from, state) do
    result =
      case lookup(hash) do
        {record, _token, _revoked} -> {:ok, Map.delete(record, :claim_retain_until)}
        nil -> :error
      end

    {:reply, result, state}
  end

  def handle_call({:claim, hash}, _from, state) do
    result =
      transition(hash, :live, &Map.merge(&1, %{state: :claimed, claim_retain_until: System.system_time(:second) + 300}))

    {:reply, result, state}
  end

  def handle_call({:flag_replay, hash}, _from, state) do
    result = transition(hash, :claimed, &%{&1 | revoked: true})
    {:reply, result, state}
  end

  def handle_call({:finish, hash, redemption}, _from, state) do
    result =
      case lookup(hash) do
        {%{state: :claimed} = record, token, revoked} ->
          save(%{record | state: :redeemed, redemption: redemption}, token, revoked)
          {:ok, record.revoked}

        _ ->
          :error
      end

    {:reply, result, state}
  end

  def handle_call({:delete_unclaimed, criteria}, _from, state) do
    count =
      :ets.foldl(
        fn {_hash, record, token, revoked}, count ->
          if Attesto.RevocationCriteria.match?(criteria, record.data),
            do: cut_off(record, token, revoked, count),
            else: count
        end,
        0,
        __MODULE__
      )

    {:reply, {:ok, count}, state}
  end

  def handle_call({:link, hash, jti, expiry}, _from, state) do
    result =
      case lookup(hash) do
        {%{state: phase} = record, nil, revoked} when phase in [:claimed, :redeemed] ->
          save(record, %{jti: jti, expires_at: expiry}, revoked)

        _ ->
          :error
      end

    {:reply, result, state}
  end

  def handle_call({:revoke, hash}, _from, state) do
    case lookup(hash) do
      {record, token, _revoked} -> save(record, token, true)
      nil -> :ok
    end

    {:reply, :ok, state}
  end

  def handle_call({:revoke_family, family}, _from, state) do
    :ets.foldl(
      fn
        {_hash, %{state: :redeemed, redemption: %{family_id: ^family}} = record, token, _}, acc ->
          save(record, token, true)
          acc

        _, acc ->
          acc
      end,
      :ok,
      __MODULE__
    )

    {:reply, :ok, state}
  end

  defp cut_off(%{state: :live, code_hash: hash}, _token, _revoked, count) do
    :ets.delete(__MODULE__, hash)
    count + 1
  end

  defp cut_off(%{state: :claimed} = record, token, revoked, count) do
    save(%{record | revoked: true}, token, revoked)
    count
  end

  defp cut_off(%{state: :redeemed}, _token, _revoked, count), do: count

  defp transition(hash, expected, change) do
    case lookup(hash) do
      {%{state: ^expected} = record, token, revoked} -> save(change.(record), token, revoked)
      _ -> :error
    end
  end

  defp lookup(hash) do
    case :ets.lookup(__MODULE__, hash) do
      [{^hash, record, token, revoked}] -> {record, token, revoked}
      [] -> nil
    end
  end

  defp save(record, token, revoked) do
    if token, do: :ets.insert(__MODULE__.Tokens, {token.jti, token.expires_at, revoked})
    true = :ets.insert(__MODULE__, {record.code_hash, record, token, revoked})
    :ok
  end

  defp delete_expired(now) do
    :ets.foldl(
      fn {hash, record, token, _}, acc ->
        if expired?(record, token, now), do: delete_record(hash, token)

        acc
      end,
      :ok,
      __MODULE__
    )
  end

  defp delete_record(hash, token) do
    :ets.delete(__MODULE__, hash)
    if token, do: :ets.delete(__MODULE__.Tokens, token.jti)
  end

  defp expired?(%{state: :claimed} = record, token, now) do
    record.claim_retain_until <= now and record.expires_at < now and
      (is_nil(token) or token.expires_at <= now)
  end

  defp expired?(%{state: :live, expires_at: expiry}, _token, now), do: expiry < now

  defp expired?(%{redemption: %{family_id: family, replay_retain_until: nil}}, _token, _now) when is_binary(family),
    do: false

  defp expired?(record, token, now) do
    deadline = max(record.expires_at, record.redemption.replay_retain_until || 0)
    deadline = max(deadline, if(token, do: token.expires_at, else: 0))
    deadline < now
  end
end
