defmodule Attesto.PollingGrant.ETSTable do
  @moduledoc false

  # Transitions shared by the CIBA and device-code ETS reference stores. Rows are
  # `{key, expires_at, record}`. Every function that writes runs inside the
  # owning store's `GenServer.call/2`, which is what makes each
  # read-modify-write a single-winner transition.

  @doc false
  @spec lookup(atom(), binary()) :: {:ok, map()} | :error
  def lookup(table, key) do
    case :ets.lookup(table, key) do
      [{^key, _expires_at, record}] -> {:ok, record}
      [] -> :error
    end
  end

  @doc false
  # Record an approval or denial. The decision lands only on a pending record
  # that has not expired; a decision on an expired request must not land, since
  # its poll outcome is `expired_token`.
  @spec decide(atom(), binary(), map(), non_neg_integer(), :approved | :denied, map()) ::
          {:ok, map()} | {:error, :expired | :already_decided}
  def decide(table, key, %{status: :pending, expires_at: expires_at} = record, now, status, fields)
      when expires_at > now do
    updated = record |> Map.put(:status, status) |> Map.merge(fields)
    :ets.insert(table, {key, expires_at, updated})
    {:ok, updated}
  end

  def decide(_table, _key, %{status: :pending}, _now, _status, _fields), do: {:error, :expired}
  def decide(_table, _key, _record, _now, _status, _fields), do: {:error, :already_decided}

  @doc false
  # Accept a poll at or after the minimum interval and record it. The first poll
  # (`last_polled_at` nil) is always accepted and a decided record is never
  # throttled. `interval_of` returns the record's interval in seconds, or
  # `:disabled` when the store turns the throttle off.
  @spec poll(atom(), binary(), non_neg_integer(), (map() -> non_neg_integer() | :disabled)) ::
          {:ok, map()} | {:error, :slow_down} | :error
  def poll(table, key, now, interval_of) do
    case lookup(table, key) do
      {:ok, record} ->
        if poll_allowed?(record, now, interval_of) do
          updated = Map.put(record, :last_polled_at, now)
          :ets.insert(table, {key, record.expires_at, updated})
          {:ok, updated}
        else
          {:error, :slow_down}
        end

      :error ->
        :error
    end
  end

  @doc false
  # Consume an approved record. Guarded on approval AND unexpiry, so a request
  # that expires between the core's poll-time check and this transition cannot
  # mint.
  @spec consume(atom(), binary(), non_neg_integer()) :: {:ok, map()} | :error
  def consume(table, key, now) do
    case :ets.lookup(table, key) do
      [{^key, expires_at, %{status: :approved} = record}] when expires_at > now ->
        consumed = Map.put(record, :status, :consumed)
        :ets.insert(table, {key, record.expires_at, consumed})
        {:ok, consumed}

      _other ->
        :error
    end
  end

  @doc false
  @spec expired_match_spec(non_neg_integer(), :key | :record) :: :ets.match_spec()
  def expired_match_spec(now, :key), do: [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [true]}]
  def expired_match_spec(now, :record), do: [{{:"$1", :"$2", :"$3"}, [{:<, :"$2", now}], [:"$3"]}]

  defp poll_allowed?(%{status: status}, _now, _interval_of) when status != :pending, do: true
  defp poll_allowed?(%{last_polled_at: nil}, _now, _interval_of), do: true

  defp poll_allowed?(%{last_polled_at: last} = record, now, interval_of) do
    case interval_of.(record) do
      :disabled -> true
      interval -> last <= now - interval
    end
  end
end
