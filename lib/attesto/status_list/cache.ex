defmodule Attesto.StatusList.Cache do
  @moduledoc """
  Per-node cache of authenticated status-list tokens. Entries are keyed by URI
  and media type and are re-verified against the caller's current trust on use.

  The cache holds at most 64 entries and 16 MiB of keys and token bytes. Freshness is
  bounded by the signed `ttl`, signed `exp`, and a fixed five-minute maximum;
  absent `ttl` uses that maximum. Expired entries are never served on error.
  It starts lazily, without linking its lifetime to a request, and may also be
  included in a host supervisor. Cache loss only causes a fresh fetch.
  """
  use GenServer

  @max_entries 64
  @max_bytes 16 * 1_048_576
  @max_age 300

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc false
  def get(key, now), do: call({:get, key, now}, :miss)

  @doc false
  def put(key, token, claims, now), do: call({:put, key, token, claims, now}, :ok)

  @doc false
  def delete(key), do: call({:delete, key}, :ok)

  defp call(message, fallback) do
    case ensure_started() do
      :ok -> GenServer.call(__MODULE__, message)
      :error -> fallback
    end
  catch
    :exit, _ -> fallback
  end

  defp ensure_started do
    case GenServer.start(__MODULE__, [], name: __MODULE__) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      _ -> :error
    end
  end

  @impl true
  def init(_opts), do: {:ok, %{entries: %{}, bytes: 0}}

  @impl true
  def handle_call({:get, key, now}, _from, state) do
    state = prune(state, now)

    reply =
      case Map.get(state.entries, key) do
        nil -> :miss
        entry -> {:ok, entry.token}
      end

    {:reply, reply, state}
  end

  def handle_call({:put, key, token, claims, now}, _from, state) do
    state = state |> prune(now) |> drop(key)

    expires =
      min(now + @max_age, min(now + claim(claims, "ttl", 65_534, @max_age), claim(claims, "exp", 4, now + @max_age)))

    {uri, media_type} = key
    size = byte_size(token) + byte_size(uri) + byte_size(media_type)

    state =
      if expires > now and byte_size(token) <= 1_048_576 and size <= @max_bytes do
        entry = %{
          token: token,
          bytes: size,
          expires: expires,
          deadline: monotonic() + (expires - now) * 1_000,
          inserted: monotonic()
        }

        state = make_room(state, size)
        %{state | entries: Map.put(state.entries, key, entry), bytes: state.bytes + size}
      else
        state
      end

    {:reply, :ok, state}
  end

  def handle_call({:delete, key}, _from, state), do: {:reply, :ok, drop(state, key)}

  defp claim(claims, text_key, integer_key, default),
    do: Map.get(claims, text_key, Map.get(claims, integer_key, default))

  defp prune(state, now) do
    mono = monotonic()

    Enum.reduce(state.entries, state, fn {key, entry}, acc ->
      if entry.expires <= now or entry.deadline <= mono, do: drop(acc, key), else: acc
    end)
  end

  defp drop(state, key) do
    case Map.pop(state.entries, key) do
      {nil, _} -> state
      {entry, entries} -> %{state | entries: entries, bytes: state.bytes - entry.bytes}
    end
  end

  defp make_room(state, size) when map_size(state.entries) < @max_entries and state.bytes + size <= @max_bytes,
    do: state

  defp make_room(state, size) do
    {key, _entry} = Enum.min_by(state.entries, fn {_key, entry} -> entry.inserted end)
    state |> drop(key) |> make_room(size)
  end

  defp monotonic, do: System.monotonic_time(:millisecond)
end
