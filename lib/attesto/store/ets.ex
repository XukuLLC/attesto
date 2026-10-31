defmodule Attesto.Store.ETS do
  @moduledoc false

  alias Attesto.Secret

  @default_table_options [
    :set,
    :public,
    :named_table,
    read_concurrency: true,
    write_concurrency: true
  ]

  defmacro __using__(opts) do
    caller = __CALLER__
    table = opts |> Keyword.get(:table, caller.module) |> Macro.expand(caller)
    table_options = Keyword.get(opts, :table_options, @default_table_options)

    extra_tables =
      opts
      |> Keyword.get(:extra_tables, [])
      |> Enum.map(&expand_table(&1, caller))

    tables = [{table, table_options} | extra_tables]
    sweep? = Keyword.get(opts, :sweep?, true)
    sweep_time = Keyword.get(opts, :sweep_time, :second)
    default_sweep_interval_ms = Keyword.get(opts, :default_sweep_interval_ms)
    cluster_guard? = Keyword.get(opts, :cluster_guard?, true)
    interval_before_tables? = Keyword.get(opts, :interval_before_tables?, true)
    reset = Keyword.get(opts, :reset, :direct)
    reset_doc = Keyword.get(opts, :reset_doc, "Clear every entry. Test-facing.")
    reset_spec? = Keyword.get(opts, :reset_spec?, true)
    reset_match? = Keyword.get(opts, :reset_match?, false)
    nonce_store = Keyword.get(opts, :nonce_store)

    table_initializers =
      Enum.map(tables, fn {name, options} ->
        quote do
          :ets.new(unquote(name), unquote(Macro.escape(options)))
        end
      end)

    guard =
      if cluster_guard? do
        [
          quote do
            Attesto.ClusterGuard.assert_single_node!(
              __MODULE__,
              Keyword.get(opts, :multi_node_acknowledged?, false)
            )
          end
        ]
      else
        []
      end

    init =
      init_ast(
        guard,
        table_initializers,
        sweep?,
        default_sweep_interval_ms,
        interval_before_tables?
      )

    reset_annotations =
      [
        if(reset_doc == false,
          do: quote(do: @doc(false)),
          else: quote(do: @doc(unquote(reset_doc)))
        ),
        if(reset_spec?, do: quote(do: @spec(reset() :: :ok)))
      ]
      |> Enum.reject(&is_nil/1)

    {reset_function, reset_handler} = reset_ast(reset, table, tables, reset_match?)
    sweep = sweep_ast(sweep?, sweep_time)
    nonce_store_functions = nonce_store_ast(nonce_store, table, caller)

    quote do
      use GenServer

      @spec start_link(keyword()) :: GenServer.on_start()
      def start_link(opts \\ []) do
        GenServer.start_link(__MODULE__, opts, name: __MODULE__)
      end

      @doc false
      def child_spec(opts) do
        %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
      end

      unquote_splicing(reset_annotations)
      unquote(reset_function)
      unquote(nonce_store_functions)
      unquote(init)
      unquote(sweep)
      unquote(reset_handler)
    end
  end

  @spec issue_nonce(:ets.tid() | atom(), pos_integer(), pos_integer(), pos_integer()) ::
          String.t()
  def issue_nonce(table, ttl_seconds, nonce_bytes, max_entries) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    evict_one_if_full(table, max_entries)
    nonce = Secret.generate(nonce_bytes)
    true = :ets.insert(table, {nonce, System.system_time(:second) + ttl_seconds})
    nonce
  end

  @spec valid_nonce?(:ets.tid() | atom(), term()) :: boolean()
  def valid_nonce?(table, nonce) when is_binary(nonce) do
    case :ets.lookup(table, nonce) do
      [{^nonce, expires_at}] -> expires_at > System.system_time(:second)
      [] -> false
    end
  end

  def valid_nonce?(_table, _nonce), do: false

  @spec consume_nonce(:ets.tid() | atom(), term()) :: :ok | {:error, :expired | :unknown}
  def consume_nonce(table, nonce) when is_binary(nonce) do
    now = System.system_time(:second)

    case :ets.take(table, nonce) do
      [{^nonce, expires_at}] when expires_at > now -> :ok
      [{^nonce, _expired}] -> {:error, :expired}
      [] -> {:error, :unknown}
    end
  end

  def consume_nonce(_table, _nonce), do: {:error, :unknown}

  @spec check_and_record(:ets.tid() | atom(), String.t(), pos_integer()) ::
          :ok | {:error, :replay}
  def check_and_record(table, key, ttl_seconds) when is_binary(key) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    expires_at_ms = System.monotonic_time(:millisecond) + ttl_seconds * 1_000

    case :ets.insert_new(table, {key, expires_at_ms}) do
      true ->
        :ok

      false ->
        now_ms = System.monotonic_time(:millisecond)
        replace_expired(table, key, now_ms, expires_at_ms)
    end
  end

  @spec size(:ets.tid() | atom()) :: non_neg_integer()
  def size(table) do
    case :ets.whereis(table) do
      :undefined -> 0
      _ -> :ets.info(table, :size)
    end
  end

  @spec delete_expired_entries(:ets.tid() | atom(), integer()) :: non_neg_integer()
  def delete_expired_entries(table, now) do
    :ets.select_delete(table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])
  end

  defp evict_one_if_full(table, max_entries) do
    if :ets.info(table, :size) >= max_entries do
      case :ets.first(table) do
        :"$end_of_table" -> :ok
        key -> :ets.delete(table, key)
      end
    end
  end

  defp replace_expired(table, key, now_ms, expires_at_ms) do
    case :ets.select_delete(table, [{{key, :"$1"}, [{:<, :"$1", now_ms}], [true]}]) do
      1 ->
        case :ets.insert_new(table, {key, expires_at_ms}) do
          true -> :ok
          false -> {:error, :replay}
        end

      0 ->
        {:error, :replay}
    end
  end

  defp sweep_ast(false, _sweep_time), do: nil

  defp sweep_ast(true, :monotonic_ms) do
    quote do
      @impl GenServer
      def handle_info(:sweep, state) do
        now_ms = System.monotonic_time(:millisecond)
        delete_expired(now_ms)
        schedule_sweep(state.sweep_interval_ms)
        {:noreply, state}
      end

      defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
    end
  end

  defp sweep_ast(true, :second) do
    quote do
      @impl GenServer
      def handle_info(:sweep, state) do
        now = System.system_time(:second)
        delete_expired(now)
        schedule_sweep(state.sweep_interval_ms)
        {:noreply, state}
      end

      defp schedule_sweep(interval_ms), do: Process.send_after(self(), :sweep, interval_ms)
    end
  end

  defp nonce_store_ast(nil, _table, _caller), do: nil

  defp nonce_store_ast(opts, table, caller) when is_list(opts) do
    behaviour = opts |> Keyword.fetch!(:behaviour) |> Macro.expand(caller)
    default_ttl_seconds = Keyword.get(opts, :default_ttl_seconds, 300)
    nonce_bytes = Keyword.get(opts, :nonce_bytes, 16)
    max_entries = Keyword.get(opts, :max_entries, 1_000_000)
    consume? = Keyword.get(opts, :consume?, false)

    consume_fn =
      if consume? do
        quote do
          @impl unquote(behaviour)
          def consume(nonce) do
            unquote(__MODULE__).consume_nonce(unquote(table), nonce)
          end
        end
      end

    quote do
      @impl unquote(behaviour)
      def issue(ttl_seconds \\ unquote(default_ttl_seconds))
          when is_integer(ttl_seconds) and ttl_seconds > 0 do
        unquote(__MODULE__).issue_nonce(
          unquote(table),
          ttl_seconds,
          unquote(nonce_bytes),
          unquote(max_entries)
        )
      end

      @impl unquote(behaviour)
      def valid?(nonce) do
        unquote(__MODULE__).valid_nonce?(unquote(table), nonce)
      end

      unquote(consume_fn)

      defp delete_expired(now) do
        unquote(__MODULE__).delete_expired_entries(unquote(table), now)
      end
    end
  end

  defp expand_table({:{}, _meta, [name, options]}, caller) do
    {Macro.expand(name, caller), options}
  end

  defp expand_table({name, options}, caller) do
    {Macro.expand(name, caller), options}
  end

  defp init_ast(guard, table_initializers, false, _default_interval, _interval_before_tables?) do
    quote do
      @impl GenServer
      def init(opts) do
        unquote_splicing(guard)
        unquote_splicing(table_initializers)
        {:ok, %{}}
      end
    end
  end

  defp init_ast(guard, table_initializers, true, default_interval, interval_before_tables?) do
    interval =
      quote do
        sweep_interval_ms = Keyword.get(opts, :sweep_interval_ms, unquote(default_interval))
      end

    body =
      if interval_before_tables? do
        guard ++ [interval] ++ table_initializers
      else
        guard ++ table_initializers ++ [interval]
      end

    quote do
      @impl GenServer
      def init(opts) do
        unquote_splicing(body)
        schedule_sweep(sweep_interval_ms)
        {:ok, %{sweep_interval_ms: sweep_interval_ms}}
      end
    end
  end

  defp reset_ast(:direct, _table, tables, _reset_match?) do
    table_names = Enum.map(tables, fn {name, _options} -> name end)

    reset_function =
      quote do
        def reset do
          # Reset EVERY table this store owns, not just the primary — a store
          # with `extra_tables:` on the default `:direct` mode would otherwise
          # silently leave the extra tables' rows intact.
          for name <- unquote(table_names),
              :ets.whereis(name) != :undefined,
              do: :ets.delete_all_objects(name)

          :ok
        end
      end

    {reset_function, nil}
  end

  defp reset_ast(:server, _table, tables, reset_match?) do
    reset_calls =
      Enum.map(tables, fn {name, _options} ->
        if reset_match? do
          quote do
            true = :ets.delete_all_objects(unquote(name))
          end
        else
          quote do
            :ets.delete_all_objects(unquote(name))
          end
        end
      end)

    reset_function =
      quote do
        def reset, do: GenServer.call(__MODULE__, :reset)
      end

    reset_handler =
      quote do
        @impl GenServer
        def handle_call(:reset, _from, state) do
          unquote_splicing(reset_calls)
          {:reply, :ok, state}
        end
      end

    {reset_function, reset_handler}
  end
end
