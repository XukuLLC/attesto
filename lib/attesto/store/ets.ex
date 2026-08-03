defmodule Attesto.Store.ETS do
  @moduledoc false

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
    default_sweep_interval_ms = Keyword.get(opts, :default_sweep_interval_ms)
    cluster_guard? = Keyword.get(opts, :cluster_guard?, true)
    interval_before_tables? = Keyword.get(opts, :interval_before_tables?, true)
    reset = Keyword.get(opts, :reset, :direct)
    reset_doc = Keyword.get(opts, :reset_doc, "Clear every entry. Test-facing.")
    reset_spec? = Keyword.get(opts, :reset_spec?, true)
    reset_match? = Keyword.get(opts, :reset_match?, false)

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

    sweep =
      if sweep? do
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
      unquote(init)
      unquote(sweep)
      unquote(reset_handler)
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

  defp reset_ast(:direct, table, _tables, _reset_match?) do
    reset_function =
      quote do
        def reset do
          if :ets.whereis(unquote(table)) != :undefined,
            do: :ets.delete_all_objects(unquote(table))

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
