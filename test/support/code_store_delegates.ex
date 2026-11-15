defmodule Attesto.CodeStoreTestDelegates do
  @moduledoc false
  alias Attesto.CodeStore.ETS

  defmacro __using__(opts) do
    target = Keyword.get(opts, :to, ETS)
    callbacks = Attesto.CodeStore.behaviour_info(:callbacks)

    definitions =
      for {name, arity} <- callbacks do
        args = Macro.generate_arguments(arity, __MODULE__)

        quote do
          @impl Attesto.CodeStore
          defdelegate unquote(name)(unquote_splicing(args)), to: unquote(target)
        end
      end

    quote do
      @behaviour Attesto.CodeStore
      unquote_splicing(definitions)
      defoverridable unquote(callbacks)
    end
  end
end
