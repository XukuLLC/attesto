defmodule Attesto.Test.CodeStoreDelegates do
  @moduledoc """
  Overridable `Attesto.CodeStore` callback delegates for test doubles.

  A host can wrap a real store and override only the callbacks a test needs
  to observe or fault. The `:to` option selects the delegate target and
  defaults to `Attesto.CodeStore.ETS`; the target must be started separately.

      defmodule Host.ObservedCodeStore do
        use Attesto.Test.CodeStoreDelegates, to: Attesto.CodeStore.ETS

        def claim(hash) do
          send(self(), {:claim, hash})
          super(hash)
        end
      end

  The generated module implements every `Attesto.CodeStore` callback and
  marks each one overridable. This helper has no ExUnit dependency.
  """

  alias Attesto.CodeStore.ETS

  @doc "Define overridable code-store callbacks delegating to `:to` (ETS by default)."
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
