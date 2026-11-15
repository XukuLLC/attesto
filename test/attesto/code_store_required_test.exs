defmodule Attesto.CodeStoreRequiredTest do
  use ExUnit.Case, async: true

  for {missing, arity} <- Attesto.CodeStore.behaviour_info(:callbacks) do
    module = Module.concat(__MODULE__, Macro.camelize(Atom.to_string(missing)))

    definitions =
      for {name, count} <- Attesto.CodeStore.behaviour_info(:callbacks), name != missing do
        args = Macro.generate_arguments(count, __MODULE__)

        quote do
          defdelegate unquote(name)(unquote_splicing(args)), to: Attesto.CodeStore.ETS
        end
      end

    Module.create(module, {:__block__, [], definitions}, Macro.Env.location(__ENV__))

    test "a missing #{missing}/#{arity} is refused before any store operation" do
      message = "#{inspect(unquote(module))} must implement Attesto.CodeStore.#{unquote(missing)}/#{unquote(arity)}"

      assert_raise ArgumentError, message, fn ->
        Attesto.AuthorizationCode.redeem(unquote(module), "unknown", %{})
      end
    end
  end
end
