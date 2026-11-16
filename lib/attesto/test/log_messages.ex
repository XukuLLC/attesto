defmodule Attesto.Test.LogMessages do
  @moduledoc """
  Source inspection for fixed `Logger.error` messages in library tests.

  Inspect a package's `lib/` directory with `errors/1`. Each entry contains
  the source file, line, and literal message (or `nil` for a nonliteral call).
  This helper is shipped with Attesto so dependent packages need no test-source
  directory from a checkout.
  """

  @doc "Return every Logger.error call in Elixir source below a directory."
  @spec errors(Path.t()) :: [%{file: Path.t(), line: pos_integer(), message: String.t() | nil}]
  def errors(directory) do
    directory
    |> Path.join("**/*.{ex,exs}")
    |> Path.wildcard()
    |> Enum.flat_map(fn file ->
      {_ast, calls} =
        file
        |> File.read!()
        |> Code.string_to_quoted!()
        |> Macro.prewalk([], fn
          {{:., _, [{:__aliases__, _, [:Logger]}, :error]}, meta, [message | _]} = node, calls ->
            {node, [%{file: file, line: meta[:line], message: if(is_binary(message), do: message)} | calls]}

          node, calls ->
            {node, calls}
        end)

      Enum.reverse(calls)
    end)
  end
end
