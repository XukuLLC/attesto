defmodule NoOptionalDeps.MixProject do
  @moduledoc """
  CI guard fixture — NOT published, NOT part of the library.

  attesto declares `:cbor` and `:plug` as `optional: true`. A downstream app
  that doesn't need mdoc (`:cbor`) or the Plug integration (`:plug`) never pulls
  them in. In that configuration attesto's optional-dep modules compile to their
  raising stubs, and any call site that still pattern-matches on a stub's return
  would emit an unreachable-clause warning — invisible to the main CI compile,
  which fetches the optional deps for attesto's own build.

  This fixture reproduces the bare-consumer view: it path-deps attesto with NO
  optional deps, so `mix deps.compile attesto` exercises the stub branches. The
  CI step greps that compile output and fails on any attesto warning.
  """
  use Mix.Project

  def project do
    [app: :no_optional_deps, version: "0.0.0", elixir: "~> 1.18", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  # attesto ONLY — deliberately no :cbor, no :plug.
  defp deps, do: [{:attesto, path: "../.."}]
end
