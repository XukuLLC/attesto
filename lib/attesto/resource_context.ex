defmodule Attesto.ResourceContext do
  @moduledoc """
  Authentication context and callback helpers for protected resources.

  For `{module, fun, extra}` callback tuples, `invoke/2` **appends** `extra`
  after the per-call `args` (`apply(module, fun, args ++ extra)`).
  """

  alias Attesto.Scope

  @doc "Read a verified scope claim or an already parsed scope list."
  @spec scopes(term()) :: [String.t()]
  def scopes(%{"scope" => scope}) when is_binary(scope), do: Scope.parse(scope, whitespace: :ascii_whitespace)

  def scopes(scopes) when is_list(scopes), do: scopes
  def scopes(_value), do: []

  @doc "Select the challenge scheme for verified confirmation claims."
  @spec scheme(term()) :: :bearer | :dpop
  def scheme(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  def scheme(_claims), do: :bearer

  @doc "Invoke a callback, appending MFA extra arguments after the call arguments."
  @spec invoke(term(), [term()]) :: term()
  def invoke(fun, args) when is_function(fun), do: apply(fun, args)
  def invoke({module, fun}, args) when is_atom(module) and is_atom(fun), do: apply(module, fun, args)

  def invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun) and is_list(extra),
    do: apply(module, fun, args ++ extra)

  def invoke(_callback, _args), do: nil
end
