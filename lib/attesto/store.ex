defmodule Attesto.Store do
  @moduledoc false

  @spec contract_violation!(String.t(), {atom(), non_neg_integer()}) :: no_return()
  def contract_violation!(label, {callback, arity})
      when is_binary(label) and label != "" and is_atom(callback) and is_integer(arity) and arity >= 0 do
    raise RuntimeError, "#{label} #{callback}/#{arity} violated its contract"
  end
end
