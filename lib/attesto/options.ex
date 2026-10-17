defmodule Attesto.Options do
  @moduledoc false

  @spec boolean!(keyword(), atom(), boolean()) :: boolean()
  def boolean!(opts, key, default) when is_list(opts) and is_atom(key) and is_boolean(default) do
    case Keyword.get(opts, key, default) do
      value when is_boolean(value) -> value
      _invalid -> raise ArgumentError, ":#{key} must be true or false"
    end
  end

  @spec positive_integer!(keyword(), atom(), pos_integer()) :: pos_integer()
  def positive_integer!(opts, key, default)
      when is_list(opts) and is_atom(key) and is_integer(default) and default > 0 do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, ":#{key} must be a positive integer"
    end
  end

  @spec optional_positive_integer!(keyword(), atom(), pos_integer() | nil) :: pos_integer() | nil
  def optional_positive_integer!(opts, key, default \\ nil)
      when is_list(opts) and is_atom(key) and (is_nil(default) or (is_integer(default) and default > 0)) do
    case Keyword.get(opts, key, default) do
      nil -> nil
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, ":#{key} must be a positive integer or nil"
    end
  end
end
