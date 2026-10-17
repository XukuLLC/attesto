defmodule Attesto.Record do
  @moduledoc false

  alias Attesto.Thumbprint

  @spec non_empty_binary?(term()) :: boolean()
  def non_empty_binary?(value), do: is_binary(value) and value != ""

  @spec optional_binary?(term()) :: boolean()
  def optional_binary?(nil), do: true
  def optional_binary?(value), do: is_binary(value)

  @spec optional_non_empty_binary?(term()) :: boolean()
  def optional_non_empty_binary?(nil), do: true
  def optional_non_empty_binary?(value), do: non_empty_binary?(value)

  @spec optional_non_negative_integer?(term()) :: boolean()
  def optional_non_negative_integer?(nil), do: true
  def optional_non_negative_integer?(value), do: is_integer(value) and value >= 0

  @spec optional_jkt?(term()) :: boolean()
  def optional_jkt?(nil), do: true
  def optional_jkt?(value), do: Thumbprint.valid?(value)

  @spec optional_field?(map(), term(), (term() -> as_boolean(term()))) :: boolean()
  def optional_field?(record, field, validator) when is_map(record) and is_function(validator, 1) do
    case Map.fetch(record, field) do
      :error -> true
      {:ok, value} -> validator.(value)
    end
  end

  @spec exact_keys?(map(), [term()]) :: boolean()
  def exact_keys?(record, keys) when is_map(record) and is_list(keys) do
    MapSet.equal?(MapSet.new(Map.keys(record)), MapSet.new(keys))
  end
end
