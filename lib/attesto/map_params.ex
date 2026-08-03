defmodule Attesto.MapParams do
  @moduledoc """
  Shared helpers for reading and validating protocol map parameters.

  Wallet builders and parsers use these helpers at the boundary where caller
  input may use atom or string keys. The helpers keep that boundary behavior
  consistent while protocol-specific validation remains with each caller.
  """

  @doc "Fetch a value by atom key, falling back to its string spelling."
  @spec fetch(map(), atom()) :: term() | nil
  def fetch(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  @doc "Put `value` into `map` unless it is nil."
  @spec put_optional(map(), term(), term()) :: map()
  def put_optional(map, _key, nil), do: map
  def put_optional(map, key, value), do: Map.put(map, key, value)

  @doc "Put a normalized non-nil value into `map`."
  @spec put_optional(map(), term(), term(), (term(), term() -> term())) :: map()
  def put_optional(map, _key, nil, _normalizer), do: map
  def put_optional(map, key, value, normalizer), do: Map.put(map, key, normalizer.(value, key))

  @doc "Raise unless `value` is a non-empty binary."
  @spec required_string!(term(), term()) :: String.t()
  def required_string!(value, _key) when is_binary(value) and value != "", do: value

  def required_string!(value, key) do
    raise ArgumentError, ":#{key} must be a non-empty string; got #{inspect(value)}"
  end

  @doc "Return a non-empty binary or raise an `ArgumentError`."
  @spec optional_string!(term(), term()) :: String.t()
  def optional_string!(value, _key) when is_binary(value) and value != "", do: value

  def optional_string!(value, key) do
    raise ArgumentError, ":#{key} must be a non-empty string; got #{inspect(value)}"
  end

  @doc "Return a list of binaries or raise an `ArgumentError`."
  @spec string_list!(term(), term()) :: [String.t()]
  def string_list!(value, key) when is_list(value) do
    if Enum.all?(value, &is_binary/1) do
      value
    else
      raise ArgumentError, ":#{key} must be a list of strings; got #{inspect(value)}"
    end
  end

  def string_list!(value, key) do
    raise ArgumentError, ":#{key} must be a list of strings; got #{inspect(value)}"
  end

  @doc "Convert atom keys in a map to strings, without recursing into values."
  @spec string_keyed_map(map()) :: map()
  def string_keyed_map(value) do
    Map.new(value, fn {key, item} -> {if(is_atom(key), do: Atom.to_string(key), else: key), item} end)
  end

  @doc "Return a keyword list or raise an `ArgumentError`."
  @spec ensure_keyword!(term()) :: keyword()
  def ensure_keyword!(opts) do
    if Keyword.keyword?(opts) do
      opts
    else
      raise ArgumentError, "expects a keyword list; got #{inspect(opts)}"
    end
  end
end
