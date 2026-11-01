defmodule Attesto.StrictJSON do
  @moduledoc """
  Strict JSON object decoder with duplicate-member rejection and nesting bounds.

  RFC 8259 §4 states that object member names SHOULD be unique and notes that
  implementations disagree when duplicate keys appear. Security-sensitive JSON
  boundaries (JWS headers and claim sets, JWE protected headers, discovery and
  metadata documents) must reject duplicate object members at parse time so an
  input cannot mean one thing to a verifier and another to an intermediary.
  """

  # Registered claim sets and headers nest a handful of levels; OpenID
  # Federation metadata, DCQL queries, and authorization details stay under
  # ten. Bounding nesting keeps an unverified payload from turning a bounded
  # byte input into a disproportionate container tree.
  @default_max_json_depth 32

  @doc """
  Decode a JSON binary into a map, rejecting duplicate object member names and
  inputs that exceed `:max_json_depth` (default `32`).

  Returns `{:ok, map}` when the top-level value is a JSON object with no
  duplicate keys in any nested object, or `{:error, :invalid_json}` otherwise.
  """
  @spec decode(term(), keyword()) :: {:ok, map()} | {:error, :invalid_json}
  def decode(bytes, opts \\ []) do
    case decode_value(bytes, opts) do
      {:ok, %{} = map} -> {:ok, map}
      _other -> {:error, :invalid_json}
    end
  end

  @doc """
  Decode a JSON binary into any JSON value (object, array, or scalar),
  rejecting duplicate object member names and inputs that exceed
  `:max_json_depth` (default `32`) at any nesting level.
  """
  @spec decode_value(term(), keyword()) :: {:ok, term()} | {:error, :invalid_json}
  def decode_value(bytes, opts \\ [])

  def decode_value(bytes, opts) when is_binary(bytes) and is_list(opts) do
    with {:ok, max_depth} <- max_json_depth(opts) do
      decoders = [
        array_start: &json_container_start(:array, &1, max_depth),
        array_push: &json_array_push/2,
        array_finish: &json_array_finish/2,
        object_start: &json_container_start(:object, &1, max_depth),
        object_push: &json_object_push/3,
        object_finish: &json_object_finish/2
      ]

      case JSON.decode(bytes, nil, decoders) do
        {value, nil, ""} -> {:ok, value}
        _other -> {:error, :invalid_json}
      end
    end
  rescue
    _error -> {:error, :invalid_json}
  catch
    _kind, _reason -> {:error, :invalid_json}
  end

  def decode_value(_bytes, _opts), do: {:error, :invalid_json}

  defp max_json_depth(opts) do
    depth =
      case Keyword.fetch(opts, :max_json_depth) do
        {:ok, value} -> value
        :error -> Keyword.get(opts, :max_depth, @default_max_json_depth)
      end

    case depth do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _invalid -> {:error, :invalid_json}
    end
  end

  defp json_container_start(kind, old_acc, max_depth) do
    depth = json_container_depth(old_acc) + 1

    if depth > max_depth do
      throw(:json_depth_limit)
    end

    value = if kind == :object, do: %{}, else: []
    {:attesto_json_container, depth, kind, value}
  end

  defp json_container_depth(nil), do: 0
  defp json_container_depth({:attesto_json_container, depth, _kind, _value}), do: depth
  defp json_container_depth(_invalid), do: throw(:invalid_json_accumulator)

  defp json_array_push(value, {:attesto_json_container, depth, :array, values}) do
    {:attesto_json_container, depth, :array, [value | values]}
  end

  defp json_array_finish({:attesto_json_container, _depth, :array, values}, old_acc) do
    {Enum.reverse(values), old_acc}
  end

  defp json_object_push(key, value, {:attesto_json_container, depth, :object, object}) do
    if Map.has_key?(object, key) do
      throw(:duplicate_json_member)
    end

    {:attesto_json_container, depth, :object, Map.put(object, key, value)}
  end

  defp json_object_finish({:attesto_json_container, _depth, :object, object}, old_acc) do
    {object, old_acc}
  end
end
