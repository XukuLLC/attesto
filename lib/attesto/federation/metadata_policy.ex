defmodule Attesto.Federation.MetadataPolicy do
  @moduledoc """
  OpenID Federation 1.0 metadata-policy resolution and application.

  Policies use string-keyed maps. `apply/2` accepts either a complete
  `metadata_policy` Claim together with complete Entity metadata, or one
  Entity Type's parameter policy together with that Entity Type's metadata.
  `merge/2` accepts the same two policy levels; its first argument is the
  policy of the more superior Entity.

  Unknown, non-critical extension operators are ignored, as required by the
  Federation specification. Critical extension operators are handled while
  validating an Entity Statement and are outside this core seven-operator API.
  """

  @operators ~w(value add default one_of subset_of superset_of essential)
  @allowed_operator_pairs [
    {"add", "default"},
    {"add", "essential"},
    {"add", "subset_of"},
    {"add", "superset_of"},
    {"add", "value"},
    {"default", "essential"},
    {"default", "one_of"},
    {"default", "subset_of"},
    {"default", "superset_of"},
    {"default", "value"},
    {"essential", "one_of"},
    {"essential", "subset_of"},
    {"essential", "superset_of"},
    {"essential", "value"},
    {"one_of", "value"},
    {"subset_of", "superset_of"},
    {"subset_of", "value"},
    {"superset_of", "value"}
  ]

  @type policy :: %{optional(String.t()) => term()}
  @type error :: :policy_error

  @doc """
  Apply a metadata policy in the standard operator order.

  The return value contains no `null` metadata parameters. Unsupported value
  types, illegal operator combinations, and failed value checks are policy
  errors.
  """
  @spec apply(policy(), map()) :: {:ok, map()} | {:error, error()}
  def apply(policy, metadata) when is_map(policy) and is_map(metadata) do
    case policy_level(policy) do
      :empty -> {:ok, metadata}
      :entity_type -> apply_entity_type_policy(policy, metadata, nil)
      :federation -> apply_federation_policy(policy, metadata)
      :invalid -> {:error, :policy_error}
    end
  end

  def apply(_policy, _metadata), do: {:error, :policy_error}

  @doc """
  Merge a superior policy with the next lower policy in a Trust Chain.

  The result is at least as restrictive as both inputs. Incompatible
  same-operator values or newly illegal operator combinations fail closed.
  """
  @spec merge(policy(), policy()) :: {:ok, policy()} | {:error, error()}
  def merge(policy_higher, policy_lower) when is_map(policy_higher) and is_map(policy_lower) do
    merge_at_level(policy_higher, policy_lower, policy_level(policy_higher), policy_level(policy_lower))
  end

  def merge(_policy_higher, _policy_lower), do: {:error, :policy_error}

  defp merge_at_level(_higher, _lower, :empty, :empty), do: {:ok, %{}}
  defp merge_at_level(_higher, lower, :empty, :entity_type), do: normalize_entity_type_policy(lower)
  defp merge_at_level(_higher, lower, :empty, :federation), do: normalize_federation_policy(lower)
  defp merge_at_level(higher, _lower, :entity_type, :empty), do: normalize_entity_type_policy(higher)
  defp merge_at_level(higher, _lower, :federation, :empty), do: normalize_federation_policy(higher)
  defp merge_at_level(higher, lower, :entity_type, :entity_type), do: merge_entity_type_policy(higher, lower)
  defp merge_at_level(higher, lower, :federation, :federation), do: merge_federation_policy(higher, lower)
  defp merge_at_level(_higher, _lower, _higher_level, _lower_level), do: {:error, :policy_error}

  # A complete policy has three levels: Entity Type, metadata parameter, and
  # operator. A per-Entity-Type policy begins at the metadata-parameter level.
  defp policy_level(policy) when map_size(policy) == 0, do: :empty

  defp policy_level(policy) do
    cond do
      not string_keyed_map?(policy) -> :invalid
      Enum.all?(policy, &entity_type_policy_entry?/1) -> :federation
      Enum.all?(policy, &parameter_policy_entry?/1) -> :entity_type
      true -> :invalid
    end
  end

  defp entity_type_policy_entry?({_entity_type, type_policy}) when is_map(type_policy) and map_size(type_policy) > 0,
    do: Enum.all?(type_policy, &parameter_policy_entry?/1)

  defp entity_type_policy_entry?(_entry), do: false

  defp parameter_policy_entry?({_parameter, parameter_policy})
       when is_map(parameter_policy) and map_size(parameter_policy) > 0 do
    string_keyed_map?(parameter_policy) and
      Enum.all?(parameter_policy, fn {_operator, value} -> not is_map(value) end)
  end

  defp parameter_policy_entry?(_entry), do: false

  defp string_keyed_map?(map), do: Enum.all?(Map.keys(map), &is_binary/1)

  defp apply_federation_policy(policy, metadata) do
    with {:ok, normalized} <- normalize_federation_policy(policy),
         :ok <- validate_federation_metadata(metadata) do
      Enum.reduce_while(metadata, {:ok, %{}}, &apply_federation_entry(&1, &2, normalized))
    end
  end

  defp apply_federation_entry({entity_type, type_metadata}, {:ok, acc}, policy) do
    case Map.fetch(policy, entity_type) do
      :error ->
        applied_federation_entry(entity_type, {:ok, type_metadata}, acc)

      {:ok, type_policy} ->
        applied_federation_entry(entity_type, apply_entity_type_policy(type_policy, type_metadata, entity_type), acc)
    end
  end

  defp applied_federation_entry(entity_type, {:ok, metadata}, acc),
    do: {:cont, {:ok, Map.put(acc, entity_type, metadata)}}

  defp applied_federation_entry(_entity_type, {:error, :policy_error} = error, _acc), do: {:halt, error}

  defp apply_entity_type_policy(policy, metadata, entity_type) do
    with {:ok, normalized} <- normalize_entity_type_policy(policy),
         :ok <- validate_type_metadata(metadata) do
      Enum.reduce_while(normalized, {:ok, metadata}, &apply_parameter_entry(&1, &2, entity_type))
    end
  end

  defp apply_parameter_entry({parameter, policy}, {:ok, metadata}, entity_type) do
    policy
    |> apply_parameter_policy(Map.fetch(metadata, parameter), entity_type, parameter)
    |> applied_parameter_entry(parameter, metadata)
  end

  defp applied_parameter_entry({:ok, :absent}, parameter, metadata), do: {:cont, {:ok, Map.delete(metadata, parameter)}}

  defp applied_parameter_entry({:ok, {:present, value}}, parameter, metadata),
    do: {:cont, {:ok, Map.put(metadata, parameter, value)}}

  defp applied_parameter_entry({:error, :policy_error} = error, _parameter, _metadata), do: {:halt, error}

  defp apply_parameter_policy(policy, fetched, entity_type, parameter) do
    state = normalize_scope_value(fetched, entity_type, parameter)

    with {:ok, state} <- apply_value(policy, state),
         {:ok, state} <- apply_add(policy, state),
         {:ok, state} <- apply_default(policy, state),
         {:ok, state} <- apply_one_of(policy, state),
         {:ok, state} <- apply_subset_of(policy, state),
         {:ok, state} <- apply_superset_of(policy, state),
         {:ok, state} <- apply_essential(policy, state) do
      {:ok, restore_scope_value(state, entity_type, parameter)}
    end
  end

  defp normalize_scope_value({:ok, value}, "oauth_client", "scope") when is_binary(value),
    do: {:present, String.split(value, " ", trim: true)}

  defp normalize_scope_value({:ok, value}, _entity_type, _parameter), do: {:present, value}
  defp normalize_scope_value(:error, _entity_type, _parameter), do: :absent

  defp restore_scope_value({:present, value}, "oauth_client", "scope") when is_list(value),
    do: {:present, Enum.join(value, " ")}

  defp restore_scope_value(state, _entity_type, _parameter), do: state

  defp apply_value(%{"value" => nil}, _state), do: {:ok, :absent}
  defp apply_value(%{"value" => value}, _state), do: {:ok, {:present, value}}
  defp apply_value(_policy, state), do: {:ok, state}

  defp apply_add(%{"add" => add}, :absent), do: {:ok, {:present, add}}

  defp apply_add(%{"add" => add}, {:present, value}) when is_list(value) do
    merged = union(value, add)
    if comparable_array?(merged), do: {:ok, {:present, merged}}, else: {:error, :policy_error}
  end

  defp apply_add(%{"add" => _add}, {:present, _value}), do: {:error, :policy_error}
  defp apply_add(_policy, state), do: {:ok, state}

  defp apply_default(%{"default" => default}, :absent), do: {:ok, {:present, default}}
  defp apply_default(_policy, state), do: {:ok, state}

  defp apply_one_of(%{"one_of" => allowed}, {:present, value}) do
    if one_of_value?(value) and member?(allowed, value),
      do: {:ok, {:present, value}},
      else: {:error, :policy_error}
  end

  defp apply_one_of(%{"one_of" => _allowed}, :absent), do: {:ok, :absent}
  defp apply_one_of(_policy, state), do: {:ok, state}

  defp apply_subset_of(%{"subset_of" => allowed}, {:present, value}) when is_list(value) do
    if comparable_array?(value),
      do: {:ok, {:present, intersection(value, allowed)}},
      else: {:error, :policy_error}
  end

  defp apply_subset_of(%{"subset_of" => _allowed}, {:present, _value}), do: {:error, :policy_error}
  defp apply_subset_of(%{"subset_of" => _allowed}, :absent), do: {:ok, :absent}
  defp apply_subset_of(_policy, state), do: {:ok, state}

  defp apply_superset_of(%{"superset_of" => required}, {:present, value}) when is_list(value) do
    if comparable_array?(value) and subset?(required, value),
      do: {:ok, {:present, value}},
      else: {:error, :policy_error}
  end

  defp apply_superset_of(%{"superset_of" => _required}, {:present, _value}), do: {:error, :policy_error}
  defp apply_superset_of(%{"superset_of" => _required}, :absent), do: {:ok, :absent}
  defp apply_superset_of(_policy, state), do: {:ok, state}

  defp apply_essential(%{"essential" => true}, :absent), do: {:error, :policy_error}
  defp apply_essential(_policy, state), do: {:ok, state}

  defp normalize_federation_policy(policy) do
    if policy_level(policy) in [:federation, :empty] do
      normalize_entries(policy, &normalize_entity_type_policy/1)
    else
      {:error, :policy_error}
    end
  end

  defp normalize_entity_type_policy(policy) do
    if policy_level(policy) in [:entity_type, :empty] do
      normalize_entries(policy, &normalize_parameter_policy/1)
    else
      {:error, :policy_error}
    end
  end

  defp normalize_entries(policy, entry_normalizer) do
    Enum.reduce_while(policy, {:ok, %{}}, &normalize_entry(&1, &2, entry_normalizer))
  end

  defp normalize_entry({key, policy}, {:ok, acc}, entry_normalizer) do
    policy
    |> entry_normalizer.()
    |> normalized_entry(key, acc)
  end

  defp normalized_entry({:ok, normalized}, _key, acc) when map_size(normalized) == 0, do: {:cont, {:ok, acc}}

  defp normalized_entry({:ok, normalized}, key, acc), do: {:cont, {:ok, Map.put(acc, key, normalized)}}

  defp normalized_entry({:error, :policy_error} = error, _key, _acc), do: {:halt, error}

  defp normalize_parameter_policy(policy) when is_map(policy) and map_size(policy) > 0 do
    normalized = Map.take(policy, @operators)

    with true <- string_keyed_map?(policy),
         :ok <- validate_operator_values(normalized),
         :ok <- validate_operator_combinations(normalized),
         :ok <- validate_conditional_combinations(normalized) do
      {:ok, normalized}
    else
      _error -> {:error, :policy_error}
    end
  end

  defp normalize_parameter_policy(_policy), do: {:error, :policy_error}

  defp validate_operator_values(policy) do
    if Enum.all?(policy, fn
         {"value", value} -> value_operator_value?(value)
         {"add", value} -> comparable_array?(value)
         {"default", value} -> default_operator_value?(value)
         {"one_of", value} -> comparable_array?(value)
         {"subset_of", value} -> comparable_array?(value)
         {"superset_of", value} -> comparable_array?(value)
         {"essential", value} -> is_boolean(value)
       end),
       do: :ok,
       else: {:error, :policy_error}
  end

  defp validate_operator_combinations(policy) do
    operators = Map.keys(policy)

    operators
    |> operator_pairs()
    |> Enum.all?(fn {left, right} -> allowed_pair?(left, right) end)
    |> policy_check_result()
  end

  defp operator_pairs(operators) do
    for {left, index} <- Enum.with_index(operators),
        right <- Enum.drop(operators, index + 1),
        do: {left, right}
  end

  defp allowed_pair?(left, right) do
    [left, right]
    |> Enum.sort()
    |> List.to_tuple()
    |> Kernel.in(@allowed_operator_pairs)
  end

  defp validate_conditional_combinations(policy) do
    checks = [
      value_add_compatible?(policy),
      value_default_compatible?(policy),
      value_one_of_compatible?(policy),
      value_subset_compatible?(policy),
      value_superset_compatible?(policy),
      value_essential_compatible?(policy),
      add_subset_compatible?(policy),
      subset_superset_compatible?(policy)
    ]

    checks |> Enum.all?() |> policy_check_result()
  end

  defp value_add_compatible?(%{"value" => value, "add" => add}) when is_list(value), do: subset?(add, value)
  defp value_add_compatible?(%{"value" => _value, "add" => _add}), do: false
  defp value_add_compatible?(_policy), do: true

  defp value_default_compatible?(%{"value" => nil, "default" => _default}), do: false
  defp value_default_compatible?(_policy), do: true

  defp value_one_of_compatible?(%{"value" => value, "one_of" => allowed}), do: member?(allowed, value)
  defp value_one_of_compatible?(_policy), do: true

  defp value_subset_compatible?(%{"value" => value, "subset_of" => allowed}) when is_list(value),
    do: subset?(value, allowed)

  defp value_subset_compatible?(%{"value" => _value, "subset_of" => _allowed}), do: false
  defp value_subset_compatible?(_policy), do: true

  defp value_superset_compatible?(%{"value" => value, "superset_of" => required}) when is_list(value),
    do: subset?(required, value)

  defp value_superset_compatible?(%{"value" => _value, "superset_of" => _required}), do: false
  defp value_superset_compatible?(_policy), do: true

  defp value_essential_compatible?(%{"value" => nil, "essential" => true}), do: false
  defp value_essential_compatible?(_policy), do: true

  defp add_subset_compatible?(%{"add" => add, "subset_of" => allowed}), do: subset?(add, allowed)
  defp add_subset_compatible?(_policy), do: true

  defp subset_superset_compatible?(%{"subset_of" => allowed, "superset_of" => required}), do: subset?(required, allowed)

  defp subset_superset_compatible?(_policy), do: true

  defp merge_federation_policy(higher, lower) do
    with {:ok, higher} <- normalize_federation_policy(higher),
         {:ok, lower} <- normalize_federation_policy(lower) do
      merge_maps(higher, lower, fn _key, higher_value, lower_value ->
        merge_entity_type_policy(higher_value, lower_value)
      end)
    end
  end

  defp merge_entity_type_policy(higher, lower) do
    with {:ok, higher} <- normalize_entity_type_policy(higher),
         {:ok, lower} <- normalize_entity_type_policy(lower) do
      merge_maps(higher, lower, fn _key, higher_value, lower_value ->
        merge_parameter_policy(higher_value, lower_value)
      end)
    end
  end

  defp merge_maps(higher, lower, merge_value) do
    Enum.reduce_while(lower, {:ok, higher}, &merge_map_entry(&1, &2, merge_value))
  end

  defp merge_map_entry({key, lower_value}, {:ok, acc}, merge_value) do
    case Map.fetch(acc, key) do
      :error -> {:cont, {:ok, Map.put(acc, key, lower_value)}}
      {:ok, higher_value} -> merge_value.(key, higher_value, lower_value) |> merged_entry(key, acc)
    end
  end

  defp merged_entry({:ok, merged}, key, acc), do: {:cont, {:ok, Map.put(acc, key, merged)}}
  defp merged_entry({:error, :policy_error} = error, _key, _acc), do: {:halt, error}

  defp merge_parameter_policy(higher, lower) do
    with {:ok, higher} <- normalize_parameter_policy(higher),
         {:ok, lower} <- normalize_parameter_policy(lower),
         {:ok, merged} <- merge_maps(higher, lower, &merge_operator/3) do
      normalize_parameter_policy(merged)
    end
  end

  defp merge_operator(operator, value, value) when operator in ~w(value default), do: {:ok, value}
  defp merge_operator(operator, _higher, _lower) when operator in ~w(value default), do: {:error, :policy_error}
  defp merge_operator("add", higher, lower), do: {:ok, union(higher, lower)}

  defp merge_operator("one_of", higher, lower) do
    case intersection(higher, lower) do
      [] -> {:error, :policy_error}
      values -> {:ok, values}
    end
  end

  defp merge_operator("subset_of", higher, lower), do: {:ok, intersection(higher, lower)}
  defp merge_operator("superset_of", higher, lower), do: {:ok, union(higher, lower)}
  defp merge_operator("essential", higher, lower), do: {:ok, higher or lower}

  defp validate_federation_metadata(metadata) do
    if string_keyed_map?(metadata) and
         Enum.all?(metadata, fn {_entity_type, value} -> is_map(value) and valid_type_metadata?(value) end),
       do: :ok,
       else: {:error, :policy_error}
  end

  defp validate_type_metadata(metadata) do
    if valid_type_metadata?(metadata), do: :ok, else: {:error, :policy_error}
  end

  defp valid_type_metadata?(metadata) do
    is_map(metadata) and string_keyed_map?(metadata) and Enum.all?(metadata, fn {_key, value} -> not is_nil(value) end)
  end

  defp value_operator_value?(value), do: is_nil(value) or default_operator_value?(value)

  defp default_operator_value?(value), do: is_binary(value) or is_number(value) or is_boolean(value) or is_list(value)

  defp one_of_value?(value), do: is_binary(value) or is_number(value) or is_map(value)

  defp comparable_array?(values) when is_list(values) do
    Enum.all?(values, &is_binary/1) or Enum.all?(values, &is_number/1) or Enum.all?(values, &is_map/1)
  end

  defp comparable_array?(_values), do: false

  defp subset?(left, right), do: Enum.all?(left, &member?(right, &1))
  defp member?(values, value), do: Enum.any?(values, &(&1 == value))

  defp intersection(left, right) do
    left
    |> Enum.uniq()
    |> Enum.filter(&member?(right, &1))
  end

  defp union(left, right) do
    Enum.reduce(right, Enum.uniq(left), fn value, acc ->
      if member?(acc, value), do: acc, else: acc ++ [value]
    end)
  end

  defp policy_check_result(true), do: :ok
  defp policy_check_result(false), do: {:error, :policy_error}
end
