defmodule Attesto.VpToken.Query do
  @moduledoc false

  alias Attesto.Options

  @default_max_presentations 16

  @type policy :: %{
          constraints: map(),
          legacy?: boolean(),
          max_presentations: pos_integer(),
          permitted_ids: [String.t()] | :unrestricted,
          required_credential_sets: list() | :absent,
          required_ids: [String.t()]
        }

  @spec normalize!(keyword()) :: policy()
  def normalize!(opts) when is_list(opts) do
    expected = expected_query_ids!(opts)
    constraints = query_constraints!(opts)
    required_sets = required_credential_sets!(opts, constraints)

    %{
      constraints: constraints,
      permitted_ids: permitted_query_ids!(opts, expected, constraints, required_sets),
      required_ids: required_query_ids(opts, expected, constraints, required_sets),
      required_credential_sets: required_sets,
      legacy?: Options.boolean!(opts, :legacy_scalar_values, false),
      max_presentations: Options.positive_integer!(opts, :max_presentations_per_query, @default_max_presentations)
    }
  end

  @spec validate_response(term(), policy()) :: :ok | {:error, term()}
  def validate_response(vp_token, policy) do
    with :ok <- validate_presentations(vp_token, policy.legacy?),
         :ok <- check_permitted_query_ids(vp_token, policy.permitted_ids),
         :ok <- check_required_query_ids(vp_token, policy.required_ids),
         :ok <- check_required_credential_sets(vp_token, policy.required_credential_sets),
         :ok <- check_empty_response(vp_token, policy.required_credential_sets) do
      check_presentation_counts(
        vp_token,
        policy.constraints,
        policy.legacy?,
        policy.max_presentations
      )
    end
  end

  defp query_constraints!(opts) do
    case Keyword.fetch(opts, :query_constraints) do
      :error ->
        %{}

      {:ok, constraints} when is_map(constraints) ->
        constraints

      {:ok, constraints} ->
        raise ArgumentError,
              "Attesto.VpToken :query_constraints must be a map of query ID to constraint; got #{inspect(constraints)}"
    end
  end

  defp required_credential_sets!(opts, constraints) do
    embedded = embedded_required_credential_sets!(constraints)

    case Keyword.fetch(opts, :required_credential_sets) do
      {:ok, required_sets} ->
        required_sets = validate_required_credential_sets!(required_sets)

        if embedded in [:absent, required_sets] do
          required_sets
        else
          raise ArgumentError, "Attesto.VpToken :required_credential_sets conflicts with :query_constraints"
        end

      :error ->
        embedded
    end
  end

  defp embedded_required_credential_sets!(constraints) do
    policies =
      constraints
      |> Map.values()
      |> Enum.flat_map(fn
        %{required_credential_sets: required_sets} -> [required_sets]
        %{"required_credential_sets" => required_sets} -> [required_sets]
        _constraint -> []
      end)
      |> Enum.uniq()

    case policies do
      [] -> :absent
      [required_sets] -> validate_required_credential_sets!(required_sets)
      _conflicting -> raise ArgumentError, "Attesto.VpToken constraints contain conflicting DCQL response policies"
    end
  end

  defp validate_required_credential_sets!(required_sets) when is_list(required_sets) do
    if Enum.all?(required_sets, &valid_required_credential_set?/1),
      do: required_sets,
      else: invalid_required_credential_sets!()
  end

  defp validate_required_credential_sets!(_required_sets), do: invalid_required_credential_sets!()

  defp valid_required_credential_set?(options) when is_list(options) and options != [] do
    Enum.all?(options, fn option ->
      is_list(option) and option != [] and Enum.all?(option, &(is_binary(&1) and &1 != "")) and
        Enum.uniq(option) == option
    end)
  end

  defp valid_required_credential_set?(_options), do: false

  defp invalid_required_credential_sets! do
    raise ArgumentError,
          "Attesto.VpToken :required_credential_sets must be a list of non-empty option lists " <>
            "containing non-empty credential-ID lists"
  end

  defp expected_query_ids!(opts) do
    case Keyword.fetch(opts, :expected_query_ids) do
      :error ->
        []

      {:ok, ids} when is_list(ids) ->
        if Enum.all?(ids, &(is_binary(&1) and &1 != "")) do
          ids
        else
          invalid_expected_query_ids!(ids)
        end

      {:ok, ids} ->
        invalid_expected_query_ids!(ids)
    end
  end

  defp invalid_expected_query_ids!(ids) do
    raise ArgumentError,
          "Attesto.VpToken :expected_query_ids must be a list of non-empty strings; got #{inspect(ids)}"
  end

  defp permitted_query_ids!(opts, expected, constraints, required_credential_sets) do
    requested = Enum.uniq(expected ++ Map.keys(constraints) ++ credential_set_ids(required_credential_sets))

    case Keyword.fetch(opts, :permitted_query_ids) do
      {:ok, ids} ->
        validate_permitted_query_ids!(ids, requested)

      :error ->
        if Keyword.has_key?(opts, :expected_query_ids) or Keyword.has_key?(opts, :query_constraints) or
             Keyword.has_key?(opts, :required_credential_sets),
           do: requested,
           else: :unrestricted
    end
  end

  defp credential_set_ids(:absent), do: []

  defp credential_set_ids(required_sets) do
    required_sets |> List.flatten() |> Enum.uniq()
  end

  defp validate_permitted_query_ids!(ids, requested) do
    if is_list(ids) and Enum.all?(ids, &(is_binary(&1) and &1 != "")) and Enum.uniq(ids) == ids and
         Enum.all?(requested, &(&1 in ids)) do
      ids
    else
      raise ArgumentError, ":permitted_query_ids must contain every required or constrained query ID"
    end
  end

  defp required_query_ids(opts, expected, constraints, required_credential_sets) do
    if Keyword.has_key?(opts, :expected_query_ids) or Keyword.has_key?(opts, :permitted_query_ids),
      do: expected,
      else: if(required_credential_sets == :absent, do: Map.keys(constraints), else: [])
  end

  defp check_permitted_query_ids(_vp_token, :unrestricted), do: :ok

  defp check_permitted_query_ids(vp_token, permitted) do
    vp_token
    |> Map.keys()
    |> Enum.reject(&(&1 in permitted))
    |> Enum.sort()
    |> case do
      [] -> :ok
      unexpected -> {:error, {:unexpected_query_ids, unexpected}}
    end
  end

  defp check_required_query_ids(vp_token, required) do
    case missing_query_ids(vp_token, required) do
      [] -> :ok
      missing -> {:error, {:missing_credentials, missing}}
    end
  end

  defp check_required_credential_sets(_vp_token, :absent), do: :ok

  defp check_required_credential_sets(vp_token, required_sets) do
    missing =
      required_sets
      |> Enum.with_index()
      |> Enum.reject(fn {options, _index} ->
        Enum.any?(options, fn option -> Enum.all?(option, &Map.has_key?(vp_token, &1)) end)
      end)
      |> Enum.map(&elem(&1, 1))

    if missing == [], do: :ok, else: {:error, {:unsatisfied_credential_sets, missing}}
  end

  defp check_empty_response(vp_token, :absent) when map_size(vp_token) == 0, do: {:error, :invalid_vp_token}

  defp check_empty_response(_vp_token, _required_credential_sets), do: :ok

  defp check_presentation_counts(vp_token, constraints, legacy?, max_presentations) do
    Enum.reduce_while(vp_token, :ok, fn {id, presentations}, :ok ->
      presentations
      |> presentation_count(legacy?)
      |> presentation_count_reduction(id, Map.get(constraints, id), max_presentations)
    end)
  end

  defp presentation_count_reduction(count, id, _constraint, max_presentations) when count > max_presentations,
    do: {:halt, {:error, {id, :too_many_presentations}}}

  defp presentation_count_reduction(count, id, constraint, _max_presentations) when count > 1 and is_map(constraint) do
    case multiple_presentations_allowed?(constraint) do
      true -> {:cont, :ok}
      false -> {:halt, {:error, {id, :multiple_presentations_not_allowed}}}
    end
  end

  defp presentation_count_reduction(_count, _id, _constraint, _max_presentations), do: {:cont, :ok}

  defp multiple_presentations_allowed?(constraint) do
    case {Map.fetch(constraint, :multiple), Map.fetch(constraint, "multiple")} do
      {{:ok, true}, :error} -> true
      {:error, {:ok, true}} -> true
      {{:ok, true}, {:ok, true}} -> true
      _absent_or_invalid -> false
    end
  end

  defp presentation_count(presentation, true) when is_binary(presentation), do: 1
  defp presentation_count(presentations, _legacy?) when is_list(presentations), do: length(presentations)

  defp validate_presentations(vp_token, legacy?) when is_map(vp_token) and not is_struct(vp_token) do
    if Enum.all?(vp_token, fn {id, value} ->
         is_binary(id) and id != "" and valid_presentation?(value, legacy?)
       end),
       do: :ok,
       else: {:error, :invalid_vp_token}
  end

  defp validate_presentations(_vp_token, _legacy?), do: {:error, :invalid_vp_token}

  defp valid_presentation?(presentation, true) when is_binary(presentation) and presentation != "", do: true

  defp valid_presentation?(presentations, _legacy?) when is_list(presentations) and presentations != [] do
    Enum.all?(presentations, &(is_binary(&1) and &1 != ""))
  end

  defp valid_presentation?(_presentation, _legacy?), do: false

  defp missing_query_ids(_vp_token, []), do: []
  defp missing_query_ids(vp_token, expected_query_ids), do: Enum.reject(expected_query_ids, &Map.has_key?(vp_token, &1))
end
