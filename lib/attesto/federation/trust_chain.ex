defmodule Attesto.Federation.TrustChain do
  @moduledoc """
  Validate an already-resolved OpenID Federation 1.0 Trust Chain.

  The input is ordered leaf first: the leaf Entity Configuration followed by
  Subordinate Statements issued successively toward the Trust Anchor. The
  final statement is verified with the Trust Anchor keys supplied out of band.
  Fetching Entity Statements and choosing among candidate chains remain host
  responsibilities.
  """

  alias Attesto.Federation.{EntityStatement, MetadataPolicy}

  @type result :: %{
          metadata: map(),
          trust_anchor: String.t(),
          exp: non_neg_integer()
        }

  @type validation_error ::
          EntityStatement.verify_error()
          | :invalid_trust_chain
          | :broken_trust_chain
          | :constraint_violation
          | :policy_error

  @doc """
  Validate signatures, statement links, time bounds, constraints, and policy.

  `:now`, `:leeway`, and `:accepted_algs` are passed to Entity Statement
  verification. `:trust_anchor` optionally pins the expected Trust Anchor
  Entity Identifier in addition to the out-of-band key pin.
  """
  @spec validate([String.t()], map() | [map()], keyword()) ::
          {:ok, result()} | {:error, validation_error()}
  def validate(chain, trust_anchor_jwks, opts \\ [])

  def validate([_ | _] = chain, trust_anchor_jwks, opts) when is_list(opts) do
    with true <- Enum.all?(chain, &is_binary/1),
         {:ok, claims} <- verify_from_anchor(chain, trust_anchor_jwks, opts),
         :ok <- verify_leaf_self_signature(hd(chain), hd(claims), opts),
         :ok <- validate_statement_roles(claims),
         :ok <- validate_links(claims),
         :ok <- validate_authority_hint(claims),
         {:ok, trust_anchor} <- validate_trust_anchor(claims, opts),
         {:ok, metadata} <- resolve_metadata(claims),
         {:ok, metadata} <- enforce_constraints(claims, metadata),
         {:ok, metadata} <- resolve_and_apply_policy(claims, metadata) do
      {:ok,
       %{
         metadata: metadata,
         trust_anchor: trust_anchor,
         exp: claims |> Enum.map(&Map.fetch!(&1, "exp")) |> Enum.min()
       }}
    else
      false -> {:error, :invalid_trust_chain}
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_trust_chain}
    end
  end

  def validate(_chain, _trust_anchor_jwks, _opts), do: {:error, :invalid_trust_chain}

  # Start at the only out-of-band trust point and work down. Each successfully
  # verified statement supplies the subject keys used for the next statement.
  defp verify_from_anchor(chain, trust_anchor_jwks, opts) do
    statement_opts = statement_opts(opts)
    last_index = length(chain) - 1

    with {:ok, anchor_statement} <-
           chain |> Enum.at(last_index) |> EntityStatement.verify(trust_anchor_jwks, statement_opts) do
      verify_toward_leaf(chain, last_index - 1, anchor_statement, [anchor_statement], statement_opts)
    end
  end

  defp verify_toward_leaf(_chain, -1, _upper_claims, verified, _opts), do: {:ok, verified}

  defp verify_toward_leaf(chain, index, upper_claims, verified, opts) do
    with %{"keys" => [_ | _]} = subject_jwks <- Map.get(upper_claims, "jwks"),
         {:ok, claims} <- chain |> Enum.at(index) |> EntityStatement.verify(subject_jwks, opts) do
      verify_toward_leaf(chain, index - 1, claims, [claims | verified], opts)
    else
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_trust_chain}
    end
  end

  defp verify_leaf_self_signature(jwt, linked_claims, opts) do
    case EntityStatement.verify_self_signed(jwt, statement_opts(opts)) do
      {:ok, ^linked_claims} -> :ok
      {:ok, _different_claims} -> {:error, :invalid_trust_chain}
      {:error, _reason} = error -> error
    end
  end

  defp statement_opts(opts), do: Keyword.take(opts, [:now, :leeway, :accepted_algs])

  defp validate_statement_roles([%{"iss" => entity, "sub" => entity} | subordinate_statements]) do
    if Enum.all?(subordinate_statements, fn
         %{"iss" => issuer, "sub" => subject} -> issuer != subject
         _claims -> false
       end),
       do: :ok,
       else: {:error, :broken_trust_chain}
  end

  defp validate_statement_roles(_claims), do: {:error, :broken_trust_chain}

  defp validate_links([_single]), do: :ok

  defp validate_links(claims) do
    claims
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.all?(fn [lower, upper] -> Map.get(lower, "iss") == Map.get(upper, "sub") end)
    |> link_result()
  end

  defp link_result(true), do: :ok
  defp link_result(false), do: {:error, :broken_trust_chain}

  defp validate_authority_hint([_single]), do: :ok

  defp validate_authority_hint([leaf, immediate_superior | _rest]) do
    case Map.fetch(leaf, "authority_hints") do
      :error ->
        :ok

      {:ok, hints} ->
        if Map.get(immediate_superior, "iss") in hints,
          do: :ok,
          else: {:error, :broken_trust_chain}
    end
  end

  defp validate_trust_anchor(claims, opts) do
    trust_anchor = claims |> List.last() |> Map.get("iss")

    case Keyword.get(opts, :trust_anchor) do
      nil -> {:ok, trust_anchor}
      ^trust_anchor -> {:ok, trust_anchor}
      _other -> {:error, :broken_trust_chain}
    end
  end

  defp resolve_metadata([leaf | subordinate_statements]) do
    metadata = Map.get(leaf, "metadata", %{})

    case subordinate_statements do
      [immediate_superior | _rest] -> apply_superior_metadata(metadata, Map.get(immediate_superior, "metadata", %{}))
      [] -> {:ok, metadata}
    end
  end

  # A direct superior may override individual parameters, but only for Entity
  # Types that the subject declared in its own Entity Configuration.
  defp apply_superior_metadata(metadata, superior_metadata) when is_map(metadata) and is_map(superior_metadata) do
    resolved =
      Enum.reduce(metadata, %{}, fn {entity_type, type_metadata}, acc ->
        overrides = Map.get(superior_metadata, entity_type, %{})
        Map.put(acc, entity_type, Map.merge(type_metadata, overrides))
      end)

    {:ok, resolved}
  rescue
    _ -> {:error, :invalid_trust_chain}
  end

  defp apply_superior_metadata(_metadata, _superior_metadata), do: {:error, :invalid_trust_chain}

  defp enforce_constraints(claims, metadata) do
    claims
    |> Enum.with_index()
    |> Enum.drop(1)
    |> Enum.reduce_while({:ok, metadata}, fn {claims, index}, {:ok, current_metadata} ->
      case apply_constraints(Map.get(claims, "constraints"), index - 1, current_metadata) do
        {:ok, constrained} -> {:cont, {:ok, constrained}}
        {:error, :constraint_violation} = error -> {:halt, error}
      end
    end)
  end

  defp apply_constraints(nil, _intermediates_below, metadata), do: {:ok, metadata}

  defp apply_constraints(constraints, intermediates_below, metadata) when is_map(constraints) do
    with :ok <- check_max_path_length(Map.get(constraints, "max_path_length"), intermediates_below) do
      filter_allowed_entity_types(Map.get(constraints, "allowed_entity_types"), metadata)
    end
  end

  defp apply_constraints(_constraints, _intermediates_below, _metadata), do: {:error, :constraint_violation}

  defp check_max_path_length(nil, _intermediates_below), do: :ok

  defp check_max_path_length(maximum, intermediates_below)
       when is_integer(maximum) and maximum >= 0 and intermediates_below <= maximum, do: :ok

  defp check_max_path_length(_maximum, _intermediates_below), do: {:error, :constraint_violation}

  defp filter_allowed_entity_types(nil, metadata), do: {:ok, metadata}

  defp filter_allowed_entity_types(allowed, metadata) when is_list(allowed) do
    valid? =
      Enum.all?(allowed, &(is_binary(&1) and &1 != "" and &1 != "federation_entity")) and
        length(allowed) == length(Enum.uniq(allowed))

    if valid? do
      constrained =
        Map.filter(metadata, fn {entity_type, _type_metadata} ->
          entity_type == "federation_entity" or entity_type in allowed
        end)

      {:ok, constrained}
    else
      {:error, :constraint_violation}
    end
  end

  defp filter_allowed_entity_types(_allowed, _metadata), do: {:error, :constraint_violation}

  defp resolve_and_apply_policy([_leaf | subordinate_statements], metadata) do
    subordinate_statements
    |> Enum.reverse()
    |> Enum.reduce_while({:ok, %{}}, fn claims, {:ok, current_policy} ->
      merge_statement_policy(Map.fetch(claims, "metadata_policy"), current_policy)
    end)
    |> apply_resolved_policy(metadata)
  end

  defp merge_statement_policy(:error, current_policy), do: {:cont, {:ok, current_policy}}

  defp merge_statement_policy({:ok, lower_policy}, current_policy) do
    case MetadataPolicy.merge(current_policy, lower_policy) do
      {:ok, merged} -> {:cont, {:ok, merged}}
      {:error, :policy_error} = error -> {:halt, error}
    end
  end

  defp apply_resolved_policy({:ok, policy}, metadata), do: MetadataPolicy.apply(policy, metadata)
  defp apply_resolved_policy({:error, :policy_error} = error, _metadata), do: error
end
