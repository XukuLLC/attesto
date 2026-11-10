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
  alias Attesto.Options

  @default_max_chain_length 10

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
  `:max_chain_length` bounds signature-verification work and defaults to 10.
  """
  @spec validate([String.t()], map() | [map()], keyword()) ::
          {:ok, result()} | {:error, validation_error()}
  def validate(chain, trust_anchor_jwks, opts \\ [])

  def validate([_ | _] = chain, trust_anchor_jwks, opts) when is_list(opts) do
    max_chain_length = max_chain_length!(opts)

    with true <- length(chain) <= max_chain_length,
         true <- Enum.all?(chain, &is_binary/1),
         {:ok, claims} <- verify_from_anchor(chain, trust_anchor_jwks, opts),
         :ok <- reject_entity_cycles(claims),
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

  defp max_chain_length!(opts), do: Options.positive_integer!(opts, :max_chain_length, @default_max_chain_length)

  defp reject_entity_cycles(claims) do
    issuers = Enum.map(claims, &Map.get(&1, "iss"))
    if Enum.uniq(issuers) == issuers, do: :ok, else: {:error, :broken_trust_chain}
  end

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
    case Map.get(leaf, "authority_hints") do
      [_ | _] = hints ->
        if Map.get(immediate_superior, "iss") in hints,
          do: :ok,
          else: {:error, :broken_trust_chain}

      _missing_or_invalid ->
        {:error, :broken_trust_chain}
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

  defp enforce_constraints(all_claims, metadata) do
    all_claims
    |> Enum.with_index()
    |> Enum.drop(1)
    |> Enum.reduce_while({:ok, metadata}, fn {statement_claims, index}, {:ok, current_metadata} ->
      subordinate_entity_ids =
        all_claims
        |> Enum.slice(1, index)
        |> Enum.map(&Map.fetch!(&1, "sub"))

      case apply_constraints(
             Map.get(statement_claims, "constraints"),
             index - 1,
             subordinate_entity_ids,
             current_metadata
           ) do
        {:ok, constrained} -> {:cont, {:ok, constrained}}
        {:error, :constraint_violation} = error -> {:halt, error}
      end
    end)
  end

  defp apply_constraints(nil, _intermediates_below, _subordinate_entity_ids, metadata), do: {:ok, metadata}

  defp apply_constraints(constraints, intermediates_below, subordinate_entity_ids, metadata) when is_map(constraints) do
    with :ok <- check_max_path_length(constraint(constraints, "max_path_length"), intermediates_below),
         :ok <- check_naming_constraints(constraint(constraints, "naming_constraints"), subordinate_entity_ids) do
      filter_allowed_entity_types(constraint(constraints, "allowed_entity_types"), metadata)
    end
  end

  defp apply_constraints(_constraints, _intermediates_below, _subordinate_entity_ids, _metadata),
    do: {:error, :constraint_violation}

  # An omitted constraint member places no restriction. A member present with a
  # JSON null is malformed, not omitted: it maps to `:null`, which every
  # constraint check refuses, whichever JSON backend decoded the statement.
  defp constraint(constraints, name) do
    case Map.fetch(constraints, name) do
      :error -> nil
      {:ok, nil} -> :null
      {:ok, value} -> value
    end
  end

  defp check_max_path_length(nil, _intermediates_below), do: :ok

  defp check_max_path_length(maximum, intermediates_below)
       when is_integer(maximum) and maximum >= 0 and intermediates_below <= maximum, do: :ok

  defp check_max_path_length(_maximum, _intermediates_below), do: {:error, :constraint_violation}

  defp check_naming_constraints(nil, _entity_ids), do: :ok

  defp check_naming_constraints(constraints, entity_ids) when is_map(constraints) do
    with true <- map_size(constraints) > 0,
         true <- Enum.all?(Map.keys(constraints), &(&1 in ["permitted", "excluded"])),
         {:ok, permitted} <- domain_constraints(constraints, "permitted"),
         {:ok, excluded} <- domain_constraints(constraints, "excluded"),
         true <- Enum.all?(entity_ids, &entity_identifier_permitted?(&1, permitted, excluded)) do
      :ok
    else
      _other -> {:error, :constraint_violation}
    end
  end

  defp check_naming_constraints(_constraints, _entity_ids), do: {:error, :constraint_violation}

  defp domain_constraints(constraints, member) do
    case Map.fetch(constraints, member) do
      :error ->
        {:ok, nil}

      {:ok, [_ | _] = values} ->
        if Enum.all?(values, &valid_domain_constraint?/1),
          do: {:ok, Enum.map(values, &(&1 |> String.downcase() |> String.trim_trailing(".")))},
          else: {:error, :constraint_violation}

      {:ok, _invalid} ->
        {:error, :constraint_violation}
    end
  end

  defp valid_domain_constraint?(constraint) when is_binary(constraint) and constraint != "" do
    domain =
      case constraint do
        "." <> suffix -> suffix
        exact -> exact
      end

    byte_size(domain) <= 253 and domain != "" and not String.ends_with?(domain, ".") and
      domain
      |> String.split(".")
      |> Enum.all?(&valid_domain_label?/1)
  end

  defp valid_domain_constraint?(_constraint), do: false

  defp valid_domain_label?(label) when byte_size(label) in 1..63 do
    String.match?(label, ~r/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/)
  end

  defp valid_domain_label?(_label), do: false

  # The host is compared case-folded and without a trailing dot, so
  # `https://le.bad.test.` cannot step around an `excluded` entry for
  # `.bad.test` (DNS treats the two names as one).
  #
  # The host must also be a DNS name made of LDH labels, the syntax the
  # constraints themselves are held to. `URI.parse/1` leaves percent-encoding
  # in the host, so `https://leaf.bad%2eexample` would compare as a name
  # outside `.bad.example` while HTTP clients resolve it to
  # `leaf.bad.example`, and `https://evil.test%2F.good.example` would match
  # `.good.example` by suffix alone. A host that is not an LDH name therefore
  # satisfies no naming constraint, permitted or excluded.
  defp entity_identifier_permitted?(entity_id, permitted, excluded) do
    with %URI{host: host} when is_binary(host) <- URI.parse(entity_id),
         host = host |> String.downcase() |> String.trim_trailing("."),
         true <- dns_name?(host) do
      permitted? = is_nil(permitted) or Enum.any?(permitted, &domain_constraint_matches?(host, &1))
      excluded? = not is_nil(excluded) and Enum.any?(excluded, &domain_constraint_matches?(host, &1))
      permitted? and not excluded?
    else
      _other -> false
    end
  end

  defp dns_name?(host) do
    host != "" and byte_size(host) <= 253 and host |> String.split(".") |> Enum.all?(&valid_domain_label?/1)
  end

  defp domain_constraint_matches?(host, "." <> domain), do: String.ends_with?(host, "." <> domain)
  defp domain_constraint_matches?(host, domain), do: host == domain

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
