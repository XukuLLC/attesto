defmodule Attesto.Claims do
  @moduledoc """
  Shared mechanics for portable persisted claims, claim-key normalization,
  and registered-claim merging.

  Protocol modules retain ownership of their registered-claim policy. This
  module defines the lossless persisted-JSON boundary used by grant stores and
  makes map-key handling explicit before claims are serialized or merged.
  """

  @type atom_policy :: :reject | :convert
  @type normalize_error :: {:invalid_key, term()} | :invalid_atom_policy
  @type audience_mode :: :scalar_only | :array | :single_element | :all_array_members
  @max_exact_integer 9_007_199_254_740_991
  @max_portable_json_depth 64

  @doc """
  Return whether `value` is a portable, lossless JSON object for persisted
  grant context.

  Objects must have string keys and values must be the lossless I-JSON subset:
  strings, booleans, `nil`, exact-range integers, arrays, or nested objects.
  Floats are rejected because JSONB can canonicalize them, and integers are
  limited to `-(2^53)+1 .. (2^53)-1` (RFC 7493 §2.2). Strings must be valid
  UTF-8 and cannot contain U+0000, which PostgreSQL JSONB cannot store.
  Other Elixir atoms (including atom keys), tuples, structs, PIDs, references,
  and other VM terms are rejected. This predicate deliberately does not
  normalize or copy values, so callers can use it before persisting a context
  that must round-trip unchanged. Composite nesting depth is capped at 64,
  counting the root object as depth 1, to keep JSONB operations within
  PostgreSQL's stack limits.
  """
  @spec portable_json_object?(term()) :: boolean()
  def portable_json_object?(value) when is_map(value), do: portable_json_object?(value, 1)

  def portable_json_object?(_value), do: false

  defp portable_json_value?(nil, _depth), do: true
  defp portable_json_value?(value, _depth) when is_boolean(value), do: true

  defp portable_json_value?(value, _depth) when is_integer(value),
    do: value >= -@max_exact_integer and value <= @max_exact_integer

  defp portable_json_value?(value, _depth) when is_float(value), do: false
  defp portable_json_value?(value, _depth) when is_binary(value), do: portable_json_string?(value)
  defp portable_json_value?(value, depth) when is_list(value), do: portable_json_array?(value, depth + 1)
  defp portable_json_value?(value, depth) when is_map(value), do: portable_json_object?(value, depth + 1)
  defp portable_json_value?(_value, _depth), do: false

  defp portable_json_string?(value) do
    is_binary(value) and String.valid?(value) and not String.contains?(value, <<0>>)
  end

  defp portable_json_array?(value, depth) when is_list(value) and depth <= @max_portable_json_depth,
    do: portable_json_array_tail?(value, depth)

  defp portable_json_array?(_value, _depth), do: false

  defp portable_json_array_tail?([], _depth), do: true

  defp portable_json_array_tail?([head | tail], depth),
    do: portable_json_value?(head, depth) and portable_json_array_tail?(tail, depth)

  defp portable_json_array_tail?(_improper_tail, _depth), do: false

  defp portable_json_object?(value, depth) when is_map(value) and depth <= @max_portable_json_depth do
    Enum.all?(value, fn {key, member} -> portable_json_string?(key) and portable_json_value?(member, depth) end)
  end

  defp portable_json_object?(_value, _depth), do: false

  @doc """
  Normalize the keys in `map` to JSON member-name binaries.

  With `atoms: :reject` (the default), every key must already be a binary.
  With `atoms: :convert`, atom keys are converted with `Atom.to_string/1`;
  all other non-binary keys are rejected.
  """
  @spec normalize_keys(map(), keyword()) :: {:ok, map()} | {:error, normalize_error()}
  def normalize_keys(map, opts \\ []) when is_map(map) and is_list(opts) do
    case Keyword.get(opts, :atoms, :reject) do
      policy when policy in [:reject, :convert] ->
        normalize_entries(map, policy)

      _other ->
        {:error, :invalid_atom_policy}
    end
  end

  @doc """
  Merge caller-supplied claims into authoritative `registered` claims.

  The caller map is normalized first. Keys in `reserved` are rejected before
  the merge; by default every key already present in `registered` is reserved.
  `atom_keys` is passed to `normalize_keys/2` as its `:atoms` policy.
  """
  @spec merge_registered(map(), map(), keyword()) ::
          {:ok, map()} | {:error, normalize_error() | :reserved_claim_conflict}
  def merge_registered(extra, registered, opts \\ []) when is_map(extra) and is_map(registered) and is_list(opts) do
    reserved = Keyword.get(opts, :reserved, Map.keys(registered))
    atom_policy = Keyword.get(opts, :atom_keys, :reject)

    with {:ok, normalized_extra} <- normalize_keys(extra, atoms: atom_policy),
         :ok <- reject_reserved(normalized_extra, reserved) do
      {:ok, Map.merge(registered, normalized_extra)}
    end
  end

  @doc """
  Compare an audience claim with an expected audience under an explicit
  protocol mode.

  The caller must select the mode because audience forms are protocol policy,
  not a single shared rule:

    * `:scalar_only` accepts only a binary claim.
    * `:array` accepts a binary claim or a non-empty all-binary array with
      intersection semantics.
    * `:single_element` accepts a scalar or exactly `[expected]`.
    * `:all_array_members` requires every member of an array to be expected.

  This is a value-level predicate; callers retain responsibility for error
  mapping and any surrounding claim validation.
  """
  @spec audience_matches?(term(), term(), audience_mode()) :: boolean()
  def audience_matches?(aud, expected, :scalar_only) when is_binary(aud) and (is_binary(expected) or is_list(expected)),
    do: aud == expected or (is_list(expected) and aud in expected)

  def audience_matches?(aud, expected, :single_element) when is_binary(expected),
    do: aud == expected or aud == [expected]

  def audience_matches?(aud, expected, :array) when is_binary(expected), do: audience_matches_array?(aud, [expected])

  def audience_matches?(aud, expected, :array) when is_list(expected), do: audience_matches_array?(aud, expected)

  def audience_matches?(aud, expected, :all_array_members) when is_list(expected),
    do: audience_matches_all_array_members?(aud, expected)

  def audience_matches?(_aud, _expected, _mode), do: false

  @doc """
  Match a JOSE `typ` value against an explicit accepted set using the
  RFC 7515 `application/` bare-subtype convention.

  The normalization option is intentionally required. Callers with exact or
  otherwise protocol-specific type rules must keep those rules local.
  """
  @spec typ_matches?(term(), [String.t() | nil], keyword()) :: boolean()
  def typ_matches?(typ, accepted, opts) when is_list(accepted) and is_list(opts) do
    case Keyword.get(opts, :normalization) do
      :application_subtype -> typ_matches_application_subtype?(typ, accepted)
      _ -> false
    end
  end

  def typ_matches?(_typ, _accepted, _opts), do: false

  defp normalize_key(key, _policy) when is_binary(key), do: {:ok, key}
  defp normalize_key(key, :convert) when is_atom(key), do: {:ok, Atom.to_string(key)}
  defp normalize_key(key, _policy), do: {:error, {:invalid_key, key}}

  defp normalize_entries(map, policy) do
    Enum.reduce_while(map, {:ok, %{}}, &normalize_entry(&1, &2, policy))
  end

  defp normalize_entry({key, value}, {:ok, normalized}, policy) do
    case normalize_key(key, policy) do
      {:ok, normalized_key} -> {:cont, {:ok, Map.put(normalized, normalized_key, value)}}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp reject_reserved(map, reserved) do
    if Enum.any?(Map.keys(map), &(&1 in reserved)),
      do: {:error, :reserved_claim_conflict},
      else: :ok
  end

  defp audience_matches_array?(aud, expected) when is_binary(aud), do: aud in expected

  defp audience_matches_array?([_ | _] = aud, expected) do
    Enum.all?(aud, &is_binary/1) and Enum.any?(aud, &(&1 in expected))
  end

  defp audience_matches_array?(_aud, _expected), do: false

  defp audience_matches_all_array_members?(aud, expected) when is_binary(aud), do: aud in expected

  defp audience_matches_all_array_members?([_ | _] = aud, expected) do
    Enum.all?(aud, &(is_binary(&1) and &1 in expected))
  end

  defp audience_matches_all_array_members?(_aud, _expected), do: false

  defp typ_matches_application_subtype?(nil, accepted), do: Enum.member?(accepted, nil)

  defp typ_matches_application_subtype?(typ, accepted) when is_binary(typ) do
    normalized = normalize_application_subtype(typ)

    Enum.any?(accepted, fn candidate ->
      is_binary(candidate) and normalize_application_subtype(candidate) == normalized
    end)
  end

  defp typ_matches_application_subtype?(_typ, _accepted), do: false

  defp normalize_application_subtype(typ) do
    case String.downcase(typ) do
      "application/" <> rest = full ->
        if String.contains?(rest, "/"), do: full, else: rest

      down ->
        down
    end
  end
end
