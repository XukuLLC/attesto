defmodule Attesto.Claims do
  @moduledoc """
  Shared mechanics for claim-key normalization and registered-claim merging.

  Protocol modules retain ownership of their registered-claim policy. This
  module only makes the map-key boundary explicit before a claim map is
  serialized or merged.
  """

  @type atom_policy :: :reject | :convert
  @type normalize_error :: {:invalid_key, term()} | :invalid_atom_policy

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
end
