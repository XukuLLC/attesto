defmodule Attesto.RevocationCriteria do
  @moduledoc """
  The criteria a store uses to select authorization codes or refresh-token
  families for bulk removal: `Attesto.CodeStore.delete_unconsumed/1` and
  `Attesto.RefreshStore.revoke_families/1`.

  Criteria are a keyword list with at least one of:

    * `:subject` - the resource owner the grant was issued for.
    * `:client_id` - the client the grant was issued to.
    * `:sid` - the session identifier recorded in the grant's claims.

  Every key given must match (they are ANDed), so
  `[subject: "u1", client_id: "c1"]` selects only that subject's grants to that
  client.

  `:sid_claim` names the member of the stored `:claims` object that holds the
  session identifier. It defaults to `"sid"` and has an effect only with
  `:sid`; an integration that records the session under another key passes
  that key.

  This module is the one definition of both the validation and the match, so
  every store, in memory or SQL, selects the same grants for the same
  criteria.
  """

  @keys [:subject, :client_id, :sid]
  @default_sid_claim "sid"

  @type criteria :: [
          {:subject, String.t()} | {:client_id, String.t()} | {:sid, String.t()} | {:sid_claim, String.t()}
        ]

  @type t :: %{
          subject: String.t() | nil,
          client_id: String.t() | nil,
          sid: String.t() | nil,
          sid_claim: String.t()
        }

  @doc """
  Validate `criteria` and return them as a map with every key present (`nil`
  for a key that was not given).

  Raises `ArgumentError` for an empty selection, an unknown key, a repeated
  key, or a value that is not a non-empty string. An empty selection is
  refused so a caller's bug cannot remove every grant in the store.
  """
  @spec new!(criteria()) :: t()
  def new!(criteria) when is_list(criteria) do
    if !Keyword.keyword?(criteria), do: invalid!(criteria)

    keys = Keyword.keys(criteria)

    cond do
      keys -- [:sid_claim | @keys] != [] -> invalid!(criteria)
      keys != Enum.uniq(keys) -> invalid!(criteria)
      not Enum.any?(@keys, &Keyword.has_key?(criteria, &1)) -> invalid!(criteria)
      not Enum.all?(criteria, fn {_key, value} -> is_binary(value) and value != "" end) -> invalid!(criteria)
      true -> :ok
    end

    %{
      subject: Keyword.get(criteria, :subject),
      client_id: Keyword.get(criteria, :client_id),
      sid: Keyword.get(criteria, :sid),
      sid_claim: Keyword.get(criteria, :sid_claim, @default_sid_claim)
    }
  end

  def new!(criteria), do: invalid!(criteria)

  @doc """
  Whether a stored grant context matches `criteria` (from `new!/1`).

  `data` is the canonical `:data` map of a code or refresh-token record: its
  `:subject`, `:client_id` and `:claims`.
  """
  @spec match?(t(), map()) :: boolean()
  def match?(%{subject: subject, client_id: client_id, sid: sid, sid_claim: sid_claim}, data) when is_map(data) do
    matches?(subject, Map.get(data, :subject)) and
      matches?(client_id, Map.get(data, :client_id)) and
      matches?(sid, session_id(data, sid_claim))
  end

  defp matches?(nil, _stored), do: true
  defp matches?(wanted, stored), do: wanted == stored

  defp session_id(data, sid_claim) do
    case Map.get(data, :claims) do
      %{} = claims -> Map.get(claims, sid_claim)
      _ -> nil
    end
  end

  defp invalid!(criteria) do
    raise ArgumentError,
          "revocation criteria must be a keyword list with at least one of :subject, :client_id or :sid " <>
            "(optionally :sid_claim), each a non-empty string and given once; got #{inspect(criteria)}"
  end
end
