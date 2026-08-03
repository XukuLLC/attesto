defmodule Attesto.CredentialResponse do
  @moduledoc """
  OID4VCI Credential Response (`draft-ietf-oauth-openid4vci` §8.3).

  Build the string-keyed response body returned by a credential endpoint. This
  module is pure and conn-free; credential issuance is the caller's concern.
  """

  alias Attesto.MapParams

  @doc """
  Build an immediate issuance response.

  A bare credential value is wrapped in a one-element list. A list of values
  is emitted in the same order, with each value under a `"credential"` key.
  """
  @spec build(term(), keyword()) :: %{required(String.t()) => term()}
  def build(credentials, opts \\ []) do
    opts = MapParams.ensure_keyword!(opts)
    credentials = normalize_credentials!(credentials)

    %{"credentials" => Enum.map(credentials, &%{"credential" => &1})}
    |> MapParams.put_optional("notification_id", Keyword.get(opts, :notification_id), &MapParams.optional_string!/2)
  end

  @doc "Build a deferred issuance response."
  @spec deferred(term(), keyword()) :: %{required(String.t()) => term()}
  def deferred(transaction_id, opts \\ []) do
    opts = MapParams.ensure_keyword!(opts)

    %{"transaction_id" => MapParams.required_string!(transaction_id, :transaction_id)}
    |> MapParams.put_optional("notification_id", Keyword.get(opts, :notification_id), &MapParams.optional_string!/2)
  end

  defp normalize_credentials!(credentials) when is_list(credentials) and credentials != [], do: credentials

  defp normalize_credentials!([]) do
    raise ArgumentError, "Attesto.CredentialResponse credentials must be non-empty"
  end

  defp normalize_credentials!(credential), do: [credential]
end
