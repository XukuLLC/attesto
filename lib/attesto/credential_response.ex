defmodule Attesto.CredentialResponse do
  @moduledoc """
  OID4VCI Credential Response (`draft-ietf-oauth-openid4vci` §8.3).

  Build the string-keyed response body returned by a credential endpoint. This
  module is pure and conn-free; credential issuance is the caller's concern.
  """

  @doc """
  Build an immediate issuance response.

  A bare credential value is wrapped in a one-element list. A list of values
  is emitted in the same order, with each value under a `"credential"` key.
  """
  @spec build(term(), keyword()) :: %{required(String.t()) => term()}
  def build(credentials, opts \\ []) do
    opts = ensure_keyword!(opts)
    credentials = normalize_credentials!(credentials)

    %{"credentials" => Enum.map(credentials, &%{"credential" => &1})}
    |> put_optional("notification_id", Keyword.get(opts, :notification_id))
  end

  @doc "Build a deferred issuance response."
  @spec deferred(term(), keyword()) :: %{required(String.t()) => term()}
  def deferred(transaction_id, opts \\ []) do
    opts = ensure_keyword!(opts)

    %{"transaction_id" => required_string!(transaction_id, :transaction_id)}
    |> put_optional("notification_id", Keyword.get(opts, :notification_id))
  end

  defp ensure_keyword!(opts) do
    if Keyword.keyword?(opts) do
      opts
    else
      raise ArgumentError,
            "Attesto.CredentialResponse options must be a keyword list; got #{inspect(opts)}"
    end
  end

  defp normalize_credentials!(credentials) when is_list(credentials) and credentials != [], do: credentials

  defp normalize_credentials!([]) do
    raise ArgumentError, "Attesto.CredentialResponse credentials must be non-empty"
  end

  defp normalize_credentials!(credential), do: [credential]

  defp required_string!(value, _key) when is_binary(value) and value != "", do: value

  defp required_string!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialResponse :#{key} must be a non-empty string; got #{inspect(value)}"
  end

  defp put_optional(map, _key, nil), do: map

  defp put_optional(map, key, value), do: Map.put(map, key, optional_string!(value, key))

  defp optional_string!(value, _key) when is_binary(value) and value != "", do: value

  defp optional_string!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialResponse :#{key} must be a non-empty string; got #{inspect(value)}"
  end
end
