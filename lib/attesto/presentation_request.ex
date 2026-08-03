defmodule Attesto.PresentationRequest do
  @moduledoc """
  OID4VP Authorization Request (`draft-ietf-oauth-openid4vp` §5).

  Build a string-keyed, JSON-ready request for a wallet and its DCQL query.
  This module is pure and conn-free; sending the request is the host's
  concern.
  """

  alias Attesto.MapParams

  @default_response_mode "direct_post"
  @response_modes ["direct_post", "direct_post.jwt"]

  @doc """
  Build an OID4VP Authorization Request.

  The request requires a client identifier, nonce, response URI, and a DCQL
  query. Optional values are included only when supplied with a non-`nil`
  value.
  """
  @spec build(keyword()) :: %{required(String.t()) => term()}
  def build(opts) when is_list(opts) do
    opts = MapParams.ensure_keyword!(opts)

    %{
      "client_id" => MapParams.required_string!(Keyword.get(opts, :client_id), :client_id),
      "nonce" => MapParams.required_string!(Keyword.get(opts, :nonce), :nonce),
      "response_uri" => MapParams.required_string!(Keyword.get(opts, :response_uri), :response_uri),
      "response_type" => "vp_token",
      "response_mode" => response_mode!(Keyword.get(opts, :response_mode, @default_response_mode)),
      "dcql_query" => required_dcql_query!(opts, :dcql_query)
    }
    |> MapParams.put_optional("state", Keyword.get(opts, :state), &MapParams.optional_string!/2)
    |> MapParams.put_optional("client_metadata", Keyword.get(opts, :client_metadata), &map!/2)
    |> MapParams.put_optional("client_id_scheme", Keyword.get(opts, :client_id_scheme), &MapParams.optional_string!/2)
  end

  def build(opts) when not is_list(opts) do
    raise ArgumentError, "expects a keyword list; got #{inspect(opts)}"
  end

  @doc "Build a DCQL query object."
  @spec dcql_query(keyword() | map()) :: %{required(String.t()) => term()}
  def dcql_query(opts) when is_list(opts) do
    opts = MapParams.ensure_keyword!(opts)
    opts |> Map.new() |> normalize_dcql_query!()
  end

  def dcql_query(opts) when is_map(opts), do: normalize_dcql_query!(opts)

  def dcql_query(opts) do
    raise ArgumentError,
          "Attesto.PresentationRequest.dcql_query/1 expects a keyword list or map; got #{inspect(opts)}"
  end

  @doc """
  Encode an Authorization Request as an `application/x-www-form-urlencoded`
  query string.
  """
  @spec to_query_string(map()) :: String.t()
  def to_query_string(params) when is_map(params) do
    params
    |> encode_json_member("dcql_query")
    |> encode_json_member("client_metadata")
    |> URI.encode_query()
  end

  def to_query_string(params) do
    raise ArgumentError,
          "Attesto.PresentationRequest.to_query_string/1 expects a map; got #{inspect(params)}"
  end

  defp required_dcql_query!(opts, key) do
    case Keyword.get(opts, key) do
      value when is_map(value) -> normalize_dcql_query!(value)
      value -> raise ArgumentError, "Attesto.PresentationRequest :#{key} must be a map; got #{inspect(value)}"
    end
  end

  defp response_mode!(value) when value in @response_modes, do: value

  defp response_mode!(value) do
    raise ArgumentError,
          ~s(Attesto.PresentationRequest :response_mode must be "direct_post" or "direct_post.jwt"; ) <>
            "got #{inspect(value)}"
  end

  defp normalize_dcql_query!(value) when is_map(value) do
    %{
      "credentials" => credentials!(MapParams.fetch(value, :credentials), :credentials)
    }
    |> MapParams.put_optional(
      "credential_sets",
      MapParams.fetch(value, :credential_sets),
      &credential_sets!/2
    )
  end

  defp normalize_dcql_query!(value) do
    raise ArgumentError,
          "Attesto.PresentationRequest :dcql_query must be a map; got #{inspect(value)}"
  end

  defp credentials!(value, key) when is_list(value) and value != [] do
    if Enum.all?(value, &is_map/1) do
      credentials = Enum.map(value, &normalize_credential_query!/1)
      ids = Enum.map(credentials, &Map.fetch!(&1, "id"))

      if length(ids) == length(Enum.uniq(ids)) do
        credentials
      else
        raise ArgumentError,
              "Attesto.PresentationRequest :#{key} credential query IDs must be unique; got #{inspect(ids)}"
      end
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
    end
  end

  defp credentials!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
  end

  defp normalize_credential_query!(value) do
    %{
      "id" => MapParams.required_string!(MapParams.fetch(value, :id), :id),
      "format" => MapParams.required_string!(MapParams.fetch(value, :format), :format)
    }
    |> MapParams.put_optional("meta", MapParams.fetch(value, :meta), &normalize_meta!/2)
    |> MapParams.put_optional("claims", MapParams.fetch(value, :claims), &claims!/2)
  end

  defp normalize_meta!(value, _key) when is_map(value) do
    value = MapParams.string_keyed_map(value)

    case Map.fetch(value, "vct_values") do
      {:ok, vct_values} ->
        Map.put(value, "vct_values", non_empty_string_list!(vct_values, :vct_values))

      :error ->
        value
    end
  end

  defp normalize_meta!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a map; got #{inspect(value)}"
  end

  defp claims!(value, key) when is_list(value) do
    if Enum.all?(value, &is_map/1) do
      Enum.map(value, &normalize_claim_query!/1)
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a list of maps; got #{inspect(value)}"
    end
  end

  defp claims!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a list of maps; got #{inspect(value)}"
  end

  defp normalize_claim_query!(value) do
    %{"path" => path!(MapParams.fetch(value, :path), :path)}
    |> MapParams.put_optional("values", MapParams.fetch(value, :values), &values!/2)
    |> MapParams.put_optional("id", MapParams.fetch(value, :id), &MapParams.optional_string!/2)
  end

  defp path!(value, key) when is_list(value) and value != [] do
    if Enum.all?(value, &(is_binary(&1) or is_integer(&1) or is_nil(&1))) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a non-empty list of strings, integers, or nil values; " <>
              "got #{inspect(value)}"
    end
  end

  defp path!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of strings, integers, or nil values; " <>
            "got #{inspect(value)}"
  end

  defp values!(value, _key) when is_list(value), do: value

  defp values!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a list; got #{inspect(value)}"
  end

  defp credential_sets!(value, key) when is_list(value) do
    if Enum.all?(value, &is_map/1) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a list of maps; got #{inspect(value)}"
    end
  end

  defp credential_sets!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a list of maps; got #{inspect(value)}"
  end

  defp non_empty_string_list!(value, key) when is_list(value) and value != [], do: MapParams.string_list!(value, key)

  defp non_empty_string_list!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of strings; got #{inspect(value)}"
  end

  defp map!(value, _key) when is_map(value), do: value

  defp map!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a map; got #{inspect(value)}"
  end

  defp encode_json_member(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_map(value) -> Map.put(params, key, JSON.encode!(value))
      _ -> params
    end
  end
end
