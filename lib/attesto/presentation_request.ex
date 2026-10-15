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
  @dcql_identifier ~r/\A[A-Za-z0-9_-]+\z/

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
    credentials = credentials!(MapParams.fetch(value, :credentials), :credentials)
    credential_ids = Enum.map(credentials, &Map.fetch!(&1, "id"))

    %{"credentials" => credentials}
    |> put_credential_sets(MapParams.fetch(value, :credential_sets), credential_ids)
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
    id = identifier!(MapParams.fetch(value, :id), :id)
    format = MapParams.required_string!(MapParams.fetch(value, :format), :format)
    claims = normalize_claims(MapParams.fetch(value, :claims), format)

    %{"id" => id, "format" => format}
    |> MapParams.put_optional("multiple", MapParams.fetch(value, :multiple), &boolean!/2)
    |> MapParams.put_optional("meta", MapParams.fetch(value, :meta), &normalize_meta!/2)
    |> MapParams.put_optional("claims", claims)
    |> put_claim_sets(MapParams.fetch(value, :claim_sets), claims)
  end

  defp normalize_meta!(value, _key) when is_map(value) do
    value = MapParams.string_keyed_map(value)

    value
    |> normalize_meta_string_list("vct_values", :vct_values)
    |> normalize_meta_string_list("doctype_values", :doctype_values)
    |> normalize_meta_string("doctype_value", :doctype_value)
  end

  defp normalize_meta!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a map; got #{inspect(value)}"
  end

  defp normalize_claims(nil, _format), do: nil

  defp normalize_claims(value, format) do
    claims = claims!(value, :claims)
    validate_claim_paths!(claims, format)
    claims
  end

  defp claims!(value, key) when is_list(value) and value != [] do
    if Enum.all?(value, &is_map/1) do
      claims = Enum.map(value, &normalize_claim_query!/1)
      ids = claims |> Enum.map(&Map.get(&1, "id")) |> Enum.reject(&is_nil/1)
      paths = Enum.map(claims, &Map.fetch!(&1, "path"))

      cond do
        length(ids) != length(Enum.uniq(ids)) ->
          raise ArgumentError,
                "Attesto.PresentationRequest :#{key} claim IDs must be unique; got #{inspect(ids)}"

        length(paths) != length(Enum.uniq(paths)) ->
          raise ArgumentError, "Attesto.PresentationRequest :#{key} must not request the same path more than once"

        true ->
          claims
      end
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
    end
  end

  defp claims!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
  end

  defp normalize_claim_query!(value) do
    %{"path" => path!(MapParams.fetch(value, :path), :path)}
    |> MapParams.put_optional("values", MapParams.fetch(value, :values), &values!/2)
    |> MapParams.put_optional("id", MapParams.fetch(value, :id), &identifier!/2)
  end

  defp path!(value, key) when is_list(value) and value != [] do
    if Enum.all?(value, &(is_binary(&1) or (is_integer(&1) and &1 >= 0) or is_nil(&1))) do
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

  defp values!(value, _key) when is_list(value) and value != [] do
    if Enum.all?(value, &(is_binary(&1) or is_integer(&1) or is_boolean(&1))) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :values must be a non-empty list of strings, integers, or booleans; " <>
              "got #{inspect(value)}"
    end
  end

  defp values!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of strings, integers, or booleans; " <>
            "got #{inspect(value)}"
  end

  defp put_credential_sets(query, nil, _credential_ids), do: query

  defp put_credential_sets(query, value, credential_ids) do
    Map.put(query, "credential_sets", credential_sets!(value, :credential_sets, credential_ids))
  end

  defp credential_sets!(value, key, credential_ids) when is_list(value) and value != [] do
    if Enum.all?(value, &is_map/1) do
      Enum.map(value, &normalize_credential_set!(&1, credential_ids))
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
    end
  end

  defp credential_sets!(value, key, _credential_ids) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of maps; got #{inspect(value)}"
  end

  defp normalize_credential_set!(value, credential_ids) do
    %{"options" => options!(MapParams.fetch(value, :options), :options, credential_ids)}
    |> MapParams.put_optional("required", MapParams.fetch(value, :required), &boolean!/2)
    |> MapParams.put_optional("purpose", MapParams.fetch(value, :purpose))
  end

  defp options!(value, key, valid_ids) when is_list(value) and value != [] do
    if Enum.all?(value, &valid_option?(&1, valid_ids)) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must be a non-empty list of non-empty identifier lists; " <>
              "every identifier must reference a declared entry"
    end
  end

  defp options!(value, key, _valid_ids) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must be a non-empty list of non-empty identifier lists; " <>
            "got #{inspect(value)}"
  end

  defp valid_option?(option, valid_ids) when is_list(option) and option != [] do
    Enum.uniq(option) == option and Enum.all?(option, &(&1 in valid_ids))
  end

  defp valid_option?(_option, _valid_ids), do: false

  defp put_claim_sets(credential, nil, _claims), do: credential

  defp put_claim_sets(credential, value, claims) when is_list(claims) do
    claim_ids = Enum.map(claims, &Map.get(&1, "id"))

    if Enum.all?(claim_ids, &is_binary/1) do
      Map.put(credential, "claim_sets", options!(value, :claim_sets, claim_ids))
    else
      raise ArgumentError, "Attesto.PresentationRequest every claim requires :id when :claim_sets is present"
    end
  end

  defp put_claim_sets(_credential, _value, _claims) do
    raise ArgumentError, "Attesto.PresentationRequest :claim_sets requires a non-empty :claims list"
  end

  defp validate_claim_paths!(claims, "mso_mdoc") do
    if Enum.all?(claims, fn %{"path" => path} -> length(path) == 2 and Enum.all?(path, &is_binary/1) end) do
      :ok
    else
      raise ArgumentError, "Attesto.PresentationRequest mso_mdoc claim paths must contain exactly two strings"
    end
  end

  defp validate_claim_paths!(_claims, _format), do: :ok

  defp normalize_meta_string_list(value, field, key) do
    case Map.fetch(value, field) do
      {:ok, values} -> Map.put(value, field, non_empty_string_list!(values, key))
      :error -> value
    end
  end

  defp normalize_meta_string(value, field, key) do
    case Map.fetch(value, field) do
      {:ok, item} -> Map.put(value, field, MapParams.optional_string!(item, key))
      :error -> value
    end
  end

  defp identifier!(value, key) when is_binary(value) do
    if Regex.match?(@dcql_identifier, value) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} must contain only letters, digits, underscores, or hyphens; " <>
              "got #{inspect(value)}"
    end
  end

  defp identifier!(value, key) do
    raise ArgumentError,
          "Attesto.PresentationRequest :#{key} must contain only letters, digits, underscores, or hyphens; " <>
            "got #{inspect(value)}"
  end

  defp boolean!(value, _key) when is_boolean(value), do: value

  defp boolean!(value, key) do
    raise ArgumentError, "Attesto.PresentationRequest :#{key} must be a boolean; got #{inspect(value)}"
  end

  defp non_empty_string_list!(value, key) when is_list(value) and value != [] do
    if Enum.all?(value, &(is_binary(&1) and &1 != "")) do
      value
    else
      raise ArgumentError,
            "Attesto.PresentationRequest :#{key} values must be non-empty strings; got #{inspect(value)}"
    end
  end

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
