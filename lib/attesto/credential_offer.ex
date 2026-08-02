defmodule Attesto.CredentialOffer do
  @moduledoc """
  OID4VCI Credential Offer (`draft-ietf-oauth-openid4vci` §4.1).

  Build the string-keyed Credential Offer object and its by-value or
  by-reference `openid-credential-offer://` deep-link forms. This module is
  pure and conn-free; fetching a referenced offer is the wallet's concern.
  """

  @default_scheme "openid-credential-offer"

  # OID4VCI §4.1.1: the pre-authorized_code grant is keyed in `grants` by its
  # full grant-type URN, while the code itself lives in the inner
  # `pre-authorized_code` member.
  @pre_authorized_code_grant_type "urn:ietf:params:oauth:grant-type:pre-authorized_code"

  @doc """
  Build an OID4VCI Credential Offer object.

  The required `:credential_issuer` and `:credential_configuration_ids`
  options are validated and normalized into a JSON-ready map. When supplied,
  `:grants` is normalized to the two OID4VCI grant types supported here:
  `authorization_code` and `pre-authorized_code`.
  """
  @spec build(keyword()) :: %{required(String.t()) => term()}
  def build(opts) when is_list(opts) do
    opts = ensure_keyword!(opts)

    %{
      "credential_issuer" => required_string!(opts, :credential_issuer),
      "credential_configuration_ids" => required_string_list!(opts, :credential_configuration_ids)
    }
    |> put_optional("grants", Keyword.get(opts, :grants), &normalize_grants!/2)
  end

  def build(opts) do
    raise ArgumentError,
          "Attesto.CredentialOffer.build/1 expects a keyword list; got #{inspect(opts)}"
  end

  @doc "JSON-encode an offer for the `credential_offer` query parameter."
  @spec to_query_value(map()) :: String.t()
  def to_query_value(offer), do: JSON.encode!(offer)

  @doc "Build a by-value `openid-credential-offer://` deep link."
  @spec deep_link(map(), keyword()) :: String.t()
  def deep_link(offer, opts \\ []) do
    scheme = scheme!(opts, "deep_link")
    value = offer |> to_query_value() |> URI.encode_www_form()

    "#{scheme}://?credential_offer=#{value}"
  end

  @doc "Build a by-reference `openid-credential-offer://` deep link."
  @spec deep_link_by_reference(String.t(), keyword()) :: String.t()
  def deep_link_by_reference(uri, opts \\ []) do
    scheme = scheme!(opts, "deep_link_by_reference")
    value = uri |> required_string_value!(:uri) |> URI.encode_www_form()

    "#{scheme}://?credential_offer_uri=#{value}"
  end

  defp ensure_keyword!(opts) do
    if Keyword.keyword?(opts) do
      opts
    else
      raise ArgumentError,
            "Attesto.CredentialOffer.build/1 expects a keyword list; got #{inspect(opts)}"
    end
  end

  defp scheme!(opts, function_name) do
    if !Keyword.keyword?(opts) do
      raise ArgumentError,
            "Attesto.CredentialOffer.#{function_name}/2 expects a keyword list; got #{inspect(opts)}"
    end

    optional_string!(Keyword.get(opts, :scheme, @default_scheme), :scheme)
  end

  defp required_string!(opts, key), do: required_string_value!(Keyword.get(opts, key), key)

  defp required_string_list!(opts, key) do
    values = Keyword.get(opts, key)

    if valid_string_list?(values) do
      values
    else
      raise ArgumentError, required_string_list_message(key, values)
    end
  end

  defp valid_string_list?(values) when is_list(values) and values != [],
    do: Enum.all?(values, fn value -> is_binary(value) and value != "" end)

  defp valid_string_list?(_values), do: false

  defp required_string_value!(value, _key) when is_binary(value) and value != "", do: value

  defp required_string_value!(value, key) do
    raise ArgumentError, required_string_message(key, value)
  end

  defp optional_string!(value, _key) when is_binary(value) and value != "", do: value

  defp optional_string!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be a non-empty string; got #{inspect(value)}"
  end

  defp put_optional(map, _key, nil, _normalizer), do: map

  defp put_optional(map, key, value, normalizer), do: Map.put(map, key, normalizer.(value, key))

  defp normalize_grants!(value, key) when is_map(value) do
    grants =
      %{}
      |> put_authorization_code(value)
      |> put_pre_authorized_code(value)

    if map_size(grants) > 0 do
      grants
    else
      raise ArgumentError,
            "Attesto.CredentialOffer :#{key} must contain at least one of " <>
              "\"authorization_code\" or \"pre-authorized_code\"; got #{inspect(value)}"
    end
  end

  defp normalize_grants!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be a map; got #{inspect(value)}"
  end

  defp put_authorization_code(grants, value) do
    if grant_present?(value, :authorization_code) do
      Map.put(
        grants,
        "authorization_code",
        normalize_authorization_code!(normalized_map_value(value, :authorization_code))
      )
    else
      grants
    end
  end

  defp put_pre_authorized_code(grants, value) do
    if pre_authorized_code_grant_present?(value) do
      Map.put(
        grants,
        @pre_authorized_code_grant_type,
        normalize_pre_authorized_code!(pre_authorized_code_grant_value(value))
      )
    else
      grants
    end
  end

  defp normalize_authorization_code!(value) when is_map(value) do
    %{}
    |> put_optional(
      "issuer_state",
      normalized_map_value(value, :issuer_state),
      &optional_string!/2
    )
    |> put_optional(
      "authorization_server",
      normalized_map_value(value, :authorization_server),
      &optional_string!/2
    )
  end

  defp normalize_authorization_code!(value) do
    raise ArgumentError,
          "Attesto.CredentialOffer :authorization_code must be a map; got #{inspect(value)}"
  end

  defp normalize_pre_authorized_code!(value) when is_map(value) do
    %{}
    |> Map.put(
      "pre-authorized_code",
      required_string_value!(pre_authorized_code_value(value), "pre-authorized_code")
    )
    |> put_optional(
      "authorization_server",
      normalized_map_value(value, :authorization_server),
      &optional_string!/2
    )
    |> put_optional("tx_code", normalized_map_value(value, :tx_code), &normalize_tx_code!/2)
  end

  defp normalize_pre_authorized_code!(value) do
    raise ArgumentError,
          "Attesto.CredentialOffer :pre-authorized_code must be a map; got #{inspect(value)}"
  end

  defp normalize_tx_code!(value, _key) when is_map(value) do
    %{}
    |> put_optional("input_mode", normalized_map_value(value, :input_mode), &input_mode!/2)
    |> put_optional("length", normalized_map_value(value, :length), &positive_integer!/2)
    |> put_optional(
      "description",
      normalized_map_value(value, :description),
      &description!/2
    )
  end

  defp normalize_tx_code!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be a map; got #{inspect(value)}"
  end

  defp input_mode!(value, _key) when value in ["numeric", "text"], do: value

  defp input_mode!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be \"numeric\" or \"text\"; got #{inspect(value)}"
  end

  defp positive_integer!(value, _key) when is_integer(value) and value > 0, do: value

  defp positive_integer!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be a positive integer; got #{inspect(value)}"
  end

  defp description!(value, key) when is_binary(value) and value != "" do
    if String.valid?(value) and String.length(value) <= 300 do
      value
    else
      raise ArgumentError,
            "Attesto.CredentialOffer :#{key} must be a non-empty string of at most 300 characters; " <>
              "got #{inspect(value)}"
    end
  end

  defp description!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialOffer :#{key} must be a non-empty string of at most 300 characters; " <>
            "got #{inspect(value)}"
  end

  defp grant_present?(map, key), do: Map.has_key?(map, key) or Map.has_key?(map, Atom.to_string(key))

  # A caller may spell the pre-authorized_code grant with the full URN, the
  # hyphenated short form, or the atom-friendly underscore form.
  @pre_authorized_code_grant_keys [
    @pre_authorized_code_grant_type,
    :"pre-authorized_code",
    "pre-authorized_code",
    :pre_authorized_code
  ]

  defp pre_authorized_code_grant_present?(map) do
    Enum.any?(@pre_authorized_code_grant_keys, &Map.has_key?(map, &1))
  end

  defp pre_authorized_code_grant_value(map) do
    key = Enum.find(@pre_authorized_code_grant_keys, &Map.has_key?(map, &1))
    Map.get(map, key)
  end

  # The inner code member is always spelled `pre-authorized_code`; accept the
  # atom, string, and underscore spellings on input.
  defp pre_authorized_code_value(map) do
    normalized_map_value(map, :"pre-authorized_code") || Map.get(map, :pre_authorized_code)
  end

  defp normalized_map_value(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp required_string_message(key, value) do
    "Attesto.CredentialOffer :#{key} must be a non-empty string; got #{inspect(value)}"
  end

  defp required_string_list_message(key, value) do
    "Attesto.CredentialOffer :#{key} must be a non-empty list of non-empty strings; got #{inspect(value)}"
  end
end
