defmodule Attesto.CredentialOffer do
  @moduledoc """
  OID4VCI Credential Offer (`draft-ietf-oauth-openid4vci` §4.1).

  Build the string-keyed Credential Offer object and its by-value or
  by-reference `openid-credential-offer://` deep-link forms. This module is
  pure and conn-free; fetching a referenced offer is the wallet's concern.
  """

  alias Attesto.MapParams
  alias Attesto.Secret

  @default_scheme "openid-credential-offer"

  # Default lifetime of a stored by-reference offer. Short by design: the offer
  # embeds a redeemable pre-authorized code, so it should live only long enough
  # for the wallet to dereference it.
  @default_reference_ttl 300

  # Hard ceiling on a by-reference offer's lifetime. A redeemable pre-authorized
  # code should not sit fetchable for long; reject absurd/accidental TTLs rather
  # than store a code for hours or (via overflow-ish nonsense) effectively
  # forever.
  @max_reference_ttl 3600

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
    opts = MapParams.ensure_keyword!(opts)

    %{
      "credential_issuer" => MapParams.required_string!(Keyword.get(opts, :credential_issuer), :credential_issuer),
      "credential_configuration_ids" => required_string_list!(opts, :credential_configuration_ids)
    }
    |> MapParams.put_optional("grants", Keyword.get(opts, :grants), &normalize_grants!/2)
  end

  def build(opts) when not is_list(opts) do
    raise ArgumentError, "expects a keyword list; got #{inspect(opts)}"
  end

  @doc "JSON-encode an offer for the `credential_offer` query parameter."
  @spec to_query_value(map()) :: String.t()
  def to_query_value(offer), do: JSON.encode!(offer)

  @doc "Build a by-value `openid-credential-offer://` deep link."
  @spec deep_link(map(), keyword()) :: String.t()
  def deep_link(offer, opts \\ []) do
    scheme = scheme!(opts)
    value = offer |> to_query_value() |> URI.encode_www_form()

    "#{scheme}://?credential_offer=#{value}"
  end

  @doc "Build a by-reference `openid-credential-offer://` deep link."
  @spec deep_link_by_reference(String.t(), keyword()) :: String.t()
  def deep_link_by_reference(uri, opts \\ []) do
    scheme = scheme!(opts)
    value = uri |> MapParams.required_string!(:uri) |> URI.encode_www_form()

    "#{scheme}://?credential_offer_uri=#{value}"
  end

  @doc """
  Store `offer` for by-reference retrieval and return the freshly generated,
  unguessable id to embed in its `credential_offer_uri`.

  The id is the ONLY thing protecting a by-reference offer: the offer endpoint
  is unauthenticated by design (OID4VCI §4.1.3, the wallet dereferences it
  before it has any token), and a pre-authorized offer embeds a redeemable
  `pre-authorized_code`. A guessable id therefore lets an attacker enumerate the
  offer endpoint, read a victim's offer, and redeem its code first. This
  function is the blessed creation path: it generates the id here with
  `Attesto.Secret.generate/0` (256-bit CSPRNG), so a host cannot substitute a
  weak one. It mirrors `Attesto.PresentationSession.create/3`, which owns its
  session-id entropy the same way. Callers MUST use this rather than calling the
  store's `put/1` with a self-chosen id.

  Options:

    * `:ttl` — lifetime in seconds (default `#{@default_reference_ttl}`).

  Returns `{:ok, id}`; build the retrieval URL from `id` and pass that URL to
  `deep_link_by_reference/2`.
  """
  @spec store_by_reference(module(), map(), keyword()) :: {:ok, String.t()}
  def store_by_reference(store, offer, opts \\ []) when is_atom(store) and is_map(offer) and is_list(opts) do
    ttl = validate_ttl!(Keyword.get(opts, :ttl, @default_reference_ttl))
    id = Secret.generate()

    case store.put(%{id: id, offer: offer, expires_at: System.system_time(:second) + ttl}) do
      :ok -> {:ok, id}
      _unexpected -> raise RuntimeError, "credential offer store put/1 violated its contract"
    end
  end

  defp validate_ttl!(ttl) when is_integer(ttl) and ttl > 0 and ttl <= @max_reference_ttl, do: ttl

  defp validate_ttl!(ttl) do
    raise ArgumentError,
          "Attesto.CredentialOffer.store_by_reference/3 :ttl must be an integer in " <>
            "1..#{@max_reference_ttl} seconds; got #{inspect(ttl)}"
  end

  defp scheme!(opts) do
    opts = MapParams.ensure_keyword!(opts)

    MapParams.optional_string!(Keyword.get(opts, :scheme, @default_scheme), :scheme)
  end

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
        normalize_authorization_code!(MapParams.fetch(value, :authorization_code))
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
    |> MapParams.put_optional(
      "issuer_state",
      MapParams.fetch(value, :issuer_state),
      &MapParams.optional_string!/2
    )
    |> MapParams.put_optional(
      "authorization_server",
      MapParams.fetch(value, :authorization_server),
      &MapParams.optional_string!/2
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
      MapParams.required_string!(pre_authorized_code_value(value), "pre-authorized_code")
    )
    |> MapParams.put_optional(
      "authorization_server",
      MapParams.fetch(value, :authorization_server),
      &MapParams.optional_string!/2
    )
    |> MapParams.put_optional("tx_code", MapParams.fetch(value, :tx_code), &normalize_tx_code!/2)
  end

  defp normalize_pre_authorized_code!(value) do
    raise ArgumentError,
          "Attesto.CredentialOffer :pre-authorized_code must be a map; got #{inspect(value)}"
  end

  defp normalize_tx_code!(value, _key) when is_map(value) do
    %{}
    |> MapParams.put_optional("input_mode", MapParams.fetch(value, :input_mode), &input_mode!/2)
    |> MapParams.put_optional("length", MapParams.fetch(value, :length), &positive_integer!/2)
    |> MapParams.put_optional(
      "description",
      MapParams.fetch(value, :description),
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
    MapParams.fetch(map, :"pre-authorized_code") || Map.get(map, :pre_authorized_code)
  end

  defp required_string_list_message(key, value) do
    "Attesto.CredentialOffer :#{key} must be a non-empty list of non-empty strings; got #{inspect(value)}"
  end
end
