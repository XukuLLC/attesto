defmodule Attesto.CredentialIssuerMetadata do
  @moduledoc """
  OID4VCI 1.0 Credential Issuer Metadata (§12.2).

  Build the JSON document a wallet fetches from
  `/.well-known/openid-credential-issuer` to discover the Credential Issuer's
  credential endpoint, supported credential configurations, and optional
  issuance capabilities.

  This module is the pure, conn-free, HTTP-free half of that endpoint. It
  returns a string-keyed map ready to serialise as JSON; serving the document
  is the host's concern. Nil values are omitted so the document advertises
  only capabilities the host provides. Unknown options and unknown fields in
  credential configurations are ignored.

  `signed/2` produces the optional signed JWT representation of the document
  (OID4VCI §12.2.3), served when a wallet requests `Accept: application/jwt`.
  """

  alias Attesto.{JWS, Key, MapParams, SigningAlg}

  @sd_jwt_vc_formats ["vc+sd-jwt", "dc+sd-jwt"]

  # OID4VCI §12.2.3: the JOSE `typ` of the signed credential issuer metadata JWT.
  @signed_metadata_typ "openidvci-issuer-metadata+jwt"

  @doc """
  Build the OID4VCI Credential Issuer Metadata document.

  Required options:

    * `:credential_issuer` - the Credential Issuer Identifier URL.
    * `:credential_endpoint` - the URL of the credential endpoint.
    * `:credential_configurations_supported` - a non-empty map from
      credential-configuration IDs to configuration maps.

  Optional options are `:authorization_servers`, `:nonce_endpoint`,
  `:deferred_credential_endpoint`, `:notification_endpoint`,
  `:credential_response_encryption`, `:batch_credential_issuance`, and
  `:display`. Each is included only when supplied with a non-`nil` value.

  Configuration maps are normalized to the supported OID4VCI members and
  their nil values are omitted. A `format` is required for every
  configuration. `vct` is additionally required for `vc+sd-jwt` and
  `dc+sd-jwt` configurations. `mso_mdoc` requires a non-empty `doctype` and
  uses integer COSE identifiers for `credential_signing_alg_values_supported`;
  JWT credential formats use string JOSE algorithm names.

  Current display and ordered claims descriptions belong in the optional
  `credential_metadata` object (§12.2.4 and Appendix B). Atom keys in this
  object are normalized to strings; JSON extensions and claim paths are
  preserved. Legacy configuration-level `claims` and `display` remain
  supported for 2.x callers without converting their claim descriptions.
  """
  @spec build(keyword()) :: %{required(String.t()) => term()}
  def build(opts) when is_list(opts) do
    opts = MapParams.ensure_keyword!(opts)

    %{
      "credential_issuer" => MapParams.required_string!(Keyword.get(opts, :credential_issuer), :credential_issuer),
      "credential_endpoint" =>
        MapParams.required_string!(Keyword.get(opts, :credential_endpoint), :credential_endpoint),
      "credential_configurations_supported" => required_configurations!(opts, :credential_configurations_supported)
    }
    |> MapParams.put_optional(
      "authorization_servers",
      Keyword.get(opts, :authorization_servers),
      &MapParams.string_list!/2
    )
    |> MapParams.put_optional("nonce_endpoint", Keyword.get(opts, :nonce_endpoint), &MapParams.optional_string!/2)
    |> MapParams.put_optional(
      "deferred_credential_endpoint",
      Keyword.get(opts, :deferred_credential_endpoint),
      &MapParams.optional_string!/2
    )
    |> MapParams.put_optional(
      "notification_endpoint",
      Keyword.get(opts, :notification_endpoint),
      &MapParams.optional_string!/2
    )
    |> MapParams.put_optional(
      "credential_response_encryption",
      Keyword.get(opts, :credential_response_encryption),
      &normalize_response_encryption!/2
    )
    |> MapParams.put_optional(
      "batch_credential_issuance",
      Keyword.get(opts, :batch_credential_issuance),
      &normalize_batch_issuance!/2
    )
    |> MapParams.put_optional("display", Keyword.get(opts, :display), &display_list!/2)
  end

  def build(opts) when not is_list(opts) do
    raise ArgumentError, "expects a keyword list; got #{inspect(opts)}"
  end

  @doc """
  Represent a metadata document as a signed JWT (OID4VCI §12.2.3).

  Served when a wallet requests signed metadata with `Accept: application/jwt`.
  The header carries `typ: #{@signed_metadata_typ}` and the issuer's public
  signing key as `jwk`, so the wallet verifies the signature without a separate
  key lookup. The claims are the document's members plus `iss`/`sub` (the
  Credential Issuer Identifier) and `iat`.

  `metadata` is a document from `build/1`. Exactly one of `:pem` or `:keystore`
  is required; optional `:now` overrides the `iat` clock (unix seconds).
  """
  @spec signed(%{required(String.t()) => term()}, keyword()) :: String.t()
  def signed(metadata, opts) when is_map(metadata) and is_list(opts) do
    {jwk, signing_source} = metadata_signing_source!(opts)
    {_modules, public_jwk} = JOSE.JWK.to_public_map(jwk)
    now = Keyword.get(opts, :now, System.system_time(:second))
    issuer = Map.get(metadata, "credential_issuer")

    claims =
      metadata
      |> Map.put("iss", issuer)
      |> Map.put("sub", issuer)
      |> Map.put("iat", now)

    sign_metadata(signing_source, public_jwk, claims)
  end

  defp metadata_signing_source!(opts) do
    case {Keyword.get(opts, :keystore), Keyword.get(opts, :pem)} do
      {keystore, nil} when is_atom(keystore) and not is_nil(keystore) ->
        context = JWS.current_signing_context(keystore)
        {context.jwk, {:keystore, keystore, context}}

      {nil, pem} when is_binary(pem) and pem != "" ->
        {Key.signing_jwk(pem), {:pem, pem}}

      {nil, nil} ->
        raise ArgumentError, "exactly one of :keystore or :pem is required"

      {_keystore, _pem} ->
        raise ArgumentError, "exactly one of :keystore or :pem is required"
    end
  end

  defp sign_metadata({:keystore, keystore, context}, public_jwk, claims) do
    public_jwk = Map.put(public_jwk, "kid", context.kid)

    JWS.sign_current(keystore, claims,
      signing_context: context,
      typ: @signed_metadata_typ,
      extra_protected: %{"jwk" => public_jwk}
    )
  end

  defp sign_metadata({:pem, pem}, public_jwk, claims) do
    jwk = Key.signing_jwk(pem)
    alg = SigningAlg.infer(jwk)
    JWS.sign_compact(pem, %{"alg" => alg, "typ" => @signed_metadata_typ, "jwk" => public_jwk}, claims)
  end

  defp required_configurations!(opts, key) do
    case Keyword.get(opts, key) do
      configurations when is_map(configurations) and map_size(configurations) > 0 ->
        normalize_configurations!(configurations)

      value ->
        raise ArgumentError,
              "Attesto.CredentialIssuerMetadata :#{key} must be a non-empty map; got #{inspect(value)}"
    end
  end

  defp normalize_configurations!(configurations) do
    Map.new(configurations, fn {configuration_id, configuration} ->
      if !is_binary(configuration_id) do
        raise ArgumentError,
              "Attesto.CredentialIssuerMetadata credential configuration ID must be a string; " <>
                "got #{inspect(configuration_id)}"
      end

      {configuration_id, normalize_configuration!(configuration_id, configuration)}
    end)
  end

  defp normalize_configuration!(configuration_id, configuration) when is_map(configuration) do
    format = required_configuration_string!(configuration_id, configuration, :format)
    vct = configuration_value(configuration, :vct)
    doctype = if format == "mso_mdoc", do: required_doctype!(configuration_id, configuration)

    signing_alg_normalizer =
      if format == "mso_mdoc", do: &configuration_integer_list!/3, else: &configuration_string_list!/3

    credential_metadata =
      credential_metadata!(configuration_value(configuration, :credential_metadata), configuration_id, format)

    if format in @sd_jwt_vc_formats and not (is_binary(vct) and vct != "") do
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
              "requires a non-empty string :vct for format #{inspect(format)}"
    end

    %{"format" => format}
    |> put_configuration_value("vct", vct, &configuration_string!/3, configuration_id, :vct)
    |> put_configuration_value("doctype", doctype, &configuration_string!/3, configuration_id, :doctype)
    |> put_configuration_value(
      "scope",
      configuration_value(configuration, :scope),
      &configuration_string!/3,
      configuration_id,
      :scope
    )
    |> put_configuration_value(
      "cryptographic_binding_methods_supported",
      configuration_value(configuration, :cryptographic_binding_methods_supported),
      &configuration_string_list!/3,
      configuration_id,
      :cryptographic_binding_methods_supported
    )
    |> put_configuration_value(
      "credential_signing_alg_values_supported",
      configuration_value(configuration, :credential_signing_alg_values_supported),
      signing_alg_normalizer,
      configuration_id,
      :credential_signing_alg_values_supported
    )
    |> put_configuration_value(
      "proof_types_supported",
      configuration_value(configuration, :proof_types_supported),
      &configuration_map!/3,
      configuration_id,
      :proof_types_supported
    )
    |> MapParams.put_optional("credential_metadata", credential_metadata)
    |> put_configuration_value(
      "claims",
      configuration_value(configuration, :claims),
      &configuration_passthrough!/3,
      configuration_id,
      :claims
    )
    |> put_configuration_value(
      "display",
      configuration_value(configuration, :display),
      &configuration_passthrough!/3,
      configuration_id,
      :display
    )
  end

  defp normalize_configuration!(configuration_id, configuration) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            "must be a map; got #{inspect(configuration)}"
  end

  defp required_doctype!(configuration_id, configuration) do
    doctype = required_configuration_string!(configuration_id, configuration, :doctype)

    if String.valid?(doctype) and String.trim(doctype) != "" do
      doctype
    else
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
              ":doctype must be a valid non-empty string; got #{inspect(doctype)}"
    end
  end

  defp required_configuration_string!(configuration_id, configuration, key) do
    case configuration_value(configuration, key) do
      value when is_binary(value) and value != "" ->
        value

      value ->
        raise ArgumentError,
              "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
                ":#{key} must be a non-empty string; got #{inspect(value)}"
    end
  end

  defp display_list!(value, key) when is_list(value) do
    if !Enum.all?(value, &is_map/1) do
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata :#{key} must be a list of maps; got #{inspect(value)}"
    end

    value
  end

  defp display_list!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata :#{key} must be a list of maps; got #{inspect(value)}"
  end

  defp normalize_response_encryption!(value, _key) when is_map(value) do
    alg_values_supported = MapParams.fetch(value, :alg_values_supported)

    %{}
    |> MapParams.put_optional("alg_values_supported", alg_values_supported, &MapParams.string_list!/2)
    |> MapParams.put_optional(
      "enc_values_supported",
      MapParams.fetch(value, :enc_values_supported),
      &MapParams.string_list!/2
    )
    |> MapParams.put_optional(
      "encryption_required",
      MapParams.fetch(value, :encryption_required),
      &boolean!/2
    )
  end

  defp normalize_response_encryption!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata :#{key} must be a map; got #{inspect(value)}"
  end

  defp normalize_batch_issuance!(value, key) when is_map(value) do
    case MapParams.fetch(value, :batch_size) do
      batch_size when is_integer(batch_size) and batch_size > 0 ->
        %{"batch_size" => batch_size}

      batch_size ->
        raise ArgumentError,
              "Attesto.CredentialIssuerMetadata :#{key}.batch_size must be a positive integer; " <>
                "got #{inspect(batch_size)}"
    end
  end

  defp normalize_batch_issuance!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata :#{key} must be a map; got #{inspect(value)}"
  end

  defp boolean!(value, _key) when is_boolean(value), do: value

  defp boolean!(value, key) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata :#{key} must be a boolean; got #{inspect(value)}"
  end

  defp put_configuration_value(map, _key, nil, _normalizer, _configuration_id, _field), do: map

  defp put_configuration_value(map, key, value, normalizer, configuration_id, field) do
    Map.put(map, key, normalizer.(value, configuration_id, field))
  end

  defp configuration_string!(value, _configuration_id, _field) when is_binary(value) and value != "", do: value

  defp configuration_string!(value, configuration_id, field) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            ":#{field} must be a non-empty string; got #{inspect(value)}"
  end

  defp configuration_string_list!(value, configuration_id, field) when is_list(value) do
    if !Enum.all?(value, &is_binary/1) do
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
              ":#{field} must be a list of strings; got #{inspect(value)}"
    end

    value
  end

  defp configuration_string_list!(value, configuration_id, field) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            ":#{field} must be a list of strings; got #{inspect(value)}"
  end

  defp configuration_integer_list!(value, configuration_id, field) do
    if is_list(value) and Enum.all?(value, &is_integer/1) do
      value
    else
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
              ":#{field} for mso_mdoc must be a list of COSE integers; got #{inspect(value)}"
    end
  end

  defp configuration_map!(value, _configuration_id, _field) when is_map(value), do: value

  defp configuration_map!(value, configuration_id, field) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            ":#{field} must be a map; got #{inspect(value)}"
  end

  defp credential_metadata!(nil, _configuration_id, _format), do: nil

  defp credential_metadata!(value, configuration_id, format) when is_map(value) and not is_struct(value) do
    metadata = metadata_json!(value, configuration_id)
    if Map.has_key?(metadata, "display"), do: metadata_display!(metadata["display"], configuration_id, true)
    if Map.has_key?(metadata, "claims"), do: metadata_claims!(metadata["claims"], configuration_id, format)
    metadata
  end

  defp credential_metadata!(_value, configuration_id, _format),
    do: metadata_error!(configuration_id, "must be an object")

  defp metadata_json!(value, configuration_id) when is_map(value) and not is_struct(value) do
    Enum.reduce(value, %{}, fn {key, item}, result ->
      key = if is_atom(key), do: Atom.to_string(key), else: key

      if not is_binary(key) or not String.valid?(key) or Map.has_key?(result, key),
        do: metadata_error!(configuration_id, "must have distinct string or atom object keys")

      Map.put(result, key, metadata_json!(item, configuration_id))
    end)
  end

  defp metadata_json!(value, configuration_id) when is_list(value),
    do: Enum.map(value, &metadata_json!(&1, configuration_id))

  defp metadata_json!(value, _configuration_id) when is_number(value) or is_boolean(value) or is_nil(value), do: value

  defp metadata_json!(value, configuration_id) when is_binary(value) do
    if String.valid?(value), do: value, else: metadata_error!(configuration_id, "must contain valid UTF-8 strings")
  end

  defp metadata_json!(_value, configuration_id), do: metadata_error!(configuration_id, "must contain JSON values")

  defp metadata_display!(display, configuration_id, credential?) when is_list(display) and display != [] do
    Enum.reduce(display, MapSet.new(), fn item, locales ->
      if not is_map(item), do: metadata_error!(configuration_id, "display must contain objects")
      if credential?, do: metadata_string!(item, "name", configuration_id, true)

      for key <- ["name", "locale"], do: metadata_string!(item, key, configuration_id, false)

      if credential? do
        for key <- ["description", "background_color", "text_color"],
            do: metadata_string!(item, key, configuration_id, false)

        for key <- ["logo", "background_image"], Map.has_key?(item, key) do
          image = item[key]
          if not is_map(image), do: metadata_error!(configuration_id, "display #{key} must be an object")
          metadata_string!(image, "uri", configuration_id, true)
          metadata_string!(image, "alt_text", configuration_id, false)

          case URI.new(image["uri"]) do
            {:ok, %URI{scheme: scheme}} when is_binary(scheme) and scheme != "" -> :ok
            _other -> metadata_error!(configuration_id, "display #{key} uri must contain a URI")
          end
        end
      end

      case Map.fetch(item, "locale") do
        :error ->
          locales

        {:ok, locale} ->
          locale = String.downcase(locale)
          if MapSet.member?(locales, locale), do: metadata_error!(configuration_id, "display locales must be unique")
          MapSet.put(locales, locale)
      end
    end)

    :ok
  end

  defp metadata_display!(_display, configuration_id, _credential?),
    do: metadata_error!(configuration_id, "display must be a non-empty array of objects")

  defp metadata_string!(item, key, configuration_id, required?) do
    case Map.fetch(item, key) do
      :error when not required? -> :ok
      {:ok, value} when is_binary(value) -> :ok
      _other -> metadata_error!(configuration_id, "#{key} must be a string")
    end
  end

  defp metadata_claims!(claims, configuration_id, format) when is_list(claims) and claims != [] do
    Enum.reduce(claims, [], fn claim, previous_paths ->
      if not is_map(claim), do: metadata_error!(configuration_id, "claims must contain objects")
      path = claim["path"]

      if not metadata_path?(path, format),
        do: metadata_error!(configuration_id, "claims require a valid non-empty path")

      if Map.has_key?(claim, "mandatory") and not is_boolean(claim["mandatory"]),
        do: metadata_error!(configuration_id, "claim mandatory must be a boolean")

      if Map.has_key?(claim, "display"), do: metadata_display!(claim["display"], configuration_id, false)

      if Enum.any?(previous_paths, &metadata_paths_conflict?(path, &1, format)),
        do: metadata_error!(configuration_id, "claims contain repeated or contradictory paths")

      [path | previous_paths]
    end)

    :ok
  end

  defp metadata_claims!(_claims, configuration_id, _format),
    do: metadata_error!(configuration_id, "claims must be a non-empty array of objects")

  defp metadata_path?([namespace, element | rest], "mso_mdoc") when is_binary(namespace) and is_binary(element),
    do: Enum.all?(rest, &(is_binary(&1) or is_integer(&1) or is_nil(&1)))

  defp metadata_path?(_path, "mso_mdoc"), do: false

  defp metadata_path?(path, _format) when is_list(path) and path != [],
    do: Enum.all?(path, &(is_binary(&1) or (is_integer(&1) and &1 >= 0) or is_nil(&1)))

  defp metadata_path?(_path, _format), do: false

  defp metadata_paths_conflict?([], [], _format), do: true

  defp metadata_paths_conflict?([same | left], [same | right], format),
    do: metadata_paths_conflict?(left, right, format)

  defp metadata_paths_conflict?([], _right, _format), do: false
  defp metadata_paths_conflict?(_left, [], _format), do: false

  defp metadata_paths_conflict?([left | _], [right | _], format) do
    left_array? = is_nil(left) or (is_integer(left) and left >= 0)
    right_array? = is_nil(right) or (is_integer(right) and right >= 0)

    is_nil(left) or is_nil(right) or
      (format != "mso_mdoc" and
         ((is_binary(left) and right_array?) or (is_binary(right) and left_array?)))
  end

  defp metadata_error!(configuration_id, reason) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            ":credential_metadata #{reason}"
  end

  defp configuration_passthrough!(value, _configuration_id, _field), do: value

  defp configuration_value(map, key), do: MapParams.fetch(map, key)
end
