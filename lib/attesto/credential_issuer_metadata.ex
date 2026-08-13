defmodule Attesto.CredentialIssuerMetadata do
  @moduledoc """
  OID4VCI Credential Issuer Metadata
  (`draft-ietf-oauth-openid4vci` §11.2).

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
  (OID4VCI §11.2.2), served when a wallet requests `Accept: application/jwt`.
  """

  alias Attesto.{JWS, Key, MapParams, SigningAlg}

  @sd_jwt_vc_formats ["vc+sd-jwt", "dc+sd-jwt"]

  # OID4VCI §11.2.2: the JOSE `typ` of the signed credential issuer metadata JWT.
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
  `dc+sd-jwt` configurations.
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
  Represent a metadata document as a signed JWT (OID4VCI §11.2.2).

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

    if format in @sd_jwt_vc_formats and not (is_binary(vct) and vct != "") do
      raise ArgumentError,
            "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
              "requires a non-empty string :vct for format #{inspect(format)}"
    end

    %{"format" => format}
    |> put_configuration_value("vct", vct, &configuration_string!/3, configuration_id, :vct)
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
      &configuration_string_list!/3,
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

  defp configuration_map!(value, _configuration_id, _field) when is_map(value), do: value

  defp configuration_map!(value, configuration_id, field) do
    raise ArgumentError,
          "Attesto.CredentialIssuerMetadata credential configuration #{inspect(configuration_id)} " <>
            ":#{field} must be a map; got #{inspect(value)}"
  end

  defp configuration_passthrough!(value, _configuration_id, _field), do: value

  defp configuration_value(map, key), do: MapParams.fetch(map, key)
end
