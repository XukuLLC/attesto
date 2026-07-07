defmodule Attesto.Discovery do
  @moduledoc """
  RFC 8414 - OAuth 2.0 Authorization Server Metadata.

  Build the JSON document a client fetches from
  `/.well-known/oauth-authorization-server` (or the OIDC
  `/.well-known/openid-configuration`) to discover how to talk to the
  issuer: where the token and JWKS endpoints are, which grants and
  challenge methods are supported, and which DPoP algorithms the server
  accepts.

  Attesto fills the fields it can derive or fix by protocol:

    * `issuer` and `token_endpoint` from the `Attesto.Config`.
    * `jwks_uri` derived from the issuer (overridable).
    * `code_challenge_methods_supported` is `["S256"]` - Attesto's PKCE is
      S256 only.
    * `dpop_signing_alg_values_supported` from `Attesto.DPoP.allowed_algs/0`.
    * `grant_types_supported` defaults to `["client_credentials"]`.

  Everything host-specific (the authorization, revocation, introspection,
  and registration endpoints; the supported scopes, response types, and
  client-authentication methods) is supplied through `opts` and merged in.
  `nil` opt values are dropped so the document only advertises what the
  host actually implements.

  The result is a string-keyed map ready to serialise as the endpoint's
  JSON body.
  """

  alias Attesto.Config
  alias Attesto.DPoP

  @default_jwks_path "/.well-known/jwks.json"
  @default_grant_types ["client_credentials"]

  @host_fields ~w(
    authorization_endpoint
    revocation_endpoint
    introspection_endpoint
    registration_endpoint
    userinfo_endpoint
    scopes_supported
    response_types_supported
    response_modes_supported
    token_endpoint_auth_methods_supported
    token_endpoint_auth_signing_alg_values_supported
    revocation_endpoint_auth_methods_supported
    introspection_endpoint_auth_methods_supported
    authorization_response_iss_parameter_supported
    tls_client_certificate_bound_access_tokens
    mtls_endpoint_aliases
    require_pushed_authorization_requests
    pushed_authorization_request_endpoint
    device_authorization_endpoint
    backchannel_authentication_endpoint
    backchannel_token_delivery_modes_supported
    backchannel_authentication_request_signing_alg_values_supported
    backchannel_user_code_parameter_supported
    end_session_endpoint
    backchannel_logout_supported
    backchannel_logout_session_supported
    frontchannel_logout_supported
    frontchannel_logout_session_supported
    check_session_iframe
    require_signed_request_object
    request_object_signing_alg_values_supported
    client_id_metadata_document_supported
    service_documentation
    ui_locales_supported
  )a

  @doc """
  Build the authorization-server metadata document for `config`.

  Options:

    * `:jwks_uri` - the full JWKS URL. Defaults to the issuer merged with
      `#{@default_jwks_path}`.
    * `:grant_types_supported` - defaults to `#{inspect(@default_grant_types)}`.
    * `:authorization_endpoint`, `:revocation_endpoint`,
      `:introspection_endpoint`, `:registration_endpoint`,
      `:userinfo_endpoint` - host endpoint URLs, included only if given.
    * `:scopes_supported`, `:response_types_supported`,
      `:response_modes_supported`, `:token_endpoint_auth_methods_supported`,
      `:service_documentation`, `:ui_locales_supported` - included only if
      given.
    * `:pushed_authorization_request_endpoint` (RFC 9126),
      `:require_pushed_authorization_requests` - the PAR endpoint URL and
      whether the server mandates PAR; included only if given.
    * `:client_id_metadata_document_supported`
      (`draft-ietf-oauth-client-id-metadata-document-01` §6) - a boolean
      advertising whether the server dereferences an HTTPS `client_id` URL to a
      client metadata document; included only if given.
    * `:backchannel_authentication_endpoint`,
      `:backchannel_token_delivery_modes_supported` (e.g. `["poll", "ping"]` -
      FAPI-CIBA forbids `"push"`),
      `:backchannel_authentication_request_signing_alg_values_supported`,
      `:backchannel_user_code_parameter_supported` (CIBA Core §4) - the CIBA
      endpoint and capability advertisement; included only if given.

  The accepted host fields are the RFC 8414 §2 allowlist in
  `@host_fields`; the enumeration above is illustrative. Any other opt key
  is ignored.
  """
  @spec metadata(Config.t(), keyword()) :: %{required(String.t()) => term()}
  def metadata(%Config{} = config, opts \\ []) do
    base = %{
      "issuer" => config.issuer,
      "token_endpoint" => Config.token_endpoint_url(config),
      "jwks_uri" => Keyword.get(opts, :jwks_uri, default_jwks_uri(config)),
      "grant_types_supported" => Keyword.get(opts, :grant_types_supported, @default_grant_types),
      "code_challenge_methods_supported" => ["S256"],
      "dpop_signing_alg_values_supported" => DPoP.allowed_algs()
    }

    Enum.reduce(@host_fields, base, fn field, acc ->
      case Keyword.get(opts, field) do
        nil -> acc
        value -> Map.put(acc, Atom.to_string(field), value)
      end
    end)
  end

  defp default_jwks_uri(%Config{issuer: issuer}) do
    issuer
    |> URI.parse()
    |> URI.merge(@default_jwks_path)
    |> URI.to_string()
  end
end
