defmodule Attesto.ProtectedResourceMetadata do
  @moduledoc """
  RFC 9728 - OAuth 2.0 Protected Resource Metadata.

  Build the JSON document a client (or an authorization server) fetches from a
  protected resource's `/.well-known/oauth-protected-resource` to learn how to
  obtain and present tokens for that resource: which authorization server(s)
  issue tokens for it, where its JWKS lives, what scopes and bearer-token
  presentation methods it accepts, and whether it requires sender-constrained
  (DPoP / mTLS) tokens.

  This is the resource-server analogue of `Attesto.Discovery` (RFC 8414, the
  authorization server's metadata) and mirrors it exactly: a base map of the
  fields Attesto can derive from the `Attesto.Config`, plus an `@host_fields`
  allowlist reduce that merges in whatever the host supplies and drops `nil`
  values so the document only advertises what the resource actually implements.

  The only protocol-fixed field is `resource` (RFC 9728 §2, REQUIRED): the
  resource identifier the metadata describes. It defaults to the config's
  `audience` - the access-token audience a resource server validates is exactly
  its resource identifier - and is overridable via the `:resource` opt for a
  deployment whose canonical resource identifier differs from the default token
  audience.

  Everything else in RFC 9728 §2 is host-specific and supplied through `opts`:
  the `authorization_servers` list, the resource's own `jwks_uri`,
  `scopes_supported`, the `bearer_methods_supported` presentation methods, the
  signing algorithms for signed responses, the human-facing
  `resource_name`/documentation/policy/ToS URLs, the sender-constraint flags,
  and a `signed_metadata` JWT. `nil` opt values are dropped.

  The result is a string-keyed map ready to serialise as the endpoint's JSON
  body. This module renders the document only; mounting a serving endpoint for
  it is the host's concern.
  """

  alias Attesto.Config

  # RFC 9728 §2: the metadata members a protected resource MAY publish. Every
  # one is host-supplied and nil-droppable; `resource` (REQUIRED) is in the base
  # map (it defaults to the config audience) rather than here.
  @host_fields ~w(
    authorization_servers
    jwks_uri
    scopes_supported
    bearer_methods_supported
    resource_signing_alg_values_supported
    authorization_details_types_supported
    resource_name
    resource_documentation
    resource_policy_uri
    resource_tos_uri
    tls_client_certificate_bound_access_tokens
    dpop_bound_access_tokens_required
    dpop_signing_alg_values_supported
    signed_metadata
  )a

  @doc """
  Build the protected-resource metadata document for `config`.

  The only field Attesto fixes is `resource` (RFC 9728 §2, REQUIRED): the
  resource identifier this metadata describes.

  Options:

    * `:resource` - the resource identifier. Defaults to `config.audience` (the
      access-token audience a resource server validates is its resource
      identifier); override for a deployment whose canonical resource
      identifier differs from the default token audience.
    * `:authorization_servers` - the list of issuer identifiers of the
      authorization servers that can issue tokens for this resource (RFC 9728
      §2). Included only if given.
    * `:jwks_uri` - the resource's own JWK Set URL (e.g. for verifying signed
      resource responses). Included only if given. Distinct from the
      authorization server's `jwks_uri`.
    * `:scopes_supported`, `:bearer_methods_supported`,
      `:resource_signing_alg_values_supported` - the scopes the resource
      recognises, the RFC 6750 token-presentation methods it accepts
      (`"header"`, `"body"`, `"query"`), and the JWS algorithms it signs
      responses with; included only if given.
    * `:resource_name`, `:resource_documentation`, `:resource_policy_uri`,
      `:resource_tos_uri` - human-facing display name and URLs; included only
      if given.
    * `:tls_client_certificate_bound_access_tokens` (RFC 8705),
      `:dpop_bound_access_tokens_required`,
      `:dpop_signing_alg_values_supported` (RFC 9449) - the sender-constraint
      flags and accepted DPoP algorithms; included only if given.
    * `:signed_metadata` - a JWT whose claims are the signed counterpart of
      this document (RFC 9728 §2); included only if given.

  The accepted host fields are the RFC 9728 §2 allowlist in `@host_fields`; the
  enumeration above is illustrative. Any other opt key is ignored.
  """
  @spec metadata(Config.t(), keyword()) :: %{required(String.t()) => term()}
  def metadata(%Config{} = config, opts \\ []) do
    base = %{"resource" => resource(config, opts)}

    Enum.reduce(@host_fields, base, fn field, acc ->
      case Keyword.get(opts, field) do
        nil -> acc
        value -> Map.put(acc, Atom.to_string(field), value)
      end
    end)
  end

  # RFC 9728 §2: `resource` is REQUIRED and is a single resource identifier. An
  # absent or `nil` `:resource` opt falls back to the configured audience (the
  # access-token audience a resource server validates is its resource
  # identifier); a present value overrides it. The selected identifier must be an
  # absolute URI with a host and no fragment (RFC 3986; RFC 9728 §2 - it is the
  # `https` URL a client dereferences), so a malformed value fails fast rather
  # than publishing a non-conformant REQUIRED member. (RFC 9728 §2 specifies the
  # `https` scheme; that is the host's deployment choice and is not enforced here
  # so a loopback `http` development resource still renders.)
  defp resource(config, opts) do
    case Keyword.get(opts, :resource) do
      nil -> require_resource_identifier!(config.audience)
      resource when is_binary(resource) and resource != "" -> require_resource_identifier!(resource)
      other -> raise ArgumentError, malformed_resource_message(other)
    end
  end

  # RFC 9728 §1.2/§2: the `resource` identifier is an `https` URL with a host and
  # no fragment. `URI.new/1` (unlike `URI.parse/1`) rejects whitespace/control
  # characters but still accepts an invalid percent-escape (a `%` not followed by
  # two hex digits, e.g. `%ZZ`), so that is rejected explicitly first.
  defp require_resource_identifier!(url) do
    with false <- invalid_percent_encoding?(url),
         {:ok, %URI{scheme: "https", host: host, fragment: nil}} <- URI.new(url),
         true <- is_binary(host) and host != "" do
      url
    else
      _ -> raise ArgumentError, malformed_resource_message(url)
    end
  end

  # RFC 3986 §2.1: a `%` is valid only as the lead of a `%HH` triplet.
  defp invalid_percent_encoding?(url), do: Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, url)

  defp malformed_resource_message(value) do
    "Attesto.ProtectedResourceMetadata: the `resource` identifier (RFC 9728 §2, REQUIRED) must " <>
      "be an absolute https URL with a host and no fragment; got #{inspect(value)}"
  end
end
