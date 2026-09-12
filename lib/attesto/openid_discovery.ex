defmodule Attesto.OpenIDDiscovery do
  @moduledoc """
  OpenID Connect Discovery 1.0 - OpenID Provider Metadata (§3).

  Build the JSON document a Relying Party fetches from
  `/.well-known/openid-configuration` to discover the OpenID Provider:
  its endpoints, the response/grant types it supports, the signing
  algorithms it uses for ID Tokens, and the scopes and claims it can
  return.

  This module builds on `Attesto.Discovery` rather than adding an OIDC
  mode flag to it. The two metadata documents are distinct: RFC 8414
  Authorization Server Metadata and OpenID Connect Discovery §3 Provider
  Metadata have different required-field sets (OIDC mandates
  `subject_types_supported`, `id_token_signing_alg_values_supported`,
  `claims_supported`, `claim_types_supported`, and a `scopes_supported`
  list that MUST contain `"openid"`), and they are served from different
  well-known URLs. Keeping a dedicated builder keeps each document's
  contract clear instead of overloading the OAuth builder with
  OIDC-only obligations. The shared OAuth fields (`issuer`,
  `token_endpoint`, `jwks_uri`, `grant_types_supported`,
  `code_challenge_methods_supported`, `dpop_signing_alg_values_supported`,
  and any host-supplied OAuth fields) are produced by
  `Attesto.Discovery.metadata/2` and merged in, so there is one source of
  truth for them.

  Attesto fills the fields it can derive or fix by protocol:

    * `issuer`, `token_endpoint`, and `jwks_uri` via `Attesto.Discovery`.
    * `subject_types_supported` is `["public"]` - Attesto does not mint
      pairwise subject identifiers.
    * `id_token_signing_alg_values_supported` defaults to the algorithms
      of the configured verification keys (RSA defaults to RS256).
    * `claim_types_supported` is `["normal"]` - Attesto returns claims
      directly, not aggregated or distributed
      (OpenID Connect Core §5.6).
    * `response_types_supported` defaults to `["code"]` - the
      Authorization Code Flow.
    * `code_challenge_methods_supported` is `["S256"]` (via
      `Attesto.Discovery`).
    * `request_parameter_supported` defaults to `false` - Attesto does
      not consume a `request` JWT parameter
      (OpenID Connect Core §6.1).

  Everything host-specific - the `authorization_endpoint`,
  `userinfo_endpoint`, and the catalog of `scopes_supported` and
  `claims_supported` the host actually serves - is supplied through
  `opts` and merged in. `nil` opt values are dropped so the document only
  advertises what the host actually implements. When `scopes_supported` is
  provided, the reserved `"openid"` scope is added when absent (OpenID Connect
  Core §3.1.2.1). This normalization applies only to the returned metadata;
  integrations remain responsible for using a matching effective catalog in
  registration and authorization policy.

  The result is a string-keyed map ready to serialise as the endpoint's
  JSON body.
  """

  alias Attesto.Config
  alias Attesto.Discovery
  alias Attesto.SigningAlg

  @default_response_types ["code"]
  @subject_types ["public"]
  @id_token_signing_alg_values ["RS256"]
  @claim_types ["normal"]

  # OIDC Provider Metadata fields this builder accepts via opts and merges
  # in only when given (OpenID Connect Discovery §3). The shared OAuth
  # fields below (authorization_endpoint, userinfo_endpoint,
  # scopes_supported, response_types_supported,
  # token_endpoint_auth_methods_supported, ...) are forwarded to
  # Attesto.Discovery, which applies the same "drop nil" rule.
  @oidc_host_fields ~w(
    claims_supported
    acr_values_supported
    display_values_supported
    claims_locales_supported
    ui_locales_supported
    claims_parameter_supported
    request_uri_parameter_supported
    require_request_uri_registration
    op_policy_uri
    op_tos_uri
  )a

  @doc """
  Build the OpenID Provider Metadata document for `config`.

  The shared OAuth fields are produced by `Attesto.Discovery.metadata/2`;
  see its docs for `:jwks_uri`, `:grant_types_supported`, the host
  endpoint URLs (`:authorization_endpoint`, `:userinfo_endpoint`, ...),
  and `:token_endpoint_auth_methods_supported`.

  OIDC-specific options:

    * `:response_types_supported` - defaults to
      `#{inspect(@default_response_types)}` (Authorization Code Flow).
    * `:request_parameter_supported` - defaults to `false`.
    * `:scopes_supported` - if given, the reserved `"openid"` scope is added
      when absent (OpenID Connect Core §3.1.2.1). Included only if given.
    * `:claims_supported`, `:acr_values_supported`,
      `:display_values_supported`, `:claims_locales_supported`,
      `:ui_locales_supported`, `:claims_parameter_supported`,
      `:request_uri_parameter_supported`,
      `:require_request_uri_registration`, `:op_policy_uri`,
      `:op_tos_uri` - included only if given.

  `subject_types_supported`, `id_token_signing_alg_values_supported`, and
  `claim_types_supported` are fixed by protocol and always present.

  Any other opt key is ignored.
  """
  @spec metadata(Config.t(), keyword()) :: %{required(String.t()) => term()}
  def metadata(%Config{} = config, opts \\ []) do
    # Forward the shared OAuth fields (including any host endpoint URLs and
    # auth-method lists) to the RFC 8414 builder, with the OIDC default
    # response_types_supported when the host did not specify it.
    oauth_opts =
      opts
      |> Keyword.put_new(:response_types_supported, @default_response_types)
      |> normalize_scopes_supported()

    base = Discovery.metadata(config, oauth_opts)

    algs = Keyword.get(opts, :id_token_signing_alg_values_supported, signing_algs(config))

    oidc_base =
      base
      |> Map.put("subject_types_supported", @subject_types)
      |> Map.put("id_token_signing_alg_values_supported", algs)
      |> Map.put("claim_types_supported", @claim_types)
      |> Map.put(
        "request_parameter_supported",
        Keyword.get(opts, :request_parameter_supported, false)
      )

    Enum.reduce(@oidc_host_fields, oidc_base, fn field, acc ->
      case Keyword.get(opts, field) do
        nil -> acc
        value -> Map.put(acc, Atom.to_string(field), value)
      end
    end)
  end

  # OpenID Connect Core §3.1.2.1: "openid" is REQUIRED in an OIDC
  # authentication request. Provider Metadata that advertises a scope catalog
  # must therefore include it. Integrations should normalize their catalog
  # centrally before calling this builder; this local normalization remains for
  # direct callers and backwards compatibility.
  defp normalize_scopes_supported(opts) do
    case Keyword.get(opts, :scopes_supported) do
      nil ->
        opts

      scopes when is_list(scopes) ->
        if "openid" in scopes do
          opts
        else
          Keyword.put(opts, :scopes_supported, ["openid" | scopes])
        end
    end
  end

  defp signing_algs(%Config{keystore: keystore}) do
    case SigningAlg.keystore_algs(keystore) do
      [] -> @id_token_signing_alg_values
      algs -> algs
    end
  end
end
