defmodule Attesto.AuthorizationRequest do
  @moduledoc """
  Authorization endpoint request validation (RFC 6749 §4.1.1, OIDC Core
  §3.1.2.1, RFC 7636 §4.3).

  This module validates the *protocol* shape of an authorization request that
  the transport layer has already parsed out of the query string. It checks the
  `response_type`, the presence of `client_id` and `redirect_uri`, the requested
  scope (surfacing whether the OpenID Connect `openid` scope was requested), and
  the PKCE parameters (`code_challenge` + `code_challenge_method`). It carries
  `state`, `nonce`, `claims`, and the optional `prompt` / `max_age` / `acr_values`
  parameters through to the normalized result.

  It deliberately does NOT:

    * authenticate the resource owner or render consent (host policy, performed
      in the Phoenix layer);
    * decide whether the `client_id` exists, beyond requiring it to be present;
    * issue an authorization code (`Attesto.AuthorizationCode.issue/3` does that,
      consuming the normalized request this module returns).

  It DOES check `redirect_uri` against the registered set the caller passes in
  `:registered_redirect_uris` by exact string match (RFC 6749 §3.1.2.3, OIDC
  Core §3.1.2.1): the registered set is a fact the host supplies, not a policy
  decision this module makes. A caller running the RFC 8252 native-app profile
  may widen that comparison to the loopback-port exception (§7.3) with
  `:redirect_uri_matching`; see `Attesto.RedirectURI`.

  ## Error disposition (OIDC Core §3.1.2.6, RFC 6749 §4.1.2.1)

  RFC 6749 §4.1.2.1 and OIDC Core §3.1.2.6 split authorization errors into two
  classes by *where the error may be reported*:

    * `{:error, {:direct, reason}}` - the request `client_id` or `redirect_uri`
      is missing or invalid. The authorization server MUST NOT redirect back to
      the supplied URI (it is untrusted); the error is shown directly to the
      user agent. Reasons: `:invalid_client_id`, `:missing_redirect_uri`,
      `:invalid_redirect_uri`, `:redirect_uri_not_registered`.

    * `{:error, {:redirect, error}}` - the `client_id`/`redirect_uri` pair is
      trusted but some other parameter is invalid. The server redirects back to
      the validated `redirect_uri` with an `error` (and `error_description`)
      query parameter, echoing `state` when present. The `error` map carries:
      `:error` (the RFC 6749 §4.1.2.1 code), `:error_description`,
      `:redirect_uri`, and `:state`.

  The Phoenix layer turns each class into the correct HTTP response; this core
  module only classifies.
  """

  alias Attesto.PKCE
  alias Attesto.RedirectURI
  alias Attesto.RequestObject
  alias Attesto.RequestObject.Policy
  alias Attesto.ResourceIndicator
  alias Attesto.Scope

  @response_type_code "code"
  @openid_scope "openid"
  @plain_method "plain"

  # OAuth 2.0 Multiple Response Type Encoding Practices + JWT Secured
  # Authorization Response Mode (JARM §2.3): the response modes this
  # authorization-code server supports. `query` is the RFC 6749 default; the
  # JARM modes (`jwt`, and the `.jwt`-suffixed variants) return the response as
  # a single signed JWT (FAPI 2.0 Message Signing §5.4). `jwt` is the shorthand
  # for the response_type's default JWT mode, which for `code` is `query.jwt`
  # (JARM §2.3.2). Plain `fragment`/`form_post` are intentionally unsupported -
  # the code flow returns its parameters in the query, signed or not.
  @supported_response_modes ["query", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]

  # OIDC Core §3.1.2.1: the complete, fixed set of prompt values. Any token
  # outside this set is an invalid_request.
  @prompt_values ["none", "login", "consent", "select_account"]

  @default_require_nonce false

  # RFC 7636 / RFC 9700: PKCE is required by default. The caller may relax it
  # (only ever for confidential clients; public clients MUST use PKCE per
  # RFC 9700 §2.1.1) by passing `require_pkce: false`. Even when relaxed, a
  # `code_challenge` that IS present is still fully enforced (S256, no `plain`).
  @default_require_pkce true

  # RFC 6749 §3.1.2.3: redirect URIs are compared by simple string match. The
  # RFC 8252 §7.3 loopback exception is opt-in, so an existing deployment sees
  # byte-identical matching behavior.
  @default_redirect_uri_matching :exact

  @typedoc """
  A normalized, validated authorization request.

  The binding fields (`client_id`, `redirect_uri`, `scope`, `code_challenge`,
  `code_challenge_method`, `nonce`) line up with the attrs
  `Attesto.AuthorizationCode.issue/3` consumes.
  """
  @type t :: %__MODULE__{
          response_type: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          scope: [String.t()],
          resource: [String.t()],
          openid?: boolean(),
          state: String.t() | nil,
          nonce: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          prompt: [String.t()],
          max_age: non_neg_integer() | nil,
          claims: map(),
          acr_values: [String.t()],
          response_mode: String.t() | nil,
          dpop_jkt: String.t() | nil
        }

  # `code_challenge`/`code_challenge_method` are NOT enforced keys: PKCE is
  # required by default but may be relaxed for a confidential client via the
  # `:require_pkce` option (RFC 9700 keeps PKCE MUST only for public clients),
  # in which case a validated request carries no challenge. They default to nil
  # in the struct.
  @enforce_keys [
    :response_type,
    :client_id,
    :redirect_uri
  ]
  defstruct [
    :client_id,
    :code_challenge,
    :code_challenge_method,
    :claims,
    :max_age,
    :nonce,
    :redirect_uri,
    :response_type,
    :state,
    acr_values: [],
    openid?: false,
    prompt: [],
    scope: [],
    resource: [],
    response_mode: nil,
    dpop_jkt: nil
  ]

  @typedoc """
  A redirectable authorization error (RFC 6749 §4.1.2.1).

  Errors raised once the client is trusted (from `validate_redirectable/5`) also
  carry `:response_mode` (the requested JARM mode, or `nil`) and `:client_id`,
  so the transport can return the error in the requested response mode
  (JARM §2.3); earlier errors omit them.
  """
  @type redirect_error :: %{
          required(:error) => String.t(),
          required(:error_description) => String.t(),
          required(:redirect_uri) => String.t(),
          required(:state) => String.t() | nil,
          optional(:response_mode) => String.t() | nil,
          optional(:client_id) => String.t()
        }

  @typedoc "The classification of a validation failure (OIDC Core §3.1.2.6)."
  @type error ::
          {:direct,
           :invalid_client_id
           | :missing_redirect_uri
           | :invalid_redirect_uri
           | :redirect_uri_not_registered}
          | {:redirect, redirect_error()}

  @doc """
  Validate a parsed authorization request parameter map (RFC 6749 §4.1.1,
  OIDC Core §3.1.2.1, RFC 7636 §4.3).

  `params` is a string-keyed map of the authorization request query parameters.

  ## Options

    * `:registered_redirect_uris` (required) - the list of redirect URIs
      registered for the client. The request `redirect_uri` MUST be an exact
      string match against one of these (RFC 6749 §3.1.2.3, OIDC Core
      §3.1.2.1). An empty list rejects every request with
      `{:direct, :redirect_uri_not_registered}`.

    * `:redirect_uri_matching` (optional, default `:exact`) - how the request
      `redirect_uri` is compared against `:registered_redirect_uris`, one of
      `Attesto.RedirectURI.matching_modes/0`. `:exact` is the RFC 6749
      §3.1.2.3 simple string comparison. `:exact_allow_loopback_port` adds the
      RFC 8252 §7.3 exception for native apps, under which a loopback redirect
      URI (`http://127.0.0.1/...` or `http://[::1]/...`, never
      `http://localhost/...` - §8.3) matches on any port while scheme, host,
      path, and query still compare exactly; nothing else is relaxed. Enabling
      it is a host decision, incompatible with profiles that mandate exact
      redirect-URI matching. An unrecognized value raises `ArgumentError`.

    * `:require_nonce` (optional, default `false`) - the host's OP nonce policy.
      When `true`, an OpenID Connect Authentication Request (one whose EFFECTIVE
      scope - after any signed `request` object is merged - carries `openid`)
      with no `nonce` is rejected with a redirectable `invalid_request` error
      (OIDC Core §3.1.2.1). The openid test runs on the merged request, so a
      `scope=openid` carried only inside a signed request object still triggers
      the requirement. A plain OAuth request (no `openid` scope) is never
      nonce-constrained (RFC 6749 keeps `code` at SHOULD). When `false`, `nonce`
      stays OPTIONAL and is carried through unenforced.

    * `:require_pkce` (optional, default `true`) - when `true`, a request with no
      `code_challenge` is rejected with a redirectable `invalid_request` error
      (RFC 7636 §4.3). When `false`, an absent `code_challenge` is permitted and
      the validated request carries none. The caller MUST pass `false` only for a
      confidential client: RFC 9700 §2.1.1 keeps PKCE a MUST for public clients.
      A `code_challenge` that IS present is fully enforced (S256, no `plain`)
      regardless of this flag - presence means the client opted into PKCE, so a
      downgrade is always rejected.

    * `:request_object_policy` (optional, default `%Attesto.RequestObject.Policy{}`)
      - the JAR verification policy for a signed `request` object (RFC 9101),
      threaded into `Attesto.RequestObject.verify/3`. The default is the generic
      OpenID Connect §6.1 baseline (`nbf`/`exp`/`typ` not required). For FAPI 2.0
      Message Signing §5.3.1 pass `Attesto.RequestObject.Policy.fapi_message_signing/0`
      and set `:request_object_audience` to the AS issuer. Has no effect unless a
      `request` object is present.

  Returns `{:ok, %Attesto.AuthorizationRequest{}}` or `{:error, error()}`, where
  `error()` is classified per the moduledoc.

  The `client_id` / `redirect_uri` checks run first, because their failure is
  non-redirectable (OIDC Core §3.1.2.6): only once a trusted `redirect_uri` is
  established may any further error be reported by redirecting to it.
  """
  @spec validate(map(), keyword()) :: {:ok, t()} | {:error, error()}
  def validate(params, opts) when is_map(params) and is_list(opts) do
    registered = Keyword.fetch!(opts, :registered_redirect_uris)
    matching = redirect_uri_matching(opts)
    require_nonce_policy = Keyword.get(opts, :require_nonce, @default_require_nonce)
    require_pkce = Keyword.get(opts, :require_pkce, @default_require_pkce)

    with {:ok, params} <- merge_request_object(params, opts),
         {:ok, client_id} <- validate_client_id(params),
         {:ok, redirect_uri} <- validate_redirect_uri(params, registered, matching) do
      # OIDC Core §3.1.2.1: the nonce requirement applies only to an OpenID
      # Connect Authentication Request, judged on the EFFECTIVE (post-merge)
      # scope. A direct JAR can carry `scope=openid` only inside the signed
      # request object, so the openid gate MUST run here, after
      # merge_request_object/2 - never on the raw outer params, or a signed
      # request object would bypass the host's `require_nonce` policy.
      require_nonce = require_nonce_policy and oidc_request?(params)

      # From here on, redirect_uri is trusted: report further errors by
      # redirecting to it (RFC 6749 §4.1.2.1).
      validate_redirectable(params, client_id, redirect_uri, require_nonce, require_pkce)
    end
  end

  # OIDC Core §3.1.2.1: an OpenID Connect Authentication Request is one whose
  # (effective) `scope` carries the reserved `openid` value.
  defp oidc_request?(params), do: @openid_scope in parse_space_list(Map.get(params, "scope"))

  # RFC 9449 §10: the `dpop_jkt` authorization-request parameter (the JWK SHA-256
  # thumbprint the issued code is bound to). Read from the effective params so a
  # signed request object's value wins; the format is enforced at code redemption.
  defp dpop_jkt(params) do
    case Map.get(params, "dpop_jkt") do
      jkt when is_binary(jkt) and jkt != "" -> jkt
      _ -> nil
    end
  end

  @doc """
  The response modes this authorization-code server accepts (OAuth 2.0 Response
  Modes / JARM §2.3): `query` and the JARM JWT modes. Exposed so the discovery
  document advertises exactly what `validate/2` enforces.
  """
  @spec supported_response_modes() :: [String.t()]
  def supported_response_modes, do: @supported_response_modes

  defp merge_request_object(%{"request" => request} = params, opts) when is_binary(request) and request != "" do
    policy = Keyword.get(opts, :request_object_policy, %Policy{})

    with {:ok, jwks} <- fetch_request_object_jwks(opts),
         {:ok, object_params} <-
           RequestObject.verify(
             request,
             jwks,
             [
               issuer: Map.get(params, "client_id"),
               audience: Keyword.get(opts, :request_object_audience)
             ] ++ Policy.to_verify_opts(policy)
           ) do
      {:ok, object_params}
    else
      {:error, :request_not_supported} ->
        redirect_request_object_error(params, "request_not_supported", "request object is not supported", opts)

      _ ->
        redirect_request_object_error(params, "invalid_request_object", "request object is invalid", opts)
    end
  end

  # No (or empty) `request` object present. RFC 9101 / FAPI 2.0 Message Signing
  # §5.3.1: when the policy requires a signed request object, a request carrying
  # none is rejected (redirectable invalid_request); otherwise the plain
  # parameters stand (generic OpenID Connect §6.1).
  defp merge_request_object(params, opts) do
    policy = Keyword.get(opts, :request_object_policy, %Policy{})

    if Policy.require_request_object?(policy) do
      require_present_request_object(params, opts)
    else
      {:ok, params}
    end
  end

  # FAPI 2.0 Message Signing §5.3.1: a required-but-absent request object is a
  # redirectable invalid_request once the client is trusted, classified entirely
  # by redirect_request_object_error/4 below.
  defp require_present_request_object(params, opts) do
    redirect_request_object_error(
      params,
      "invalid_request",
      "a signed request object is required",
      opts
    )
  end

  # A request-object failure (invalid object, or a required one absent) is only
  # redirectable once the client is trusted: OIDC Core §3.1.2.6 keeps a
  # missing/invalid client_id or an unregistered redirect_uri non-redirectable
  # (direct). Once both are trusted, enrich the error with the requested JARM
  # response_mode and the client_id audience (JARM §2.3 / §5.4) so the transport
  # can return the error as a signed JWT, exactly as validate_redirectable/5
  # does for the checks it owns. response_mode is read from the top-level
  # parameters: an invalid object's signed contents are untrusted, so a mode
  # carried only inside it is unknowable and the transport falls back to query.
  defp redirect_request_object_error(params, error, description, opts) do
    with {:ok, client_id} <- validate_client_id(params),
         {:ok, redirect_uri} <-
           validate_redirect_uri(
             params,
             Keyword.fetch!(opts, :registered_redirect_uris),
             redirect_uri_matching(opts)
           ) do
      state = string_or_nil(Map.get(params, "state"))
      {:redirect, base} = redirect_error(error, description, redirect_uri, state)
      {:error, {:redirect, Map.merge(base, redirect_error_context(params, client_id))}}
    end
  end

  defp fetch_request_object_jwks(opts) do
    case Keyword.get(opts, :request_object_jwks) do
      nil -> {:error, :missing_request_object_jwks}
      jwks -> {:ok, jwks}
    end
  end

  # --- Non-redirectable checks (OIDC Core §3.1.2.6) ---

  # RFC 6749 §4.1.1: client_id is REQUIRED. A missing or non-string client_id
  # cannot be trusted, so the error is reported directly, not by redirect.
  defp validate_client_id(params) do
    case Map.get(params, "client_id") do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, {:direct, :invalid_client_id}}
    end
  end

  # The caller's redirect-URI matching policy (RFC 6749 §3.1.2.3, RFC 8252
  # §7.3). Normalized through `Attesto.RedirectURI.matching!/1` so an
  # unrecognized value raises rather than silently selecting a policy the host
  # did not ask for.
  defp redirect_uri_matching(opts) do
    opts
    |> Keyword.get(:redirect_uri_matching, @default_redirect_uri_matching)
    |> RedirectURI.matching!()
  end

  # RFC 6749 §3.1.2.3 / OIDC Core §3.1.2.1: redirect_uri is REQUIRED for OIDC
  # and MUST match one of the client's registered URIs under the caller's
  # matching policy (exact by default; see `Attesto.RedirectURI`). A mismatch is
  # non-redirectable because the supplied URI is untrusted (OIDC Core §3.1.2.6):
  # an unmatched URI is never returned as a redirect target under any policy.
  defp validate_redirect_uri(params, registered, matching) do
    case Map.get(params, "redirect_uri") do
      uri when is_binary(uri) and uri != "" ->
        if RedirectURI.registered?(uri, registered, matching) do
          {:ok, uri}
        else
          {:error, {:direct, :redirect_uri_not_registered}}
        end

      nil ->
        {:error, {:direct, :missing_redirect_uri}}

      _ ->
        {:error, {:direct, :invalid_redirect_uri}}
    end
  end

  # --- Redirectable checks (RFC 6749 §4.1.2.1) ---

  defp validate_redirectable(params, client_id, redirect_uri, require_nonce, require_pkce) do
    state = string_or_nil(Map.get(params, "state"))

    with :ok <- validate_request_object_params(params, redirect_uri, state),
         :ok <- validate_response_type(params, redirect_uri, state),
         {:ok, scope} <- validate_scope(params, redirect_uri, state),
         {:ok, resource} <- validate_resource(params, redirect_uri, state),
         {:ok, code_challenge, method} <- validate_pkce(params, require_pkce, redirect_uri, state),
         {:ok, max_age} <- validate_max_age(params, redirect_uri, state),
         {:ok, prompt} <- validate_prompt(params, redirect_uri, state),
         {:ok, claims} <- validate_claims(params, redirect_uri, state),
         {:ok, nonce} <- validate_nonce(params, require_nonce, redirect_uri, state),
         {:ok, response_mode} <- validate_response_mode(params, redirect_uri, state) do
      {:ok,
       %__MODULE__{
         response_type: @response_type_code,
         client_id: client_id,
         redirect_uri: redirect_uri,
         scope: scope,
         resource: resource,
         openid?: @openid_scope in scope,
         state: state,
         nonce: nonce,
         code_challenge: code_challenge,
         code_challenge_method: method,
         prompt: prompt,
         max_age: max_age,
         claims: claims,
         acr_values: parse_space_list(Map.get(params, "acr_values")),
         response_mode: response_mode,
         # RFC 9449 §10: the DPoP key thumbprint to bind the issued code to,
         # read from the EFFECTIVE params - so a signed request object's
         # `dpop_jkt` is authoritative and an unsigned outer-query `dpop_jkt` is
         # ignored when a request object is present (the object replaces the
         # outer params above). A bare/empty value is treated as absent.
         dpop_jkt: dpop_jkt(params)
       }}
    else
      # JARM §2.3 / FAPI 2.0 Message Signing §5.4: a redirectable error must be
      # returned in the requested response mode too. The client is trusted by
      # now (client_id resolved, redirect_uri registered), so enrich the error
      # with the requested response_mode and the audience (client_id) the
      # transport needs to encode the error as a signed JWT. A request whose
      # response_mode is itself unsupported never reaches here as a JWT mode, so
      # such errors fall back to the default (query) at the transport.
      {:error, {:redirect, error}} ->
        {:error, {:redirect, Map.merge(error, redirect_error_context(params, client_id))}}
    end
  end

  # Only a supported JARM response_mode is carried onto an error; an absent or
  # unsupported value leaves it nil so the transport uses its default encoding.
  defp redirect_error_context(params, client_id) do
    response_mode =
      case Map.get(params, "response_mode") do
        mode when mode in @supported_response_modes -> mode
        _ -> nil
      end

    %{response_mode: response_mode, client_id: client_id}
  end

  # OAuth 2.0 Response Modes / JARM §2.3: response_mode is OPTIONAL; absent means
  # the response_type's default (`query` for code), surfaced here as nil so the
  # transport applies its default. A supported value is carried through; an
  # unsupported or non-string value is a redirectable invalid_request.
  defp validate_response_mode(params, redirect_uri, state) do
    case Map.get(params, "response_mode") do
      nil ->
        {:ok, nil}

      mode when mode in @supported_response_modes ->
        {:ok, mode}

      _ ->
        {:error,
         redirect_error(
           "invalid_request",
           "unsupported response_mode",
           redirect_uri,
           state
         )}
    end
  end

  # OpenID Connect Core §6 / RFC 9101 §6.3: when a request object is present,
  # `merge_request_object/2` has already replaced the effective authorization
  # parameter map with the verified object parameters. A raw `request_uri` is
  # still rejected here unless the transport layer has already resolved it
  # (PAR) into normal params.
  defp validate_request_object_params(params, redirect_uri, state) do
    if present?(Map.get(params, "request_uri")) do
      {:error,
       redirect_error(
         "request_uri_not_supported",
         "request_uri parameter is not supported",
         redirect_uri,
         state
       )}
    else
      :ok
    end
  end

  # RFC 6749 §4.1.1 / OIDC Core §3.1.2.1: response_type is REQUIRED and must be
  # "code" for the authorization-code flow. Any other value is the
  # "unsupported_response_type" error (RFC 6749 §4.1.2.1); a wholly absent one
  # is "invalid_request".
  defp validate_response_type(params, redirect_uri, state) do
    case Map.get(params, "response_type") do
      @response_type_code ->
        :ok

      nil ->
        {:error, redirect_error("invalid_request", "response_type is required", redirect_uri, state)}

      _ ->
        {:error,
         redirect_error(
           "unsupported_response_type",
           "only response_type=code is supported",
           redirect_uri,
           state
         )}
    end
  end

  # RFC 6749 §3.3: scope is OPTIONAL and space-delimited. Each token must satisfy
  # the RFC 6749 Appendix A scope-token ABNF (`Attesto.Scope.valid_token?/1`); an
  # out-of-ABNF token is the "invalid_scope" error (RFC 6749 §4.1.2.1). The
  # OpenID Connect `openid` scope (OIDC Core §3.1.2.1) is surfaced via `openid?`
  # so the host can branch OIDC vs plain OAuth without re-parsing.
  defp validate_scope(params, redirect_uri, state) do
    case Map.get(params, "scope") do
      nil ->
        {:ok, []}

      value when is_binary(value) ->
        tokens = String.split(value, " ", trim: true)

        if Enum.all?(tokens, &Scope.valid_token?/1) do
          {:ok, tokens}
        else
          {:error,
           redirect_error(
             "invalid_scope",
             "scope contains an invalid token",
             redirect_uri,
             state
           )}
        end

      _ ->
        {:error, redirect_error("invalid_scope", "scope must be a string", redirect_uri, state)}
    end
  end

  # RFC 8707 §2: the OPTIONAL `resource` parameter (scalar or array) requests
  # that the issued token be audienced to the named protected resource(s). Each
  # value must be an absolute URI with no fragment (§2.1); a malformed value is
  # the redirectable `invalid_target` error (RFC 6749 §4.1.2.1). Authorization
  # against the resources this server actually serves (§2.2) is applied where the
  # token is minted; here the syntactically valid set is bound to the request so
  # the issued code carries the resources the user authorized.
  defp validate_resource(params, redirect_uri, state) do
    case ResourceIndicator.validate(Map.get(params, "resource")) do
      {:ok, resources} ->
        {:ok, resources}

      {:error, :invalid_target} ->
        {:error,
         redirect_error(
           "invalid_target",
           "resource is not a valid absolute-URI indicator",
           redirect_uri,
           state
         )}
    end
  end

  # RFC 7636 §4.3 / RFC 9700: code_challenge is REQUIRED by default and
  # code_challenge_method must be "S256". A missing/malformed challenge or the
  # "plain" method is rejected as "invalid_request" (RFC 7636 §4.4.1, OAuth 2.0
  # Security BCP); "plain" is matched explicitly so the host can see the
  # downgrade attempt.
  #
  # When the caller relaxes the requirement (`require_pkce: false`, only ever
  # for a confidential client - public clients MUST use PKCE per RFC 9700
  # §2.1.1), a wholly absent `code_challenge` is permitted and the request
  # carries none (`{:ok, nil, nil}`). A challenge that IS present is still fully
  # enforced regardless of the flag: presence implies the client opted into
  # PKCE, so a downgrade or non-S256 method is always rejected.
  defp validate_pkce(params, require_pkce, redirect_uri, state) do
    challenge = Map.get(params, "code_challenge")
    method = Map.get(params, "code_challenge_method")

    cond do
      is_nil(challenge) and not require_pkce ->
        {:ok, nil, nil}

      not PKCE.valid_challenge?(challenge) ->
        {:error,
         redirect_error(
           "invalid_request",
           "a valid S256 code_challenge is required",
           redirect_uri,
           state
         )}

      method == @plain_method ->
        {:error,
         redirect_error(
           "invalid_request",
           "code_challenge_method=plain is not supported; use S256",
           redirect_uri,
           state
         )}

      method != PKCE.method() ->
        {:error,
         redirect_error(
           "invalid_request",
           "code_challenge_method=S256 is required",
           redirect_uri,
           state
         )}

      true ->
        {:ok, challenge, method}
    end
  end

  # OIDC Core §3.1.2.1: max_age is OPTIONAL and, when present, a non-negative
  # integer number of seconds. A non-integer or negative value is
  # "invalid_request".
  defp validate_max_age(params, redirect_uri, state) do
    case Map.get(params, "max_age") do
      nil ->
        {:ok, nil}

      value when is_integer(value) and value >= 0 ->
        {:ok, value}

      value when is_binary(value) ->
        case Integer.parse(value) do
          {seconds, ""} when seconds >= 0 -> {:ok, seconds}
          _ -> {:error, invalid_max_age(redirect_uri, state)}
        end

      _ ->
        {:error, invalid_max_age(redirect_uri, state)}
    end
  end

  defp invalid_max_age(redirect_uri, state) do
    redirect_error(
      "invalid_request",
      "max_age must be a non-negative integer",
      redirect_uri,
      state
    )
  end

  # OIDC Core §3.1.2.1: prompt is OPTIONAL and a space-delimited list whose
  # values are drawn from the fixed set {none, login, consent, select_account}.
  # An unknown token is "invalid_request" (OIDC Core §3.1.2.1). The parsed list
  # is exposed for the controller, which enforces semantics such as prompt=none
  # (the OP MUST NOT show UI); this module does not act on the values.
  defp validate_prompt(params, redirect_uri, state) do
    tokens = parse_space_list(Map.get(params, "prompt"))

    if Enum.all?(tokens, &(&1 in @prompt_values)) do
      {:ok, tokens}
    else
      {:error,
       redirect_error(
         "invalid_request",
         "prompt contains an unknown value",
         redirect_uri,
         state
       )}
    end
  end

  # OIDC Core §5.5: `claims` is OPTIONAL and, when present, is a JSON object.
  # The engine treats it as opaque request context and leaves claim-release
  # policy to the host/UserInfo layer; malformed JSON or a non-object value is
  # a redirectable invalid_request.
  defp validate_claims(params, redirect_uri, state) do
    case Map.get(params, "claims") do
      nil ->
        {:ok, %{}}

      value when is_binary(value) ->
        case JSON.decode(value) do
          {:ok, claims} when is_map(claims) ->
            {:ok, claims}

          _ ->
            {:error, redirect_error("invalid_request", "claims must be a JSON object", redirect_uri, state)}
        end

      _ ->
        {:error, redirect_error("invalid_request", "claims must be a JSON object", redirect_uri, state)}
    end
  end

  # OIDC Core §3.1.2.1: nonce is OPTIONAL for the code flow (RFC 6749 stays at
  # SHOULD), but REQUIRED when the OP policy demands it. The caller signals that
  # policy via require_nonce; a missing nonce under that policy is the
  # redirectable "invalid_request" error (OIDC Core §3.1.2.1).
  defp validate_nonce(params, require_nonce, redirect_uri, state) do
    case {string_or_nil(Map.get(params, "nonce")), require_nonce} do
      {nil, true} ->
        {:error,
         redirect_error(
           "invalid_request",
           "nonce is required",
           redirect_uri,
           state
         )}

      {nonce, _} ->
        {:ok, nonce}
    end
  end

  defp redirect_error(code, description, redirect_uri, state) do
    {:redirect,
     %{
       error: code,
       error_description: description,
       redirect_uri: redirect_uri,
       state: state
     }}
  end

  # OIDC Core §3.1.2.1 defines prompt and acr_values as space-delimited lists.
  defp parse_space_list(value) when is_binary(value), do: String.split(value, " ", trim: true)
  defp parse_space_list(_), do: []

  defp present?(value) when is_binary(value) and value != "", do: true
  defp present?(_), do: false

  defp string_or_nil(value) when is_binary(value) and value != "", do: value
  defp string_or_nil(_), do: nil
end
