defmodule Attesto.CIBA.Request do
  @moduledoc """
  A validated CIBA backchannel authentication request (CIBA Core §7.1).

  `validate/3` runs the request-shape validation of the backchannel
  authentication endpoint on the *authenticated* client's wire parameters:
  the scope rules, the exactly-one-hint rule, the delivery-mode-dependent
  `client_notification_token` requirement, `binding_message` / `user_code` /
  `requested_expiry` shape checks, and - when the client sends a signed
  authentication request (§7.1.1) - JWT verification against the client's
  registered JWKS via `Attesto.RequestObject`.

  It is deliberately conn-free and registry-free: client authentication
  (`invalid_client`) and the client's registered CIBA metadata are the host's
  concern; the host passes the latter in as the `client` map. What this module
  can NOT decide is anything requiring the resolved end-user - hint resolution
  (`unknown_user_id`, `expired_login_hint_token`) and user-code verification
  (`missing_user_code`, `invalid_user_code`) happen in the host between
  `validate/3` and `Attesto.CIBA.issue/4`.

  ## Signed authentication requests (§7.1.1, FAPI-CIBA §5.2.2)

  When `params` carries a `request` JWT it MUST be the only authentication
  request parameter - the spec forbids parameters outside the JWT, so any
  other key present alongside `request` is rejected. (Client-authentication
  parameters such as `client_assertion` are allowed on the wire; the caller
  strips them before calling `validate/3`.) The JWT is verified with the
  client's registered JWKS and must carry `iss` (the `client_id`), `aud` (the
  OP's Issuer Identifier, passed as `:issuer`), `exp`, `iat`, `nbf`, and
  `jti` - all REQUIRED by §7.1.1. FAPI-CIBA additionally requires that ALL
  requests be signed (`require_signed_request: true`) and bounds the
  `nbf`→`exp` lifetime to 60 minutes (the `:max_request_lifetime_seconds`
  default).

  Each known CIBA authentication-request parameter carried in the signed JWT
  (`scope`, the hints, `binding_message`, `user_code`, `acr_values`,
  `client_notification_token`) MUST be a JSON string per §7.1.1; a non-string
  value is rejected as `invalid_request` rather than coerced. `requested_expiry`
  may be a string or a number.

  ## Replay defense (FAPI-CIBA §5.2.2)

  A verified signed request exposes its `jti` and `exp` on the returned struct
  as `request_jti` / `request_exp` (both `nil` for an unsigned request). The
  core does NOT track `jti` - it is stateless by design - so **the host MUST
  record each signed request's `request_jti` for the request's lifetime (until
  `request_exp`) and reject a repeat** at the `validate/3` boundary. Without
  this, a captured signed authentication request can be replayed to start
  duplicate CIBA transactions within its lifetime.
  """

  alias Attesto.RequestObject
  alias Attesto.Scope
  alias Attesto.SigningAlg

  @hint_params ~w(login_hint login_hint_token id_token_hint)

  # CIBA Core §7.1.1: the known authentication-request parameters MUST be JSON
  # strings in a signed request (a non-string value is invalid_request, not a
  # coerced string). `requested_expiry` is deliberately excluded - §7.1.1 lets
  # it be a string OR a number - as are extension claims, which may be other
  # JSON types. This is CIBA-signed-request specific: RFC 9101 JAR keeps the
  # lenient claim coercion.
  @signed_string_params ~w(
    scope login_hint login_hint_token id_token_hint binding_message
    user_code acr_values client_notification_token
  )

  # RFC 6750 §2.1 b64token syntax, the required form of a
  # client_notification_token (CIBA Core §7.1).
  @b64token ~r/\A[A-Za-z0-9\-._~+\/]+=*\z/

  # CIBA Core §7.1: the client_notification_token must not exceed 1024
  # characters and must carry >=128 bits of entropy (160 recommended). The
  # entropy floor is approximated as a length floor: 128 bits base64-encoded
  # is 22 characters.
  @notification_token_max_length 1024
  @default_notification_token_min_length 22

  @default_binding_message_max_length 128
  @default_user_code_max_length 64

  # FAPI-CIBA §5.2.2: the signed authentication request's nbf/exp lifetime
  # must not exceed 60 minutes.
  @default_max_request_lifetime_seconds 3600

  @enforce_keys [:client_id, :delivery_mode, :hint, :scope]
  defstruct [
    :binding_message,
    :client_id,
    :client_notification_token,
    :delivery_mode,
    :hint,
    :request_exp,
    :request_jti,
    :requested_expiry,
    :user_code,
    acr_values: [],
    scope: [],
    signed?: false
  ]

  @typedoc "Which of the three CIBA §7.1 hints the client sent, and its value."
  @type hint :: {:login_hint | :login_hint_token | :id_token_hint, String.t()}

  @type delivery_mode :: :poll | :ping | :push

  @type t :: %__MODULE__{
          acr_values: [String.t()],
          binding_message: String.t() | nil,
          client_id: String.t(),
          client_notification_token: String.t() | nil,
          delivery_mode: delivery_mode(),
          hint: hint(),
          request_exp: non_neg_integer() | nil,
          request_jti: String.t() | nil,
          requested_expiry: pos_integer() | nil,
          scope: [String.t()],
          signed?: boolean(),
          user_code: String.t() | nil
        }

  @typedoc """
  The authenticated client's registered CIBA metadata (CIBA Core §4):

    * `:client_id` (required) - the authenticated client.
    * `:token_delivery_mode` (required) - `:poll` | `:ping` | `:push`, the
      registered `backchannel_token_delivery_mode`. A client without one is
      not registered for CIBA (`unauthorized_client`). Note FAPI-CIBA forbids
      `:push`.
    * `:jwks` - the client's registered public keys, required to accept a
      signed authentication request.
    * `:request_signing_alg` - the registered
      `backchannel_authentication_request_signing_alg`; when set, a signed
      request must use exactly this algorithm.
    * `:user_code_parameter` - the registered
      `backchannel_user_code_parameter` (default `false`).
  """
  @type client :: %{
          required(:client_id) => String.t(),
          required(:token_delivery_mode) => delivery_mode(),
          optional(:jwks) => map() | [map()] | nil,
          optional(:request_signing_alg) => String.t() | nil,
          optional(:user_code_parameter) => boolean()
        }

  @type error :: :invalid_request | :invalid_scope | :invalid_binding_message | :unauthorized_client

  @doc """
  Validate the wire parameters of a backchannel authentication request for an
  authenticated client (CIBA Core §7.1 / §7.1.1).

  `params` is the string-keyed parameter map with any client-authentication
  parameters (`client_id`, `client_assertion`, ...) already stripped by the
  caller. Options:

    * `:issuer` - the OP's Issuer Identifier, the required `aud` of a signed
      authentication request. Required to accept signed requests.
    * `:require_signed_request` - when `true`, reject a plain-parameter
      request (FAPI-CIBA §5.2.2 requires signed requests). Default `false`.
    * `:accepted_algs` - JOSE algorithms acceptable for signed requests.
      Defaults to `Attesto.SigningAlg.default_client_algs/0`, including legacy
      EdDSA only over Ed25519 and RFC 9864 Ed25519, never Ed448. Supplying a
      list selects an explicit non-FAPI algorithm policy unless
      `:enforce_fapi_alg_policy` is also `true`. The client's registered
      `:request_signing_alg`, when set, must be inside this set and becomes the
      only accepted algorithm.
    * `:enforce_fapi_alg_policy` - enforce the FAPI RSA modulus and Edwards
      curve restrictions in addition to `:accepted_algs`. Defaults to `true`
      when `:accepted_algs` is omitted and `false` when the caller supplies an
      explicit algorithm policy. Composed FAPI profiles that narrow the
      allowlist must pass `true`.
    * `:max_request_lifetime_seconds` - bound on a signed request's
      `nbf`→`exp` lifetime. Default `#{@default_max_request_lifetime_seconds}`
      (FAPI-CIBA §5.2.2's 60 minutes).
    * `:user_code_supported` - whether this OP advertises
      `backchannel_user_code_parameter_supported`. A `user_code` sent when the
      OP or the client's registration does not support it is rejected.
      Default `false`.
    * `:binding_message_max_length` - maximum `binding_message` length in
      graphemes. Default `#{@default_binding_message_max_length}`.
    * `:require_binding_message` - when `true`, a request without a
      `binding_message` is rejected with `invalid_binding_message` (FAPI-CIBA
      §5.2.2 requires one when no other unique authorization context exists).
      Default `false`.
    * `:min_client_notification_token_length` - entropy floor for ping/push
      `client_notification_token`s, as a length lower bound. Default
      `#{@default_notification_token_min_length}` (128 bits base64-encoded).
    * `:now` - unix seconds or `DateTime`, for signed-request time checks.

  Returns `{:ok, %#{inspect(__MODULE__)}{}}` or `{:error, reason}` where
  `reason` is the CIBA §13 error code the endpoint renders: `:invalid_request`
  (malformed/missing parameters, or a signed request that fails verification),
  `:invalid_scope`, `:invalid_binding_message`, or `:unauthorized_client` (the
  client is not registered for CIBA).
  """
  @spec validate(client(), map(), keyword()) :: {:ok, t()} | {:error, error()}
  def validate(client, params, opts \\ []) when is_map(client) and is_map(params) and is_list(opts) do
    with {:ok, client_id, mode} <- validate_client(client),
         {:ok, params, signed} <- unwrap_signed_request(client, params, opts),
         :ok <- reject_request_uri(params),
         {:ok, scope} <- validate_scope(params),
         {:ok, hint} <- validate_hint(params),
         {:ok, notification_token} <- validate_notification_token(mode, params, opts),
         {:ok, binding_message} <- validate_binding_message(params, opts),
         {:ok, user_code} <- validate_user_code(client, params, opts),
         {:ok, requested_expiry} <- validate_requested_expiry(params),
         {:ok, acr_values} <- validate_acr_values(params) do
      {:ok,
       %__MODULE__{
         acr_values: acr_values,
         binding_message: binding_message,
         client_id: client_id,
         client_notification_token: notification_token,
         delivery_mode: mode,
         hint: hint,
         request_exp: signed.exp,
         request_jti: signed.jti,
         requested_expiry: requested_expiry,
         scope: scope,
         signed?: signed.signed?,
         user_code: user_code
       }}
    end
  end

  # ----- client registration -----

  defp validate_client(%{client_id: client_id, token_delivery_mode: mode})
       when is_binary(client_id) and client_id != "" and mode in [:poll, :ping, :push], do: {:ok, client_id, mode}

  # A client without a registered backchannel_token_delivery_mode is not
  # registered for CIBA (CIBA Core §4: the parameter is REQUIRED).
  defp validate_client(_client), do: {:error, :unauthorized_client}

  # ----- signed authentication request (§7.1.1) -----

  defp unwrap_signed_request(client, %{"request" => jwt} = params, opts) do
    # §7.1.1: authentication request parameters MUST NOT be present outside
    # the JWT, so `request` must be the only key the caller passed.
    with :ok <- require_lone_request_param(params),
         {:ok, algs} <- signed_request_algs(client, opts),
         {:ok, jwks} <- registered_jwks(client),
         {:ok, unwrapped, claims} <- verify_signed_request(jwt, jwks, client, algs, opts) do
      # §7.1.1 makes jti/exp REQUIRED and RequestObject verified them, so they
      # are present; surface them for the host's FAPI-CIBA replay guard.
      {:ok, unwrapped, %{signed?: true, jti: Map.get(claims, "jti"), exp: Map.get(claims, "exp")}}
    end
  end

  defp unwrap_signed_request(_client, params, opts) do
    if Keyword.get(opts, :require_signed_request, false) == true,
      do: {:error, :invalid_request},
      else: {:ok, params, %{signed?: false, jti: nil, exp: nil}}
  end

  defp require_lone_request_param(params) do
    if map_size(params) == 1, do: :ok, else: {:error, :invalid_request}
  end

  # The client's registered backchannel_authentication_request_signing_alg,
  # when present, pins the accepted algorithm - and must itself sit inside the
  # caller's policy set.
  defp signed_request_algs(client, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.default_client_algs())

    case Map.get(client, :request_signing_alg) do
      nil -> {:ok, accepted}
      alg when is_binary(alg) -> if alg in accepted, do: {:ok, [alg]}, else: {:error, :invalid_request}
      _other -> {:error, :invalid_request}
    end
  end

  defp registered_jwks(%{jwks: jwks}) when is_map(jwks) or is_list(jwks), do: {:ok, jwks}
  # A client with no registered keys cannot have signed anything.
  defp registered_jwks(_client), do: {:error, :invalid_request}

  defp verify_signed_request(jwt, jwks, client, algs, opts) when is_binary(jwt) do
    issuer = Keyword.get(opts, :issuer)

    if is_binary(issuer) and issuer != "" do
      verify_opts = [
        now: Keyword.get(opts, :now),
        # §7.1.1: `iss` MUST be the client_id; there is no separate client_id
        # claim in a CIBA signed authentication request.
        issuer: client.client_id,
        require_client_id_claim: false,
        # §7.1.1: `aud` MUST contain the OP's Issuer Identifier.
        audience: issuer,
        # Explicit typing (RFC 9101 §10.8): a CIBA signed authentication request
        # and an authorization-endpoint JAR both require `aud` = this issuer and
        # `iss` = the client, so `aud` cannot tell them apart. CIBA §7.1.1
        # defines no `typ`, so accept an absent header or the generic `JWT`
        # media type (RFC 7519 §5.1; the value JOSE-family signers emit by
        # default) and reject a request bearing the authorization endpoint's
        # `oauth-authz-req+jwt` - that explicit type must not be honoured as a
        # backchannel request. Defence-in-depth: the client is separately
        # authenticated before we get here, so a cross-context request object
        # already cannot arrive without the client's own credentials.
        accepted_typ: [nil, "JWT"],
        accepted_algs: algs,
        enforce_fapi_alg_policy:
          Keyword.get(opts, :enforce_fapi_alg_policy, not Keyword.has_key?(opts, :accepted_algs)),
        # §7.1.1 makes exp, iat, nbf, and jti all REQUIRED.
        require_exp: true,
        require_iat: true,
        require_nbf: true,
        require_jti: true,
        max_lifetime_seconds: Keyword.get(opts, :max_request_lifetime_seconds, @default_max_request_lifetime_seconds),
        # §7.1.1: known CIBA authentication-request parameters MUST be JSON
        # strings; reject a non-string value instead of coercing it.
        string_valued_claims: @signed_string_params
      ]

      case RequestObject.verify_with_claims(jwt, jwks, verify_opts) do
        {:ok, unwrapped, claims} -> {:ok, unwrapped, claims}
        # CIBA §13 has no request-object-specific error code; every
        # verification failure is an invalid_request at this endpoint.
        {:error, _reason} -> {:error, :invalid_request}
      end
    else
      raise ArgumentError,
            "accepting a CIBA signed authentication request requires the :issuer option " <>
              "(the OP's Issuer Identifier, the JWT's required aud)"
    end
  end

  defp verify_signed_request(_jwt, _jwks, _client, _algs, _opts), do: {:error, :invalid_request}

  # CIBA defines no request_uri at the backchannel authentication endpoint;
  # fail closed rather than silently ignoring it.
  defp reject_request_uri(params) do
    if Map.has_key?(params, "request_uri"), do: {:error, :invalid_request}, else: :ok
  end

  # ----- scope (§7.1: REQUIRED, MUST contain openid) -----

  defp validate_scope(%{"scope" => scope}) when is_binary(scope) do
    scopes = Scope.parse(scope, allow_empty?: false)

    cond do
      scopes == :empty -> {:error, :invalid_request}
      not Scope.valid_list?(scopes) -> {:error, :invalid_scope}
      "openid" not in scopes -> {:error, :invalid_scope}
      true -> {:ok, scopes}
    end
  end

  # Missing required parameter → invalid_request; a non-string is malformed.
  defp validate_scope(_params), do: {:error, :invalid_request}

  # ----- hints (§7.1: one and only one) -----

  defp validate_hint(params) do
    case Enum.filter(@hint_params, &Map.has_key?(params, &1)) do
      [key] ->
        case Map.fetch!(params, key) do
          value when is_binary(value) and value != "" -> {:ok, {hint_kind(key), value}}
          _other -> {:error, :invalid_request}
        end

      _zero_or_many ->
        {:error, :invalid_request}
    end
  end

  defp hint_kind("login_hint"), do: :login_hint
  defp hint_kind("login_hint_token"), do: :login_hint_token
  defp hint_kind("id_token_hint"), do: :id_token_hint

  # ----- client_notification_token (§7.1: REQUIRED for ping and push) -----

  defp validate_notification_token(mode, params, opts) when mode in [:ping, :push] do
    min_length = Keyword.get(opts, :min_client_notification_token_length, @default_notification_token_min_length)

    case Map.get(params, "client_notification_token") do
      token when is_binary(token) ->
        if byte_size(token) >= min_length and byte_size(token) <= @notification_token_max_length and
             Regex.match?(@b64token, token) do
          {:ok, token}
        else
          {:error, :invalid_request}
        end

      _missing_or_malformed ->
        {:error, :invalid_request}
    end
  end

  # Poll mode has no notification callback, so the token is not required and
  # not carried; a value a poll client sends anyway is ignored.
  defp validate_notification_token(_mode, _params, _opts), do: {:ok, nil}

  # ----- binding_message (§7.1, FAPI-CIBA §5.2.2) -----

  defp validate_binding_message(params, opts) do
    max_length = Keyword.get(opts, :binding_message_max_length, @default_binding_message_max_length)

    case Map.get(params, "binding_message") do
      nil ->
        if Keyword.get(opts, :require_binding_message, false) == true,
          do: {:error, :invalid_binding_message},
          else: {:ok, nil}

      message when is_binary(message) ->
        if displayable?(message) and String.length(message) in 1..max_length,
          do: {:ok, message},
          else: {:error, :invalid_binding_message}

      _other ->
        {:error, :invalid_binding_message}
    end
  end

  # §7.1: the binding message is displayed verbatim on both devices, so it
  # must be valid UTF-8 plain text with no control characters.
  defp displayable?(message) do
    String.valid?(message) and not Regex.match?(~r/[\x00-\x1F\x7F]/u, message)
  end

  # ----- user_code (§7.1: only when client registration + OP support say so) -----

  defp validate_user_code(client, params, opts) do
    case Map.get(params, "user_code") do
      nil ->
        {:ok, nil}

      code when is_binary(code) ->
        if user_code_accepted?(client, opts) and displayable?(code) and
             String.length(code) in 1..@default_user_code_max_length do
          {:ok, code}
        else
          {:error, :invalid_request}
        end

      _other ->
        {:error, :invalid_request}
    end
  end

  defp user_code_accepted?(client, opts) do
    Keyword.get(opts, :user_code_supported, false) == true and
      Map.get(client, :user_code_parameter, false) == true
  end

  # ----- requested_expiry (§7.1: positive integer; §7.1.1 allows a JSON string) -----

  defp validate_requested_expiry(params) do
    case Map.get(params, "requested_expiry") do
      nil -> {:ok, nil}
      n when is_integer(n) and n > 0 -> {:ok, n}
      s when is_binary(s) -> parse_requested_expiry(s)
      _other -> {:error, :invalid_request}
    end
  end

  defp parse_requested_expiry(s) do
    case Integer.parse(s) do
      {n, ""} when n > 0 -> {:ok, n}
      _other -> {:error, :invalid_request}
    end
  end

  # ----- acr_values (§7.1: space-separated string, order of preference) -----

  defp validate_acr_values(params) do
    case Map.get(params, "acr_values") do
      nil -> {:ok, []}
      values when is_binary(values) -> {:ok, Scope.parse(values)}
      _other -> {:error, :invalid_request}
    end
  end
end
