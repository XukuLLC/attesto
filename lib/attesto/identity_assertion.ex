defmodule Attesto.IdentityAssertion do
  @moduledoc """
  Identity Assertion JWT Authorization Grant (ID-JAG) verification - the resource
  Authorization Server's half of the Identity Assertion Authorization Grant
  (`draft-ietf-oauth-identity-assertion-authz-grant-04`), the grant behind MCP
  Enterprise-Managed Authorization (EMA).

  In EMA the client first performs an RFC 8693 token exchange *at the enterprise
  IdP*, trading the user's ID token / SAML assertion for an **ID-JAG**: a
  short-lived JWT, signed by the IdP, asserting one user for one resource
  application. The client then presents that ID-JAG to *this* server's token
  endpoint as an RFC 7523 §4 JWT-bearer authorization grant
  (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, the assertion in the
  `assertion` parameter) and receives a normal access token. This module verifies
  that assertion.

  It is deliberately **conn-free and side-effect-free**: it verifies the
  compact JWT's signature against a caller-supplied trusted JWKS and validates
  the draft's claim rules, returning the claims or a typed error. The caller
  (the `AttestoPhoenix` token layer) owns the stateful concerns: resolving which
  trusted issuer's JWKS to use (and fetching/caching it), `jti` replay
  protection, subject resolution, and mapping every error here to the RFC 6749
  §5.2 `invalid_grant` the token endpoint must return.

  This is NOT `private_key_jwt` client authentication (RFC 7523 §3, which asserts
  the *client's* identity) nor the RFC 8693 token-exchange grant (which runs at
  the IdP, not here). It shares JWT-validation shape with
  `Attesto.RequestObject` but enforces ID-JAG's distinct claim rules - notably
  `iss` is the IdP (NOT equal to `client_id`), `aud` is this server's issuer,
  and the JOSE `typ` is pinned to `oauth-id-jag+jwt`.

  ## Validated per the draft

    * JOSE header `typ` MUST be `oauth-id-jag+jwt` (a media type, compared
      case-insensitively per RFC 7515 §4.1.9 / RFC 2045 §5.1).
    * signature verifies against the trusted issuer JWKS, selecting the key by
      `kid` and the accepted algorithms.
    * `iss` matches the caller-supplied trusted issuer.
    * `aud` is exactly this server's issuer identifier - a single string, or an
      array of exactly one element equal to it (draft §6.1).
    * `client_id` matches the authenticated client making the token request.
    * the REQUIRED claims `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat`
      are present and well-typed.
    * `exp` is in the future; `iat`/`nbf` are not in the future (60s skew); the
      lifetime `exp - iat` does not exceed `:max_lifetime_seconds` when set.
  """

  alias Attesto.{Claims, JWS}
  alias Attesto.NumericDate
  alias Attesto.SigningAlg

  @typ "oauth-id-jag+jwt"
  @clock_skew_seconds 60
  @required_claims ~w(iss sub aud client_id jti exp iat)

  @typedoc "The validated, string-keyed ID-JAG claim set."
  @type claims :: %{optional(String.t()) => term()}

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:issuer, String.t()}
          | {:audience, String.t()}
          | {:client_id, String.t()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:max_lifetime_seconds, pos_integer() | nil}
        ]

  @type verify_error ::
          :malformed
          | :unsupported_critical_header
          | :unsupported_alg
          | :invalid_typ
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :missing_claim
          | :invalid_claims
          | :client_mismatch
          | :expired
          | :not_yet_valid

  @doc """
  Read the unverified `iss` claim from an assertion so the caller can select the
  trusted issuer (and its JWKS) before verifying the signature.

  This decodes the JWT payload WITHOUT verifying it - the returned issuer is
  untrusted until `verify/3` confirms the signature and re-checks `iss` against
  the caller-supplied `:issuer`. Returns `:error` for a malformed JWT or an
  absent/blank `iss`.
  """
  @spec peek_issuer(String.t()) :: {:ok, String.t()} | :error
  def peek_issuer(jwt) when is_binary(jwt) do
    with {:ok, claims} <- peek_json(jwt, :payload),
         {:ok, iss} when is_binary(iss) and iss != "" <- Map.fetch(claims, "iss") do
      {:ok, iss}
    else
      _ -> :error
    end
  end

  def peek_issuer(_jwt), do: :error

  @doc """
  Verify an ID-JAG assertion against a trusted issuer JWKS and return its claims.

  `trusted_jwks` is the asserting IdP's JWK set (a `%{"keys" => [...]}` map, a
  bare list of JWK maps, or a single JWK map). Required opts:

    * `:issuer` - the trusted issuer the assertion's `iss` must equal.
    * `:audience` - this server's issuer identifier the assertion's `aud` must
      identify.
    * `:client_id` - the authenticated client; the `client_id` claim must equal
      it (draft §6.1).

  Optional opts:

    * `:accepted_algs` - JOSE algorithms a candidate key may sign with. Defaults
      to `Attesto.SigningAlg.allowed/0` (includes RS256, which enterprise IdPs
      commonly use - unlike the FAPI request-object default).
    * `:max_lifetime_seconds` - reject an assertion whose `exp - iat` exceeds
      this bound.
    * `:now` - the verification instant (a `DateTime` or unix seconds); defaults
      to the system clock.

  Returns `{:ok, claims}` (string-keyed, including the registered claims) or
  `{:error, t:verify_error/0}`. The caller maps every error to `invalid_grant`.
  """
  @spec verify(String.t(), map() | [map()], verify_opts()) ::
          {:ok, claims()} | {:error, verify_error()}
  def verify(jwt, trusted_jwks, opts \\ [])

  def verify(jwt, trusted_jwks, opts) when is_binary(jwt) and is_list(opts) do
    with {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header),
         :ok <- check_supported_alg(header),
         :ok <- check_typ(header),
         {:ok, claims} <- verify_signature(jwt, header, trusted_jwks, opts),
         :ok <- check_required_claims(claims),
         :ok <- check_issuer(claims, Keyword.get(opts, :issuer)),
         :ok <- check_audience(claims, Keyword.get(opts, :audience)),
         :ok <- check_client(claims, Keyword.get(opts, :client_id)),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_nbf(claims, opts),
         :ok <- check_lifetime(claims, opts) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _trusted_jwks, _opts), do: {:error, :malformed}

  # ── Signature (mirrors Attesto.RequestObject's proven kid selection) ──────

  defp verify_signature(jwt, header, trusted_jwks, opts) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    candidates =
      JWS.verification_candidates(trusted_jwks,
        kid: Map.get(header, "kid"),
        accepted_algs: accepted_algs,
        malformed_key: :reject_set
      )

    JWS.verify_strict(jwt, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :continue,
      malformed_error: :invalid_signature
    )
  end

  # ── Header checks ─────────────────────────────────────────────────────────

  defp peek_header(jwt) do
    case peek_json(jwt, :protected) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp peek_json(jwt, segment) do
    case JWS.peek_json(jwt, segment) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  defp check_supported_alg(%{"alg" => "none"}), do: {:error, :unsupported_alg}
  defp check_supported_alg(%{"alg" => alg}) when is_binary(alg), do: :ok
  defp check_supported_alg(_header), do: {:error, :unsupported_alg}

  # draft §5: the JOSE header `typ` MUST be `oauth-id-jag+jwt`. `typ` is a media
  # type (RFC 7515 §4.1.9), and media types are case-insensitive (RFC 2045
  # §5.1), so compare case-insensitively.
  defp check_typ(%{"typ" => typ}) when is_binary(typ) do
    if String.downcase(typ) == @typ, do: :ok, else: {:error, :invalid_typ}
  end

  defp check_typ(_header), do: {:error, :invalid_typ}

  # ── Claim checks ──────────────────────────────────────────────────────────

  # draft §6.1: iss, sub, aud, client_id, jti, exp, iat are all REQUIRED. String
  # claims must be non-empty strings; exp/iat must be NumericDate integers; aud
  # must be a string or a list (its single-value rule is enforced separately).
  defp check_required_claims(claims) do
    if Enum.all?(@required_claims, &valid_required_claim?(claims, &1)),
      do: :ok,
      else: {:error, :missing_claim}
  end

  defp valid_required_claim?(claims, claim) when claim in ~w(exp iat) do
    numericdate?(Map.get(claims, claim))
  end

  defp valid_required_claim?(claims, "aud") do
    case Map.get(claims, "aud") do
      aud when is_binary(aud) and aud != "" -> true
      [_ | _] -> true
      _ -> false
    end
  end

  defp valid_required_claim?(claims, claim) do
    case Map.get(claims, claim) do
      value when is_binary(value) and value != "" -> true
      _ -> false
    end
  end

  defp check_issuer(_claims, nil), do: {:error, :invalid_issuer}
  defp check_issuer(%{"iss" => iss}, iss) when is_binary(iss) and iss != "", do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  # draft §6.1: aud "MUST contain the issuer identifier of the Resource
  # Authorization Server ... MAY be a string ... or an array containing a single
  # issuer identifier. If the aud claim is an array, it MUST contain exactly one
  # element, and that element MUST be the issuer identifier." Stricter than a
  # generic intersection: an array of two values - even if one matches - fails.
  defp check_audience(_claims, nil), do: {:error, :invalid_audience}

  defp check_audience(%{"aud" => aud}, expected) when is_binary(expected) do
    if Claims.audience_matches?(aud, expected, :single_element),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  # draft §6.1: the client_id claim MUST identify the same client as the client
  # authentication in the request.
  defp check_client(_claims, nil), do: {:error, :client_mismatch}
  defp check_client(%{"client_id" => client_id}, client_id), do: :ok
  defp check_client(_claims, _client_id), do: {:error, :client_mismatch}

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    if NumericDate.not_expired?(
         exp,
         NumericDate.now(opts, default: :system, invalid_override: :fallback),
         leeway: 0
       ),
       do: :ok,
       else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if NumericDate.not_before_reached?(
         iat,
         NumericDate.now(opts, default: :system, invalid_override: :fallback),
         skew: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :not_yet_valid}
  end

  defp check_iat(_claims, _opts), do: {:error, :not_yet_valid}

  # RFC 7519 §4.1.5: `nbf` is OPTIONAL for an ID-JAG, but when present it must
  # not be in the future (clock skew tolerated).
  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    if NumericDate.not_before_reached?(
         nbf,
         NumericDate.now(opts, default: :system, invalid_override: :fallback),
         skew: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :not_yet_valid}
  end

  # A PRESENT `nbf` that is not an integer NumericDate is malformed, and must be
  # rejected rather than treated as absent - otherwise a garbage `nbf` bypasses
  # the not-yet-valid check entirely. Mirrors `Attesto.Token.check_not_before/2`.
  defp check_nbf(%{"nbf" => _}, _opts), do: {:error, :invalid_claims}

  defp check_nbf(_claims, _opts), do: :ok

  # Bound the assertion's lifetime when the caller sets `:max_lifetime_seconds`.
  # `exp`/`iat` are REQUIRED NumericDates (already validated), so the bound is
  # always computable; reject a lifetime that exceeds the configured maximum.
  defp check_lifetime(%{"exp" => exp, "iat" => iat}, opts) when is_integer(exp) and is_integer(iat) do
    case Keyword.get(opts, :max_lifetime_seconds) do
      max when is_integer(max) and max > 0 ->
        if NumericDate.within_lifetime?(exp, iat, max), do: :ok, else: {:error, :expired}

      _ ->
        :ok
    end
  end

  defp check_lifetime(_claims, _opts), do: :ok

  defp numericdate?(value), do: NumericDate.valid?(value, non_negative: true)
end
