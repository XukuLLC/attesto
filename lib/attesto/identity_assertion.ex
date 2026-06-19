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
    with [_header, payload, _signature] <- String.split(jwt, ".", parts: 3),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, %{"iss" => iss}} when is_binary(iss) and iss != "" <- JSON.decode(json) do
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
    with :ok <- check_compact_form(jwt),
         {:ok, header} <- peek_header(jwt),
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

    case candidates(trusted_jwks, Map.get(header, "kid"), accepted_algs) do
      [] -> {:error, :invalid_signature}
      jwks -> verify_against_any(jwks, jwt)
    end
  end

  defp candidates(trusted_jwks, header_kid, accepted_algs) do
    trusted_jwks
    |> normalize_jwks()
    |> Enum.map(fn jwk_map ->
      jwk = JOSE.JWK.from_map(jwk_map)
      alg = Map.get(jwk_map, "alg") || SigningAlg.infer(jwk)
      {Map.get(jwk_map, "kid"), SigningAlg.validate!(alg), jwk}
    end)
    |> Enum.filter(fn {_kid, alg, _jwk} -> alg in accepted_algs end)
    |> filter_by_kid(header_kid)
  rescue
    _ -> []
  end

  defp normalize_jwks(%{"keys" => keys}) when is_list(keys), do: keys
  defp normalize_jwks(keys) when is_list(keys), do: keys
  defp normalize_jwks(%{} = jwk), do: [jwk]
  defp normalize_jwks(_), do: []

  defp filter_by_kid(keyed, nil), do: keyed
  defp filter_by_kid(keyed, kid), do: Enum.filter(keyed, fn {k, _alg, _jwk} -> k == kid end)

  defp verify_against_any(candidates, jwt) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, alg, jwk}, acc ->
      case JOSE.JWT.verify_strict(jwk, [alg], jwt) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims}}
        {false, _jwt, _jws} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_signature}}
      end
    end)
  end

  # ── Header checks ─────────────────────────────────────────────────────────

  defp check_compact_form(jwt) do
    case String.split(jwt, ".") do
      [_, _, _] -> :ok
      _ -> {:error, :malformed}
    end
  end

  defp peek_header(jwt) do
    with [header, _payload, _signature] <- String.split(jwt, ".", parts: 3),
         {:ok, json} <- Base.url_decode64(header, padding: false),
         {:ok, %{} = map} <- JSON.decode(json) do
      {:ok, map}
    else
      _ -> {:error, :malformed}
    end
  end

  defp check_crit(header) do
    if Map.has_key?(header, "crit"), do: {:error, :unsupported_critical_header}, else: :ok
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
    if aud == expected or aud == [expected], do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  # draft §6.1: the client_id claim MUST identify the same client as the client
  # authentication in the request.
  defp check_client(_claims, nil), do: {:error, :client_mismatch}
  defp check_client(%{"client_id" => client_id}, client_id), do: :ok
  defp check_client(_claims, _client_id), do: {:error, :client_mismatch}

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    if exp > unix_now(opts), do: :ok, else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if iat <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat(_claims, _opts), do: {:error, :not_yet_valid}

  # RFC 7519 §4.1.5: `nbf` is OPTIONAL for an ID-JAG, but when present it must
  # not be in the future (clock skew tolerated).
  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    if nbf <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_nbf(_claims, _opts), do: :ok

  # Bound the assertion's lifetime when the caller sets `:max_lifetime_seconds`.
  # `exp`/`iat` are REQUIRED NumericDates (already validated), so the bound is
  # always computable; reject a lifetime that exceeds the configured maximum.
  defp check_lifetime(%{"exp" => exp, "iat" => iat}, opts) when is_integer(exp) and is_integer(iat) do
    case Keyword.get(opts, :max_lifetime_seconds) do
      max when is_integer(max) and max > 0 ->
        if exp - iat <= max, do: :ok, else: {:error, :expired}

      _ ->
        :ok
    end
  end

  defp check_lifetime(_claims, _opts), do: :ok

  defp numericdate?(value), do: is_integer(value) and value >= 0

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt)
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end
end
