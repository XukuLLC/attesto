defmodule Attesto.IdentityAssertion do
  @moduledoc """
  Verify Identity Assertion JWT Authorization Grants (ID-JAGs) at the Resource
  Authorization Server.

  The client redeems the ID-JAG at the token endpoint with the RFC 7523 §4
  JWT-bearer authorization grant. The verifier checks the signature against a
  trusted JWKS supplied by the caller and returns the verified claims. The caller
  selects the issuer, prevents replay, and applies authorization policy.
  [ID-JAG draft -06, §§3.1 and 4.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4.1).

    * The JOSE `typ` is `oauth-id-jag+jwt`, compared case-insensitively
      (RFC 7515 §4.1.9 and RFC 2045 §5.1).
    * The trusted issuer matches `iss`. The expected audience is the sole
      value in `aud`, which may be a string or a one-element array.
    * The request client matches `client_id`.
    * `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, and `iat` are required.
    * The assertion must be unexpired. The verifier allows 60 seconds of skew
      for `iat` and `nbf` and checks the configured lifetime bound.
    * The verifier checks the types of optional claims and returns validated
      `authorization_details` for the caller to process under RFC 9396.

  """

  alias Attesto.{Claims, Config, JWS, ResourceIndicator, Scope, Secret, Thumbprint}
  alias Attesto.NumericDate
  alias Attesto.SigningAlg

  @typ "oauth-id-jag+jwt"
  @default_lifetime_seconds 60
  @clock_skew_seconds NumericDate.default_clock_skew_seconds()
  @max_jti_bytes 256
  # Read at the token endpoint before client authentication; an identity
  # assertion is ID-Token-sized at most.
  @max_assertion_bytes 64 * 1_024
  @required_claims ~w(iss sub aud client_id jti exp iat)

  @doc "Maximum accepted wire size in bytes of a compact Identity Assertion (ID-JAG)."
  @spec max_assertion_bytes() :: pos_integer()
  def max_assertion_bytes, do: @max_assertion_bytes

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
    case peek_claims(jwt) do
      {:ok, %{"iss" => iss}} when is_binary(iss) and iss != "" -> {:ok, iss}
      _ -> :error
    end
  end

  def peek_issuer(_jwt), do: :error

  @doc """
  Decode the unverified claims of a size-bounded ID-JAG for issuer selection.

  Use `verify/3` with the selected trusted issuer before using any claim for
  authorization.
  """
  @spec peek_claims(String.t()) :: {:ok, claims()} | {:error, :malformed}
  def peek_claims(jwt) do
    case JWS.peek_json(jwt, :payload, max_compact_bytes: @max_assertion_bytes) do
      {:ok, claims} -> {:ok, claims}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  @doc """
  Verify an ID-JAG assertion against a trusted issuer JWKS and return its claims.

  `trusted_jwks` is the asserting IdP's JWK set (a `%{"keys" => [...]}` map, a
  bare list of JWK maps, or a single JWK map). Required opts:

    * `:issuer` - the trusted issuer the assertion's `iss` must equal.
    * `:audience` - this server's issuer identifier the assertion's `aud` must
      identify.
    * `:client_id` - the authenticated client; the `client_id` claim must equal
      it (draft §3.1).

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
    with {:ok, header} <-
           JWS.protected_header(jwt,
             error: :malformed,
             crit_error: :unsupported_critical_header,
             max_compact_bytes: @max_assertion_bytes
           ),
         :ok <- check_supported_alg(header, opts),
         :ok <- check_typ(header),
         {:ok, claims} <- verify_signature(jwt, header, trusted_jwks, opts),
         :ok <- check_required_claims(claims),
         :ok <- check_jti(claims),
         :ok <- check_optional_scope(claims),
         :ok <- check_optional_resource(claims),
         :ok <- check_optional_cnf(claims),
         :ok <- check_authorization_details(claims),
         :ok <- check_optional_identity_claims(claims),
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

    JWS.verify_trusted(jwt, header, trusted_jwks,
      accepted_algs: accepted_algs,
      malformed_key: :reject_set,
      terminal_error: :invalid_signature,
      malformed_result: :continue,
      malformed_error: :invalid_signature
    )
  end

  # ── Header checks ─────────────────────────────────────────────────────────

  defp check_supported_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    # Keep the library-wide asymmetric allow-list as a second boundary. A host
    # cannot opt an Identity Assertion into a symmetric or otherwise unsupported
    # algorithm merely by including it in :accepted_algs.
    if alg in SigningAlg.allowed() and SigningAlg.valid_verification_algorithms?(accepted) and alg in accepted,
      do: :ok,
      else: {:error, :unsupported_alg}
  end

  defp check_supported_alg(_header, _opts), do: {:error, :unsupported_alg}

  # ID-JAG draft -06 §3.1: the JOSE header `typ` MUST be `oauth-id-jag+jwt`. `typ` is a media
  # type (RFC 7515 §4.1.9), and media types are case-insensitive (RFC 2045
  # §5.1), so compare case-insensitively.
  defp check_typ(%{"typ" => typ}) do
    if is_binary(typ) and Claims.typ_matches?(typ, [@typ], normalization: :case_insensitive),
      do: :ok,
      else: {:error, :invalid_typ}
  end

  defp check_typ(_header), do: {:error, :invalid_typ}

  # ── Claim checks ──────────────────────────────────────────────────────────

  # ID-JAG draft -06 §3.1: iss, sub, aud, client_id, jti, exp, iat are all REQUIRED. String
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

  # `jti` is persisted by the HTTP integration's replay store. Bound it before
  # it can become a store key; the integration additionally hashes it with the
  # verified issuer so storage is fixed-size and issuer-local.
  defp check_jti(%{"jti" => jti}) when is_binary(jti) and byte_size(jti) <= @max_jti_bytes, do: :ok
  defp check_jti(_claims), do: {:error, :invalid_claims}

  # ID-JAG draft -06 §3.1: optional claims are still type- and syntax-constrained when
  # present. In particular, treating a malformed `scope` as absent would erase
  # the IdP's authorization ceiling.
  defp check_optional_scope(%{"scope" => scope}) when is_binary(scope) do
    if scope |> Scope.parse() |> Scope.valid_list?(allow_empty?: false),
      do: :ok,
      else: {:error, :invalid_claims}
  end

  defp check_optional_scope(%{"scope" => _scope}), do: {:error, :invalid_claims}
  defp check_optional_scope(_claims), do: :ok

  defp check_optional_resource(%{"resource" => resource}) do
    case ResourceIndicator.validate(resource) do
      {:ok, [_ | _]} -> :ok
      _ -> {:error, :invalid_claims}
    end
  end

  defp check_optional_resource(_claims), do: :ok

  # The draft permits an RFC 7800 confirmation claim. Attesto currently
  # implements its DPoP `jkt` method; reject a malformed value here so the
  # integration can never mistake it for an unbound assertion.
  defp check_optional_cnf(%{"cnf" => %{"jkt" => jkt} = cnf}) when map_size(cnf) == 1 do
    if Thumbprint.valid?(jkt), do: :ok, else: {:error, :invalid_claims}
  end

  defp check_optional_cnf(%{"cnf" => _cnf}), do: {:error, :invalid_claims}
  defp check_optional_cnf(_claims), do: :ok

  # Reject malformed `authorization_details` so an invalid signed constraint
  # cannot be treated as absent. Require an array of objects with string
  # `type` members (ID-JAG draft -06 §§3.1 and 4.4.1 and RFC 9396 §2). The
  # caller applies policy to the authorization details in the verified claims.
  defp check_authorization_details(%{"authorization_details" => details}) when is_list(details) do
    if Enum.all?(details, &match?(%{"type" => type} when is_binary(type), &1)),
      do: :ok,
      else: {:error, :invalid_claims}
  end

  defp check_authorization_details(%{"authorization_details" => _details}), do: {:error, :invalid_claims}
  defp check_authorization_details(_claims), do: :ok

  defp check_optional_identity_claims(claims) do
    identity_claims = Map.take(claims, ~w(tenant aud_tenant aud_sub email auth_time amr acr sub_id))

    if Enum.all?(identity_claims, &valid_identity_claim?/1),
      do: :ok,
      else: {:error, :invalid_claims}
  end

  # RFC 7519 §2 permits fractional NumericDate values.
  defp valid_identity_claim?({"auth_time", value}), do: is_number(value)
  defp valid_identity_claim?({"amr", values}), do: is_list(values) and Enum.all?(values, &is_binary/1)
  defp valid_identity_claim?({"sub_id", value}), do: is_map(value)
  defp valid_identity_claim?({_claim, value}), do: is_binary(value)

  defp check_issuer(_claims, nil), do: {:error, :invalid_issuer}
  defp check_issuer(%{"iss" => iss}, iss) when is_binary(iss) and iss != "", do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  # ID-JAG draft -06 §4.4.1: aud "MUST contain the issuer identifier of the Resource
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

  # Match the assertion's `client_id` to the request client supplied by the
  # caller. With client authentication it identifies the authenticated client.
  # Without it the caller verifies proof of possession for a sender-constrained
  # assertion (ID-JAG draft -06 §§4.4 and 4.4.1).
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
    max = Keyword.get(opts, :max_lifetime_seconds)

    cond do
      exp < iat ->
        {:error, :expired}

      is_integer(max) and max > 0 ->
        if NumericDate.within_lifetime?(exp, iat, max), do: :ok, else: {:error, :expired}

      true ->
        :ok
    end
  end

  defp check_lifetime(_claims, _opts), do: :ok

  @doc """
  Sign an Identity Assertion JWT Authorization Grant as a trust domain A
  authorization server (`draft-ietf-oauth-identity-chaining-17` / RFC 10092;
  `draft-ietf-oauth-identity-assertion-authz-grant-06`).

  Options:

    * `:typ` - JOSE header `typ` value. Defaults to `"oauth-id-jag+jwt"` for
      ID-JAG (`urn:ietf:params:oauth:token-type:id-jag`); pass `"JWT"` for a
      plain RFC 7523 authorization grant (`urn:ietf:params:oauth:token-type:jwt`).
    * `:now` / `:lifetime` - clock override and assertion lifetime in seconds.

  The issuer is always `config.issuer`. A supplied `iss` attribute must match;
  a conflicting value returns `{:error, :invalid_claims}`.
  """
  @spec sign(Config.t(), map() | keyword(), keyword()) ::
          {:ok, String.t()} | {:error, :missing_claim | :invalid_claims}
  def sign(%Config{} = config, attrs, opts \\ []) when (is_map(attrs) or is_list(attrs)) and is_list(opts) do
    typ = validate_sign_typ!(Keyword.get(opts, :typ, @typ))
    attrs = normalize_attrs(attrs)
    iat = NumericDate.now(opts)
    lifetime = NumericDate.bounded_lifetime(opts, :lifetime, @default_lifetime_seconds)

    with {:ok, sub} <- require_non_empty_attr(attrs, "sub"),
         {:ok, aud} <- require_non_empty_attr(attrs, "aud"),
         {:ok, client_id} <- require_non_empty_attr(attrs, "client_id"),
         {:ok, iss} <- configured_issuer(config.issuer),
         :ok <- validate_issuer_attr(attrs, iss),
         {:ok, jti} <- resolve_jti_attr(attrs),
         claims = %{
           "iss" => iss,
           "sub" => sub,
           "aud" => aud,
           "client_id" => client_id,
           "jti" => jti,
           "iat" => iat,
           "exp" => iat + lifetime
         },
         {:ok, claims} <- put_optional_scope(claims, Map.get(attrs, "scope")),
         {:ok, claims} <- put_optional_resource(claims, Map.get(attrs, "resource")),
         {:ok, claims} <- put_optional_cnf(claims, Map.get(attrs, "cnf")),
         {:ok, claims} <- put_optional_nbf(claims, Map.get(attrs, "nbf")) do
      {:ok, JWS.sign_current(config.keystore, claims, typ: typ)}
    end
  end

  defp validate_sign_typ!(typ) when typ in [@typ, "JWT"], do: typ

  defp validate_sign_typ!(typ) do
    raise ArgumentError, "IdentityAssertion.sign/3 :typ must be #{inspect(@typ)} or \"JWT\"; got #{inspect(typ)}"
  end

  defp normalize_attrs(attrs) when is_list(attrs), do: Map.new(attrs, fn {k, v} -> {to_string(k), v} end)
  defp normalize_attrs(attrs) when is_map(attrs), do: Map.new(attrs, fn {k, v} -> {to_string(k), v} end)

  defp require_non_empty_attr(attrs, key) do
    case Map.get(attrs, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      nil -> {:error, :missing_claim}
      "" -> {:error, :missing_claim}
      _other -> {:error, :invalid_claims}
    end
  end

  defp configured_issuer(iss) when is_binary(iss) and iss != "", do: {:ok, iss}
  defp configured_issuer(_iss), do: {:error, :invalid_claims}

  defp validate_issuer_attr(attrs, issuer) do
    case Map.fetch(attrs, "iss") do
      :error -> :ok
      {:ok, ^issuer} -> :ok
      _ -> {:error, :invalid_claims}
    end
  end

  defp resolve_jti_attr(attrs) do
    case Map.get(attrs, "jti") do
      nil -> {:ok, Secret.generate(16)}
      jti when is_binary(jti) and jti != "" and byte_size(jti) <= @max_jti_bytes -> {:ok, jti}
      _other -> {:error, :invalid_claims}
    end
  end

  defp put_optional_scope(claims, nil), do: {:ok, claims}
  defp put_optional_scope(claims, []), do: {:ok, claims}

  defp put_optional_scope(claims, scopes) when is_list(scopes) do
    if Scope.valid_list?(scopes, allow_empty?: false) do
      {:ok, Map.put(claims, "scope", Enum.join(scopes, " "))}
    else
      {:error, :invalid_claims}
    end
  end

  defp put_optional_scope(claims, scope) when is_binary(scope) do
    scope
    |> Scope.parse()
    |> then(&put_optional_scope(claims, &1))
  end

  defp put_optional_scope(_claims, _other), do: {:error, :invalid_claims}

  defp put_optional_resource(claims, nil), do: {:ok, claims}
  defp put_optional_resource(claims, []), do: {:ok, claims}

  defp put_optional_resource(claims, [single]) when is_binary(single), do: put_optional_resource(claims, single)

  defp put_optional_resource(claims, resource) do
    case ResourceIndicator.validate(resource) do
      {:ok, [single]} -> {:ok, Map.put(claims, "resource", single)}
      {:ok, [_ | _] = list} -> {:ok, Map.put(claims, "resource", list)}
      _ -> {:error, :invalid_claims}
    end
  end

  defp put_optional_cnf(claims, nil), do: {:ok, claims}

  defp put_optional_cnf(claims, %{"jkt" => jkt} = cnf) when map_size(cnf) == 1 do
    if Thumbprint.valid?(jkt), do: {:ok, Map.put(claims, "cnf", cnf)}, else: {:error, :invalid_claims}
  end

  defp put_optional_cnf(_claims, _cnf), do: {:error, :invalid_claims}

  defp put_optional_nbf(claims, nil), do: {:ok, claims}

  defp put_optional_nbf(claims, nbf) when is_integer(nbf) and nbf >= 0 do
    {:ok, Map.put(claims, "nbf", nbf)}
  end

  defp put_optional_nbf(_claims, _nbf), do: {:error, :invalid_claims}

  defp numericdate?(value), do: NumericDate.valid?(value, non_negative: true)
end
