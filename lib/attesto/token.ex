defmodule Attesto.Token do
  @moduledoc """
  Mint and verify RS256 JWT access tokens.

  This is the heart of the engine: a single mint point and a single
  verifier that one issuer uses for every kind of principal. The two
  operations are pure - they read no database, no process state, and no
  application config beyond the `Attesto.Config` you pass in. Effects that
  surround issuance (auditing, persisting refresh state, looking up
  revocation) belong to the host application, which wraps these functions.

  ## Claims

  Every minted token carries:

    * `iss` - the configured issuer.
    * `aud` - the configured audience, or the per-call `:audience` mint
      option when the host derived a resource-specific audience (RFC 8707
      §2 resource indicator → access-token `aud`).
    * `sub` - the subject's public identifier, which MUST begin with the
      `sub_prefix` of its principal kind.
    * `exp` / `iat` - expiry and issued-at, unix seconds.
    * `jti` - a 128-bit crypto-random identifier, base64url-no-pad
      (RFC 7519 §4.1.7), so a resource server can reject replay.
    * `scope` - the space-separated granted scope list (resolved by the
      host's policy and passed in; Attesto does not decide who gets what).
    * `typ` - the token purpose, `"access"` or `"refresh"`.
    * the configured principal-kind claim - the kind's `claim_value`,
      cross-checked against `sub` on verify.
    * any per-kind required claims (e.g. `client_id`).
    * `cnf` - present iff the token is sender-constrained (DPoP or mTLS).

  Tokens are signed RS256 with the key the configured `Attesto.Keystore`
  provides; the JWS header carries the key's `kid` (its RFC 7638
  thumbprint). The algorithm is pinned: `verify/3` rejects anything but
  RS256, so `none`/`HS256` alg-confusion is impossible by construction.

  ## Sender constraints

  `mint/3` accepts at most one of `:dpop_jkt` (RFC 9449) or
  `:mtls_cert_thumbprint` (RFC 8705); supplying both is
  `:conflicting_confirmation`. The chosen binding becomes a `cnf` claim
  (RFC 7800), and `verify/3` enforces it: a DPoP- or mTLS-bound token
  presented without (or with a mismatched) proof is rejected, and a proof
  presented against a token that is not bound that way is rejected too.
  See `verify/3` for the full binding matrix.

  ## What this module does NOT do

  Scope *policy* (which scopes a principal may hold, downscoping rules) is
  the host's; pass the already-resolved scope list to `mint/3`. Revocation
  lookup, `jti` replay rejection of the access token, and audit are the
  resource server's. Keeping them out is what lets the verifier stay pure
  and reusable (token introspection, multiple surfaces).
  """

  alias Attesto.Config
  alias Attesto.Key
  alias Attesto.PrincipalKind
  alias Attesto.Scope
  alias Attesto.SigningAlg
  alias Attesto.Thumbprint

  @signing_alg "RS256"
  @bearer_token_type "Bearer"
  @dpop_token_type "DPoP"

  @typ_access "access"
  @typ_refresh "refresh"
  @typ_values [@typ_access, @typ_refresh]

  @jti_byte_length 16

  # Modest tolerance for a verifier clock running slightly ahead of the
  # issuer's, applied to the `nbf` (not-before) and future-`iat` checks.
  @clock_skew_seconds 60

  @type principal :: %{
          required(:kind) => String.t(),
          required(:sub) => String.t(),
          required(:scopes) => [String.t()],
          optional(:claims) => %{optional(String.t()) => term()}
        }

  @type mint_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:lifetime, pos_integer()}
          | {:typ, String.t()}
          | {:audience, String.t()}
          | {:dpop_jkt, String.t() | nil}
          | {:mtls_cert_thumbprint, String.t() | nil}
        ]

  @type token_response :: %{
          access_token: String.t(),
          expires_in: pos_integer(),
          scope: String.t(),
          token_type: String.t()
        }

  @type mint_error ::
          :unknown_principal_kind
          | :invalid_sub
          | :invalid_claims
          | :reserved_claim_conflict
          | :invalid_scopes
          | :invalid_typ
          | :invalid_audience
          | :invalid_dpop_jkt
          | :invalid_mtls_thumbprint
          | :conflicting_confirmation

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:expected_typ, String.t()}
          | {:dpop_jkt, String.t() | nil}
          | {:mtls_cert_thumbprint, String.t() | nil}
          | {:require_confirmation_binding, boolean()}
        ]

  @type verify_error ::
          :invalid_token
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :expired
          | :not_yet_valid
          | :invalid_claims
          | :invalid_principal
          | :invalid_typ
          | :unexpected_typ
          | :unsupported_critical_header
          | :unsupported_confirmation
          | :dpop_proof_required
          | :dpop_binding_mismatch
          | :dpop_proof_unexpected
          | :mtls_cert_required
          | :mtls_binding_mismatch
          | :mtls_cert_unexpected

  @type claims :: %{optional(String.t()) => term()}

  @doc """
  Mint a token for `principal` under `config`.

  `principal` is a map with:

    * `:kind` - the `claim_value` of one of the configured principal
      kinds.
    * `:sub` - the subject's public identifier; MUST begin with the
      kind's `sub_prefix`.
    * `:scopes` - the final, policy-resolved list of scope strings. Joined
      verbatim into the `scope` claim; Attesto applies no scope policy.
    * `:claims` (optional) - extra principal claims (e.g.
      `%{"client_id" => ...}`). MUST satisfy the kind's `required_claims`
      and MUST NOT collide with a reserved protocol claim.

  Options:

    * `:typ` - `"access"` (default) or `"refresh"`.
    * `:audience` - the `aud` claim for this token, overriding
      `config.audience`. RFC 8707 §2: when a token request carries a
      `resource` indicator the access token's `aud` MUST identify that
      resource, so the host passes the validated resource identifier here;
      absent, `config.audience` is used (the default surface). The override
      is per-call and conn-free - it does not mutate `config` - so a single
      issuer can mint resource-audienced tokens for one grant without
      changing `aud` for any other.
    * `:now` - `DateTime` or unix-seconds clock override. Defaults to now.
    * `:lifetime` - positive seconds; may only *shorten* the configured
      default (a larger value is capped to the default, so a miswired
      caller cannot mint a long-lived token).
    * `:dpop_jkt` - RFC 7638 JWK thumbprint to bind the token to a DPoP
      key (`cnf.jkt`). Must be a canonical 43-char base64url thumbprint or
      `:invalid_dpop_jkt`.
    * `:mtls_cert_thumbprint` - RFC 8705 certificate thumbprint to bind
      the token to a client certificate (`cnf.x5t#S256`). Same shape rule
      or `:invalid_mtls_thumbprint`.

  `:dpop_jkt` and `:mtls_cert_thumbprint` are mutually exclusive
  (`:conflicting_confirmation`).

  Returns `{:ok, %{access_token, token_type, expires_in, scope}}`.
  `token_type` is `"DPoP"` for a DPoP-bound token (RFC 9449 §5) and
  `"Bearer"` otherwise (mTLS binding does not change the type per
  RFC 8705 §3).
  """
  @spec mint(Config.t(), principal(), mint_opts()) ::
          {:ok, token_response()} | {:error, mint_error()}
  def mint(%Config{} = config, principal, opts \\ []) when is_map(principal) and is_list(opts) do
    with {:ok, kind} <- fetch_kind(config, principal),
         :ok <- check_sub(kind, principal),
         {:ok, extra} <- normalize_extra_claims(config, kind, principal),
         {:ok, scopes} <- normalize_scopes(principal),
         {:ok, typ} <- normalize_typ(opts),
         {:ok, audience} <- normalize_audience(config, opts),
         {:ok, confirmation} <- normalize_confirmation(opts) do
      iat = unix_now(opts)
      lifetime = lifetime_seconds(config, opts)
      scope_string = Enum.join(scopes, " ")

      claims =
        %{
          # RFC 8707 §2: a per-call `:audience` (a validated `resource`
          # indicator) takes precedence over the configured default audience.
          "aud" => audience,
          "exp" => iat + lifetime,
          "iat" => iat,
          "iss" => config.issuer,
          "jti" => generate_jti(),
          config.principal_kind_claim => kind.claim_value,
          "scope" => scope_string,
          "sub" => principal.sub,
          "typ" => typ
        }
        |> Map.merge(extra)
        |> maybe_put_confirmation(confirmation)

      {:ok,
       %{
         access_token: sign(config, claims),
         expires_in: lifetime,
         scope: scope_string,
         token_type: token_type_for(confirmation)
       }}
    end
  end

  @doc """
  Verify and decode a token previously minted by `mint/3` under the same
  `config`.

  Runs, in order:

    1. **Signature.** The compact JWS is canonical - three base64url-no-pad
       segments (Attesto rejects `=` padding or any non-base64url byte at
       its boundary, refusing to verify a serialization the issuer never
       emitted) - and its RS256 signature
       verifies against a key the keystore trusts, selected by the JWS
       header `kid`. A token whose `kid` names a key we do not hold, or
       whose header `alg` is anything but RS256, fails as
       `:invalid_signature` (alg-confusion is impossible). A token whose
       protected header carries a `crit` parameter (RFC 7515 §4.1.11) is
       rejected with `:unsupported_critical_header` - Attesto implements no
       JWS extensions, so it must not honour a token that demands one.
    2. **Confirmation shape.** If a `cnf` is present it MUST be exactly
       `%{"jkt" => <thumbprint>}` (DPoP) or `%{"x5t#S256" => <thumbprint>}`
       (mTLS), with a canonical thumbprint and no other members; anything
       else is `:unsupported_confirmation` (accepting it as bearer would
       silently strip the binding).
    3. **`iss`** equals the configured issuer.
    4. **`aud`** equals (or, in array form, contains) the configured
       audience.
    5. **Temporal.** `exp` is strictly greater than `now` (no skew
       leeway). If `nbf` is present it MUST be an integer no later than
       `now` (RFC 7519 §4.1.5; a small clock-skew tolerance applies), else
       `:not_yet_valid`. An `iat` meaningfully in the future is also
       `:not_yet_valid`.
    6. **Required claims** are present and well-typed: `sub`/`jti`
       non-empty strings, `scope` a string, `iat` a non-negative integer,
       and both the principal-kind claim and `typ` present.
    7. **Principal.** The principal-kind claim names a configured kind AND
       `sub` begins with that kind's `sub_prefix`; otherwise
       `:invalid_principal`.
    8. **Per-kind claims.** The kind's `required_claims` are all present
       with the right shape; otherwise `:invalid_claims`.
    9. **`typ`** is a known value AND equals the expected purpose
       (`:expected_typ`, default `"access"`).
   10. **Binding.** A DPoP-bound token requires a matching `:dpop_jkt`; an
       mTLS-bound token a matching `:mtls_cert_thumbprint`; an unbound
       token requires neither. The cross-scheme option MUST be absent.
       See the error list for the precise outcomes.

  ## Options

    * `:now` - clock override.
    * `:expected_typ` - `"access"` (default) or `"refresh"`.
    * `:dpop_jkt` - the verified DPoP proof's `jkt` (from
      `Attesto.DPoP.verify_proof/2`). Required iff the token carries
      `cnf.jkt`.
    * `:mtls_cert_thumbprint` - the presented certificate's thumbprint
      (from `Attesto.MTLS.compute_thumbprint/1`). Required iff the token
      carries `cnf.x5t#S256`.

  Returns `{:ok, claims}` (string-keyed payload) or `{:error, reason}`.
  """
  @spec verify(Config.t(), String.t(), verify_opts()) ::
          {:ok, claims()} | {:error, verify_error()}
  def verify(config, jwt, opts \\ [])

  def verify(%Config{} = config, jwt, opts) when is_binary(jwt) and is_list(opts) do
    with {:ok, claims} <- verify_signature(config, jwt),
         :ok <- check_confirmation_shape(claims),
         :ok <- check_issuer(config, claims),
         :ok <- check_audience(config, claims),
         :ok <- check_expiry(claims, opts),
         :ok <- check_not_before(claims, opts),
         :ok <- check_required_claims(config, claims),
         :ok <- check_iat_not_future(claims, opts),
         {:ok, kind} <- check_principal(config, claims),
         :ok <- check_principal_identity_claims(kind, claims),
         :ok <- check_typ(claims, opts),
         :ok <- maybe_check_confirmation_binding(claims, opts) do
      {:ok, claims}
    end
  end

  def verify(%Config{}, _jwt, _opts), do: {:error, :invalid_token}

  # The sender-constraint confirmation has two independent checks: the `cnf`
  # *shape* (always enforced in verify/3), and the *binding* - that the
  # presented proof key matches `cnf` (RFC 9449 §4 / RFC 8705 §3). A caller that
  # is not the token's presenter - notably token introspection (RFC 9701), which
  # never holds the proof key - passes `require_confirmation_binding: false` to
  # skip the binding match while keeping every other check, including `cnf` shape.
  defp maybe_check_confirmation_binding(claims, opts) do
    if Keyword.get(opts, :require_confirmation_binding, true) do
      check_confirmation_binding(claims, opts)
    else
      :ok
    end
  end

  @doc """
  Return a token's claims iff its RS256 signature verifies against a
  keystore key. Skips every other check (`iss`, `aud`, `exp`, claim
  shape, binding).

  This is NOT an authentication primitive - the token may be expired,
  replayed, wrongly scoped, or bound to a key the request did not present.
  Its sole legitimate use is denial-audit attribution: after `verify/3`
  fails, a caller may read the claims to identify the credential being
  abused so the audit row names a real actor rather than `:unknown`. A
  forged-signature token still surfaces as an error.
  """
  @spec peek_signed_claims(Config.t(), String.t()) ::
          {:ok, claims()} | {:error, :invalid_signature | :invalid_token}
  def peek_signed_claims(%Config{} = config, jwt) when is_binary(jwt), do: verify_signature(config, jwt)

  def peek_signed_claims(%Config{}, _), do: {:error, :invalid_token}

  @doc "The default JWS algorithm for RSA keys. Keystores may label individual keys with another supported alg."
  @spec signing_alg() :: String.t()
  def signing_alg, do: @signing_alg

  @doc ~s(The known `typ` values: `"access"` and `"refresh"`.)
  @spec typ_values() :: [String.t()]
  def typ_values, do: @typ_values

  @doc "The default token lifetime for `config`, in seconds."
  @spec default_lifetime_seconds(Config.t()) :: pos_integer()
  def default_lifetime_seconds(%Config{default_lifetime_seconds: n}), do: n

  # ----- internal: minting -----

  defp fetch_kind(config, %{kind: kind_value}) do
    case Config.principal_kind(config, kind_value) do
      %PrincipalKind{} = kind -> {:ok, kind}
      nil -> {:error, :unknown_principal_kind}
    end
  end

  defp fetch_kind(_config, _principal), do: {:error, :unknown_principal_kind}

  defp check_sub(%PrincipalKind{sub_prefix: prefix}, %{sub: sub}) when is_binary(sub) and sub != "" do
    if String.starts_with?(sub, prefix), do: :ok, else: {:error, :invalid_sub}
  end

  defp check_sub(_kind, _principal), do: {:error, :invalid_sub}

  defp normalize_extra_claims(config, kind, principal) do
    extra = Map.get(principal, :claims, %{})

    cond do
      not is_map(extra) ->
        {:error, :invalid_claims}

      not all_string_keys?(extra) ->
        {:error, :invalid_claims}

      Enum.any?(Map.keys(extra), &(&1 in Config.reserved_claims(config))) ->
        {:error, :reserved_claim_conflict}

      true ->
        case PrincipalKind.check_required(kind, extra) do
          :ok -> {:ok, extra}
          {:error, _} -> {:error, :invalid_claims}
        end
    end
  end

  defp normalize_scopes(%{scopes: scopes}) when is_list(scopes) do
    # Each scope must be a valid RFC 6749 scope-token: a scope containing
    # whitespace would, once space-joined into the `scope` claim, be
    # indistinguishable from several grants to any resource server.
    if Enum.all?(scopes, &Scope.valid_token?/1),
      do: {:ok, Enum.uniq(scopes)},
      else: {:error, :invalid_scopes}
  end

  defp normalize_scopes(_), do: {:error, :invalid_scopes}

  defp normalize_typ(opts) do
    case Keyword.get(opts, :typ, @typ_access) do
      typ when typ in @typ_values -> {:ok, typ}
      _ -> {:error, :invalid_typ}
    end
  end

  # RFC 8707 §2: when present, the `:audience` override (a validated `resource`
  # indicator) becomes the `aud` claim and so MUST be a single non-empty string
  # identifier - a `nil`, `""`, list, or other shape is a miswired caller and is
  # rejected `:invalid_audience` rather than minted into a malformed or
  # attacker-influenced `aud`. Absent, the configured default audience (already
  # validated at `Config.new/1`) is used.
  defp normalize_audience(config, opts) do
    case Keyword.fetch(opts, :audience) do
      :error -> {:ok, config.audience}
      {:ok, aud} when is_binary(aud) and aud != "" -> {:ok, aud}
      {:ok, _} -> {:error, :invalid_audience}
    end
  end

  # RFC 7800 `cnf` assembly. DPoP (`jkt`) and mTLS (`x5t#S256`) are
  # mutually exclusive, and each thumbprint is shape-validated: a
  # non-canonical value would pass a structural check downstream but
  # could never be matched by a real proof or certificate, silently
  # turning the binding into a no-op.
  defp normalize_confirmation(opts) do
    case {Keyword.get(opts, :dpop_jkt), Keyword.get(opts, :mtls_cert_thumbprint)} do
      {nil, nil} -> {:ok, nil}
      {jkt, nil} -> normalize_dpop_jkt(jkt)
      {nil, thumb} -> normalize_mtls_thumbprint(thumb)
      {_, _} -> {:error, :conflicting_confirmation}
    end
  end

  defp normalize_dpop_jkt(jkt) do
    if Thumbprint.valid?(jkt), do: {:ok, %{"jkt" => jkt}}, else: {:error, :invalid_dpop_jkt}
  end

  defp normalize_mtls_thumbprint(thumb) do
    if Thumbprint.valid?(thumb),
      do: {:ok, %{"x5t#S256" => thumb}},
      else: {:error, :invalid_mtls_thumbprint}
  end

  defp maybe_put_confirmation(claims, nil), do: claims
  defp maybe_put_confirmation(claims, cnf) when is_map(cnf), do: Map.put(claims, "cnf", cnf)

  # RFC 9449 §5: DPoP-bound tokens advertise `token_type: "DPoP"`.
  # RFC 8705 §3: mTLS-bound tokens stay `"Bearer"`.
  defp token_type_for(nil), do: @bearer_token_type
  defp token_type_for(%{"jkt" => _}), do: @dpop_token_type
  defp token_type_for(%{"x5t#S256" => _}), do: @bearer_token_type

  defp generate_jti do
    @jti_byte_length
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  # Sign via JOSE.JWS, not JOSE.JWT: `JOSE.JWT.sign/3` injects a default
  # `typ: "JWT"` whenever the supplied header omits `typ`, which would
  # defeat both the RFC 9068 `at+jwt` tagging and the deliberate
  # no-`typ` case (refresh tokens, or a host that sets the header to
  # `nil`). `JOSE.JWS.sign/3` emits the protected header verbatim, so the
  # header `jose_header/3` computes is exactly what ends up on the wire.
  defp sign(config, claims) do
    pem = config.keystore.signing_pem()
    alg = SigningAlg.for_key(config.keystore, pem, signing?: true)
    Attesto.JWS.sign_compact(pem, jose_header(config, pem, claims, alg), claims)
  end

  # RFC 9068 §2.1: an OAuth JWT access token SHOULD carry the JOSE header
  # `typ: "at+jwt"`, distinguishing it (by media type) from an ID token or
  # any other JWT a resource server might be handed. Emitted for access
  # tokens when `config.access_token_header_typ` is set (the default);
  # a host that needs a different/legacy header sets it to a custom value
  # or `nil`.
  defp jose_header(config, pem, claims, alg) do
    base = %{"alg" => alg, "kid" => Key.kid(pem)}

    case {config.access_token_header_typ, Map.get(claims, "typ")} do
      {typ, @typ_access} when is_binary(typ) -> Map.put(base, "typ", typ)
      _ -> base
    end
  end

  defp all_string_keys?(map), do: Enum.all?(Map.keys(map), &is_binary/1)

  # ----- internal: verification -----

  defp verify_signature(config, jwt) do
    with :ok <- check_compact_form(jwt),
         {:ok, header} <- peek_protected_header(jwt),
         :ok <- check_crit(header) do
      case candidate_jwks(config, Map.get(header, "kid")) do
        [] -> {:error, :invalid_signature}
        jwks -> verify_against_any(jwks, jwt)
      end
    end
  end

  # RFC 7515 §2/§7.1 + RFC 4648 §3.5/§5: a JWS compact serialization is
  # three base64url-no-pad segments joined by ".". Attesto verifies only the
  # *canonical* form at its own boundary BEFORE handing the token to JOSE.
  # JOSE's decoder is tolerant - it strips trailing "=" and normalises a
  # non-canonical serialization into a verifiable one - so without this guard
  # `header.payload==.sig` would verify against a signing input the issuer
  # never emitted. An alphabet-only check is not enough: the last character
  # of a partial-quantum segment (length not a multiple of 4) carries unused
  # low-order bits, and several distinct characters share the same
  # significant bits and so decode to the *same* bytes (RFC 4648 §3.5). The
  # 342-byte RS256 signature segment is exactly such a partial quantum
  # (342 rem 4 == 2): swapping its final character for a same-decoding
  # sibling yields a different string JOSE decodes to the issuer's signature
  # and accepts - a signature-malleability bypass. We close it by requiring
  # each segment to round-trip through Base.url_decode64/encode64
  # byte-identically, rejecting "=" padding, non-alphabet bytes, AND non-zero
  # unused trailing bits in one check. The empty signature segment of an
  # unsecured `alg:none` token round-trips ("" -> <<>> -> ""), so it still
  # falls through to the signature check and is classified there as
  # `:invalid_signature` rather than swallowed as a generic structural error.
  # Collapses to the same opaque `:invalid_token` as every other structural
  # failure so callers cannot fingerprint it.
  defp check_compact_form(jwt) do
    case String.split(jwt, ".") do
      [_, _, _] = segments ->
        if Enum.all?(segments, &canonical_base64url?/1),
          do: :ok,
          else: {:error, :invalid_token}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp canonical_base64url?(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> Base.url_encode64(decoded, padding: false) == segment
      :error -> false
    end
  end

  # RFC 7515 §4.1.11: a recipient that does not understand a JWS extension
  # named in the `crit` header MUST reject the JWS. Attesto understands no
  # extension parameters, so any `crit` member is fatal - this prevents a
  # malicious or buggy issuer from smuggling a critical extension the
  # resource server believes it is honouring. (An empty `crit` is itself
  # malformed per the RFC, so its presence is rejected too.) Tokens
  # Attesto mints never carry `crit`.
  defp check_crit(header) do
    if Map.has_key?(header, "crit"), do: {:error, :unsupported_critical_header}, else: :ok
  end

  # Build the {kid, alg, jwk} set the keystore trusts, then narrow by the JWS
  # header `kid`. A header `kid` naming a key we do not hold yields `[]`
  # (-> `:invalid_signature`) before any signature math. A token with no
  # `kid` header (a hand-forged token) is tried against every trusted key,
  # which is safe - they are all ours.
  defp candidate_jwks(config, header_kid) do
    config.keystore.verification_pems()
    |> Enum.map(fn pem ->
      {Key.kid(pem), SigningAlg.for_key(config.keystore, pem), Key.jwk(pem)}
    end)
    |> filter_by_kid(header_kid)
  end

  defp filter_by_kid(keyed, nil), do: keyed
  defp filter_by_kid(keyed, kid), do: Enum.filter(keyed, fn {k, _alg, _jwk} -> k == kid end)

  defp verify_against_any(candidates, jwt) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, alg, jwk}, acc ->
      case verify_strict_against(jwk, alg, jwt) do
        {:ok, _claims} = ok -> {:halt, ok}
        # A structural parse failure is terminal regardless of key.
        {:error, :invalid_token} = err -> {:halt, err}
        {:error, :invalid_signature} -> {:cont, acc}
      end
    end)
  end

  defp verify_strict_against(jwk, alg, jwt) do
    case JOSE.JWT.verify_strict(jwk, [alg], jwt) do
      {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} ->
        {:ok, claims}

      {false, _jwt_struct, _jws_struct} ->
        # Covers signature-tamper and alg-confusion: the whitelist passed
        # to verify_strict forces any non-RS256 header here with
        # verified? == false.
        {:error, :invalid_signature}

      _other ->
        # JOSE wraps malformed input in an internal try/catch returning
        # `{class, reason}`; collapse to one opaque error so callers
        # cannot fingerprint the parser.
        {:error, :invalid_token}
    end
  end

  defp peek_protected_header(jwt) do
    case JOSE.JWS.peek_protected(jwt) do
      protected when is_binary(protected) ->
        case JSON.decode(protected) do
          {:ok, %{} = header} -> {:ok, header}
          _ -> {:error, :invalid_token}
        end

      _ ->
        {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  # ----- internal: confirmation -----

  defp check_confirmation_shape(claims) do
    case Map.get(claims, "cnf") do
      nil -> :ok
      cnf when is_map(cnf) -> check_known_confirmation(cnf)
      _other -> {:error, :unsupported_confirmation}
    end
  end

  defp check_known_confirmation(%{"jkt" => jkt} = cnf) when map_size(cnf) == 1 do
    if Thumbprint.valid?(jkt), do: :ok, else: {:error, :unsupported_confirmation}
  end

  defp check_known_confirmation(%{"x5t#S256" => thumb} = cnf) when map_size(cnf) == 1 do
    if Thumbprint.valid?(thumb), do: :ok, else: {:error, :unsupported_confirmation}
  end

  defp check_known_confirmation(_cnf), do: {:error, :unsupported_confirmation}

  defp check_confirmation_binding(claims, opts) do
    cond do
      is_binary(get_in(claims, ["cnf", "jkt"])) -> check_dpop_pair(claims, opts)
      is_binary(get_in(claims, ["cnf", "x5t#S256"])) -> check_mtls_pair(claims, opts)
      true -> check_unbound(opts)
    end
  end

  defp check_dpop_pair(claims, opts) do
    bound = get_in(claims, ["cnf", "jkt"])
    presented = Keyword.get(opts, :dpop_jkt)
    cross = Keyword.get(opts, :mtls_cert_thumbprint)

    cond do
      cross != nil -> {:error, :mtls_cert_unexpected}
      presented == nil -> {:error, :dpop_proof_required}
      presented == bound -> :ok
      true -> {:error, :dpop_binding_mismatch}
    end
  end

  defp check_mtls_pair(claims, opts) do
    bound = get_in(claims, ["cnf", "x5t#S256"])
    presented = Keyword.get(opts, :mtls_cert_thumbprint)
    cross = Keyword.get(opts, :dpop_jkt)

    cond do
      cross != nil -> {:error, :dpop_proof_unexpected}
      presented == nil -> {:error, :mtls_cert_required}
      presented == bound -> :ok
      true -> {:error, :mtls_binding_mismatch}
    end
  end

  defp check_unbound(opts) do
    cond do
      Keyword.get(opts, :dpop_jkt) != nil -> {:error, :dpop_proof_unexpected}
      Keyword.get(opts, :mtls_cert_thumbprint) != nil -> {:error, :mtls_cert_unexpected}
      true -> :ok
    end
  end

  # ----- internal: claim checks -----

  defp check_issuer(config, %{"iss" => iss}) when is_binary(iss) do
    if iss == config.issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_config, _claims), do: {:error, :invalid_issuer}

  # RFC 7519 §4.1.3 allows `aud` as a StringOrURI or an array of them. In
  # the array form every member must be a string (a mixed array carrying a
  # non-string alongside the expected audience is malformed and rejected,
  # not silently tolerated).
  defp check_audience(config, %{"aud" => aud}) do
    expected = config.audience

    cond do
      aud == expected -> :ok
      is_list(aud) and Enum.all?(aud, &is_binary/1) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_audience(_config, _claims), do: {:error, :invalid_audience}

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) do
    if exp > unix_now(opts), do: :ok, else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  # RFC 7519 §4.1.5: a token MUST NOT be accepted before its `nbf`. `nbf`
  # is optional - absent is fine - but if present it must be an integer no
  # later than now (a small skew tolerates a slightly fast verifier clock).
  defp check_not_before(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    if nbf <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_not_before(%{"nbf" => _}, _opts), do: {:error, :invalid_claims}
  defp check_not_before(_claims, _opts), do: :ok

  # A token whose `iat` is meaningfully in the future was either issued by
  # a clock far ahead of ours or forged; reject it (with the same modest
  # skew). `iat` integer-ness is established by `check_required_claims/2`.
  defp check_iat_not_future(%{"iat" => iat}, opts) when is_integer(iat) do
    if iat <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat_not_future(_claims, _opts), do: :ok

  defp check_required_claims(config, claims) do
    cond do
      not non_empty_binary?(Map.get(claims, "sub")) -> {:error, :invalid_claims}
      not non_empty_binary?(Map.get(claims, "jti")) -> {:error, :invalid_claims}
      not is_binary(Map.get(claims, "scope")) -> {:error, :invalid_claims}
      not non_negative_integer?(Map.get(claims, "iat")) -> {:error, :invalid_claims}
      not non_empty_binary?(Map.get(claims, config.principal_kind_claim)) -> {:error, :invalid_claims}
      not non_empty_binary?(Map.get(claims, "typ")) -> {:error, :invalid_claims}
      true -> :ok
    end
  end

  # The principal-kind claim MUST name a configured kind AND `sub` MUST
  # carry that kind's namespace prefix. We never default to a kind on a
  # missing or unknown value: a mismatch fails verify, so a token can
  # never be silently routed down the wrong principal path.
  defp check_principal(config, claims) do
    kind_value = Map.get(claims, config.principal_kind_claim)
    sub = Map.get(claims, "sub")

    with %PrincipalKind{} = kind <- Config.principal_kind(config, kind_value),
         true <- is_binary(sub) and String.starts_with?(sub, kind.sub_prefix) do
      {:ok, kind}
    else
      _ -> {:error, :invalid_principal}
    end
  end

  defp check_principal_identity_claims(%PrincipalKind{} = kind, claims) do
    case PrincipalKind.check_required(kind, claims) do
      :ok -> :ok
      {:error, _} -> {:error, :invalid_claims}
    end
  end

  defp check_typ(%{"typ" => typ}, opts) when typ in @typ_values do
    expected = Keyword.get(opts, :expected_typ, @typ_access)

    cond do
      expected not in @typ_values -> {:error, :unexpected_typ}
      typ == expected -> :ok
      true -> {:error, :unexpected_typ}
    end
  end

  defp check_typ(_claims, _opts), do: {:error, :invalid_typ}

  # ----- internal: helpers -----

  defp non_empty_binary?(value), do: is_binary(value) and value != ""
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end

  # `:lifetime` may only shorten the configured default - a larger value
  # (or a non-positive / non-integer) falls back to the default, capping
  # the blast radius of a miswired caller.
  defp lifetime_seconds(config, opts) do
    default = config.default_lifetime_seconds

    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 and n <= default -> n
      _ -> default
    end
  end
end
