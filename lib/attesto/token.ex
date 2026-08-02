defmodule Attesto.Token do
  @moduledoc """
  Mint and verify JWT access tokens with trusted, key-bound algorithms.

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

  Tokens are signed with the key the configured `Attesto.Keystore` provides;
  the JWS header carries the key's `kid` (its RFC 7638 thumbprint) and the
  algorithm resolved by `Attesto.SigningAlg`. Minting resolves that algorithm
  from per-key `key_algs/0` metadata, then `signing_alg/0` for the current
  signing key, then the trusted key type and curve. The supported set is
  RS256, PS256, ES256, ES384, ES512, legacy EdDSA, and RFC 9864 Ed25519 / Ed448;
  RSA defaults to RS256, while Edwards-curve inference retains EdDSA for wire
  compatibility unless trusted metadata selects an explicit identifier.

  Verification never learns algorithm policy from the presented JWS header.
  The header `kid` only narrows the configured verification-key set; each
  candidate key's permitted algorithm is resolved independently from per-key
  `key_algs/0` metadata or the key type and curve, then passed as a singleton
  allowlist to JOSE's strict verifier. `Attesto.Keystore.Static` mirrors an
  explicitly configured `signing_alg` onto the current key's `kid`, so its
  mint and verification policies agree without weakening that binding. A
  token carrying `none`, an `HS*` algorithm, or any asymmetric algorithm other
  than the one bound to that trusted key fails as `:invalid_signature`.

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

  alias Attesto.Claims
  alias Attesto.Config
  alias Attesto.JWS
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
          | {:audience, String.t() | [String.t()]}
          | {:acr, String.t()}
          | {:auth_time, non_neg_integer()}
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
          | {:trusted_audiences, [String.t()] | (claims() -> [String.t()])}
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
         {:ok, auth_context} <- normalize_auth_context(opts),
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
        # RFC 9470 / OIDC Core §2: the authentication context (`acr` /
        # `auth_time`) the end-user grant established, carried onto the access
        # token so a resource server can enforce a step-up requirement. Present
        # only when the issuing flow actually established it.
        |> Map.merge(auth_context)
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
       emitted) - and its signature verifies against a key the keystore
       trusts, selected by the JWS header `kid`. The accepted algorithm for
       each candidate key comes from trusted keystore metadata or the key
       type/curve, never from the presented header. A token whose `kid` names
       a key we do not hold, or whose header `alg` does not exactly match the
       algorithm bound to that key, fails as `:invalid_signature`
       (alg-confusion is impossible). A token whose protected header carries
       a `crit` parameter (RFC 7515 §4.1.11) is rejected with
       `:unsupported_critical_header` - Attesto implements no JWS extensions,
       so it must not honour a token that demands one.
    2. **Confirmation shape.** If a `cnf` is present it MUST be exactly
       `%{"jkt" => <thumbprint>}` (DPoP) or `%{"x5t#S256" => <thumbprint>}`
       (mTLS), with a canonical thumbprint and no other members; anything
       else is `:unsupported_confirmation` (accepting it as bearer would
       silently strip the binding).
    3. **`iss`** equals the configured issuer.
    4. **`aud`** equals (or, in array form, contains) the configured
       audience. When a `:trusted_audiences` list is supplied, a scalar
       audience must be in that explicit set and every member of an array
       audience must be trusted. A resolver-backed audience decision is
       deferred until every other check EXCEPT the binding (step 10) has
       succeeded - see that step for why it goes last.
    5. **Temporal.** `exp` is strictly greater than `now` (no skew
       leeway). If `nbf` is present it MUST be an integer no later than
       `now` (RFC 7519 §4.1.5; a small clock-skew tolerance applies), else
       `:not_yet_valid`.
    6. **Required claims** are present and well-typed: `sub`/`jti`
       non-empty strings, `scope` a string, `iat` a non-negative integer,
       and both the principal-kind claim and `typ` present. This runs BEFORE
       the future-`iat` check below, so a token that is both malformed and
       future-dated reports `:invalid_claims`.
    7. **`iat` not meaningfully in the future**, else `:not_yet_valid`.
    8. **Principal.** The principal-kind claim names a configured kind AND
       `sub` begins with that kind's `sub_prefix`; otherwise
       `:invalid_principal`.
    9. **Per-kind claims.** The kind's `required_claims` are all present
       with the right shape; otherwise `:invalid_claims`.
   10. **`typ`** is a known value AND equals the expected purpose
       (`:expected_typ`, default `"access"`).
   11. **Binding.** A DPoP-bound token requires a matching `:dpop_jkt`; an
       mTLS-bound token a matching `:mtls_cert_thumbprint`; an unbound
       token requires neither. The cross-scheme option MUST be absent.
       See the error list for the precise outcomes.

       This runs LAST, after a resolver-backed audience decision, because a
       binding mismatch emits
       `[:attesto, :token, :sender_constraint_mismatch]`. Checking it earlier
       let any sender-bound token from this issuer - not one this resource
       would accept - raise that event by being presented under another key.
       A token failing both therefore reports `:invalid_audience`, not the
       binding error.

  ## Options

    * `:now` - clock override.
    * `:expected_typ` - `"access"` (default) or `"refresh"`.
    * `:trusted_audiences` - a non-empty list of trusted audience identifiers,
      or a one-arity resolver returning that list.
      This is intended for authorization-server operations such as RFC 7662
      introspection that recognize multiple RFC 8707 resource audiences. The
      resolver receives claims only after signature, exact issuer, temporal,
      required-claim, principal, purpose, and confirmation-SHAPE checks
      succeed; the `aud` claim is syntactically valid but has not yet been
      authorized, and the sender BINDING has not yet been checked, so a
      resolver may see a token whose proof of possession later proves wrong.
      Use
      those claims only to select audience policy. Do not derive trust from
      `aud` itself or perform irreversible work in the resolver. A resolver
      failure or malformed return fails closed. This option never disables
      audience verification. Array-valued `aud` claims are accepted only when
      every member occurs in the resolved list. An explicit list or resolver
      replaces the configured-audience rule, so include `config.audience` when
      it should remain accepted. When absent, verification retains the
      configured single-audience behavior.
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
         :ok <- check_audience_before_claim_validation(config, claims, opts),
         :ok <- check_expiry(claims, opts),
         :ok <- check_not_before(claims, opts),
         :ok <- check_required_claims(config, claims),
         :ok <- check_iat_not_future(claims, opts),
         {:ok, kind} <- check_principal(config, claims),
         :ok <- check_principal_identity_claims(kind, claims),
         :ok <- check_typ(claims, opts),
         # Audience before binding, deliberately. `maybe_check_confirmation_binding/2`
         # emits `[:attesto, :token, :sender_constraint_mismatch]`, an event
         # documented as evidence that a token has left its holder. Evaluating
         # it first meant any sender-bound token from this issuer - not one for
         # this resource - could be presented here under a second DPoP key to
         # raise that alarm. Nothing claims the proof's `jti` on a failed
         # verification either, so the same proof could be replayed for its
         # whole freshness window, making the alarm arbitrarily cheap to ring.
         #
         # Deciding "is this token even for me" first means a token this
         # resource would refuse anyway never reaches the check that reports.
         :ok <- check_deferred_audience(claims, opts),
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
  Return a token's claims iff its signature verifies against a keystore key
  under that trusted key's configured or derived algorithm. Skips every other
  check (`iss`, `aud`, `exp`, claim shape, binding).

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

    if is_map(extra),
      do: normalize_extra_claim_map(config, kind, extra),
      else: {:error, :invalid_claims}
  end

  defp normalize_extra_claim_map(config, kind, extra) do
    with {:ok, normalized} <-
           Claims.merge_registered(extra, %{},
             reserved: Config.reserved_claims(config),
             atom_keys: :reject
           ),
         :ok <- PrincipalKind.check_required(kind, normalized) do
      {:ok, normalized}
    else
      {:error, :reserved_claim_conflict} -> {:error, :reserved_claim_conflict}
      {:error, _reason} -> {:error, :invalid_claims}
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

  # RFC 8707 §2: when present, the `:audience` override (the validated
  # `resource` indicator(s)) becomes the `aud` claim. A single resource is a
  # non-empty string; multiple resources (§2.2) are a list of them, written as
  # a JWT `aud` array (RFC 7519 §4.1.3). A `nil`, `""`, empty list, or list with
  # a blank/non-binary member is a miswired caller and is rejected
  # `:invalid_audience` rather than minted into a malformed or
  # attacker-influenced `aud`. Absent, the configured default audience (already
  # validated at `Config.new/1`) is used.
  defp normalize_audience(config, opts) do
    case Keyword.fetch(opts, :audience) do
      :error -> {:ok, config.audience}
      {:ok, aud} -> normalize_audience_value(aud)
    end
  end

  defp normalize_audience_value(aud) when is_binary(aud) and aud != "", do: {:ok, aud}

  defp normalize_audience_value(aud) when is_list(aud) do
    cond do
      aud == [] -> {:error, :invalid_audience}
      Enum.any?(aud, &(not (is_binary(&1) and &1 != ""))) -> {:error, :invalid_audience}
      # A single requested resource collapses to a plain string `aud`; only a
      # genuine multi-resource grant is written as a JWT `aud` array.
      true -> {:ok, collapse_audience(Enum.uniq(aud))}
    end
  end

  defp normalize_audience_value(_aud), do: {:error, :invalid_audience}

  defp collapse_audience([single]), do: single
  defp collapse_audience(many), do: many

  # RFC 9470 / OIDC Core §2: optional `:acr` (authentication context class, a
  # non-empty string) and `:auth_time` (the authentication event time, a
  # non-negative integer NumericDate) for the access token. Absent opts add no
  # claim; a present-but-malformed value is a miswired caller and is rejected
  # rather than minted into a claim a resource server would trust for step-up.
  defp normalize_auth_context(opts) do
    with {:ok, acr} <- normalize_acr(Keyword.fetch(opts, :acr)),
         {:ok, auth_time} <- normalize_auth_time(Keyword.fetch(opts, :auth_time)) do
      {:ok, Map.merge(acr, auth_time)}
    end
  end

  defp normalize_acr(:error), do: {:ok, %{}}
  defp normalize_acr({:ok, acr}) when is_binary(acr) and acr != "", do: {:ok, %{"acr" => acr}}
  defp normalize_acr({:ok, _other}), do: {:error, :invalid_acr}

  defp normalize_auth_time(:error), do: {:ok, %{}}

  defp normalize_auth_time({:ok, auth_time}) when is_integer(auth_time) and auth_time >= 0,
    do: {:ok, %{"auth_time" => auth_time}}

  defp normalize_auth_time({:ok, _other}), do: {:error, :invalid_auth_time}

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

  # ----- internal: verification -----

  defp verify_signature(config, jwt) do
    with {:ok, header} <- peek_protected_header(jwt),
         :ok <- check_crit(header) do
      case candidate_jwks(config, Map.get(header, "kid")) do
        [] -> {:error, :invalid_signature}
        jwks -> verify_against_any(jwks, jwt)
      end
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
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  # Build the {kid, alg, jwk} set the keystore trusts, then narrow by the JWS
  # header `kid`. A header `kid` naming a key we do not hold yields `[]`
  # (-> `:invalid_signature`) before any signature math. A token with no
  # `kid` header (a hand-forged token) is tried against every trusted key,
  # which is safe - they are all ours.
  defp candidate_jwks(config, header_kid) do
    JWS.verification_candidates(config.keystore.verification_pems(),
      kid: header_kid,
      malformed_key: :raise,
      candidate_builder: fn pem ->
        {Key.kid(pem), SigningAlg.for_key(config.keystore, pem), Key.jwk(pem)}
      end
    )
  end

  defp verify_against_any(candidates, jwt) do
    JWS.verify_strict(jwt, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_token
    )
  end

  defp peek_protected_header(jwt) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_token}
    end
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
      true -> sender_constraint_mismatch(:dpop, :dpop_binding_mismatch, claims)
    end
  end

  # A sender-bound token presented with the wrong proof of possession is the
  # signature of a token that has left the holder it was issued to, so it is
  # reported as well as refused (see `Attesto.Telemetry`).
  defp sender_constraint_mismatch(binding, reason, claims) do
    Attesto.Telemetry.sender_constraint_mismatch(binding, reason, claims)
    {:error, reason}
  end

  defp check_mtls_pair(claims, opts) do
    bound = get_in(claims, ["cnf", "x5t#S256"])
    presented = Keyword.get(opts, :mtls_cert_thumbprint)
    cross = Keyword.get(opts, :dpop_jkt)

    cond do
      cross != nil -> {:error, :dpop_proof_unexpected}
      presented == nil -> {:error, :mtls_cert_required}
      presented == bound -> :ok
      true -> sender_constraint_mismatch(:mtls, :mtls_binding_mismatch, claims)
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
  # Keep the long-standing configured-audience and explicit-list checks in
  # their original position, preserving error precedence. A callback may do
  # host work (for example, resolve the signed token client), so validate only
  # the aud claim here and defer invoking it until every other token check has
  # succeeded.
  defp check_audience_before_claim_validation(config, claims, opts) do
    case Keyword.fetch(opts, :trusted_audiences) do
      :error -> check_configured_audience(config, claims)
      {:ok, trusted} when is_list(trusted) -> check_trusted_audiences(claims, trusted)
      {:ok, resolver} when is_function(resolver, 1) -> check_audience_claim(claims)
      {:ok, _invalid} -> {:error, :invalid_audience}
    end
  end

  defp check_deferred_audience(claims, opts) do
    case Keyword.fetch(opts, :trusted_audiences) do
      {:ok, resolver} when is_function(resolver, 1) ->
        check_trusted_audiences(claims, resolve_trusted_audiences(resolver, claims))

      _immediate_or_default ->
        :ok
    end
  end

  defp check_audience_claim(%{"aud" => aud}) when is_binary(aud) and aud != "", do: :ok

  defp check_audience_claim(%{"aud" => audiences}) when is_list(audiences) and audiences != [] do
    if Enum.all?(audiences, &(is_binary(&1) and &1 != "")),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience_claim(_claims), do: {:error, :invalid_audience}

  defp check_configured_audience(config, %{"aud" => aud}) do
    expected = config.audience

    cond do
      aud == expected -> :ok
      is_list(aud) and Enum.all?(aud, &is_binary/1) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_configured_audience(_config, _claims), do: {:error, :invalid_audience}

  defp check_trusted_audiences(%{"aud" => aud}, trusted) when is_list(trusted) and trusted != [] do
    if Enum.all?(trusted, &(is_binary(&1) and &1 != "")) and trusted_audience?(aud, trusted),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_trusted_audiences(_claims, _trusted), do: {:error, :invalid_audience}

  defp resolve_trusted_audiences(resolver, claims) when is_function(resolver, 1) do
    resolver.(claims)
  rescue
    _error -> :invalid
  catch
    _kind, _reason -> :invalid
  end

  defp trusted_audience?(aud, trusted) when is_binary(aud), do: aud in trusted

  defp trusted_audience?(audiences, trusted) when is_list(audiences) do
    audiences != [] and Enum.all?(audiences, &(is_binary(&1) and &1 in trusted))
  end

  defp trusted_audience?(_audience, _trusted), do: false

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
