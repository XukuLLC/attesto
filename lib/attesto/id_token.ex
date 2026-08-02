defmodule Attesto.IDToken do
  @moduledoc """
  Mint and verify OpenID Connect ID Tokens (OpenID Connect Core 1.0 §2).

  An ID Token is the JWT that asserts the authentication of an End-User to
  a Relying Party. It is a different artifact from the RFC 9068 access
  token `Attesto.Token` produces, with different semantics: its `aud` is
  the OAuth `client_id` rather than the protected-resource audience, it
  carries no `scope` claim, and its JOSE header `typ` is the generic
  `JWT` (NOT `at+jwt`, which is reserved for access tokens). The two are
  kept in separate modules rather than overloading one mint path.

  Like `Attesto.Token`, the operations are pure: they read only the
  `Attesto.Config` passed in. Signing uses the same keystore/`kid` path and
  trusted, key-bound algorithm resolution: RS256, PS256, ES256, ES384, ES512,
  legacy EdDSA, or RFC 9864 Ed25519 / Ed448 as selected by
  `Attesto.SigningAlg`. Verification derives each
  candidate key's accepted algorithm from per-key keystore metadata or the
  key type and curve rather than the presented header, then calls
  `JOSE.JWT.verify_strict` with that singleton allowlist. `none`, `HS*`, and
  any asymmetric algorithm not bound to the trusted key fail closed.

  ## Claims (OpenID Connect Core §2)

  Every minted ID Token carries:

    * `iss` - the configured issuer.
    * `sub` - the subject identifier for the End-User.
    * `aud` - the OAuth `client_id` of the Relying Party. This is the
      client, NOT the `Attesto.Config` `audience` an access token uses.
    * `exp` / `iat` - expiry and issued-at, unix seconds.

  Conditionally / optionally present:

    * `nonce` - the value from the Authentication Request. REQUIRED to be
      present and identical when the request carried one
      (OIDC Core §2, §3.1.3.7 item 11).
    * `azp` - the authorized party. REQUIRED when `aud` contains a value
      other than the `client_id` (OIDC Core §2); always safe to include.
    * `auth_time` - time of End-User authentication (OIDC Core §2).
    * `acr` - Authentication Context Class Reference (OIDC Core §2).
    * `amr` - Authentication Methods References, a JSON array (OIDC Core §2).
    * `at_hash` - Access Token hash (OIDC Core §3.1.3.6 / §3.3.2.11).
    * `c_hash` - Authorization Code hash (OIDC Core §3.3.2.11).
    * `sid` - Session ID (OIDC Back-Channel Logout 1.0 §2.1 / Front-Channel
      Logout 1.0 §3). Present when the host runs back-channel-logout-capable
      sessions, so a later `logout_token` can target this exact session.

  There is deliberately no `scope` claim: scope is a property of the
  authorization grant, not of the identity assertion.

  ## Additional claims (`claims` parameter / userinfo mapping)

  Claims an RP requests through the OIDC Core §5.5 `claims` request
  parameter, or that a host maps from its userinfo source, are passed to
  `mint/3` as `:extra_claims`: a string-keyed map merged after the protocol
  claims above. The merge is non-overriding by construction - a key that
  collides with a reserved protocol claim (`iss`, `sub`, `aud`, `exp`,
  `iat`, `nonce`, `azp`, `auth_time`, `acr`, `amr`, `at_hash`, `c_hash`) is
  rejected with `:reserved_claim_conflict` rather than silently shadowing
  the value this module computes; a non-map or non-string-keyed value is
  `:invalid_extra_claims`. This keeps claim provenance in the caller (the
  host/RP decides which profile claims to assert) while the protocol claims
  stay authoritative.

  ## Hash claims

  `at_hash` and `c_hash` use the same construction (OIDC Core §3.1.3.6,
  §3.3.2.11): hash the ASCII octets of the `access_token` / `code` with
  the hash associated with the ID Token's signature algorithm (for example,
  SHA-256 for RS256), take the left-most half of the digest, and
  base64url-encode it without padding. Applying that generic rule to RFC 8032,
  Ed25519 uses SHA-512 and takes 32 bytes; Ed448 uses SHAKE256 with 114 bytes
  of output and takes 57 bytes. The trusted signing key curve selects between
  them; the untrusted JWS header never selects the digest.
  """

  alias Attesto.Claims
  alias Attesto.Config
  alias Attesto.JWS
  alias Attesto.Key
  alias Attesto.NumericDate
  alias Attesto.SigningAlg

  @signing_alg "RS256"

  # ID Tokens use the generic JWT media type in the JOSE header. RFC 9068
  # §2.1 reserves `at+jwt` for access tokens, and OIDC Core §2 specifies a
  # JWT; pinning `JWT` here lets a verifier reject an access token presented
  # where an ID Token is expected (and vice versa) on `typ`.
  @header_typ "JWT"

  # 1 hour. ID Token lifetime is a host policy; this is a sane default and
  # may only be shortened, mirroring `Attesto.Token`'s lifetime cap.
  @default_lifetime_seconds 3600

  # Modest tolerance for a verifier clock running slightly ahead of the
  # issuer's, applied to the future-`iat` check, mirroring `Attesto.Token`.
  @clock_skew_seconds 60

  @type mint_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:lifetime, pos_integer()}
          | {:nonce, String.t()}
          | {:azp, String.t()}
          | {:auth_time, non_neg_integer()}
          | {:acr, String.t()}
          | {:amr, [String.t()]}
          | {:access_token, String.t()}
          | {:code, String.t()}
          | {:sid, String.t()}
          | {:extra_claims, %{optional(String.t()) => term()}}
        ]

  @type mint_error :: :invalid_subject | :invalid_client_id | :invalid_extra_claims | :reserved_claim_conflict

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:client_id, String.t()}
          | {:nonce, String.t()}
        ]

  @type verify_error ::
          :invalid_token
          | :invalid_signature
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_issuer
          | :invalid_audience
          | :invalid_azp
          | :expired
          | :not_yet_valid
          | :invalid_claims
          | :missing_client_id
          | :nonce_required
          | :nonce_mismatch

  @type claims :: %{optional(String.t()) => term()}

  # Claims this module assembles itself: a caller's `:extra_claims` may not
  # shadow one (mirrors `Attesto.Config` reserved-claim discipline).
  @reserved_claims ~w(iss sub aud exp iat nonce azp auth_time acr amr at_hash c_hash sid)

  @doc """
  Mint a signed OpenID Connect ID Token for `subject`, addressed to the
  Relying Party identified by `client_id`.

  `client_id` becomes the `aud` claim (OIDC Core §2), distinguishing the
  ID Token from a resource-addressed access token; `config.audience` is
  not used here.

  Options:

    * `:nonce` - the Authentication Request nonce. When supplied it is
      placed in the `nonce` claim, and `verify/3` then requires a match
      (OIDC Core §2). Omit only when the request carried no nonce.
    * `:azp` - the authorized party (OIDC Core §2). REQUIRED by the spec
      when `aud` has more than one audience.
    * `:auth_time` - unix time of End-User authentication (OIDC Core §2).
    * `:acr` - Authentication Context Class Reference (OIDC Core §2).
    * `:amr` - Authentication Methods References, a list (OIDC Core §2).
    * `:access_token` - when given, the `at_hash` claim is computed from it
      (OIDC Core §3.1.3.6).
    * `:code` - when given, the `c_hash` claim is computed from it
      (OIDC Core §3.3.2.11).
    * `:sid` - the session id to assert (OIDC Back-Channel Logout 1.0 §2.1).
      Supply it when the host issues logout-capable sessions so a future
      `Attesto.LogoutToken` can target this session.
    * `:extra_claims` - a string-keyed map of additional claims (e.g.
      profile claims). MUST NOT collide with a reserved protocol claim
      (`:reserved_claim_conflict`) and MUST have string keys.
    * `:now` - `DateTime` or unix-seconds clock override. Defaults to now.
    * `:lifetime` - positive seconds; may only *shorten* the default
      (a larger value is capped to the default), so a miswired caller
      cannot mint a long-lived identity assertion.

  Returns `{:ok, id_token}` (compact JWS) or `{:error, reason}`.
  """
  @spec mint(Config.t(), String.t(), String.t(), mint_opts()) ::
          {:ok, String.t()} | {:error, mint_error()}
  def mint(config, subject, client_id, opts \\ [])

  def mint(%Config{} = config, subject, client_id, opts)
      when is_binary(subject) and is_binary(client_id) and is_list(opts) do
    with :ok <- check_non_empty(subject, :invalid_subject),
         :ok <- check_non_empty(client_id, :invalid_client_id),
         {:ok, extra} <- normalize_extra_claims(opts) do
      iat = NumericDate.now(opts)
      lifetime = lifetime_seconds(opts)
      signing_context = JWS.current_signing_context(config.keystore)
      jwk = signing_context.jwk
      alg = signing_context.alg

      claims =
        %{
          "iss" => config.issuer,
          "sub" => subject,
          "aud" => client_id,
          "iat" => iat,
          "exp" => iat + lifetime
        }
        |> put_optional("nonce", Keyword.get(opts, :nonce))
        |> put_optional("azp", Keyword.get(opts, :azp))
        |> put_optional("auth_time", Keyword.get(opts, :auth_time))
        |> put_optional("acr", Keyword.get(opts, :acr))
        |> put_optional("amr", Keyword.get(opts, :amr))
        |> put_optional("at_hash", hash_claim(Keyword.get(opts, :access_token), alg, jwk))
        |> put_optional("c_hash", hash_claim(Keyword.get(opts, :code), alg, jwk))
        |> put_optional("sid", Keyword.get(opts, :sid))
        |> Map.merge(extra)

      {:ok,
       JWS.sign_current(config.keystore, claims,
         typ: @header_typ,
         signing_context: signing_context
       )}
    end
  end

  def mint(%Config{}, _subject, _client_id, _opts), do: {:error, :invalid_subject}

  @doc """
  Verify and decode an ID Token previously minted under the same `config`.

  Mirrors `Attesto.Token.verify/3` where the OIDC semantics line up. Runs,
  in order:

    1. **Signature.** The compact JWS is canonical - three base64url-no-pad
       segments - and its signature verifies against a keystore key selected
       by the JWS header `kid`. Each candidate key's accepted algorithm comes
       from trusted keystore metadata or the key type/curve, never from the
       presented header. A `kid` naming a key we do not hold, or an `alg` that
       does not exactly match the algorithm bound to that key, fails as
       `:invalid_signature` (alg-confusion is impossible). A protected header
       carrying a `crit` parameter (RFC 7515 §4.1.11) is rejected with
       `:unsupported_critical_header`. The JOSE header `typ`, when present,
       MUST be `"JWT"`; an access-token header such as `"at+jwt"` is
       `:unexpected_typ`. Verification also rejects access-token-only payload
       claims such as `scope`, `typ: "access"`, and the configured
       principal-kind claim, so token-type separation does not depend solely
       on the optional JOSE `typ` header.
    2. **`iss`** equals the configured issuer (OIDC Core §3.1.3.7 item 1).
    3. **`aud`** contains the expected `client_id`
       (OIDC Core §3.1.3.7 item 3).
    4. **`azp`** - when present, equals the `client_id`
       (OIDC Core §3.1.3.7 item 4/5).
    5. **Required claims** are present and well-typed: `sub` a non-empty
       string, `iat` a non-negative integer.
    6. **Temporal.** `exp` is strictly greater than `now` (no skew leeway);
       an `iat` meaningfully in the future is `:not_yet_valid`.
    7. **`nonce`** - when a `:nonce` is supplied, the claim is present and
       identical (OIDC Core §3.1.3.7 item 11).

  Options:

    * `:client_id` - the Relying Party client id to require in `aud`
      (REQUIRED; OIDC Core §3.1.3.7 item 3).
    * `:nonce` - the nonce sent in the Authentication Request. When
      supplied, the `nonce` claim MUST be present and equal.
    * `:now` - clock override.

  Returns `{:ok, claims}` (string-keyed payload) or `{:error, reason}`.
  """
  @spec verify(Config.t(), String.t(), verify_opts()) ::
          {:ok, claims()} | {:error, verify_error()}
  def verify(config, id_token, opts \\ [])

  def verify(%Config{} = config, id_token, opts) when is_binary(id_token) and is_list(opts) do
    with {:ok, client_id} <- fetch_client_id(opts),
         {:ok, claims} <- verify_signature(config, id_token),
         :ok <- check_token_purpose(config, claims),
         :ok <- check_issuer(config, claims),
         :ok <- check_audience(claims, client_id),
         :ok <- check_azp(claims, client_id),
         :ok <- check_required_claims(claims),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat_not_future(claims, opts),
         :ok <- check_nonce(claims, Keyword.get(opts, :nonce)) do
      {:ok, claims}
    end
  end

  def verify(%Config{}, _id_token, _opts), do: {:error, :invalid_token}

  @doc """
  Verify an ID Token presented as an `id_token_hint` to the end-session
  endpoint (OpenID Connect RP-Initiated Logout 1.0 §2), returning its claims.

  This is a deliberately *looser* check than `verify/3`: the signature, token
  purpose, issuer, required-claim shape, and a non-future `iat` are all
  enforced, but

    * the `aud` (client) is **not** required up front — the caller reads the
      Relying Party from the returned `aud` claim, and
    * **expiry is tolerated** — RP-Initiated Logout §2 says the OP SHOULD
      accept an otherwise-valid hint even after it has expired, since the
      user is logging out precisely because their session is ending.

  A logout token's authenticity still rests entirely on the signature, so a
  forged or tampered hint is rejected as `:invalid_signature` / `:invalid_token`.

  Returns `{:ok, claims}` (string-keyed payload) or `{:error, reason}`.
  """
  @spec verify_logout_hint(Config.t(), String.t()) :: {:ok, claims()} | {:error, verify_error()}
  def verify_logout_hint(%Config{} = config, id_token) when is_binary(id_token) do
    with {:ok, claims} <- verify_signature(config, id_token),
         :ok <- check_token_purpose(config, claims),
         :ok <- check_issuer(config, claims),
         :ok <- check_required_claims(claims),
         :ok <- check_iat_not_future(claims, []) do
      {:ok, claims}
    end
  end

  def verify_logout_hint(%Config{}, _id_token), do: {:error, :invalid_token}

  @doc "The default JWS algorithm for RSA keys. Keystores may label individual keys with another supported alg."
  @spec signing_alg() :: String.t()
  def signing_alg, do: @signing_alg

  @doc ~s(The JOSE header `typ` ID Tokens carry: `"JWT"` \(never `"at+jwt"`\).)
  @spec header_typ() :: String.t()
  def header_typ, do: @header_typ

  # ----- internal: minting -----

  defp put_optional(claims, _key, nil), do: claims
  defp put_optional(claims, key, value), do: Map.put(claims, key, value)

  # OIDC Core §3.1.3.6: left-most half of the hash of the ASCII octets of
  # the value, base64url-encoded without padding. nil means "not requested".
  defp hash_claim(nil, _alg, _jwk), do: nil

  defp hash_claim(value, alg, jwk) when is_binary(value), do: SigningAlg.oidc_hash(value, alg, jwk)

  defp normalize_extra_claims(opts) do
    case Keyword.get(opts, :extra_claims) do
      nil ->
        {:ok, %{}}

      extra when is_map(extra) ->
        case Claims.merge_registered(extra, %{},
               reserved: @reserved_claims,
               atom_keys: :reject
             ) do
          {:ok, normalized} -> {:ok, normalized}
          {:error, :reserved_claim_conflict} -> {:error, :reserved_claim_conflict}
          {:error, _reason} -> {:error, :invalid_extra_claims}
        end

      _other ->
        {:error, :invalid_extra_claims}
    end
  end

  # `:lifetime` may only shorten the default - a larger value (or a
  # non-positive / non-integer) falls back to the default.
  defp lifetime_seconds(opts) do
    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 and n <= @default_lifetime_seconds -> n
      _ -> @default_lifetime_seconds
    end
  end

  # ----- internal: verification -----

  # Mirrors `Attesto.Token`'s signature path: peek the protected header,
  # reject any `crit` member (RFC 7515 §4.1.11), select keystore keys by
  # `kid`, and verify strictly against each trusted key's bound algorithm.
  defp verify_signature(config, jwt) do
    with {:ok, header} <- peek_protected_header(jwt),
         :ok <- check_crit(header),
         :ok <- check_header_typ(header) do
      case candidate_jwks(config, Map.get(header, "kid")) do
        [] -> {:error, :invalid_signature}
        jwks -> verify_against_any(jwks, jwt)
      end
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_header_typ(%{"typ" => @header_typ}), do: :ok
  defp check_header_typ(%{"typ" => _other}), do: {:error, :unexpected_typ}
  defp check_header_typ(_header), do: :ok

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

  # ----- internal: claim checks -----

  defp fetch_client_id(opts) do
    case Keyword.get(opts, :client_id) do
      client_id when is_binary(client_id) and client_id != "" -> {:ok, client_id}
      _ -> {:error, :missing_client_id}
    end
  end

  defp check_token_purpose(config, claims) do
    cond do
      Map.has_key?(claims, "scope") ->
        {:error, :unexpected_typ}

      Map.get(claims, "typ") in ["access", "refresh"] ->
        {:error, :unexpected_typ}

      Map.has_key?(claims, config.principal_kind_claim) ->
        {:error, :unexpected_typ}

      true ->
        :ok
    end
  end

  defp check_issuer(config, %{"iss" => iss}) when is_binary(iss) do
    if iss == config.issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_config, _claims), do: {:error, :invalid_issuer}

  # OIDC Core §3.1.3.7 item 3: the client MUST be present in `aud`, which
  # may be a single string or an array of strings (a mixed array carrying a
  # non-string is malformed and rejected, not silently tolerated).
  defp check_audience(%{"aud" => aud}, client_id) do
    cond do
      aud == client_id -> :ok
      is_list(aud) and Enum.all?(aud, &is_binary/1) and client_id in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_audience(_claims, _client_id), do: {:error, :invalid_audience}

  # OIDC Core §3.1.3.7 item 4/5: if `azp` is present it MUST equal the
  # client. Absent `azp` is permitted (single-audience case).
  defp check_azp(%{"azp" => azp}, client_id) do
    if azp == client_id, do: :ok, else: {:error, :invalid_azp}
  end

  defp check_azp(_claims, _client_id), do: :ok

  defp check_required_claims(claims) do
    cond do
      not non_empty_binary?(Map.get(claims, "sub")) -> {:error, :invalid_claims}
      not non_negative_integer?(Map.get(claims, "iat")) -> {:error, :invalid_claims}
      true -> :ok
    end
  end

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) do
    if NumericDate.not_expired?(exp, NumericDate.now(opts), leeway: 0),
      do: :ok,
      else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  # An `iat` meaningfully in the future was issued by a clock far ahead of
  # ours or forged; reject it (with the same modest skew as Attesto.Token).
  defp check_iat_not_future(%{"iat" => iat}, opts) when is_integer(iat) do
    if NumericDate.not_before_reached?(iat, NumericDate.now(opts), skew: @clock_skew_seconds),
      do: :ok,
      else: {:error, :not_yet_valid}
  end

  defp check_iat_not_future(_claims, _opts), do: :ok

  # OIDC Core §3.1.3.7 item 11: when the request carried a nonce, the claim
  # MUST be present and identical. No supplied nonce means the caller
  # asserts none was sent: a present-but-unverifiable nonce claim is then
  # not checked, but a supplied nonce with no claim is `:nonce_required`.
  defp check_nonce(_claims, nil), do: :ok

  defp check_nonce(claims, expected) do
    case Map.get(claims, "nonce") do
      ^expected -> :ok
      nil -> {:error, :nonce_required}
      _other -> {:error, :nonce_mismatch}
    end
  end

  # ----- internal: helpers -----

  defp check_non_empty(value, _error) when is_binary(value) and value != "", do: :ok
  defp check_non_empty(_value, error), do: {:error, error}

  defp non_empty_binary?(value), do: is_binary(value) and value != ""
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0
end
