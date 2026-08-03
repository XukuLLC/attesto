defmodule Attesto.WalletAttestation do
  @moduledoc """
  OAuth 2.0 Attestation-Based Client Authentication
  (`draft-ietf-oauth-attestation-based-client-auth-10`, 2026-07-06), the
  "Wallet Attestation" client authentication method OID4VCI recommends for
  native-app Wallets in place of `private_key_jwt`/mTLS.

  A Wallet Provider (the Client Attester) issues its Wallet a **Client
  Attestation JWT** (`typ` `oauth-client-attestation+jwt`) binding the
  Wallet/Client Instance's public key into its `cnf` claim. To authenticate a
  request, the Client Instance additionally presents a **Client Attestation
  PoP JWT** (`typ` `oauth-client-attestation-pop+jwt`) signed by that
  instance key, proving possession of it to this Authorization or Resource
  Server.

  `verify/3` verifies both JWTs together per the draft's §7
  "Verification and Processing" rules and returns the proven Client Instance
  key. The host owns the trusted Wallet Provider key material and any
  Challenge issuance/tracking; this module only performs the checks the
  draft prescribes. Conn-free and fail-closed.

  ## Client Attestation JWT (`typ=oauth-client-attestation+jwt`, draft §4)

    * `sub` - REQUIRED. The OAuth `client_id` of the Wallet instance.
    * `exp` - REQUIRED. Expiration time; rejected once passed.
    * `cnf` - REQUIRED. A `{"jwk" => <public JWK>}` (RFC 7800) confirmation
      key - the Client Instance Key used to sign the PoP JWT.
    * `iat` - OPTIONAL.

  The draft version implemented here carries **no `aud`** on the Client
  Attestation JWT itself (earlier drafts did; it was removed) - the
  receiving server's identity is asserted by the PoP JWT's `aud` instead.
  Trust in the signer (the Wallet Provider / Client Attester) is
  out-of-band, per host-supplied trusted keys; the draft leaves the
  discovery mechanism (PKI, `kid`+`jku`, pre-shared metadata) unspecified.

  ## Client Attestation PoP JWT (`typ=oauth-client-attestation-pop+jwt`, draft §5.1)

    * `aud` - REQUIRED. This Authorization Server's issuer identifier URL
      (RFC 8414) or, for a Resource Server, its resource identifier URL
      (RFC 9728). Single-valued; a Client Attestation PoP JWT targets one
      audience only.
    * `jti` - REQUIRED. A unique identifier the caller may use for its own
      replay tracking (see `:replay_check`).
    * `iat` - REQUIRED. Freshness is checked against `:max_age_seconds`.
    * `challenge` - OPTIONAL. Echoes a server-issued Challenge (draft §6);
      checked when the caller supplies `:expected_challenge`.

  It MUST be signed by the private half of the Client Attestation's `cnf`
  key - this module verifies exactly that.
  """

  alias Attesto.{Claims, JWS, Key, NumericDate, SigningAlg, Thumbprint}

  @attestation_typ "oauth-client-attestation+jwt"
  @pop_typ "oauth-client-attestation-pop+jwt"
  @default_pop_max_age_seconds 300
  @future_skew_seconds 60
  # No normative limit in the draft; bounded so a replay store keying on
  # `jti` cannot be forced to retain unbounded-size identifiers.
  @max_jti_length 256

  @type replay_check_fun :: (String.t(), pos_integer() -> :ok | {:error, :replay})

  @type instance_key :: %{jwk: map(), jkt: String.t()}

  @type verified :: %{
          instance_key: instance_key(),
          attestation_claims: map(),
          pop_claims: map(),
          replay_key: String.t(),
          replay_ttl: pos_integer()
        }

  @type verify_opts :: [
          {:trusted_wallet_provider_jwks, map() | [map()]}
          | {:audience, String.t()}
          | {:client_id, String.t()}
          | {:expected_challenge, String.t()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:max_age_seconds, pos_integer()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:enforce_fapi_alg_policy, boolean()}
          | {:replay_check, replay_check_fun() | nil}
        ]

  @type verify_error ::
          :invalid_attestation
          | :invalid_typ
          | :invalid_alg
          | :unsupported_critical_header
          | :invalid_signature
          | :expired
          | :invalid_client_id
          | :missing_cnf
          | :invalid_cnf
          | :invalid_pop
          | :invalid_pop_typ
          | :invalid_pop_alg
          | :unsupported_pop_critical_header
          | :invalid_pop_signature
          | :invalid_pop_audience
          | :invalid_pop_challenge
          | :missing_pop_jti
          | :invalid_pop_jti
          | :missing_pop_iat
          | :invalid_pop_iat
          | :pop_expired
          | :replay

  @doc """
  Verify a Client Attestation JWT together with its Client Attestation PoP
  JWT and return the proven Client Instance key.

  ## Required opts

    * `:trusted_wallet_provider_jwks` - an RFC 7517 JWK Set, a single public
      JWK map, or a list of public JWK maps the Client Attestation JWT's
      signature is checked against. Establishing which Wallet Provider(s) to
      trust is the host's responsibility (draft §7.1 leaves this out of
      scope).
    * `:audience` - this Authorization/Resource Server's own identifier; the
      PoP JWT's `aud` MUST equal it exactly.

  ## Optional opts

    * `:client_id` - when set, the Client Attestation's `sub` MUST equal it.
    * `:expected_challenge` - a Challenge (draft §6) previously issued to
      the client; when set, the PoP's `challenge` claim MUST match it. The
      Challenge is a server-issued, non-secret freshness token (visible on
      the wire already), so this is a plain equality check, matching
      `Attesto.CredentialProof`'s `c_nonce` check.
    * `:now` - clock reference (DateTime or unix seconds).
    * `:max_age_seconds` - how far in the past the PoP's `iat` may be.
      Default #{@default_pop_max_age_seconds}.
    * `:accepted_algs` - JWS algorithms accepted for both JWTs' signatures.
      Defaults to `Attesto.SigningAlg.fapi_algs/0`.
    * `:enforce_fapi_alg_policy` - additionally enforce the FAPI RSA
      modulus / Edwards curve restrictions on the Client Attestation
      signer's key. Defaults to `true` when `:accepted_algs` is omitted,
      `false` otherwise (matches `Attesto.ClientAssertion.verify/5`).
    * `:replay_check` - a 2-arity function `(replay_key, ttl_seconds) -> :ok
      | {:error, :replay}`, called after every other PoP check passes.
      `replay_key` is a fixed-length digest namespacing the `jti` by the
      Client Instance Key's thumbprint - do not assume it is the raw `jti`.
      Omitted, no replay check is performed inline; the caller may instead
      record the returned `replay_key`/`replay_ttl` itself after any later
      binding step (see `Attesto.DPoP`'s "Replay protection" for why that
      order matters when there is one).

  Returns `{:ok, %{instance_key: %{jwk:, jkt:}, attestation_claims:,
  pop_claims:, replay_key:, replay_ttl:}}`.
  """
  @spec verify(String.t(), String.t(), verify_opts()) :: {:ok, verified()} | {:error, verify_error()}
  def verify(attestation, pop, opts \\ [])

  def verify(attestation, pop, opts) when is_binary(attestation) and is_binary(pop) and is_list(opts) do
    with {:ok, attestation_claims, jwk_map, jkt} <- verify_attestation(attestation, opts),
         {:ok, pop_claims, replay_key} <- verify_pop(pop, jwk_map, jkt, opts) do
      {:ok,
       %{
         instance_key: %{jwk: jwk_map, jkt: jkt},
         attestation_claims: attestation_claims,
         pop_claims: pop_claims,
         replay_key: replay_key,
         replay_ttl: replay_ttl(opts)
       }}
    end
  end

  def verify(_attestation, _pop, _opts), do: {:error, :invalid_attestation}

  # ── Client Attestation JWT ───────────────────────────────────────────────

  defp verify_attestation(attestation, opts) do
    with {:ok, header} <- parse_header(attestation, :invalid_attestation),
         :ok <- check_crit(header, :unsupported_critical_header),
         :ok <- check_typ(header, @attestation_typ, :invalid_typ),
         {:ok, claims} <- verify_attestation_signature(attestation, header, opts),
         :ok <- check_client_id(claims, opts),
         :ok <- check_attestation_expiry(claims, opts),
         {:ok, jwk_map} <- extract_cnf_jwk_map(claims),
         {:ok, jkt} <- jwk_thumbprint(jwk_map, :invalid_cnf) do
      {:ok, claims, jwk_map, jkt}
    end
  end

  defp verify_attestation_signature(attestation, header, opts) do
    trusted = Keyword.fetch!(opts, :trusted_wallet_provider_jwks)
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    enforce_fapi_policy =
      Keyword.get(opts, :enforce_fapi_alg_policy, not Keyword.has_key?(opts, :accepted_algs))

    candidates =
      JWS.verification_candidates(trusted,
        kid: Map.get(header, "kid"),
        accepted_algs: accepted_algs,
        fapi?: enforce_fapi_policy,
        malformed_key: :reject_set
      )

    JWS.verify_strict(attestation, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_attestation
    )
  end

  defp check_client_id(claims, opts) do
    case Keyword.get(opts, :client_id) do
      nil -> :ok
      client_id -> if Map.get(claims, "sub") == client_id, do: :ok, else: {:error, :invalid_client_id}
    end
  end

  defp check_attestation_expiry(%{"exp" => exp}, opts) when is_integer(exp) do
    now = NumericDate.now(opts, invalid_override: :fallback)
    if NumericDate.not_expired?(exp, now, leeway: 0), do: :ok, else: {:error, :expired}
  end

  defp check_attestation_expiry(_claims, _opts), do: {:error, :expired}

  # Structural extraction only - `map()` with entries, nothing more. Whether
  # it is usable key material (not private, alg-compatible) is validated at
  # PoP-verification time against the PoP's own declared `alg`, exactly as
  # `Attesto.CredentialProof` validates its embedded proof `jwk` against its
  # own header `alg`.
  defp extract_cnf_jwk_map(%{"cnf" => %{"jwk" => jwk_map}}) when is_map(jwk_map) and map_size(jwk_map) > 0,
    do: {:ok, jwk_map}

  defp extract_cnf_jwk_map(_claims), do: {:error, :missing_cnf}

  # ── Client Attestation PoP JWT ───────────────────────────────────────────

  defp verify_pop(pop, cnf_jwk_map, jkt, opts) do
    with {:ok, header} <- parse_header(pop, :invalid_pop),
         :ok <- check_crit(header, :unsupported_pop_critical_header),
         :ok <- check_typ(header, @pop_typ, :invalid_pop_typ),
         {:ok, alg} <- check_pop_alg(header, opts),
         {:ok, cnf_jwk} <- verification_jwk_from_cnf(cnf_jwk_map, alg),
         {:ok, claims} <- verify_pop_signature(pop, alg, cnf_jwk),
         :ok <- check_pop_audience(claims, opts),
         :ok <- check_pop_challenge(claims, opts),
         :ok <- check_pop_iat(claims, opts),
         {:ok, jti} <- check_pop_jti(claims),
         replay_key = replay_key(jkt, jti),
         :ok <- check_pop_replay(replay_key, jti, opts) do
      {:ok, claims, replay_key}
    end
  end

  defp check_pop_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())
    if alg != "none" and alg in accepted, do: {:ok, alg}, else: {:error, :invalid_pop_alg}
  end

  defp check_pop_alg(_header, _opts), do: {:error, :invalid_pop_alg}

  defp verification_jwk_from_cnf(jwk_map, alg) do
    case Key.verification_jwk(jwk_map, alg: alg) do
      {:ok, jwk} -> {:ok, jwk}
      {:error, _reason} -> {:error, :invalid_cnf}
    end
  end

  defp verify_pop_signature(pop, alg, jwk) do
    JWS.verify_strict(pop, [{nil, alg, jwk}],
      terminal_error: :invalid_pop_signature,
      malformed_result: :halt,
      malformed_error: :invalid_pop_signature
    )
  end

  # Client Attestation PoP JWTs are single-audience by draft §5.1; an array
  # `aud` is rejected even when it contains the expected value.
  defp check_pop_audience(%{"aud" => aud}, opts) do
    expected = Keyword.fetch!(opts, :audience)
    if Claims.audience_matches?(aud, expected, :scalar_only), do: :ok, else: {:error, :invalid_pop_audience}
  end

  defp check_pop_audience(_claims, _opts), do: {:error, :invalid_pop_audience}

  defp check_pop_challenge(claims, opts) do
    case Keyword.get(opts, :expected_challenge) do
      nil ->
        :ok

      expected ->
        if Map.get(claims, "challenge") == expected, do: :ok, else: {:error, :invalid_pop_challenge}
    end
  end

  defp check_pop_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    now = NumericDate.now(opts, invalid_override: :fallback)
    max_age = Keyword.get(opts, :max_age_seconds, @default_pop_max_age_seconds)

    case NumericDate.fresh?(iat, now, future_skew: @future_skew_seconds, max_age: max_age) do
      :ok -> :ok
      :future -> {:error, :invalid_pop_iat}
      :stale -> {:error, :pop_expired}
      :invalid -> {:error, :invalid_pop_iat}
    end
  end

  defp check_pop_iat(%{"iat" => _}, _opts), do: {:error, :invalid_pop_iat}
  defp check_pop_iat(_claims, _opts), do: {:error, :missing_pop_iat}

  defp check_pop_jti(%{"jti" => jti}) when is_binary(jti) and jti != "" do
    if byte_size(jti) > @max_jti_length, do: {:error, :invalid_pop_jti}, else: {:ok, jti}
  end

  defp check_pop_jti(%{"jti" => _}), do: {:error, :invalid_pop_jti}
  defp check_pop_jti(_claims), do: {:error, :missing_pop_jti}

  defp check_pop_replay(replay_key, _jti, opts) do
    case Keyword.get(opts, :replay_check) do
      nil ->
        :ok

      fun when is_function(fun, 2) ->
        case fun.(replay_key, replay_ttl(opts)) do
          :ok -> :ok
          {:error, :replay} -> {:error, :replay}
          other -> raise ArgumentError, ":replay_check must return :ok or {:error, :replay}; got #{inspect(other)}"
        end

      other ->
        raise ArgumentError, ":replay_check must be a 2-arity function or nil; got #{inspect(other)}"
    end
  end

  # Namespace the replay identity by the Client Instance Key's thumbprint:
  # `jti` uniqueness is only meaningful per key, so hashing the (jkt, jti)
  # pair to a fixed-length identifier keeps one instance's `jti` choices from
  # colliding with another's in a shared store. Mirrors `Attesto.DPoP`.
  defp replay_key(jkt, jti) do
    :sha256 |> :crypto.hash(jkt <> ":" <> jti) |> Base.url_encode64(padding: false)
  end

  # See `Attesto.DPoP`'s `replay_ttl/1` for why `+ 1`: the freshness check is
  # inclusive at the accepted boundary, so the store must outlive it by a
  # whole second to avoid a still-fresh-but-forgotten `jti`.
  defp replay_ttl(opts) do
    Keyword.get(opts, :max_age_seconds, @default_pop_max_age_seconds) + @future_skew_seconds + 1
  end

  # ── shared header/claim helpers ──────────────────────────────────────────

  defp parse_header(jwt, error) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, error}
    end
  end

  defp check_crit(header, error) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, error}
    end
  end

  defp check_typ(%{"typ" => typ}, typ, _error), do: :ok
  defp check_typ(_header, _typ, error), do: {:error, error}

  defp jwk_thumbprint(jwk_map, error) do
    case Thumbprint.of_jwk(jwk_map) do
      {:ok, jkt} -> {:ok, jkt}
      {:error, :malformed_jwk} -> {:error, error}
    end
  end
end
