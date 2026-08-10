defmodule Attesto.KeyAttestation do
  @moduledoc """
  OID4VCI Key Attestation in JWT format (OpenID4VCI 1.0 draft 15/ID2,
  "Key Attestation in JWT format" §D.1, `#keyattestation-jwt`).

  A key attestation is a statement - issued by a Wallet's key storage
  component or its Wallet Provider - that a set of cryptographic public
  keys are held in a specific class of secure storage and (optionally)
  gated behind a specific class of user authentication. A Wallet MAY attach
  one to a Credential Request, either:

    * in the `key_attestation` JOSE header of a `jwt` proof (alongside a
      proof of possession of one of the attested keys), or
    * as the sole element of an `attestation` proof type (no proof of
      possession of any attested key - one attestation can vouch for many).

  `verify/2` validates the attestation JWT and returns its `attested_keys`
  plus any assurance claims (`key_storage`, `user_authentication`,
  `certification`). Trust in the signer (the key storage component / Wallet
  Provider) is host-supplied, exactly as `Attesto.ClientAssertion` and
  `Attesto.WalletAttestation` take trusted keys from the caller. Conn-free
  and fail-closed.

  ## JWT shape (`typ=key-attestation+jwt`)

    * `alg` - REQUIRED header; MUST NOT be `none` or a MAC algorithm.
    * `typ` - REQUIRED header; MUST be `key-attestation+jwt`.
    * `iat` - REQUIRED.
    * `exp` - OPTIONAL per the spec text, but "MUST be present if the
      attestation is used with the `jwt` proof type". Since this module
      cannot see the surrounding proof type, it defaults to requiring `exp`
      (fail-closed); pass `require_exp: false` for a deployment that only
      ever uses the `attestation` proof type and intentionally issues
      attestations with no expiry.
    * `attested_keys` - REQUIRED, a non-empty array of public JWKs.
    * `key_storage`, `user_authentication` - OPTIONAL non-empty arrays of
      attack-potential-resistance strings (`iso_18045_*` or an
      ecosystem-defined value).
    * `certification` - OPTIONAL, a URL.
    * `nonce` - OPTIONAL; MUST echo the Issuer's `c_nonce` when one was
      provided. Checked against `:nonce` when supplied.

  As of this draft, the key attestation JWT carries no formal `iss`/`aud`
  claim (unlike the Client/Wallet Attestation JWT) - the spec's own example
  includes `iss`, but the normative claim list does not. `verify/2` still
  lets a caller pin `:issuer` for deployments that populate and rely on it
  by convention; it is not checked unless supplied.
  """

  alias Attesto.{JWS, NumericDate, SigningAlg, Thumbprint}

  @typ "key-attestation+jwt"
  @future_skew_seconds 60

  @type verified :: %{
          attested_keys: [map()],
          key_storage: [String.t()] | nil,
          user_authentication: [String.t()] | nil,
          certification: String.t() | nil,
          claims: map()
        }

  @type verify_opts :: [
          {:trusted_jwks, map() | [map()]}
          | {:issuer, String.t()}
          | {:nonce, String.t()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:require_exp, boolean()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:enforce_fapi_alg_policy, boolean()}
        ]

  @type verify_error ::
          :invalid_attestation
          | :invalid_typ
          | :invalid_alg
          | :unsupported_critical_header
          | :invalid_signature
          | :missing_iat
          | :invalid_iat
          | :missing_exp
          | :expired
          | :not_yet_valid
          | :missing_attested_keys
          | :invalid_attested_keys
          | :invalid_issuer
          | :invalid_nonce

  @doc """
  Verify a key attestation JWT.

  ## Required opts

    * `:trusted_jwks` - an RFC 7517 JWK Set, a single public JWK map, or a
      list of public JWK maps the attestation's signature is checked
      against. Establishing which key-storage components / Wallet
      Providers to trust is the host's responsibility.

  ## Optional opts

    * `:issuer` - when set, the attestation's `iss` (if present) MUST equal
      it. Not required to be present unless the caller relies on it -
      see the module doc.
    * `:nonce` - the expected `c_nonce`; when set, the attestation's
      `nonce` claim MUST match it exactly.
    * `:now` - clock reference (DateTime or unix seconds).
    * `:require_exp` - whether `exp` must be present. Defaults to `true`.
    * `:accepted_algs` - JWS algorithms accepted. Defaults to
      `Attesto.SigningAlg.fapi_algs/0`.
    * `:enforce_fapi_alg_policy` - additionally enforce the FAPI RSA modulus
      and Edwards-curve restrictions on the attestation signer's key (parity
      with `Attesto.ClientAssertion` and `Attesto.WalletAttestation`). Defaults
      to `true` when `:accepted_algs` is omitted and `false` when the caller
      supplies its own `:accepted_algs`.

  Returns `{:ok, %{attested_keys:, key_storage:, user_authentication:,
  certification:, claims:}}`, where `attested_keys` is the list of public
  JWK maps this attestation vouches for.
  """
  @spec verify(String.t(), verify_opts()) :: {:ok, verified()} | {:error, verify_error()}
  def verify(attestation, opts \\ [])

  def verify(attestation, opts) when is_binary(attestation) and is_list(opts) do
    with {:ok, header} <- parse_header(attestation),
         :ok <- check_crit(header),
         :ok <- check_typ(header),
         {:ok, claims} <- verify_signature(attestation, header, opts),
         :ok <- check_issuer(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_exp(claims, opts),
         :ok <- check_nbf(claims, opts),
         :ok <- check_nonce(claims, opts),
         {:ok, attested_keys} <- extract_attested_keys(claims) do
      {:ok,
       %{
         attested_keys: attested_keys,
         key_storage: Map.get(claims, "key_storage"),
         user_authentication: Map.get(claims, "user_authentication"),
         certification: Map.get(claims, "certification"),
         claims: claims
       }}
    end
  end

  def verify(_attestation, _opts), do: {:error, :invalid_attestation}

  @doc """
  Returns `true` iff `jwk` (a public JWK map) is among `attested_keys`,
  compared by RFC 7638 thumbprint rather than raw map equality so key
  members in a different order, or an added `alg`/`use`/`kid`, do not cause
  a false negative.

  Used to cross-check a credential-request proof's holder key against a
  key attestation's `attested_keys` (see `Attesto.CredentialProof`'s
  `:key_attestation` opt).
  """
  @spec covers_key?([map()], map()) :: boolean()
  def covers_key?(attested_keys, jwk) when is_list(attested_keys) and is_map(jwk) do
    case Thumbprint.of_jwk(jwk) do
      {:ok, jkt} ->
        Enum.any?(attested_keys, fn candidate ->
          match?({:ok, ^jkt}, Thumbprint.of_jwk(candidate))
        end)

      {:error, _reason} ->
        false
    end
  end

  def covers_key?(_attested_keys, _jwk), do: false

  # ── header ───────────────────────────────────────────────────────────────

  defp parse_header(attestation) do
    case JWS.peek_json(attestation, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_attestation}
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_typ(%{"typ" => @typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  # ── signature ────────────────────────────────────────────────────────────

  defp verify_signature(attestation, header, opts) do
    trusted = Keyword.fetch!(opts, :trusted_jwks)
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    # Parity with client_assertion/wallet_attestation: also enforce the FAPI
    # RSA-modulus / Edwards-curve strength gate on the attestation signer,
    # unless the caller narrowed `:accepted_algs` itself.
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

  # ── claims ───────────────────────────────────────────────────────────────

  defp check_issuer(claims, opts) do
    case {Keyword.get(opts, :issuer), Map.get(claims, "iss")} do
      {nil, _iss} -> :ok
      {_expected, nil} -> :ok
      {expected, iss} -> if iss == expected, do: :ok, else: {:error, :invalid_issuer}
    end
  end

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    now = NumericDate.now(opts, invalid_override: :fallback)
    if NumericDate.not_before_reached?(iat, now, skew: @future_skew_seconds), do: :ok, else: {:error, :invalid_iat}
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :invalid_iat}
  defp check_iat(_claims, _opts), do: {:error, :missing_iat}

  defp check_exp(%{"exp" => exp}, opts) when is_integer(exp) do
    now = NumericDate.now(opts, invalid_override: :fallback)
    if NumericDate.not_expired?(exp, now, leeway: 0), do: :ok, else: {:error, :expired}
  end

  defp check_exp(%{"exp" => _}, _opts), do: {:error, :expired}

  defp check_exp(_claims, opts) do
    if Keyword.get(opts, :require_exp, true), do: {:error, :missing_exp}, else: :ok
  end

  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    now = NumericDate.now(opts, invalid_override: :fallback)
    if NumericDate.not_before_reached?(nbf, now, skew: @future_skew_seconds), do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_nbf(%{"nbf" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_nbf(_claims, _opts), do: :ok

  defp check_nonce(claims, opts) do
    case Keyword.get(opts, :nonce) do
      nil -> :ok
      expected -> if Map.get(claims, "nonce") == expected, do: :ok, else: {:error, :invalid_nonce}
    end
  end

  defp extract_attested_keys(%{"attested_keys" => [_ | _] = keys}) do
    if Enum.all?(keys, &valid_attested_key?/1),
      do: {:ok, keys},
      else: {:error, :invalid_attested_keys}
  end

  defp extract_attested_keys(_claims), do: {:error, :missing_attested_keys}

  # Structural check only (a non-empty JWK-shaped map with no private
  # members) - these are the Credential Issuer's own binding targets, not
  # verification keys for this JWT's signature, so `Attesto.Key` public-key
  # policy (alg/use/rsa-strength) does not apply the same way. A caller that
  # goes on to bind a credential to one of these keys is responsible for its
  # own key-strength policy at that point, same as any other holder-supplied
  # `cnf` key.
  defp valid_attested_key?(%{"kty" => kty} = jwk) when is_binary(kty) do
    not Enum.any?(~w(d p q dp dq qi oth k), &Map.has_key?(jwk, &1))
  end

  defp valid_attested_key?(_jwk), do: false
end
