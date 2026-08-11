defmodule Attesto.CredentialProof do
  @moduledoc """
  OID4VCI credential-request key proof of type `jwt`
  (draft-ietf-oauth-openid4vci §8.2.1.1).

  When a wallet asks the credential endpoint for a credential, it proves
  possession of the key the issued credential will be bound to (its `cnf`) with
  a `proof` object `{"proof_type": "jwt", "jwt": <JWS>}`. The proof JWS is typed
  `openid4vci-proof+jwt`; its header carries the holder's public key (as `jwk`);
  its payload carries:

    * `aud` - the Credential Issuer Identifier (this issuer). REQUIRED.
    * `iat` - issuance time. REQUIRED, and must be fresh.
    * `nonce` - the `c_nonce` the issuer previously handed out, when it did.
    * `iss` - the client_id, for the authorized code flow.

  `verify_jwt/2` validates the proof and returns the holder public JWK (and its
  RFC 7638 thumbprint) so the caller binds the credential to it via `cnf`.

  This is the issuance-time sibling of `Attesto.DPoP` / `Attesto.SdJwt`'s Key
  Binding JWT: same "prove you hold this key" shape, different claim set.
  Conn-free and fail-closed.

  ## Optional key attestation cross-check

  A Wallet MAY additionally carry a key attestation (`Attesto.KeyAttestation`)
  in the proof's `key_attestation` JOSE header, vouching that the proof's
  `jwk` is held in attested secure storage (OID4VCI Appendix D). This is
  off by default - passing neither `:key_attestation_trusted_jwks` nor
  `:require_key_attestation` reproduces the exact behavior of every prior
  release. Supplying `:key_attestation_trusted_jwks` opts a caller into
  verifying a present `key_attestation` header and rejecting a proof whose
  key is not among its `attested_keys`; `:require_key_attestation` additionally
  rejects a proof that carries no `key_attestation` header at all.
  """

  alias Attesto.{JWS, Key, KeyAttestation, NumericDate, SigningAlg, Thumbprint}

  @proof_typ "openid4vci-proof+jwt"
  @default_max_age_seconds 300
  @future_skew_seconds 60

  @type verified :: %{jwk: map(), jkt: String.t(), key_attestation: KeyAttestation.verified() | nil}

  @type verify_error ::
          :invalid_proof
          | :invalid_typ
          | :invalid_alg
          | :missing_jwk
          | :invalid_jwk
          | :invalid_signature
          | :invalid_audience
          | :invalid_nonce
          | :invalid_iat
          | :invalid_issuer
          | :missing_key_attestation
          | :invalid_key_attestation
          | :key_not_attested

  @doc """
  Verify a `jwt` credential-request key proof.

  Required opts:

    * `:issuer` - the Credential Issuer Identifier the proof's `aud` must equal.

  Optional opts:

    * `:nonce` - the expected `c_nonce`. When set, the proof MUST carry a
      matching `nonce`; when omitted, no `nonce` is required (issuers that do
      not use `c_nonce`).
    * `:client_id` - when set, the proof's `iss` MUST equal it.
    * `:now` - clock reference (DateTime or unix seconds).
    * `:max_age_seconds` - how far in the past `iat` may be. Default
      #{@default_max_age_seconds}.
    * `:accepted_algs` - JWS algorithms accepted. Defaults to
      `Attesto.SigningAlg.fapi_algs/0`.
    * `:key_attestation_trusted_jwks` - opts into verifying a `key_attestation`
      JOSE header (see "Optional key attestation cross-check" above) against
      these trusted keys and rejecting a proof whose key is not among the
      attestation's `attested_keys`. Omitted (the default), no such header is
      looked at.
    * `:require_key_attestation` - when true, a proof with no `key_attestation`
      header is rejected. Only meaningful alongside
      `:key_attestation_trusted_jwks`; defaults to `false`.

  Returns `{:ok, %{jwk: holder_public_jwk, jkt: thumbprint, key_attestation:
  verified_attestation_or_nil}}`. `key_attestation` is `nil` unless
  `:key_attestation_trusted_jwks` was supplied and a `key_attestation` header
  was present and verified.
  """
  @spec verify_jwt(String.t(), keyword()) :: {:ok, verified()} | {:error, verify_error()}
  def verify_jwt(proof, opts) when is_binary(proof) and is_list(opts) do
    with {:ok, header} <- parse_header(proof),
         :ok <- check_typ(header),
         :ok <- check_crit(header),
         {:ok, alg} <- check_alg(header, opts),
         {:ok, jwk_map, jwk} <- extract_jwk(header, alg),
         {:ok, claims} <- verify_signature(proof, alg, jwk),
         :ok <- check_audience(claims, opts),
         :ok <- check_nonce(claims, opts),
         :ok <- check_issuer(claims, opts),
         :ok <- check_iat(claims, opts),
         {:ok, jkt} <- jwk_thumbprint(jwk),
         {:ok, key_attestation} <- check_key_attestation(header, jwk_map, opts) do
      {:ok, %{jwk: jwk_map, jkt: jkt, key_attestation: key_attestation}}
    end
  end

  def verify_jwt(_proof, _opts), do: {:error, :invalid_proof}

  # ── header ───────────────────────────────────────────────────────────────

  defp parse_header(proof) do
    case JWS.peek_json(proof, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_proof}
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :invalid_proof}
    end
  end

  defp check_typ(%{"typ" => @proof_typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())
    # Guard is_list: a malformed `accepted_algs` (e.g. nil — host config) fails
    # closed rather than raising on `alg in nil`.
    if is_list(accepted) and alg != "none" and alg in accepted,
      do: {:ok, alg},
      else: {:error, :invalid_alg}
  end

  defp check_alg(_header, _opts), do: {:error, :invalid_alg}

  # The holder key rides in the header `jwk` and MUST be a public key usable for
  # signature verification whose declared `alg` (if any) agrees with the header.
  defp extract_jwk(%{"jwk" => jwk_map}, alg) when is_map(jwk_map) and map_size(jwk_map) > 0 do
    case Key.verification_jwk(jwk_map, alg: alg) do
      {:ok, jwk} -> {:ok, jwk_map, jwk}
      {:error, _reason} -> {:error, :invalid_jwk}
    end
  end

  defp extract_jwk(_header, _alg), do: {:error, :missing_jwk}

  # ── signature ────────────────────────────────────────────────────────────

  defp verify_signature(proof, alg, jwk) do
    JWS.verify_strict(proof, [{nil, alg, jwk}],
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_signature
    )
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp jwk_thumbprint(jwk) do
    case Thumbprint.of_jwk(jwk) do
      {:ok, jkt} -> {:ok, jkt}
      {:error, :malformed_jwk} -> {:error, :invalid_jwk}
    end
  end

  # ── claims ───────────────────────────────────────────────────────────────

  defp check_audience(%{"aud" => aud}, opts) do
    expected = Keyword.fetch!(opts, :issuer)

    cond do
      is_binary(aud) and aud == expected -> :ok
      is_list(aud) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_audience(_claims, _opts), do: {:error, :invalid_audience}

  defp check_nonce(claims, opts) do
    case Keyword.get(opts, :nonce) do
      nil -> :ok
      expected -> if Map.get(claims, "nonce") == expected, do: :ok, else: {:error, :invalid_nonce}
    end
  end

  defp check_issuer(claims, opts) do
    case Keyword.get(opts, :client_id) do
      nil -> :ok
      client_id -> if Map.get(claims, "iss") == client_id, do: :ok, else: {:error, :invalid_issuer}
    end
  end

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) do
    now = NumericDate.now(opts, invalid_override: :fallback)
    max_age = Keyword.get(opts, :max_age_seconds, @default_max_age_seconds)

    if NumericDate.fresh?(iat, now, future_skew: @future_skew_seconds, max_age: max_age) == :ok,
      do: :ok,
      else: {:error, :invalid_iat}
  end

  defp check_iat(_claims, _opts), do: {:error, :invalid_iat}

  # ── key attestation cross-check (opt-in) ────────────────────────────────

  defp check_key_attestation(header, jwk_map, opts) do
    case Keyword.get(opts, :key_attestation_trusted_jwks) do
      nil -> {:ok, nil}
      trusted_jwks -> check_key_attestation_header(header, jwk_map, trusted_jwks, opts)
    end
  end

  defp check_key_attestation_header(header, jwk_map, trusted_jwks, opts) do
    case Map.get(header, "key_attestation") do
      nil ->
        if Keyword.get(opts, :require_key_attestation, false),
          do: {:error, :missing_key_attestation},
          else: {:ok, nil}

      attestation when is_binary(attestation) ->
        verify_key_attestation(attestation, jwk_map, trusted_jwks, opts)

      _other ->
        {:error, :invalid_key_attestation}
    end
  end

  # The Issuer's own `c_nonce` (`opts[:nonce]`) doubles as the key
  # attestation's freshness nonce per OID4VCI Appendix D.1: "If the
  # Credential Issuer provided a `c_nonce`, the `nonce` claim in the key
  # attestation MUST be set to a server-provided `c_nonce`." Reusing the same
  # `:now` keeps both checks on one clock reference.
  defp verify_key_attestation(attestation, jwk_map, trusted_jwks, opts) do
    key_attestation_opts =
      [trusted_jwks: trusted_jwks]
      |> put_if_present(:nonce, Keyword.get(opts, :nonce))
      |> put_if_present(:now, Keyword.get(opts, :now))

    case KeyAttestation.verify(attestation, key_attestation_opts) do
      {:ok, %{attested_keys: attested_keys} = result} ->
        if KeyAttestation.covers_key?(attested_keys, jwk_map),
          do: {:ok, result},
          else: {:error, :key_not_attested}

      {:error, _reason} ->
        {:error, :invalid_key_attestation}
    end
  end

  defp put_if_present(kw, _key, nil), do: kw
  defp put_if_present(kw, key, value), do: Keyword.put(kw, key, value)
end
