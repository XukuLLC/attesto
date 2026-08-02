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
  """

  alias Attesto.{JWS, Key, SigningAlg, Thumbprint}

  @proof_typ "openid4vci-proof+jwt"
  @default_max_age_seconds 300
  @future_skew_seconds 60

  @type verified :: %{jwk: map(), jkt: String.t()}

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

  Returns `{:ok, %{jwk: holder_public_jwk, jkt: thumbprint}}`.
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
         {:ok, jkt} <- jwk_thumbprint(jwk) do
      {:ok, %{jwk: jwk_map, jkt: jkt}}
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
    if alg != "none" and alg in accepted, do: {:ok, alg}, else: {:error, :invalid_alg}
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
    case JOSE.JWT.verify_strict(jwk, [alg], proof) do
      {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:ok, claims}
      _ -> {:error, :invalid_signature}
    end
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
    now = unix_now(opts)
    max_age = Keyword.get(opts, :max_age_seconds, @default_max_age_seconds)
    if iat <= now + @future_skew_seconds and iat >= now - max_age, do: :ok, else: {:error, :invalid_iat}
  end

  defp check_iat(_claims, _opts), do: {:error, :invalid_iat}

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      n when is_integer(n) -> n
      _ -> DateTime.utc_now() |> DateTime.to_unix(:second)
    end
  end
end
