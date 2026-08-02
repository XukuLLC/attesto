defmodule Attesto.Key do
  @moduledoc """
  Pure helpers for working with signing material as PEM strings.

  An RSA private key already contains its public half, so there is never
  a separately stored public PEM to drift out of sync. `public_pem/1`
  derives the public key from a private PEM, giving exactly one source of
  truth: the verification key always matches the signing key. This closes
  a real failure mode where a tracked public PEM and a regenerated
  private key silently mismatch and every verification fails.

  `kid/1` is the RFC 7638 JWK thumbprint of a key's public half. It is
  stable for a given key and changes iff the key changes, so rotating to a
  new key yields a distinct `kid` automatically - no separate identifier
  to assign or track.
  """

  alias Attesto.Thumbprint

  @private_jwk_members ~w(d p q dp dq qi oth k)
  @rsa_verification_algs ~w(RS256 RS384 RS512 PS256 PS384 PS512)
  @default_minimum_rsa_bits 2048

  @type verification_jwk_error ::
          :private_material
          | :invalid_use
          | :alg_mismatch
          | :incompatible_key
          | :weak_key
          | :malformed_jwk

  @doc """
  Derive the public key, in conventional SPKI
  (`-----BEGIN PUBLIC KEY-----`) PEM form, from a private RSA key PEM.

  Accepts the PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) forms.
  Raises `ArgumentError` - signing material is operator-provided, so a
  misconfiguration is a deploy-time failure that should be loud rather
  than silently verifying against garbage - if `pem` contains no key
  entry, contains more than one, contains a non-RSA key, or is
  public-only. EC/OKP deployments should publish JWKS instead.
  """
  @spec public_pem(String.t()) :: String.t()
  def public_pem(pem) when is_binary(pem) do
    pem
    |> decode_rsa_private_key!()
    |> rsa_public_from_private()
    |> encode_spki_pem()
    |> normalize_pem()
  end

  @doc """
  The RFC 7638 SHA-256 JWK thumbprint (`kid`) of the public half of the
  key in `pem`. Accepts a private or public PEM; both yield the same
  thumbprint because it is computed over the public members only.
  """
  @spec kid(String.t()) :: String.t()
  def kid(pem) when is_binary(pem) do
    {:ok, kid} = pem |> jwk() |> Thumbprint.of_jwk()
    kid
  end

  @doc """
  Validate and parse an untrusted JWK for signature verification.

  The raw map is checked before parsing so private members and contradictory
  RFC 7517 metadata cannot be normalized away by the JOSE library. By default,
  private material is rejected and RSA verification keys must be at least 2048
  bits.

  `:alg` is required and is compared with a JWK's optional `alg` member.
  `:require_public?` defaults to `true`, and `:minimum_rsa_bits` defaults to
  #{@default_minimum_rsa_bits}.

  To retain DPoP's error semantics, explicit Edwards identifiers are checked
  against the key curve here, while other key-type/algorithm mismatches remain
  the signature verifier's responsibility.
  """
  @spec verification_jwk(map(), keyword()) ::
          {:ok, JOSE.JWK.t()} | {:error, verification_jwk_error()}
  def verification_jwk(jwk_map, opts) when is_map(jwk_map) and is_list(opts) do
    alg = Keyword.fetch!(opts, :alg)
    require_public? = Keyword.get(opts, :require_public?, true)
    minimum_rsa_bits = Keyword.get(opts, :minimum_rsa_bits, @default_minimum_rsa_bits)

    validate_verification_options!(require_public?, minimum_rsa_bits)

    with :ok <- reject_private_members(jwk_map, require_public?),
         :ok <- validate_jwk_usage(jwk_map),
         :ok <- validate_jwk_alg(jwk_map, alg),
         {:ok, jwk} <- from_verification_map(jwk_map),
         :ok <- validate_rsa_strength(alg, jwk, minimum_rsa_bits),
         :ok <- validate_edwards_curve(alg, jwk) do
      {:ok, jwk}
    end
  end

  @doc """
  Parse a PEM (private or public) into a `JOSE.JWK`.

  Raises `ArgumentError` if `pem` does not contain exactly one parseable
  key. `JOSE.JWK.from_pem/1` returns `[]` for input with no key entry and
  a list for a multi-key PEM; left unguarded, `thumbprint/1` of those
  returns `[]` rather than a string, which would silently poison `kid/1`
  and verification-key selection. Failing loudly here surfaces a
  malformed keystore PEM as a configuration error instead of a
  request-time mystery.

  Also raises if the key type/curve is not supported by Attesto's
  asymmetric signing algorithms. Algorithms are derived from trusted key
  metadata, not from a presented token header.
  """
  @spec jwk(String.t()) :: JOSE.JWK.t()
  def jwk(pem) when is_binary(pem) do
    case safe_from_pem(pem) do
      %JOSE.JWK{} = jwk ->
        ensure_supported!(jwk)

      _other ->
        raise ArgumentError,
              "PEM did not contain exactly one parseable key (it was empty, " <>
                "malformed, or carried multiple key entries)"
    end
  end

  defp ensure_supported!(%JOSE.JWK{} = jwk) do
    Attesto.SigningAlg.infer(jwk)
    jwk
  end

  defp reject_private_members(_jwk_map, false), do: :ok

  defp reject_private_members(jwk_map, true) do
    if Enum.any?(@private_jwk_members, &Map.has_key?(jwk_map, &1)),
      do: {:error, :private_material},
      else: :ok
  end

  defp validate_jwk_usage(jwk_map) do
    use_ok? = Map.get(jwk_map, "use") in [nil, "sig"]

    key_ops_ok? =
      case Map.get(jwk_map, "key_ops") do
        nil -> true
        key_ops when is_list(key_ops) -> "verify" in key_ops
        _other -> false
      end

    if use_ok? and key_ops_ok?, do: :ok, else: {:error, :invalid_use}
  end

  defp validate_jwk_alg(jwk_map, alg) do
    case Map.get(jwk_map, "alg") do
      nil -> :ok
      ^alg -> :ok
      _other -> {:error, :alg_mismatch}
    end
  end

  defp from_verification_map(jwk_map) do
    case JOSE.JWK.from_map(jwk_map) do
      %JOSE.JWK{} = jwk -> {:ok, jwk}
      _other -> {:error, :malformed_jwk}
    end
  rescue
    _ -> {:error, :malformed_jwk}
  catch
    _, _ -> {:error, :malformed_jwk}
  end

  defp validate_rsa_strength(alg, jwk, minimum_rsa_bits) when alg in @rsa_verification_algs do
    case JOSE.JWK.to_public_map(jwk) do
      {_metadata, %{"kty" => "RSA"}} ->
        if Attesto.SigningAlg.rsa_modulus_at_least?(jwk, minimum_rsa_bits),
          do: :ok,
          else: {:error, :weak_key}

      _other ->
        :ok
    end
  end

  defp validate_rsa_strength(_alg, _jwk, _minimum_rsa_bits), do: :ok

  defp validate_edwards_curve(alg, jwk) when alg in ["EdDSA", "Ed25519", "Ed448"] do
    Attesto.SigningAlg.validate_for_key!(alg, jwk)
    :ok
  rescue
    _ -> {:error, :incompatible_key}
  end

  defp validate_edwards_curve(_alg, _jwk), do: :ok

  defp validate_verification_options!(require_public?, minimum_rsa_bits)
       when is_boolean(require_public?) and is_integer(minimum_rsa_bits) and minimum_rsa_bits > 0, do: :ok

  defp validate_verification_options!(_require_public?, _minimum_rsa_bits) do
    raise ArgumentError,
          ":require_public? must be a boolean and :minimum_rsa_bits must be a positive integer"
  end

  # `JOSE.JWK.from_pem/1` returns `[]` for an empty/no-entry PEM and, for a
  # multi-entry PEM, raises a `FunctionClauseError` from deep inside JOSE
  # rather than returning a list. Normalise both into a single non-`JWK`
  # sentinel so `jwk/1` can fail with one clear `ArgumentError`.
  defp safe_from_pem(pem) do
    JOSE.JWK.from_pem(pem)
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @doc """
  Parse a private PEM into a `JOSE.JWK` whose public half can sign and
  derive a `kid`.

  Unlike `jwk/1`, this rejects public-only PEMs: they are valid
  verification material, but cannot sign tokens.
  """
  @spec signing_jwk(String.t()) :: JOSE.JWK.t()
  def signing_jwk(pem) when is_binary(pem) do
    jwk = jwk(pem)

    if private_jwk?(jwk) do
      jwk
    else
      raise ArgumentError,
            "expected a private signing key PEM; got public verification material"
    end
  end

  # Decode the private key PEM to a key record. Accepts the PKCS#1
  # `RSA PRIVATE KEY` and the PKCS#8 `PRIVATE KEY` (PrivateKeyInfo, which
  # `pem_entry_decode/1` unwraps to an `:RSAPrivateKey`) forms. Rejects an
  # empty PEM and a multi-entry PEM loudly rather than silently using the
  # first key.
  defp decode_rsa_private_key!(pem) do
    case :public_key.pem_decode(pem) do
      [entry] ->
        :public_key.pem_entry_decode(entry)

      [] ->
        raise ArgumentError, "signing key PEM contained no key entry"

      [_ | _] ->
        raise ArgumentError,
              "signing key PEM contained multiple key entries; expected exactly one"
    end
  end

  # An RSA private key record carries the modulus and public exponent, so
  # the public key is recoverable with no separate material.
  defp rsa_public_from_private({:RSAPrivateKey, _ver, modulus, public_exponent, _d, _p, _q, _e1, _e2, _c, _other}) do
    {:RSAPublicKey, modulus, public_exponent}
  end

  # public_pem/1 is a legacy RSA helper; EC/OKP deployments should publish
  # JWK Sets rather than derive an SPKI PEM through this path.
  defp rsa_public_from_private(other) do
    raise ArgumentError,
          "expected an RSA private key for public_pem/1; got a " <>
            "#{inspect(elem(other, 0))} key"
  end

  defp private_jwk?(%JOSE.JWK{} = jwk) do
    jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.get("d")
    |> is_binary()
  end

  defp encode_spki_pem(public_key) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)])
  end

  # `:public_key.pem_encode/1` appends a trailing blank line after the
  # final `-----END ...-----` marker. Trim it so the derived PEM ends with
  # a single newline, matching the on-disk and env-var key shape.
  defp normalize_pem(pem) when is_binary(pem), do: String.trim_trailing(pem) <> "\n"
end
