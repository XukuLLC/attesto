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
  # Short Weierstrass parameters {coordinate bytes, p, a, b}: SEC 2 v2 §2.4.1
  # (secp256k1) and §§2.4.2, 2.5.1, 2.6.1 (P-256, P-384, P-521; FIPS 186-5).
  @p256_prime Bitwise.bsl(1, 256) - Bitwise.bsl(1, 224) + Bitwise.bsl(1, 192) + Bitwise.bsl(1, 96) - 1
  @p384_prime Bitwise.bsl(1, 384) - Bitwise.bsl(1, 128) - Bitwise.bsl(1, 96) + Bitwise.bsl(1, 32) - 1
  @p521_prime Bitwise.bsl(1, 521) - 1
  @secp256k1_prime Bitwise.bsl(1, 256) - Bitwise.bsl(1, 32) - 977
  @p521_b String.to_integer(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1" <>
              "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            16
          )
  @verification_ec_curves %{
    "P-256" => {32, @p256_prime, @p256_prime - 3, 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B},
    "P-384" =>
      {48, @p384_prime, @p384_prime - 3,
       0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF},
    "P-521" => {66, @p521_prime, @p521_prime - 3, @p521_b},
    "secp256k1" => {32, @secp256k1_prime, 0, 7}
  }
  @ed25519_prime Bitwise.bsl(1, 255) - 19
  @ed448_prime Bitwise.bsl(1, 448) - Bitwise.bsl(1, 224) - 1
  @supported_pem_curves [
    {1, 2, 840, 10_045, 3, 1, 7},
    {1, 3, 132, 0, 34},
    {1, 3, 132, 0, 35},
    {1, 3, 101, 112},
    {1, 3, 101, 113}
  ]

  @type verification_jwk_error ::
          :private_material
          | :invalid_use
          | :alg_mismatch
          | :incompatible_key
          | :weak_key
          | :oversized_key
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
  rescue
    error in ArgumentError -> reraise error, __STACKTRACE__
    _error -> raise ArgumentError, "invalid RSA private key PEM"
  catch
    _kind, _reason -> raise ArgumentError, "invalid RSA private key PEM"
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

  EC coordinates must have the curve's byte length, be smaller than its
  field prime and satisfy its curve equation (RFC 7518 §6.2.1 and SEC 1 v2
  §3.2.2.1). This applies to P-256, P-384, P-521 and secp256k1. Ed25519 and
  Ed448 keys must use canonical encodings with `y` below the field prime and
  the sign bit clear when `x` is zero (RFC 8032 §§5.1.3 and 5.2.3).

  The requested algorithm must match the key type and curve, including
  explicit Edwards and ES256K identifiers.
  """
  @spec verification_jwk(map(), keyword()) ::
          {:ok, JOSE.JWK.t()} | {:error, verification_jwk_error()}
  def verification_jwk(jwk_map, opts) when is_map(jwk_map) and is_list(opts) do
    alg = Keyword.fetch!(opts, :alg)
    require_public? = Keyword.get(opts, :require_public?, true)
    minimum_rsa_bits = Keyword.get(opts, :minimum_rsa_bits, @default_minimum_rsa_bits)

    validate_verification_options!(require_public?, minimum_rsa_bits)

    with :ok <- validate_single_jwk(jwk_map),
         :ok <- reject_private_members(jwk_map, require_public?),
         :ok <- validate_jwk_usage(jwk_map),
         :ok <- validate_jwk_alg(jwk_map, alg),
         :ok <- validate_rsa_params(jwk_map),
         :ok <- validate_public_point(jwk_map),
         {:ok, jwk} <- from_verification_map(jwk_map),
         :ok <- validate_rsa_strength(alg, jwk, minimum_rsa_bits),
         :ok <- validate_verification_algorithm(alg, jwk) do
      {:ok, jwk}
    end
  end

  @doc """
  Whether `jwk_map` is a single JWK rather than a JWK Set.

  A JWK has a string `kty` member (RFC 7517 §4.1) and no `keys` member. JOSE
  parses a map that has both as the outer key with the inner keys attached,
  and a map that has only `keys` as a set, so a caller that expects one key
  must refuse both before parsing.
  """
  @spec single_jwk_map?(term()) :: boolean()
  def single_jwk_map?(%{"kty" => kty} = jwk_map) when is_binary(kty), do: not is_map_key(jwk_map, "keys")
  def single_jwk_map?(_jwk_map), do: false

  @doc """
  Check whether key selection requires a protected-header `kid`.

  `:require_kid` is `false` by default, `true` to require it for every token,
  or `:multiple` to require it when the original key set contains more than
  one entry. Count entries before filtering by algorithm, usage, or strength;
  even duplicate entries count. Pass the complete list of keys before candidate
  filtering. A required identifier must be a non-empty string.
  """
  @spec validate_kid(list(), term(), keyword()) :: :ok | {:error, :missing_kid}
  def validate_kid(keys, kid, opts \\ []) do
    required = Keyword.get(opts, :require_kid, false)

    if required not in [false, true, :multiple] do
      raise ArgumentError, ":require_kid must be false, true, or :multiple"
    end

    needs_kid? = required == true or (required == :multiple and length(keys) > 1)

    if needs_kid? and not (is_binary(kid) and kid != ""),
      do: {:error, :missing_kid},
      else: :ok
  end

  @doc "Default minimum accepted RSA modulus bit length."
  @spec default_minimum_rsa_bits() :: pos_integer()
  def default_minimum_rsa_bits, do: @default_minimum_rsa_bits

  # Exposed for the test that checks the constants against OTP's curve data.
  @doc false
  @spec verification_ec_curve_parameters() :: %{
          String.t() => {pos_integer(), pos_integer(), non_neg_integer(), pos_integer()}
        }
  def verification_ec_curve_parameters, do: @verification_ec_curves

  @doc """
  Return the public JWK field map for a single `JOSE.JWK` struct or single JWK map.

  When deriving from private material, omit its `key_ops`: private signing
  permissions do not describe the public half's verification permissions.
  Public-only inputs retain their `key_ops`, so this is not a way to relax a
  verification key's declared usage. Raises `ArgumentError` for JWK Set inputs
  or non-JWK values.
  """
  @spec public_map(JOSE.JWK.t() | map()) :: map()
  def public_map(%JOSE.JWK{keys: :undefined} = jwk) do
    {_metadata, fields} = JOSE.JWK.to_public_map(jwk)

    if single_jwk_map?(fields) do
      {_metadata, original} = JOSE.JWK.to_map(jwk)
      if private_members?(original), do: Map.delete(fields, "key_ops"), else: fields
    else
      raise ArgumentError, "expected a single JWK"
    end
  end

  def public_map(jwk_map) when is_map(jwk_map) do
    if single_jwk_map?(jwk_map) do
      jwk_map |> JOSE.JWK.from_map() |> public_map()
    else
      raise ArgumentError, "expected a single JWK map, not a JWK set"
    end
  end

  def public_map(_other), do: raise(ArgumentError, "expected a single JWK")

  defp validate_single_jwk(jwk_map) do
    if single_jwk_map?(jwk_map), do: :ok, else: {:error, :malformed_jwk}
  end

  # Bound RSA modulus/exponent on the RAW map before `JOSE.JWK.from_map/1` so a
  # huge-exponent (or oversized-modulus) key is rejected in microseconds, never
  # reaching a scheduler-pinning modexp at verify time (availability DoS).
  defp validate_rsa_params(jwk_map) do
    if Attesto.SigningAlg.rsa_params_ok?(jwk_map), do: :ok, else: {:error, :oversized_key}
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
  def jwk(pem) do
    # Checked in the body, not a head guard, so a mistyped key (a charlist PEM,
    # for example) is never echoed through a FunctionClauseError's arguments.
    if !is_binary(pem), do: raise(ArgumentError, "expected a PEM-encoded key as a binary")

    case safe_from_pem(pem) do
      %JOSE.JWK{} = jwk ->
        ensure_supported!(jwk)

      _other ->
        raise ArgumentError,
              "PEM did not contain exactly one parseable key (it was empty, " <>
                "malformed, or carried multiple key entries)"
    end
  end

  @doc """
  Import one PEM key without matching exception messages.

  Returns `{:ok, jwk}`, `{:error, :malformed_key}` for empty, malformed,
  multi-entry or non-binary input, or `{:error, :unsupported_key}` for a
  parseable key whose type or curve is unsupported. Neither error includes
  key material. Accepts public and private keys, as `jwk/1` does.
  """
  @spec import_pem(term()) :: {:ok, JOSE.JWK.t()} | {:error, :malformed_key | :unsupported_key}
  def import_pem(pem) when is_binary(pem) do
    case safe_from_pem(pem) do
      %JOSE.JWK{} = jwk -> import_supported(jwk)
      _other -> classify_unparsed_pem(pem)
    end
  end

  def import_pem(_other), do: {:error, :malformed_key}

  defp import_supported(jwk) do
    _fields = public_map(jwk)
    import_algorithm(jwk)
  rescue
    _error -> {:error, :malformed_key}
  catch
    _kind, _reason -> {:error, :malformed_key}
  end

  defp import_algorithm(jwk) do
    {:ok, ensure_supported!(jwk)}
  rescue
    ArgumentError -> {:error, :unsupported_key}
  end

  defp classify_unparsed_pem(pem) do
    case :public_key.pem_decode(pem) do
      [entry] ->
        if unsupported_pem_key?(:public_key.pem_entry_decode(entry)),
          do: {:error, :unsupported_key},
          else: {:error, :malformed_key}

      _other ->
        {:error, :malformed_key}
    end
  rescue
    _error -> {:error, :malformed_key}
  catch
    _kind, _reason -> {:error, :malformed_key}
  end

  defp unsupported_pem_key?({:ECPrivateKey, _version, _private, {:namedCurve, curve}, _public, _attributes}),
    do: curve not in @supported_pem_curves

  defp unsupported_pem_key?({{:ECPoint, _public}, {:namedCurve, curve}}), do: curve not in @supported_pem_curves

  defp unsupported_pem_key?({public, {:Dss_Parms, _p, _q, _g}}) when is_integer(public), do: true

  defp unsupported_pem_key?(key) when is_tuple(key), do: elem(key, 0) in [:DSAPrivateKey, :Dss_Parms, :DHParameter]

  defp unsupported_pem_key?(_other), do: false

  defp ensure_supported!(%JOSE.JWK{} = jwk) do
    Attesto.SigningAlg.infer(jwk)
    jwk
  end

  @doc false
  @spec private_members?(map()) :: boolean()
  def private_members?(jwk_map) when is_map(jwk_map), do: Enum.any?(@private_jwk_members, &Map.has_key?(jwk_map, &1))

  defp reject_private_members(_jwk_map, false), do: :ok

  defp reject_private_members(jwk_map, true) do
    if private_members?(jwk_map),
      do: {:error, :private_material},
      else: :ok
  end

  # RFC 7517 §§4.2-4.4: `use`, `key_ops`, and `alg` are optional, but a present
  # member must be a string (an array for `key_ops`). An omitted member places
  # no restriction; a present JSON null is malformed, not omitted.
  defp validate_jwk_usage(jwk_map) do
    use_ok? = Map.fetch(jwk_map, "use") in [:error, {:ok, "sig"}]

    key_ops_ok? =
      case Map.fetch(jwk_map, "key_ops") do
        :error -> true
        {:ok, key_ops} when is_list(key_ops) -> "verify" in key_ops
        {:ok, _other} -> false
      end

    if use_ok? and key_ops_ok?, do: :ok, else: {:error, :invalid_use}
  end

  defp validate_jwk_alg(jwk_map, alg) do
    case Map.fetch(jwk_map, "alg") do
      :error ->
        :ok

      {:ok, jwk_alg} ->
        if Attesto.SigningAlg.equivalent_okp_algs?(jwk_alg, alg, jwk_map),
          do: :ok,
          else: {:error, :alg_mismatch}
    end
  end

  defp validate_public_point(%{"kty" => "EC", "crv" => curve} = jwk_map)
       when is_map_key(@verification_ec_curves, curve) do
    {coordinate_bytes, prime, a, b} = Map.fetch!(@verification_ec_curves, curve)

    with {:ok, x} <- decode_point_member(jwk_map["x"], coordinate_bytes),
         {:ok, y} <- decode_point_member(jwk_map["y"], coordinate_bytes),
         true <- on_weierstrass_curve?(x, y, prime, a, b) do
      :ok
    else
      _ -> {:error, :malformed_jwk}
    end
  end

  defp validate_public_point(%{"kty" => "OKP", "crv" => "Ed25519"} = jwk_map),
    do: validate_edwards_encoding(jwk_map["x"], 32, @ed25519_prime)

  defp validate_public_point(%{"kty" => "OKP", "crv" => "Ed448"} = jwk_map),
    do: validate_edwards_encoding(jwk_map["x"], 57, @ed448_prime)

  defp validate_public_point(_jwk_map), do: :ok

  defp decode_point_member(encoded, size) when is_binary(encoded) and byte_size(encoded) <= div(size + 2, 3) * 4 do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, bytes} when byte_size(bytes) == size -> {:ok, bytes}
      _ -> :error
    end
  end

  defp decode_point_member(_encoded, _size), do: :error

  defp on_weierstrass_curve?(x_bytes, y_bytes, prime, a, b) do
    x = :binary.decode_unsigned(x_bytes)
    y = :binary.decode_unsigned(y_bytes)

    x < prime and y < prime and rem(y * y - x * x * x - a * x - b, prime) == 0
  end

  defp validate_edwards_encoding(encoded, size, prime) do
    prefix_bytes = size - 1

    with {:ok, <<prefix::binary-size(^prefix_bytes), sign::1, high_bits::7>>} <- decode_point_member(encoded, size),
         y = :binary.decode_unsigned(<<prefix::binary, high_bits>>, :little),
         true <- y < prime,
         # On both curves, x = 0 gives y² = 1.
         false <- sign == 1 and y in [1, prime - 1] do
      :ok
    else
      _ -> {:error, :malformed_jwk}
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

  defp validate_verification_algorithm(alg, jwk) do
    Attesto.SigningAlg.validate_verification_for_key!(alg, jwk)
    :ok
  rescue
    _ -> {:error, :incompatible_key}
  end

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
  Parse a private PEM, JWK map, or `JOSE.JWK` for signing.

  A JWK's `use` must be absent or `"sig"`; `key_ops` must be absent or a list
  of strings containing `"sign"`. Public material and JWK Sets are refused
  with `ArgumentError`. `public_map/1` derives verification material without
  carrying the private key's operations.

  Unlike `jwk/1`, this rejects public-only PEMs: they are valid
  verification material, but cannot sign tokens.
  """
  @spec signing_jwk(String.t() | map() | JOSE.JWK.t()) :: JOSE.JWK.t()
  def signing_jwk(%JOSE.JWK{keys: :undefined} = jwk) do
    {_metadata, fields} = JOSE.JWK.to_map(jwk)
    validate_signing_usage!(fields)

    if private_jwk?(jwk) do
      jwk
    else
      raise ArgumentError, "expected a private signing key PEM or JWK; got public verification material"
    end
  end

  def signing_jwk(%JOSE.JWK{}), do: raise(ArgumentError, "expected a single private signing key")

  def signing_jwk(fields) when is_map(fields) do
    if not single_jwk_map?(fields), do: raise(ArgumentError, "expected a single private signing JWK")
    validate_signing_usage!(fields)
    fields |> JOSE.JWK.from_map() |> signing_jwk()
  rescue
    _error -> raise ArgumentError, "invalid private signing JWK"
  catch
    _kind, _reason -> raise ArgumentError, "invalid private signing JWK"
  end

  def signing_jwk(pem), do: pem |> jwk() |> signing_jwk()

  defp validate_signing_usage!(fields) do
    use_ok? = Map.fetch(fields, "use") in [:error, {:ok, "sig"}]

    ops_ok? =
      case Map.fetch(fields, "key_ops") do
        :error -> true
        {:ok, ops} when is_list(ops) -> Enum.all?(ops, &is_binary/1) and "sign" in ops
        _other -> false
      end

    if not (use_ok? and ops_ok?), do: raise(ArgumentError, "invalid signing JWK usage")
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
