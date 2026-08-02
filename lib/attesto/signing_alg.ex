defmodule Attesto.SigningAlg do
  @moduledoc """
  Key-derived JOSE signing algorithm helpers.

  Attesto treats the algorithm as metadata of the trusted key selected by
  `kid`, never as policy learned from the presented token. RSA keys infer
  RS256 (RSASSA-PKCS1-v1_5) as the JWA default for the `RSA` key type, while
  EC/OKP keys infer their JOSE algorithm from the public JWK curve. For wire
  compatibility, Ed25519 and Ed448 inference retains the legacy `EdDSA`
  identifier; trusted keystore metadata can opt into RFC 9864's explicit
  `Ed25519` or `Ed448` identifiers. RSA deployments that intentionally use
  PS256 can likewise label the key through keystore metadata. Ed448 requires
  a JOSE backend with Curve448 and SHAKE256 support.
  """

  alias Attesto.{Key, Thumbprint}

  @type alg :: String.t()

  @type oidc_hash_profile ::
          {:fixed, :sha256 | :sha384 | :sha512, pos_integer()}
          | {:xof, :shake256, pos_integer(), pos_integer()}

  @allowed ~w(RS256 PS256 ES256 ES384 ES512 EdDSA Ed25519 Ed448)

  @doc "Algorithms Attesto can sign/verify when backed by a matching key."
  @spec allowed() :: [alg()]
  def allowed, do: @allowed

  @fapi_algs ~w(PS256 ES256 EdDSA Ed25519)
  @fapi_min_rsa_modulus_bits 2048

  @doc """
  Signing algorithms permitted for FAPI 2 client authentication and, when a
  signed Request Object is processed, its signature: PS256, ES256, legacy
  EdDSA over Ed25519, and RFC 9864 Ed25519.

  The algorithm list alone cannot express legacy EdDSA's curve. Verifiers
  using this policy also call `fapi_compatible?/2`, which requires an RSA
  modulus of at least 2048 bits and rejects an Ed448 key even when its trusted
  metadata uses the legacy `EdDSA` identifier.

  RS256 (RSASSA-PKCS1-v1_5) is deliberately excluded - FAPI 2 mandates PS256
  for RSA keys. This is the policy gate for verifying a signature a *client*
  presents; it is narrower than `allowed/0`, which still admits RS256 for the
  provider's own token signing.
  """
  @spec fapi_algs() :: [alg()]
  def fapi_algs, do: @fapi_algs

  @doc """
  Default set of algorithms accepted for signatures a *client* presents
  (client assertions and request objects).

  Equal to `fapi_algs/0`: PS256, ES256, legacy EdDSA over Ed25519, and explicit
  Ed25519. A host with a non-FAPI profile can pass an explicit `:accepted_algs`
  option to the relevant verifier. A composed FAPI profile that narrows this
  list also passes `enforce_fapi_alg_policy: true` to retain the FAPI 2
  key-strength and curve gates.
  """
  @spec default_client_algs() :: [alg()]
  def default_client_algs, do: @fapi_algs

  @doc """
  Resolve the algorithm for a key in `keystore`.

  Resolution order:

    * per-key metadata from `key_algs/0`, keyed by RFC 7638 `kid`
    * `signing_alg/0` for the current signing key only
    * inference from the JWK type/curve
  """
  @spec for_key(module(), String.t(), keyword()) :: alg()
  def for_key(keystore, pem, opts \\ []) when is_atom(keystore) and is_binary(pem) do
    for_jwk(keystore, Key.jwk(pem), opts)
  end

  @doc """
  Resolve the algorithm for an already parsed key in the keystore.

  This is the key-preserving counterpart to for_key/3; callers that already
  loaded a PEM can derive its algorithm without parsing the PEM a second time.
  """
  @spec for_jwk(module(), JOSE.JWK.t(), keyword()) :: alg()
  def for_jwk(keystore, %JOSE.JWK{} = jwk, opts \\ []) when is_atom(keystore) and is_list(opts) do
    {:ok, kid} = Thumbprint.of_jwk(jwk)

    key_algs(keystore)
    |> Map.get(kid)
    |> fallback_signing_alg(keystore, opts)
    |> fallback_inferred_alg(jwk)
    |> validate_for_key!(jwk)
  end

  @doc """
  Validate an algorithm and bind it to a compatible trusted key.

  RFC 9864's explicit `Ed25519` and `Ed448` identifiers require the matching
  OKP curve. Legacy `EdDSA` remains compatible with either curve. RSA and EC
  algorithms are likewise checked against their key type and curve so trusted
  metadata cannot relabel a key with an incompatible algorithm.
  """
  @spec validate_for_key!(term(), JOSE.JWK.t()) :: alg()
  def validate_for_key!(alg, %JOSE.JWK{} = jwk) do
    alg = validate!(alg)
    fields = public_fields(jwk)

    if compatible?(alg, fields) do
      alg
    else
      raise ArgumentError,
            "signing algorithm #{inspect(alg)} is not compatible with trusted key " <>
              "#{inspect(Map.take(fields, ["kty", "crv"]))}"
    end
  end

  @doc """
  Whether `alg` and its trusted key satisfy Attesto's default FAPI policy.

  RSA keys require a modulus of at least 2048 bits. The legacy `EdDSA`
  identifier is accepted only over an Ed25519 key. Ed448 and weaker RSA keys
  remain available to callers that explicitly select a non-FAPI algorithm
  policy.
  """
  @spec fapi_compatible?(term(), JOSE.JWK.t()) :: boolean()
  def fapi_compatible?(alg, %JOSE.JWK{} = jwk) do
    alg = validate_for_key!(alg, jwk)
    fields = public_fields(jwk)

    alg in @fapi_algs and fapi_key_compatible?(alg, fields)
  rescue
    _ -> false
  end

  @doc """
  Whether an RSA JWK's unsigned modulus is at least `minimum_bits` long.

  Returns `false` for a non-RSA key or malformed modulus. This keeps protocol
  policy checks independent from JOSE's backend-specific key representation.
  """
  @spec rsa_modulus_at_least?(JOSE.JWK.t(), pos_integer()) :: boolean()
  def rsa_modulus_at_least?(%JOSE.JWK{} = jwk, minimum_bits) when is_integer(minimum_bits) and minimum_bits > 0 do
    fields = public_fields(jwk)
    Map.get(fields, "kty") == "RSA" and rsa_modulus_bits(fields) >= minimum_bits
  rescue
    _ -> false
  end

  @doc """
  The unique signing algorithms across a keystore's verification keys.

  Used to advertise the algorithms the server itself signs with (the
  `id_token_signing_alg_values_supported` and the JARM
  `authorization_signing_alg_values_supported`, which share the same keys).
  Returns `[]` when the keystore exposes no verification keys (or resolution
  fails), leaving the caller to apply any default.
  """
  @spec keystore_algs(module()) :: [alg()]
  def keystore_algs(keystore) when is_atom(keystore) do
    if exports?(keystore, :verification_pems, 0) do
      keystore.verification_pems()
      |> Enum.map(&for_key(keystore, &1))
      |> Enum.uniq()
    else
      []
    end
  rescue
    _ -> []
  end

  @doc "Infer the default algorithm from a parsed JWK's public members."
  @spec infer(JOSE.JWK.t()) :: alg()
  def infer(%JOSE.JWK{} = jwk) do
    jwk
    |> public_fields()
    |> infer_from_fields()
  end

  @doc """
  Return the fixed digest associated with an ID Token signing algorithm.

  Deprecated because EdDSA's digest is curve-dependent. Its keyless EdDSA
  result corresponds to Ed25519; use `oidc_hash_profile/2` or `oidc_hash/3`
  for key-aware calculation.
  """
  @deprecated "EdDSA is curve-dependent; use oidc_hash_profile/2 or oidc_hash/3"
  @spec hash_alg(alg()) :: :sha256 | :sha384 | :sha512
  def hash_alg(alg) do
    case validate!(alg) do
      alg when alg in ~w(RS256 PS256 ES256) -> :sha256
      "ES384" -> :sha384
      alg when alg in ~w(ES512 EdDSA Ed25519) -> :sha512
      "Ed448" -> raise ArgumentError, "Ed448 uses SHAKE256; use oidc_hash_profile/2 or oidc_hash/3"
    end
  end

  @doc """
  Return half the fixed digest length for an ID Token signing algorithm.

  Deprecated because EdDSA's digest length is curve-dependent. Its keyless
  EdDSA result corresponds to Ed25519; use `oidc_hash_profile/2` or
  `oidc_hash/3` for key-aware calculation.
  """
  @deprecated "EdDSA is curve-dependent; use oidc_hash_profile/2 or oidc_hash/3"
  @spec hash_half_bytes(alg()) :: pos_integer()
  def hash_half_bytes(alg) do
    case validate!(alg) do
      alg when alg in ~w(RS256 PS256 ES256) -> 16
      "ES384" -> 24
      alg when alg in ~w(ES512 EdDSA Ed25519) -> 32
      "Ed448" -> raise ArgumentError, "Ed448 uses SHAKE256; use oidc_hash_profile/2 or oidc_hash/3"
    end
  end

  @doc """
  Return the OIDC hash profile bound to `alg` and a trusted key.

  Fixed-output hashes return `{:fixed, digest, half_bytes}`. Ed448 returns
  `{:xof, :shake256, output_bytes, half_bytes}`, making both SHAKE256 lengths
  explicit and avoiding the ambiguity of the keyless legacy helpers.
  """
  @spec oidc_hash_profile(alg(), JOSE.JWK.t()) :: oidc_hash_profile()
  def oidc_hash_profile(alg, %JOSE.JWK{} = jwk) do
    do_oidc_hash_profile(validate_for_key!(alg, jwk), public_fields(jwk))
  end

  @doc """
  Calculate an OIDC `at_hash` / `c_hash` value for a key-bound algorithm.

  Applying OIDC's generic "hash associated with the signing algorithm" rule
  to RFC 8032, legacy EdDSA selects from the trusted key curve: SHA-512 (left
  32 bytes) for Ed25519, or SHAKE256 with 114 bytes of output (left 57 bytes)
  for Ed448. SHAKE256 is invoked through JOSE's configured SHA3 module,
  preserving the application's chosen pure-Erlang, NIF, or driver backend.
  """
  @spec oidc_hash(binary(), alg(), JOSE.JWK.t()) :: String.t()
  def oidc_hash(value, alg, %JOSE.JWK{} = jwk) when is_binary(value) do
    profile = oidc_hash_profile(alg, jwk)

    profile
    |> digest(value)
    |> binary_part(0, profile_half_bytes(profile))
    |> Base.url_encode64(padding: false)
  end

  @doc "Validate that `alg` is one of Attesto's supported asymmetric JOSE algorithms."
  @spec validate!(term()) :: alg()
  def validate!(alg) when alg in @allowed, do: alg

  def validate!(alg) do
    raise ArgumentError,
          "unsupported signing algorithm #{inspect(alg)}; expected one of #{Enum.join(@allowed, ", ")}"
  end

  defp key_algs(keystore) do
    if exports?(keystore, :key_algs, 0) do
      keystore.key_algs()
      |> Map.new(fn {kid, alg} -> {to_string(kid), alg} end)
    else
      %{}
    end
  end

  defp fallback_signing_alg(nil, keystore, opts) do
    if Keyword.get(opts, :signing?) && exports?(keystore, :signing_alg, 0),
      do: keystore.signing_alg()
  end

  defp fallback_signing_alg(alg, _keystore, _opts), do: alg

  defp exports?(module, function, arity) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> function_exported?(module, function, arity)
      {:error, _reason} -> false
    end
  end

  defp fallback_inferred_alg(nil, jwk), do: infer(jwk)
  defp fallback_inferred_alg(alg, _jwk), do: alg

  defp public_fields(jwk) do
    jwk
    |> JOSE.JWK.to_public_map()
    |> elem(1)
  end

  defp infer_from_fields(%{"kty" => "RSA"}), do: "RS256"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-256"}), do: "ES256"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-384"}), do: "ES384"
  defp infer_from_fields(%{"kty" => "EC", "crv" => "P-521"}), do: "ES512"
  defp infer_from_fields(%{"kty" => "OKP", "crv" => crv}) when crv in ["Ed25519", "Ed448"], do: "EdDSA"

  defp infer_from_fields(%{"kty" => kty} = fields) do
    raise ArgumentError,
          "unsupported signing key type #{inspect(kty)}#{curve_suffix(fields)}; expected RSA, EC P-256/P-384/P-521, or OKP Ed25519/Ed448"
  end

  defp infer_from_fields(_fields) do
    raise ArgumentError, "unsupported signing key; missing JWK kty"
  end

  defp curve_suffix(%{"crv" => crv}), do: " curve #{inspect(crv)}"
  defp curve_suffix(_), do: ""

  defp compatible?(alg, %{"kty" => "RSA"}) when alg in ~w(RS256 PS256), do: true
  defp compatible?("ES256", %{"kty" => "EC", "crv" => "P-256"}), do: true
  defp compatible?("ES384", %{"kty" => "EC", "crv" => "P-384"}), do: true
  defp compatible?("ES512", %{"kty" => "EC", "crv" => "P-521"}), do: true
  defp compatible?("EdDSA", %{"kty" => "OKP", "crv" => crv}) when crv in ["Ed25519", "Ed448"], do: true
  defp compatible?("Ed25519", %{"kty" => "OKP", "crv" => "Ed25519"}), do: true
  defp compatible?("Ed448", %{"kty" => "OKP", "crv" => "Ed448"}), do: true
  defp compatible?(_alg, _fields), do: false

  defp fapi_key_compatible?("PS256", %{"kty" => "RSA"} = fields) do
    rsa_modulus_bits(fields) >= @fapi_min_rsa_modulus_bits
  end

  defp fapi_key_compatible?("EdDSA", %{"kty" => "OKP", "crv" => "Ed25519"}), do: true
  defp fapi_key_compatible?("EdDSA", _fields), do: false
  defp fapi_key_compatible?(_alg, _fields), do: true

  defp rsa_modulus_bits(%{"n" => encoded_modulus}) when is_binary(encoded_modulus) do
    with {:ok, modulus_bytes} <- Base.url_decode64(encoded_modulus, padding: false),
         modulus when modulus > 0 <- :binary.decode_unsigned(modulus_bytes) do
      modulus
      |> Integer.to_string(2)
      |> byte_size()
    else
      _ -> 0
    end
  end

  defp rsa_modulus_bits(_fields), do: 0

  defp do_oidc_hash_profile(alg, _fields) when alg in ~w(RS256 PS256 ES256), do: {:fixed, :sha256, 16}
  defp do_oidc_hash_profile("ES384", _fields), do: {:fixed, :sha384, 24}
  defp do_oidc_hash_profile("ES512", _fields), do: {:fixed, :sha512, 32}
  defp do_oidc_hash_profile("EdDSA", %{"kty" => "OKP", "crv" => "Ed25519"}), do: {:fixed, :sha512, 32}
  defp do_oidc_hash_profile("EdDSA", %{"kty" => "OKP", "crv" => "Ed448"}), do: {:xof, :shake256, 114, 57}
  defp do_oidc_hash_profile("Ed25519", _fields), do: {:fixed, :sha512, 32}
  defp do_oidc_hash_profile("Ed448", _fields), do: {:xof, :shake256, 114, 57}

  defp profile_half_bytes({:fixed, _algorithm, half_bytes}), do: half_bytes
  defp profile_half_bytes({:xof, _algorithm, _output_bytes, half_bytes}), do: half_bytes

  defp digest({:fixed, algorithm, _half_bytes}, value), do: :crypto.hash(algorithm, value)

  defp digest({:xof, :shake256, output_bytes, _half_bytes}, value) do
    digest_shake256(JOSE.sha3_module(), value, output_bytes)
  end

  defp digest_shake256(sha3_module, value, output_bytes) do
    case Code.ensure_loaded(sha3_module) do
      {:module, _module} ->
        if function_exported?(sha3_module, :shake256, 2) do
          sha3_module.shake256(value, output_bytes)
        else
          raise_missing_sha3!(sha3_module, "shake256/2 is not exported")
        end

      {:error, reason} ->
        raise_missing_sha3!(sha3_module, "module could not be loaded: #{inspect(reason)}")
    end
  rescue
    error in ErlangError ->
      if error.original == :operation_not_supported do
        raise_missing_sha3!(sha3_module, Exception.message(error))
      else
        reraise error, __STACKTRACE__
      end
  end

  defp raise_missing_sha3!(sha3_module, detail) do
    raise ArgumentError,
          "Ed448 OIDC hash claims require a configured JOSE SHA3 backend with " <>
            "SHAKE256 support; #{inspect(sha3_module)} could not provide shake256/2 " <>
            "(#{detail})"
  end
end
