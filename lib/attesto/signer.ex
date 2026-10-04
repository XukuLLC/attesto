defmodule Attesto.Signer do
  @moduledoc """
  Additive signing contract for non-extractable private keys.

  A module implementing this behaviour exposes only the public JWK and signs
  the already-encoded JWS signing input. The private key may therefore remain
  inside an HSM, KMS, enclave, or remote custody service; it never needs to be
  returned to Attesto or loaded into BEAM memory.

  The signature returned by `sign/2` is the JWS signature octet sequence, not
  a base64url string. In particular, ECDSA implementations return the fixed
  width `R || S` encoding required by RFC 7518, rather than ASN.1 DER.
  Implementations are responsible for the algorithm-specific requirements,
  including the required RSA-PSS salt length.

  Attesto verifies every returned signature against `signing_jwk/0` and the
  selected `alg` before returning a compact JWS. A signer using the wrong
  remote key, message/digest mode, signature encoding, or algorithm therefore
  fails locally instead of issuing an unusable token.

  Existing `Attesto.Keystore` implementations need no changes. When a module
  does not implement this behaviour, Attesto continues to read its
  `signing_pem/0` and uses the established in-process JOSE path. A
  non-extractable implementation supplies `signing_jwk/0` and `sign/2` while
  retaining `verification_pems/0` (with public PEMs) for verification and JWKS
  publication.

  A signer using an algorithm that cannot be inferred from its public key,
  such as `PS256`, also implements the optional `c:Attesto.Keystore.signing_alg/0`
  callback or publishes an `"alg"` member in `signing_jwk/0`.
  """

  alias Attesto.{Key, SigningAlg}

  @type alg :: String.t()
  @type signature_error :: term()

  @doc "The current signing key's public JWK. Private members are forbidden."
  @callback signing_jwk() :: map() | JOSE.JWK.t()

  @doc "Sign an encoded JWS signing input with the named JOSE algorithm."
  @callback sign(signing_input :: binary(), alg()) ::
              {:ok, signature :: binary()} | {:error, signature_error()}

  @doc false
  @spec external?(module()) :: boolean()
  def external?(module) when is_atom(module) do
    exports?(module, :signing_jwk, 0) and exports?(module, :sign, 2)
  end

  @doc false
  @spec signing_jwk!(module()) :: JOSE.JWK.t()
  def signing_jwk!(module) when is_atom(module) do
    if !external?(module) do
      raise ArgumentError,
            "#{inspect(module)} must export both signing_jwk/0 and sign/2 to use non-extractable signing"
    end

    module
    |> invoke!(:signing_jwk, [])
    |> public_jwk!()
  end

  @doc false
  @spec sign!(module(), binary(), alg()) :: binary()
  def sign!(module, signing_input, alg) when is_atom(module) and is_binary(signing_input) and is_binary(alg) do
    SigningAlg.validate!(alg)

    case invoke!(module, :sign, [signing_input, alg]) do
      {:ok, signature} when is_binary(signature) and byte_size(signature) > 0 ->
        signature

      {:error, _reason} ->
        raise RuntimeError, "external signer failed"

      _other ->
        raise RuntimeError, "external signer returned an invalid result"
    end
  end

  defp public_jwk!(%JOSE.JWK{} = jwk) do
    {_kind, jwk_map} = JOSE.JWK.to_map(jwk)
    public_jwk!(jwk_map)
  end

  defp public_jwk!(jwk_map) when is_map(jwk_map) do
    alg = infer_public_alg!(jwk_map)

    case Key.verification_jwk(jwk_map, alg: alg) do
      {:ok, jwk} -> jwk
      {:error, _reason} -> raise ArgumentError, "invalid signer public JWK"
    end
  end

  defp public_jwk!(_other) do
    raise ArgumentError,
          "signing_jwk/0 must return a public JWK map or JOSE.JWK"
  end

  # External custody adapters can fail with an exception, throw, or exit whose
  # payload contains provider responses, key handles, or other private backend
  # details. Normalize every callback failure before it crosses Attesto's API
  # boundary. Validation of a callback's successful return still happens
  # outside this wrapper so configuration errors retain their useful messages.
  defp invoke!(module, function, arguments) do
    apply(module, function, arguments)
  rescue
    _exception -> raise RuntimeError, "external signer failed"
  catch
    _kind, _reason -> raise RuntimeError, "external signer failed"
  end

  defp infer_public_alg!(jwk_map) do
    case Map.get(jwk_map, "alg") do
      alg when is_binary(alg) -> SigningAlg.validate!(alg)
      nil -> jwk_map |> JOSE.JWK.from_map() |> SigningAlg.infer()
      _other -> raise ArgumentError, "signer public JWK alg must be a string"
    end
  rescue
    _error ->
      reraise ArgumentError,
              [message: "invalid signer public JWK"],
              __STACKTRACE__
  end

  defp exports?(module, function, arity) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> function_exported?(module, function, arity)
      {:error, _reason} -> false
    end
  end
end
