defmodule Attesto.Thumbprint do
  @moduledoc """
  Canonical SHA-256 thumbprint shape, shared across the sender-constraint
  schemes.

  Three different specs converge on the same 32-byte-digest-as-base64url
  shape:

    * RFC 7638 JWK thumbprints (DPoP `cnf.jkt`),
    * RFC 8705 §3.1 X.509 certificate thumbprints (`cnf.x5t#S256`), and
    * the RFC 7515 §4.1.8 `x5t#S256` JOSE header parameter.

  In every case the value is

      Base.url_encode64(<32-byte SHA-256 digest>, padding: false)

  which is exactly 43 characters drawn from the RFC 4648 §5 alphabet
  `[A-Za-z0-9_-]`.

  ## Why 43 base64url characters is necessary but not sufficient

  The last character of a 43-character base64url-no-pad string encodes
  only the final 4 bits of the 256-bit digest, so its low 2 bits are
  structurally zero. A 43-character string whose last character carries
  non-zero trailing bits is therefore **not** something
  `Base.url_encode64/2` could ever have produced. Accepting such a value
  as a thumbprint would let a caller embed a `cnf` binding that no real
  key or certificate could ever match - silently turning a
  sender-constraint into a no-op. `valid?/1` rejects these by decoding
  and re-encoding: a value is canonical iff it round-trips to itself and
  decodes to exactly 32 bytes.
  """

  # 32 raw bytes -> 43 base64url chars, no padding.
  @length 43
  @alphabet ~r/\A[A-Za-z0-9_-]+\z/
  @digest_bytes 32

  @doc """
  The fixed character length of a well-formed SHA-256 base64url-no-pad
  thumbprint. Exposed so documentation / API specs can advertise the
  same shape this module enforces.
  """
  @spec length() :: pos_integer()
  def length, do: @length

  @doc """
  Returns `true` iff `value` is the canonical base64url-no-pad encoding
  of a 32-byte SHA-256 digest: 43 characters from the base64url
  alphabet that decode to exactly 32 bytes and re-encode unchanged.
  Anything else - wrong length, illegal characters, non-canonical
  trailing bits, or a non-binary - returns `false`.
  """
  @spec valid?(term()) :: boolean()
  def valid?(value) when is_binary(value) do
    byte_size(value) == @length and Regex.match?(@alphabet, value) and canonical?(value)
  end

  def valid?(_), do: false

  @doc """
  Compute the SHA-256 thumbprint of `bytes` in the canonical
  base64url-no-pad shape this module validates.
  """
  @spec of(binary()) :: String.t()
  def of(bytes) when is_binary(bytes) do
    :sha256
    |> :crypto.hash(bytes)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Compute an RFC 7638 SHA-256 thumbprint for a JWK.

  Accepts either a `%JOSE.JWK{}` or a plain JWK map. JOSE selects the
  key-type-specific public members, serializes them canonically, and hashes
  that representation. Private and optional metadata therefore do not affect
  the result.

  Returns `{:error, :malformed_jwk}` when the input cannot be parsed or
  canonicalized as a JWK.
  """
  @spec of_jwk(JOSE.JWK.t() | map()) :: {:ok, String.t()} | {:error, :malformed_jwk}
  def of_jwk(%JOSE.JWK{} = jwk), do: jwk_thumbprint(jwk)

  def of_jwk(jwk_map) when is_map(jwk_map) do
    jwk_map
    |> JOSE.JWK.from_map()
    |> jwk_thumbprint()
  rescue
    _ -> {:error, :malformed_jwk}
  catch
    _, _ -> {:error, :malformed_jwk}
  end

  def of_jwk(_jwk), do: {:error, :malformed_jwk}

  defp canonical?(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, decoded} when byte_size(decoded) == @digest_bytes ->
        Base.url_encode64(decoded, padding: false) == value

      _ ->
        false
    end
  end

  defp jwk_thumbprint(jwk) do
    case JOSE.JWK.thumbprint(jwk) do
      thumbprint when is_binary(thumbprint) -> {:ok, thumbprint}
      _other -> {:error, :malformed_jwk}
    end
  rescue
    _ -> {:error, :malformed_jwk}
  catch
    _, _ -> {:error, :malformed_jwk}
  end
end
