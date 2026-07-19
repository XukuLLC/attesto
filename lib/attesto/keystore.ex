defmodule Attesto.Keystore do
  @moduledoc """
  The behaviour Attesto uses to obtain signing and verification keys.

  A keystore answers two questions:

    * **What key do we sign new tokens with?** `signing_pem/0` returns the
      private signing key PEM. Attesto derives the public half and the `kid`
      from it (`Attesto.Key`), so the keystore never has to compute a
      thumbprint.

    * **What keys may verify a presented token?** `verification_pems/0`
      returns a list of PEMs (private or public) whose public halves are
      trusted. With a single key this is just `[signing_pem()]`. During a
      key rotation it carries both the outgoing and incoming keys so
      tokens minted under either verify, and `Attesto.Token.verify/3`
      selects the right one by the JWS header `kid`.

  Implementations decide *where* keys come from - an environment
  variable, a secrets manager, a file, a hardware module. Attesto only
  consumes the PEMs, so the security-sensitive resolution and any
  fail-fast boot checks stay in the host application.

  `Attesto.Keystore.Static` is a ready-made implementation for the common
  single-key (or manually-rotated) case.
  """

  @doc """
  The private signing-key PEM used to sign newly issued tokens.

  The key must support one of the asymmetric algorithms accepted by
  `Attesto.SigningAlg`.
  """
  @callback signing_pem() :: String.t()

  @doc """
  The PEMs (private or public) whose public halves are trusted to verify
  a presented token. MUST include the public half of whatever
  `signing_pem/0` currently returns.
  """
  @callback verification_pems() :: [String.t()]

  @doc """
  Optional per-key JOSE algorithm metadata, keyed by RFC 7638 `kid`.

  When omitted, Attesto infers an algorithm from the public key shape:
  RSA -> RS256, P-256 -> ES256, P-384 -> ES384, P-521 -> ES512, and
  Ed25519/Ed448 -> EdDSA. Use this callback to label RSA keys that should
  verify as PS256, or to make a rotation window explicit.
  """
  @callback key_algs() :: %{String.t() => String.t()} | keyword(String.t())

  @doc """
  Optional global algorithm for the current signing key.

  This is a convenience for single-key RSA deployments that want PS256
  without precomputing the signing key's `kid`. A custom keystore whose value
  differs from key inference MUST expose the same binding through `key_algs/0`
  so its newly minted tokens also verify. `Attesto.Keystore.Static` does that
  automatically. Verification otherwise uses `key_algs/0` when present, then
  key inference.
  """
  @callback signing_alg() :: String.t()

  @optional_callbacks key_algs: 0, signing_alg: 0
end
