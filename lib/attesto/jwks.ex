defmodule Attesto.JWKS do
  @moduledoc """
  RFC 7517 - publish the signing keys' public halves as a JWK Set.

  A resource server (or a mobile / third-party client) that wants to
  verify Attesto-issued tokens without sharing a secret fetches a JWK Set
  from the issuer's `jwks_uri`, then selects the key whose `kid` matches
  the token's JWS header. This module builds that set from a keystore: for
  every verification key it derives the public JWK, stamps the RFC 7638
  `kid` Attesto signs with, and marks it `use: "sig"` plus the key's
  configured or inferred `alg`.

  Because the set carries every key in `verification_pems/0`, it covers a
  rotation window: tokens minted under the outgoing key still verify
  against the set while the incoming key is also published.

  The result is a plain map (`%{"keys" => [...]}`) ready to serialise as
  the JSON body of a `/.well-known/jwks.json` (or equivalent) endpoint.
  Only public key material is emitted; private components never appear.
  """

  alias Attesto.Config
  alias Attesto.Key
  alias Attesto.SigningAlg

  @doc """
  Build the JWK Set from a `Attesto.Config`'s keystore.

  Equivalent to `from_pems/1` over `config.keystore.verification_pems()`,
  while preserving any per-key algorithm metadata the keystore exposes.
  """
  @spec from_config(Config.t()) :: %{required(String.t()) => [map()]}
  def from_config(%Config{keystore: keystore}), do: from_keystore(keystore)

  @doc "Build the JWK Set from a keystore module."
  @spec from_keystore(module()) :: %{required(String.t()) => [map()]}
  def from_keystore(keystore) when is_atom(keystore) do
    keys =
      keystore.verification_pems()
      |> Enum.map(fn pem -> public_jwk(pem, SigningAlg.for_key(keystore, pem)) end)
      |> Enum.uniq_by(&Map.get(&1, "kid"))

    %{"keys" => keys}
  end

  @doc """
  Build the JWK Set from a list of PEMs (private or public; only the
  public half is published).

  Returns `%{"keys" => [jwk, ...]}` where each `jwk` is the public JWK
  with `kid` (RFC 7638 thumbprint), `use: "sig"`, and an inferred `alg`.
  Duplicate keys (same `kid`) are de-duplicated so a key listed twice in
  the verification set appears once in the published set.
  """
  @spec from_pems([String.t()]) :: %{required(String.t()) => [map()]}
  def from_pems(pems) when is_list(pems) do
    keys =
      pems
      |> Enum.map(fn pem -> public_jwk(pem, SigningAlg.infer(Key.jwk(pem))) end)
      |> Enum.uniq_by(&Map.get(&1, "kid"))

    %{"keys" => keys}
  end

  defp public_jwk(pem, alg) do
    public_map =
      pem
      |> Key.jwk()
      |> Key.public_map()

    Map.merge(public_map, %{"kid" => Key.kid(pem), "use" => "sig", "alg" => alg})
  end
end
