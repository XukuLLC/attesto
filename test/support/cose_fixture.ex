defmodule Attesto.Test.CoseFixture do
  @moduledoc false

  # Independent signatures, including mathematically valid signatures with
  # intentionally nonconforming algorithm/curve pairs. Production signing
  # remains ES256-only.
  def sign1(payload, jwk, alg, opts \\ []) do
    hash = Map.fetch!(%{-7 => :sha256, -35 => :sha384, -36 => :sha512}, alg)
    {_, %{"crv" => curve}} = JOSE.JWK.to_public_map(jwk)
    bits = Map.fetch!(%{"P-256" => 256, "P-384" => 384, "P-521" => 528}, curve)
    protected = bytes(CBOR.encode(%{1 => alg}))
    signing_input = CBOR.encode(["Signature1", protected, bytes(""), bytes(payload)])
    private_key = jwk |> JOSE.JWK.to_key() |> elem(1)
    signature = :public_key.sign(signing_input, hash, private_key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", signature)
    raw = <<r::unsigned-big-size(bits), s::unsigned-big-size(bits)>>
    transmitted_payload = if !Keyword.get(opts, :detached, false), do: bytes(payload)
    [protected, Keyword.get(opts, :unprotected, %{}), transmitted_payload, bytes(raw)]
  end

  def resign_issuer(issuer_signed, jwk, alg, opts \\ []) do
    [_protected, unprotected, %CBOR.Tag{value: payload}, _signature] = issuer_signed["issuerAuth"]
    auth = sign1(payload, jwk, alg, Keyword.put_new(opts, :unprotected, unprotected))
    Map.put(issuer_signed, "issuerAuth", auth)
  end

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}
end
