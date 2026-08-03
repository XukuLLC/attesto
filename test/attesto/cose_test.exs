defmodule Attesto.CoseTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Cose

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp decode!(encoded) do
    assert {:ok, value, ""} = CBOR.decode(encoded)
    value
  end

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  defp unwrap_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value

  test "sign1/3 and verify1/3 round-trip an ES256 payload" do
    {pem, public} = keypair()
    payload = <<0, 1, 2, 3, 255>>
    signed = Cose.sign1(pem, payload, [])

    assert [protected, %{}, encoded_payload, signature] = decode!(signed)
    assert %{1 => -7} = protected |> unwrap_bytes() |> decode!()
    assert payload == unwrap_bytes(encoded_payload)
    assert byte_size(unwrap_bytes(signature)) == 64
    assert {:ok, ^payload} = Cose.verify1(signed, public, [])
  end

  test "tampered signature and payload are rejected" do
    {pem, public} = keypair()
    payload = "issuer payload"
    signed = Cose.sign1(pem, payload, [])
    [protected, unprotected, encoded_payload, signature_value] = decode!(signed)

    signature = unwrap_bytes(signature_value)
    <<prefix::binary-size(63), last>> = signature
    tampered_signature = CBOR.encode([protected, unprotected, encoded_payload, bytes(prefix <> <<bxor(last, 1)>>)])

    tampered_payload = CBOR.encode([protected, unprotected, bytes(payload <> "!"), signature_value])

    assert {:error, :invalid_signature} = Cose.verify1(tampered_signature, public, [])
    assert {:error, :invalid_signature} = Cose.verify1(tampered_payload, public, [])
  end

  test "key_to_cose/1 and cose_to_key/1 round-trip a P-256 public JWK" do
    {_pem, public} = keypair()
    cose_key = Cose.key_to_cose(public)

    assert %{1 => 2, -1 => 1, -2 => %CBOR.Tag{tag: :bytes}, -3 => %CBOR.Tag{tag: :bytes}} = cose_key
    assert public == Cose.cose_to_key(cose_key)
  end

  test "verify1/3 rejects a wrong key" do
    {pem, _public} = keypair()
    {_wrong_pem, wrong_public} = keypair()
    signed = Cose.sign1(pem, "payload", [])

    assert {:error, :invalid_signature} = Cose.verify1(signed, wrong_public, [])
  end

  defp bxor(left, right), do: :erlang.bxor(left, right)
end
