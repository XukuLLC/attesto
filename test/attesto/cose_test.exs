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

  defp sign_with_protected(pem, payload, protected_header, unprotected \\ %{}) do
    protected = CBOR.encode(protected_header)
    signing_input = CBOR.encode(["Signature1", bytes(protected), bytes(""), bytes(payload)])
    jwk = JOSE.JWK.from_pem(pem)
    private_key = jwk |> JOSE.JWK.to_key() |> elem(1)
    der_signature = :public_key.sign(signing_input, :sha256, private_key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_signature)
    signature = <<r::unsigned-big-size(256), s::unsigned-big-size(256)>>

    CBOR.encode([bytes(protected), unprotected, bytes(payload), bytes(signature)])
  end

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

  test "processes protected crit and rejects unknown critical headers" do
    {pem, public} = keypair()
    payload = "payload"

    understood = sign_with_protected(pem, payload, %{1 => -7, 2 => [1]})
    unknown_noncritical = sign_with_protected(pem, payload, %{1 => -7, 99 => "extension"})
    unknown_critical = sign_with_protected(pem, payload, %{1 => -7, 2 => [99], 99 => "extension"})

    assert {:ok, ^payload} = Cose.verify1(understood, public, [])
    assert {:ok, ^payload} = Cose.verify1(unknown_noncritical, public, [])

    assert {:error, :unsupported_critical_header} =
             Cose.verify1(unknown_critical, public, [])
  end

  test "rejects malformed or unprotected crit headers" do
    {pem, public} = keypair()
    payload = "payload"

    empty_crit = sign_with_protected(pem, payload, %{1 => -7, 2 => []})
    missing_critical_parameter = sign_with_protected(pem, payload, %{1 => -7, 2 => [99]})
    unprotected_crit = sign_with_protected(pem, payload, %{1 => -7}, %{2 => [1]})

    assert {:error, :invalid_cose} = Cose.verify1(empty_crit, public, [])
    assert {:error, :invalid_cose} = Cose.verify1(missing_critical_parameter, public, [])
    assert {:error, :invalid_cose} = Cose.verify1(unprotected_crit, public, [])
  end

  # A COSE_Sign1 assembled from raw header bytes, so a header map can carry
  # what `CBOR.encode/1` cannot produce: the same label twice.
  defp sign_with_raw_headers(pem, payload, protected_bytes, unprotected_bytes) do
    signing_input = CBOR.encode(["Signature1", bytes(protected_bytes), bytes(""), bytes(payload)])
    private_key = pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_key() |> elem(1)
    der_signature = :public_key.sign(signing_input, :sha256, private_key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_signature)
    signature = <<r::unsigned-big-size(256), s::unsigned-big-size(256)>>

    <<0x84>> <>
      CBOR.encode(bytes(protected_bytes)) <>
      unprotected_bytes <> CBOR.encode(bytes(payload)) <> CBOR.encode(bytes(signature))
  end

  describe "a header label that appears more than once (RFC 9052 §3)" do
    # {1: -7}
    @alg_once <<0xA1, 0x01, 0x26>>
    @empty_map <<0xA0>>

    test "the control with each label once is accepted" do
      {pem, public} = keypair()
      assert {:ok, "payload"} = Cose.verify1(sign_with_raw_headers(pem, "payload", @alg_once, @empty_map), public, [])
    end

    test "is refused in the protected header, whether or not the two values agree" do
      {pem, public} = keypair()

      for {label, protected} <- [
            # {1: -7, 1: -7}
            same_value: <<0xA2, 0x01, 0x26, 0x01, 0x26>>,
            # {1: -7, 1: -35}: ES256 first, ES384 second
            es256_then_other: <<0xA2, 0x01, 0x26, 0x01, 0x38, 0x22>>,
            # {1: -35, 1: -7}: the general-purpose decoder keeps the last value
            other_then_es256: <<0xA2, 0x01, 0x38, 0x22, 0x01, 0x26>>,
            # {1: -7, 0x1801: -7}: the second key is 1 in a non-minimal encoding
            non_minimal_repeat: <<0xA2, 0x01, 0x26, 0x18, 0x01, 0x26>>,
            # indefinite-length map {1: -7, 1: -7}
            indefinite_length: <<0xBF, 0x01, 0x26, 0x01, 0x26, 0xFF>>,
            # {1: -7, 99: "a", 99: "b"}: a repeated label other than alg
            other_label: <<0xA3, 0x01, 0x26, 0x18, 0x63, 0x61, 0x61, 0x18, 0x63, 0x61, 0x62>>
          ] do
        cose = sign_with_raw_headers(pem, "payload", protected, @empty_map)
        assert {:error, :invalid_cose} = Cose.verify1(cose, public, []), "#{label} was accepted"
      end
    end

    test "is refused in the unprotected header" do
      {pem, public} = keypair()
      # {33: h'01', 33: h'02'}
      unprotected = <<0xA2, 0x18, 0x21, 0x41, 0x01, 0x18, 0x21, 0x41, 0x02>>

      assert {:error, :invalid_cose} =
               Cose.verify1(sign_with_raw_headers(pem, "payload", @alg_once, unprotected), public, [])
    end

    test "is refused when the label is in both the protected and the unprotected header" do
      {pem, public} = keypair()
      # protected {1: -7, 99: "a"}, unprotected {99: "b"}
      protected = <<0xA2, 0x01, 0x26, 0x18, 0x63, 0x61, 0x61>>
      unprotected = <<0xA1, 0x18, 0x63, 0x61, 0x62>>

      assert {:error, :invalid_cose} =
               Cose.verify1(sign_with_raw_headers(pem, "payload", protected, unprotected), public, [])
    end

    test "is refused for a detached-payload COSE_Sign1 as well" do
      {pem, public} = keypair()
      payload = "detached"
      [_protected, unprotected, nil, _signature] = Cose.sign1_detached(pem, payload, []) |> decode!()
      assert unprotected == %{}

      duplicate = <<0xA2, 0x01, 0x26, 0x01, 0x26>>
      signing_input = CBOR.encode(["Signature1", bytes(duplicate), bytes(""), bytes(payload)])
      private_key = pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_key() |> elem(1)

      {:"ECDSA-Sig-Value", r, s} =
        :public_key.der_decode(:"ECDSA-Sig-Value", :public_key.sign(signing_input, :sha256, private_key))

      cose =
        <<0x84>> <>
          CBOR.encode(bytes(duplicate)) <>
          <<0xA0, 0xF6>> <> CBOR.encode(bytes(<<r::unsigned-big-size(256), s::unsigned-big-size(256)>>))

      assert {:error, :invalid_cose} = Cose.verify1_detached(cose, payload, public, [])
    end
  end

  test "rejects a tagged value where COSE requires a plain unprotected-header map" do
    {pem, public} = keypair()
    payload = "payload"
    [protected, _unprotected, encoded_payload, signature] = Cose.sign1(pem, payload, []) |> decode!()
    tagged_map = %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(%{}))}
    malformed = CBOR.encode([protected, tagged_map, encoded_payload, signature])

    assert {:error, :invalid_cose} = Cose.verify1(malformed, public, [])
  end

  test "sign1_detached/3 and verify1_detached/4 round-trip an ES256 payload with a null payload on the wire" do
    {pem, public} = keypair()
    external_payload = <<0, 1, 2, 3, 255>>
    signed = Cose.sign1_detached(pem, external_payload, [])

    assert [protected, %{}, nil, signature] = decode!(signed)
    assert %{1 => -7} = protected |> unwrap_bytes() |> decode!()
    assert byte_size(unwrap_bytes(signature)) == 64
    assert :ok = Cose.verify1_detached(signed, external_payload, public, [])
  end

  test "verify1_detached/4 rejects a tampered signature, a tampered external payload, and a wrong key" do
    {pem, public} = keypair()
    {_wrong_pem, wrong_public} = keypair()
    external_payload = "device authentication bytes"
    signed = Cose.sign1_detached(pem, external_payload, [])
    [protected, unprotected, nil, signature_value] = decode!(signed)

    signature = unwrap_bytes(signature_value)
    <<prefix::binary-size(63), last>> = signature
    tampered_signature = CBOR.encode([protected, unprotected, nil, bytes(prefix <> <<bxor(last, 1)>>)])

    assert {:error, :invalid_signature} = Cose.verify1_detached(tampered_signature, external_payload, public, [])
    assert {:error, :invalid_signature} = Cose.verify1_detached(signed, external_payload <> "!", public, [])
    assert {:error, :invalid_signature} = Cose.verify1_detached(signed, external_payload, wrong_public, [])
  end

  test "verify1_detached/4 rejects a COSE_Sign1 with an embedded (non-detached) payload" do
    {pem, public} = keypair()
    embedded = Cose.sign1(pem, "not detached", [])

    assert {:error, :invalid_cose} = Cose.verify1_detached(embedded, "not detached", public, [])
  end

  defp bxor(left, right), do: :erlang.bxor(left, right)
end
