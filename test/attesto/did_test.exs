defmodule Attesto.DidTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Bitwise

  alias Attesto.Did

  @base58_alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @p256_p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

  describe "resolve/2 did:jwk" do
    test "round-trips a real P-256 public JWK" do
      {_private, public} = keypair({:ec, "P-256"})

      assert {:ok, ^public} = Did.resolve(did_jwk(public))
    end

    test "round-trips a real Ed25519 public JWK" do
      {_private, public} = keypair({:okp, :Ed25519})

      assert {:ok, ^public} = Did.resolve(did_jwk(public))
    end

    test "rejects an oversized RSA did:jwk before bignum-decoding it (DoS gate)" do
      big_n = :binary.copy(<<255>>, 256 * 1024) |> Base.url_encode64(padding: false)
      did = did_jwk(%{"kty" => "RSA", "n" => big_n, "e" => "AQAB"})

      {micros, result} = :timer.tc(fn -> Did.resolve(did) end)
      assert {:error, :invalid_jwk} = result
      # Rejected on the raw map, not after a multi-second bignum decode.
      assert micros < 500_000
    end

    test "preserves permitted public JWK metadata" do
      {_private, public} = keypair({:ec, "P-256"})
      public = Map.merge(public, %{"alg" => "ES256", "kid" => "key-1", "use" => "sig"})

      assert {:ok, ^public} = Did.resolve(did_jwk(public))
    end

    test "rejects private, malformed, and non-canonical embedded JWKs" do
      {private, _public} = keypair({:ec, "P-256"})
      {_metadata, private_map} = JOSE.JWK.to_map(private)

      assert {:error, :private_jwk} = Did.resolve(did_jwk(private_map))
      assert {:error, :invalid_base64url} = Did.resolve("did:jwk:not+padded=")
      assert {:error, :invalid_jwk} = Did.resolve("did:jwk:" <> encode_json(["not", "a", "jwk"]))
      assert {:error, :invalid_jwk} = Did.resolve("did:jwk:" <> encode_json(%{"kty" => "EC"}))
      assert {:error, :invalid_base64url} = Did.resolve("did:jwk:")
    end
  end

  describe "resolve/2 did:key" do
    test "round-trips a real P-256 JWK from its compressed public key" do
      {private, public} = keypair({:ec, "P-256"})

      assert {:ok, resolved} = Did.resolve(did_key(public))
      assert resolved == public
      assert JOSE.JWK.thumbprint(JOSE.JWK.from_map(resolved)) == JOSE.JWK.thumbprint(private)
    end

    test "round-trips a real Ed25519 JWK from its raw public key" do
      {private, public} = keypair({:okp, :Ed25519})

      assert {:ok, resolved} = Did.resolve(did_key(public))
      assert resolved == public
      assert JOSE.JWK.thumbprint(JOSE.JWK.from_map(resolved)) == JOSE.JWK.thumbprint(private)
    end

    test "resolves published Ed25519 and P-256 did:key vectors" do
      assert {:ok, %{"crv" => "Ed25519", "kty" => "OKP", "x" => ed_x}} =
               Did.resolve("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

      assert byte_size(Base.url_decode64!(ed_x, padding: false)) == 32

      assert {:ok, %{"crv" => "P-256", "kty" => "EC"} = p256} =
               Did.resolve("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv")

      assert %JOSE.JWK{} = JOSE.JWK.from_map(p256)
    end

    test "rejects malformed multibase and base58btc values" do
      assert {:error, :invalid_multibase} = Did.resolve("did:key:")
      assert {:error, :invalid_multibase} = Did.resolve("did:key:z")
      assert {:error, :unsupported_multibase} = Did.resolve("did:key:uAA")
      assert {:error, :invalid_base58} = Did.resolve("did:key:z0OIl")
      assert {:error, :invalid_base58} = Did.resolve("did:key:z" <> String.duplicate("2", 65))
    end

    test "rejects malformed and unsupported multicodec headers" do
      assert {:error, :invalid_multicodec} = Did.resolve(encoded_did_key(<<0xED>>))
      assert {:error, :invalid_multicodec} = Did.resolve(encoded_did_key(<<0xED, 0x00, 0::256>>))
      assert {:error, :unsupported_codec} = Did.resolve(encoded_did_key(<<0xE7, 0x01, 0::264>>))
    end

    test "rejects wrong key lengths and invalid compressed P-256 points" do
      assert {:error, :invalid_public_key_length} =
               Did.resolve(encoded_did_key(<<0xED, 0x01, 0::248>>))

      assert {:error, :invalid_public_key_length} =
               Did.resolve(encoded_did_key(<<0x80, 0x24, 0::256>>))

      assert {:error, :invalid_public_key} =
               Did.resolve(encoded_did_key(<<0x80, 0x24, 4, 0::256>>))

      assert {:error, :invalid_public_key} =
               Did.resolve(encoded_did_key(<<0x80, 0x24, 2, @p256_p::unsigned-big-size(256)>>))
    end
  end

  describe "resolve/2 did:web" do
    test "returns the well-known HTTPS URL for a bare domain" do
      assert {:needs_fetch, "https://example.com/.well-known/did.json"} =
               Did.resolve("did:web:example.com")
    end

    test "returns path and percent-encoded-port URLs from the method rules" do
      assert {:needs_fetch, "https://example.com/users/alice/did.json"} =
               Did.resolve("did:web:example.com:users:alice")

      assert {:needs_fetch, "https://example.com:3000/users/alice/did.json"} =
               Did.resolve("did:web:example.com%3A3000:users:alice")

      assert {:needs_fetch, "https://example.com/a%20b/did.json"} =
               Did.resolve("did:web:example.com:a%20b")
    end

    test "uses an optional host resolver without performing HTTP itself" do
      {_private, public} = keypair({:ec, "P-256"})
      test_process = self()

      resolver = fn url ->
        send(test_process, {:resolved_url, url})
        {:ok, public}
      end

      assert {:ok, ^public} = Did.resolve("did:web:example.com:wallet", resolver: resolver)
      assert_receive {:resolved_url, "https://example.com/wallet/did.json"}
    end

    test "passes host errors through and contains resolver failures" do
      assert {:error, :unavailable} =
               Did.resolve("did:web:example.com", resolver: fn _url -> {:error, :unavailable} end)

      assert {:error, :invalid_resolver_response} =
               Did.resolve("did:web:example.com", resolver: fn _url -> :unexpected end)

      assert {:error, :resolver_failed} =
               Did.resolve("did:web:example.com", resolver: fn _url -> raise "boom" end)
    end

    test "rejects malformed web DIDs" do
      malformed = [
        "did:web:",
        "did:web:127.0.0.1",
        "did:web:example.com%3A0",
        "did:web:example.com%3A65536",
        "did:web:example.com%ZZ",
        "did:web:example.com:",
        "did:web:example.com:..",
        "did:web:example.com/path",
        "did:web:example.com?query",
        "did:web:example.com#fragment"
      ]

      for did <- malformed do
        assert {:error, :invalid_web_did} = Did.resolve(did), "expected #{did} to be rejected"
      end
    end
  end

  test "rejects unsupported methods, malformed DIDs, and invalid options" do
    assert {:error, :unsupported_method} = Did.resolve("did:example:123")
    assert {:error, :invalid_did} = Did.resolve("https://example.com")
    assert {:error, :invalid_did} = Did.resolve(nil)
    assert {:error, :invalid_options} = Did.resolve("did:web:example.com", resolver: :http_client)
    assert {:error, :invalid_options} = Did.resolve("did:web:example.com", %{})
  end

  defp keypair(spec) do
    private = JOSE.JWK.generate_key(spec)
    {_metadata, public} = JOSE.JWK.to_public_map(private)
    {private, public}
  end

  defp did_jwk(jwk), do: "did:jwk:" <> encode_json(jwk)
  defp encode_json(value), do: value |> JSON.encode!() |> Base.url_encode64(padding: false)

  defp did_key(%{"crv" => "Ed25519", "x" => x}) do
    encoded_did_key(<<0xED, 0x01>> <> Base.url_decode64!(x, padding: false))
  end

  defp did_key(%{"crv" => "P-256", "x" => x, "y" => y}) do
    x_bytes = Base.url_decode64!(x, padding: false)
    y_bytes = Base.url_decode64!(y, padding: false)
    prefix = if band(:binary.last(y_bytes), 1) == 0, do: 2, else: 3
    encoded_did_key(<<0x80, 0x24, prefix>> <> x_bytes)
  end

  defp encoded_did_key(bytes), do: "did:key:z" <> encode_base58(bytes)

  defp encode_base58(bytes) do
    zeroes = count_leading_zeroes(bytes, 0)
    encoded = bytes |> :binary.decode_unsigned() |> encode_base58_integer("")
    String.duplicate("1", zeroes) <> encoded
  end

  defp count_leading_zeroes(<<0, rest::binary>>, count), do: count_leading_zeroes(rest, count + 1)
  defp count_leading_zeroes(_rest, count), do: count

  defp encode_base58_integer(0, encoded), do: encoded

  defp encode_base58_integer(number, encoded) do
    character = binary_part(@base58_alphabet, rem(number, 58), 1)
    encode_base58_integer(div(number, 58), character <> encoded)
  end
end
