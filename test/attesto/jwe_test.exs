defmodule Attesto.JWETest do
  use ExUnit.Case, async: true

  alias Attesto.{JWE, JWS}

  setup do
    private = JOSE.JWK.generate_key({:ec, "P-256"})
    {_modules, public} = JOSE.JWK.to_public_map(private)
    {:ok, private: private, public: public, header: %{"alg" => "ECDH-ES", "enc" => "A256GCM"}}
  end

  test "both GCM algorithms interoperate with JOSE and preserve protected bindings", context do
    for enc <- ~w(A128GCM A256GCM) do
      header =
        Map.merge(context.header, %{
          "enc" => enc,
          "kid" => "recipient",
          "apu" => JWS.encode64("wallet"),
          "apv" => JWS.encode64("nonce")
        })

      assert {:ok, compact} = JWE.encrypt(context.public, "credential contents", header)
      assert {"credential contents", %JOSE.JWE{}} = JOSE.JWE.block_decrypt(context.private, compact)
      assert {:ok, "credential contents", decoded} = JWE.decrypt(context.private, compact)
      assert Map.take(decoded, Map.keys(header)) == header
      assert %{"kty" => "EC", "crv" => "P-256"} = decoded["epk"]
      refute Map.has_key?(decoded["epk"], "d")
    end
  end

  test "decrypts a JWE produced directly by JOSE", context do
    {_modules, compact} =
      JOSE.JWE.block_encrypt(
        {JOSE.JWK.from_map(context.public), JOSE.JWK.generate_key({:ec, "P-256"})},
        "external",
        context.header
      )
      |> JOSE.JWE.compact()

    assert {:ok, "external", _header} = JWE.decrypt(context.private, compact)
  end

  test "each encryption has a fresh ephemeral key and IV", context do
    assert {:ok, first} = JWE.encrypt(context.public, "same contents", context.header)
    assert {:ok, second} = JWE.encrypt(context.public, "same contents", context.header)
    assert {:ok, _, first_header} = JWE.decrypt(context.private, first)
    assert {:ok, _, second_header} = JWE.decrypt(context.private, second)
    refute first_header["epk"] == second_header["epk"]
    refute Enum.at(String.split(first, "."), 2) == Enum.at(String.split(second, "."), 2)
  end

  test "wrong recipient and modified ciphertext fail authentication", context do
    assert {:ok, compact} = JWE.encrypt(context.public, "private", context.header)
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    assert {:error, :invalid_jwe} = JWE.decrypt(other, compact)
    assert {:error, :invalid_jwe} = JWE.decrypt(context.private, rewrite_segment(compact, 3, &flip_byte/1))
    assert {:error, :invalid_jwe} = JWE.decrypt(context.private, rewrite_segment(compact, 4, &flip_byte/1))
  end

  test "rejects public-only decryption and keys restricted to signing", context do
    assert {:ok, compact} = JWE.encrypt(context.public, "private", context.header)
    assert {:error, :invalid_key} = JWE.decrypt(context.public, compact)

    for field <- [%{"use" => "sig"}, %{"alg" => "ES256"}, %{"key_ops" => ["verify"]}] do
      assert {:error, :invalid_key} = JWE.encrypt(Map.merge(context.public, field), "private", context.header)
    end
  end

  test "narrowed algorithm policy rejects another otherwise supported algorithm", context do
    header = %{context.header | "enc" => "A128GCM"}
    assert {:ok, compact} = JWE.encrypt(context.public, "private", header)
    assert {:error, :invalid_header} = JWE.decrypt(context.private, compact, accepted_encs: ["A256GCM"])
    assert {:error, :invalid_header} = JWE.encrypt(context.public, "private", header, accepted_encs: ["A256GCM"])
    assert {:error, :invalid_options} = JWE.decrypt(context.private, compact, accepted_algs: ["RSA1_5"])
  end

  test "rejects compression, critical extensions and caller-supplied ephemeral keys", context do
    for extra <- [
          %{"zip" => "DEF"},
          %{"zip" => nil},
          %{"crit" => ["unknown"]},
          %{"crit" => []},
          %{"epk" => context.public}
        ] do
      assert {:error, :invalid_header} = JWE.encrypt(context.public, "private", Map.merge(context.header, extra))
    end

    assert {:ok, compact} = JWE.encrypt(context.public, "private", context.header)

    for extra <- [
          %{"zip" => "DEF"},
          %{"crit" => ["unknown"]},
          %{"epk" => Map.put(context.public, "d", JWS.encode64(<<1::256>>))}
        ] do
      changed = rewrite_header(compact, &Map.merge(&1, extra))
      assert {:error, :invalid_header} = JWE.decrypt(context.private, changed)
    end
  end

  test "rejects duplicate JSON members including inside the ephemeral key", context do
    assert {:ok, compact} = JWE.encrypt(context.public, "private", context.header)
    duplicate = ~s({"alg":"ECDH-ES","alg":"ECDH-ES","enc":"A256GCM"})
    nested = ~s({"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","kty":"EC"}})

    for bytes <- [duplicate, nested] do
      assert {:error, :invalid_header} = JWE.decrypt(context.private, put_segment(compact, 0, JWS.encode64(bytes)))
    end
  end

  test "rejects padding, fixed-length parameter errors and extra compact segments", context do
    assert {:ok, compact} = JWE.encrypt(context.public, "private", context.header)
    [header, _key, _iv, _cipher, _tag] = segments = String.split(compact, ".")
    assert {:error, :invalid_header} = JWE.decrypt(context.private, put_segment(compact, 0, header <> "="))

    for {index, value} <- [
          {1, "key"},
          {2, JWS.encode64(<<1, 2>>)},
          {4, JWS.encode64(<<1>>)},
          {4, Enum.at(segments, 4) <> "="}
        ] do
      assert {:error, :invalid_jwe} = JWE.decrypt(context.private, put_segment(compact, index, value))
    end

    assert {:error, :invalid_jwe} = JWE.decrypt(context.private, compact <> ".extra")
    assert {:error, :invalid_jwe} = JWE.decrypt(context.private, ".")
  end

  test "enforces compact, plaintext and protected-header bounds", context do
    assert {:ok, compact} = JWE.encrypt(context.public, "12345", context.header)
    assert {:error, :size_limit} = JWE.encrypt(context.public, "12345", context.header, max_plaintext_bytes: 4)
    assert {:error, :size_limit} = JWE.decrypt(context.private, compact, max_compact_bytes: 10)
    assert {:error, :invalid_jwe} = JWE.decrypt(context.private, compact, max_plaintext_bytes: 4)

    assert {:error, :size_limit} =
             JWE.encrypt(context.public, "private", Map.put(context.header, "extension", String.duplicate("x", 20_000)))

    assert {:error, :size_limit} = JWE.decrypt(context.private, String.duplicate(".", 1_048_577))
  end

  test "malformed inputs and options return controlled errors", context do
    for value <- [nil, 1, %{}, "", "a.b.c.d.e", String.duplicate(".", 500)] do
      assert {:error, _reason} = JWE.decrypt(context.private, value)
    end

    for opts <- [[max_plaintext_bytes: 0], [max_compact_bytes: -1], [accepted_encs: []], [accepted_algs: nil]] do
      assert {:error, :invalid_options} = JWE.encrypt(context.public, "private", context.header, opts)
    end

    assert {:error, :invalid_header} =
             JWE.encrypt(context.public, "private", Map.put(context.header, "apu", "not+base64url"))
  end

  defp rewrite_header(compact, update) do
    rewrite_segment(compact, 0, fn bytes -> bytes |> JSON.decode!() |> update.() |> JSON.encode!() end)
  end

  defp rewrite_segment(compact, index, update) do
    encoded = compact |> String.split(".") |> Enum.at(index)
    put_segment(compact, index, encoded |> Base.url_decode64!(padding: false) |> update.() |> JWS.encode64())
  end

  defp put_segment(compact, index, replacement),
    do: compact |> String.split(".") |> List.replace_at(index, replacement) |> Enum.join(".")

  defp flip_byte(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
end
