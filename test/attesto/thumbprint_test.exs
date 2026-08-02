defmodule Attesto.ThumbprintTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Thumbprint

  describe "of/1" do
    test "is the base64url-no-pad SHA-256 of the input, 43 characters long" do
      tp = Thumbprint.of("hello world")

      assert byte_size(tp) == 43

      expected =
        :sha256
        |> :crypto.hash("hello world")
        |> Base.url_encode64(padding: false)

      assert tp == expected
    end

    test "uses only the base64url alphabet (no +, /, or =)" do
      # Many inputs to exercise the trailing-character variety.
      for input <- Enum.map(0..200, &Integer.to_string/1) do
        tp = Thumbprint.of(input)
        assert tp =~ ~r/\A[A-Za-z0-9_-]{43}\z/
        refute String.contains?(tp, "+")
        refute String.contains?(tp, "/")
        refute String.contains?(tp, "=")
      end
    end

    test "is deterministic and distinguishes distinct inputs" do
      assert Thumbprint.of("a") == Thumbprint.of("a")
      assert Thumbprint.of("a") != Thumbprint.of("b")
    end

    test "accepts the empty binary" do
      tp = Thumbprint.of("")
      assert byte_size(tp) == 43
      assert Thumbprint.valid?(tp)
    end
  end

  describe "of_jwk/1" do
    test "accepts a JOSE.JWK and its equivalent public map" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, public_map} = JOSE.JWK.to_public_map(key)

      assert {:ok, from_jwk} = Thumbprint.of_jwk(key)
      assert {:ok, from_map} = Thumbprint.of_jwk(public_map)
      assert from_jwk == from_map
      assert Thumbprint.valid?(from_jwk)
    end

    test "uses only the required public members" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, private_map} = JOSE.JWK.to_map(key)
      {_, public_map} = JOSE.JWK.to_public_map(key)

      assert Thumbprint.of_jwk(private_map) == Thumbprint.of_jwk(public_map)
    end

    test "returns an error for a malformed JWK" do
      assert {:error, :malformed_jwk} = Thumbprint.of_jwk(%{})
      assert {:error, :malformed_jwk} = Thumbprint.of_jwk(%{"kty" => "RSA"})
      assert {:error, :malformed_jwk} = Thumbprint.of_jwk("not-a-jwk")
    end
  end

  describe "valid?/1" do
    test "true for the output of of/1" do
      for input <- Enum.map(0..200, &Integer.to_string/1) do
        assert Thumbprint.valid?(Thumbprint.of(input))
      end
    end

    test "false for a string of the wrong length" do
      refute Thumbprint.valid?(String.duplicate("A", 42))
      refute Thumbprint.valid?(String.duplicate("A", 44))
      refute Thumbprint.valid?("")
    end

    test "false for a 43-char string containing illegal characters" do
      base = Thumbprint.of("anchor")

      # Swap the first character for each forbidden symbol, keeping length 43.
      for illegal <- ["+", "/", "="] do
        candidate = illegal <> String.slice(base, 1, 42)
        assert byte_size(candidate) == 43
        refute Thumbprint.valid?(candidate)
      end
    end

    test "false for a 43-char base64url string with non-canonical trailing bits" do
      # The final char of a 43-char no-pad string encodes only 4 bits, so its
      # low 2 bits are structurally zero. "A" (value 0) is canonical for the
      # last position; "B" (value 1) sets a low bit that no 32-byte digest
      # could produce, so it must be rejected despite legal length/alphabet.
      canonical = String.duplicate("A", 42) <> "A"
      non_canonical = String.duplicate("A", 42) <> "B"

      assert byte_size(non_canonical) == 43
      assert non_canonical =~ ~r/\A[A-Za-z0-9_-]{43}\z/
      assert Thumbprint.valid?(canonical)
      refute Thumbprint.valid?(non_canonical)
    end

    test "false for non-binary values" do
      refute Thumbprint.valid?(nil)
      refute Thumbprint.valid?(:atom)
      refute Thumbprint.valid?(42)
      refute Thumbprint.valid?(["A"])
      refute Thumbprint.valid?(%{})
    end
  end

  describe "length/0" do
    test "is 43" do
      assert Thumbprint.length() == 43
    end
  end
end
