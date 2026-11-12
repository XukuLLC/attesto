defmodule Attesto.StrictCBORTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.StrictCBOR

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  describe "decode/2 on well-formed input" do
    test "returns what the general-purpose decoder returns" do
      for value <- [
            0,
            23,
            24,
            65_536,
            18_446_744_073_709_551_615,
            -1,
            -1000,
            "text",
            bytes(<<1, 2, 3>>),
            [],
            [1, [2, [3]]],
            %{},
            %{1 => -7, 33 => [bytes("der")]},
            %{"docType" => "org.example", "nameSpaces" => %{"ns" => [%{"a" => 1}, %{"a" => 2}]}},
            %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(%{"x" => 1}))},
            true,
            false,
            nil,
            1.5
          ] do
        encoded = CBOR.encode(value)
        assert {:ok, decoded, ""} = CBOR.decode(encoded)
        assert StrictCBOR.decode(encoded) == {:ok, decoded}
      end
    end

    test "accepts indefinite-length strings, arrays and maps" do
      # (_ h'01', h'02')
      assert {:ok, _} = StrictCBOR.decode(<<0x5F, 0x41, 0x01, 0x41, 0x02, 0xFF>>)
      # (_ "a", "b")
      assert {:ok, _} = StrictCBOR.decode(<<0x7F, 0x61, 0x61, 0x61, 0x62, 0xFF>>)
      # [_ 1, 2]
      assert StrictCBOR.decode(<<0x9F, 0x01, 0x02, 0xFF>>) == {:ok, [1, 2]}
      # {_ 1: 2, 3: 4}
      assert StrictCBOR.decode(<<0xBF, 0x01, 0x02, 0x03, 0x04, 0xFF>>) == {:ok, %{1 => 2, 3 => 4}}
    end

    test "the same key in two different maps is not a repeat" do
      assert {:ok, [%{1 => 1}, %{1 => 2}]} = StrictCBOR.decode(CBOR.encode([%{1 => 1}, %{1 => 2}]))
      assert {:ok, %{1 => %{1 => %{1 => 0}}}} = StrictCBOR.decode(CBOR.encode(%{1 => %{1 => %{1 => 0}}}))
    end

    test "keys of different types that print alike are different keys" do
      # {1: 0, "1": 0, h'31': 0}
      assert {:ok, map} = StrictCBOR.decode(<<0xA3, 0x01, 0x00, 0x61, 0x31, 0x00, 0x41, 0x31, 0x00>>)
      assert map_size(map) == 3
    end
  end

  describe "decode/2 refuses a map that repeats a key" do
    test "at the top level" do
      # {1: -7, 1: -7}
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xA2, 0x01, 0x26, 0x01, 0x26>>)
      # {1: -7, 1: -35}
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xA2, 0x01, 0x26, 0x01, 0x38, 0x22>>)
      # {"a": 1, "a": 2}
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02>>)
    end

    test "when the two keys are one value in two encodings" do
      # {1: 0, 0x1801: 0}
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xA2, 0x01, 0x00, 0x18, 0x01, 0x00>>)
      # {"a": 0, (_ "a"): 0}
      assert {:error, :invalid_cbor} =
               StrictCBOR.decode(<<0xA2, 0x61, 0x61, 0x00, 0x7F, 0x61, 0x61, 0xFF, 0x00>>)
    end

    test "nested in an array, a map value, a tag, or an indefinite-length map" do
      duplicate = <<0xA2, 0x01, 0x00, 0x01, 0x00>>

      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0x81>> <> duplicate)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xA1, 0x05>> <> duplicate)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xC1>> <> duplicate)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0xBF, 0x01, 0x00, 0x01, 0x00, 0xFF>>)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(<<0x9F>> <> duplicate <> <<0xFF>>)
    end

    test "a byte string is opaque: CBOR inside it is checked when it is decoded" do
      duplicate = <<0xA2, 0x01, 0x00, 0x01, 0x00>>
      wrapped = CBOR.encode(bytes(duplicate))

      assert {:ok, %CBOR.Tag{tag: :bytes, value: ^duplicate}} = StrictCBOR.decode(wrapped)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(duplicate)
    end
  end

  describe "decode/2 refuses malformed or oversized input" do
    test "truncated items, trailing bytes, stray breaks and reserved encodings" do
      for malformed <- [
            "",
            <<0x18>>,
            <<0x42, 0x01>>,
            <<0x82, 0x01>>,
            <<0xA1, 0x01>>,
            <<0x01, 0x02>>,
            <<0xFF>>,
            <<0x9F, 0x01>>,
            <<0xBF, 0x01, 0xFF>>,
            <<0x1C>>,
            <<0x5F, 0x61, 0x61, 0xFF>>,
            <<0xF8>>
          ] do
        assert {:error, :invalid_cbor} = StrictCBOR.decode(malformed), "#{inspect(malformed)} was accepted"
      end

      assert {:error, :invalid_cbor} = StrictCBOR.decode(:not_a_binary)
    end

    test "input nested deeper than :max_depth" do
      nested = fn depth -> :binary.copy(<<0x81>>, depth) <> <<0x00>> end

      assert {:ok, _} = StrictCBOR.decode(nested.(32))
      assert {:error, :invalid_cbor} = StrictCBOR.decode(nested.(33))
      assert {:ok, _} = StrictCBOR.decode(nested.(3), max_depth: 3)
      assert {:error, :invalid_cbor} = StrictCBOR.decode(nested.(4), max_depth: 3)
      # Far past the bound: refused by the walk, without building anything.
      assert {:error, :invalid_cbor} = StrictCBOR.decode(nested.(200_000))
    end

    test "input longer than :max_bytes" do
      encoded = CBOR.encode(String.duplicate("a", 100))
      assert {:ok, _} = StrictCBOR.decode(encoded, max_bytes: byte_size(encoded))
      assert {:error, :invalid_cbor} = StrictCBOR.decode(encoded, max_bytes: byte_size(encoded) - 1)
    end
  end
end
