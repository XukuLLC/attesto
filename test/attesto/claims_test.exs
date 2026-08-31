defmodule Attesto.ClaimsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Claims

  @max_exact_integer 9_007_199_254_740_991

  describe "portable_json_object?/1" do
    test "accepts JSON-native scalar, array, and nested object values" do
      value = %{
        "string" => "value",
        "null" => nil,
        "boolean" => true,
        "integer" => 7,
        "array" => [false, nil, %{"nested" => "ok"}]
      }

      assert Claims.portable_json_object?(value)
    end

    test "rejects atom keys and non-JSON values at any nesting level" do
      refute Claims.portable_json_object?(%{atom_key: "value"})
      refute Claims.portable_json_object?(%{"nested" => %{atom_key: "value"}})
      refute Claims.portable_json_object?(%{"nested" => [%{"ok" => self()}]})
      refute Claims.portable_json_object?(%{"tuple" => {:not, "json"}})
      refute Claims.portable_json_object?(%{"atom" => :admin})
      refute Claims.portable_json_object?(%{"improper_array" => ["ok" | "tail"]})
      refute Claims.portable_json_object?(%{<<255>> => "invalid key"})
      refute Claims.portable_json_object?(%{"nul" => <<0>>})
      refute Claims.portable_json_object?(%{"nested" => %{"nul" => "a\0b"}})
      refute Claims.portable_json_object?(%{"nested" => %{<<0>> => "invalid key"}})
      refute Claims.portable_json_object?(%{<<0>> => "invalid key"})
      refute Claims.portable_json_object?(%{"bitstring" => <<1::size(1)>>})
    end

    test "rejects invalid UTF-8 binaries while accepting empty objects and arrays" do
      assert Claims.portable_json_object?(%{"empty_object" => %{}, "empty_array" => []})
      refute Claims.portable_json_object?(%{"invalid_utf8" => <<255>>})
    end

    test "accepts only I-JSON exact-range integers" do
      assert Claims.portable_json_object?(%{"minimum" => -@max_exact_integer, "maximum" => @max_exact_integer})
    end

    test "rejects floats and integers outside the I-JSON exact range" do
      for value <- [1.5, 1.0e100, @max_exact_integer + 1, -@max_exact_integer - 1] do
        refute Claims.portable_json_object?(%{"value" => value}), "accepted non-exact number #{inspect(value)}"
      end

      refute Claims.portable_json_object?(%{"nested" => [%{"value" => @max_exact_integer + 1}]})
      refute Claims.portable_json_object?(%{"nested" => %{"value" => -@max_exact_integer - 1}})
    end

    test "caps composite nesting at 64 while allowing wide flat arrays" do
      assert Claims.portable_json_object?(nested_objects(64))
      refute Claims.portable_json_object?(nested_objects(65))
      assert Claims.portable_json_object?(%{"values" => List.duplicate(1, 1_000)})
    end

    test "counts alternating object and array containers toward the same depth" do
      assert Claims.portable_json_object?(nested_object_arrays(32))
      refute Claims.portable_json_object?(nested_object_arrays(33))
    end
  end

  defp nested_objects(1), do: %{"value" => 1}
  defp nested_objects(depth), do: %{"nested" => nested_objects(depth - 1)}

  defp nested_object_arrays(1), do: %{"value" => 1}
  defp nested_object_arrays(depth), do: %{"nested" => [nested_object_arrays(depth - 1)]}

  describe "normalize_keys/2 with atoms: :reject (default)" do
    test "passes an all-binary-key map through unchanged" do
      assert {:ok, %{"a" => 1, "b" => 2}} = Claims.normalize_keys(%{"a" => 1, "b" => 2})
    end

    test "rejects an atom key, naming the offending key" do
      assert {:error, {:invalid_key, :iss}} = Claims.normalize_keys(%{:iss => 1})
    end

    test "rejects a charlist key (the duplicate-JSON-member forge vector)" do
      assert {:error, {:invalid_key, ~c"iss"}} = Claims.normalize_keys(%{~c"iss" => 1})
    end

    test "rejects a non-string, non-atom key" do
      assert {:error, {:invalid_key, 7}} = Claims.normalize_keys(%{7 => 1})
    end

    test "an empty map is fine" do
      assert {:ok, %{}} = Claims.normalize_keys(%{})
    end
  end

  describe "normalize_keys/2 with atoms: :convert" do
    test "converts atom keys to strings and passes binaries through" do
      assert {:ok, out} = Claims.normalize_keys(%{:iss => 1, "aud" => 2}, atoms: :convert)
      assert out == %{"iss" => 1, "aud" => 2}
    end

    test "still rejects a charlist or numeric key" do
      assert {:error, {:invalid_key, ~c"x"}} = Claims.normalize_keys(%{~c"x" => 1}, atoms: :convert)
      assert {:error, {:invalid_key, 1}} = Claims.normalize_keys(%{1 => 1}, atoms: :convert)
    end

    test "converts the special atoms nil/true/false as Atom.to_string does" do
      # Documents the boundary: these ARE atoms, so :convert stringifies them.
      assert {:ok, %{"nil" => 1}} = Claims.normalize_keys(%{nil => 1}, atoms: :convert)
      assert {:ok, %{"true" => 1}} = Claims.normalize_keys(%{true => 1}, atoms: :convert)
    end
  end

  test "normalize_keys/2 rejects an unknown atoms policy" do
    assert {:error, :invalid_atom_policy} = Claims.normalize_keys(%{"a" => 1}, atoms: :bogus)
  end

  describe "merge_registered/3" do
    test "merges caller claims under the authoritative registered claims" do
      assert {:ok, merged} =
               Claims.merge_registered(%{"scope" => "openid"}, %{"iss" => "i", "iat" => 1})

      assert merged == %{"iss" => "i", "iat" => 1, "scope" => "openid"}
    end

    test "rejects a caller claim that collides with a registered claim (default reserved)" do
      assert {:error, :reserved_claim_conflict} =
               Claims.merge_registered(%{"iss" => "spoof"}, %{"iss" => "authoritative"})
    end

    test "honours an explicit reserved list beyond the registered keys" do
      assert {:error, :reserved_claim_conflict} =
               Claims.merge_registered(%{"nbf" => 1}, %{"iss" => "i"}, reserved: ["iss", "nbf"])
    end

    test "defaults to rejecting atom caller keys, but :convert accepts them" do
      assert {:error, {:invalid_key, :scope}} =
               Claims.merge_registered(%{scope: "openid"}, %{"iss" => "i"})

      assert {:ok, merged} =
               Claims.merge_registered(%{scope: "openid"}, %{"iss" => "i"}, atom_keys: :convert)

      assert merged == %{"iss" => "i", "scope" => "openid"}
    end

    test "propagates a normalization error from a malformed caller key" do
      assert {:error, {:invalid_key, ~c"scope"}} =
               Claims.merge_registered(%{~c"scope" => "openid"}, %{"iss" => "i"})
    end

    test "a caller key that stringifies onto a registered claim is still a conflict" do
      # :iss (atom) -> "iss" collides with the reserved registered "iss".
      assert {:error, :reserved_claim_conflict} =
               Claims.merge_registered(%{iss: "spoof"}, %{"iss" => "i"}, atom_keys: :convert)
    end
  end
end
