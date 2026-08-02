defmodule Attesto.ClaimsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Claims

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
