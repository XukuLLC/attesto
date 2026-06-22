defmodule Attesto.ResourceIndicatorTest do
  use ExUnit.Case, async: true

  alias Attesto.ResourceIndicator

  describe "validate/1" do
    test "absent parameter yields the empty set" do
      assert ResourceIndicator.validate(nil) == {:ok, []}
    end

    test "a single absolute-URI indicator (scalar form)" do
      assert ResourceIndicator.validate("https://api.example.com/a") ==
               {:ok, ["https://api.example.com/a"]}
    end

    test "multiple indicators (array form), de-duplicated and order-preserved" do
      assert ResourceIndicator.validate([
               "https://api.example.com/a",
               "https://api.example.com/b",
               "https://api.example.com/a"
             ]) == {:ok, ["https://api.example.com/a", "https://api.example.com/b"]}
    end

    test "a custom scheme with a path (no host) is a valid absolute URI" do
      assert ResourceIndicator.validate("urn:example:resource") ==
               {:ok, ["urn:example:resource"]}
    end

    test "rejects a present-but-empty value" do
      assert ResourceIndicator.validate("") == {:error, :invalid_target}
      assert ResourceIndicator.validate([]) == {:error, :invalid_target}
      assert ResourceIndicator.validate([""]) == {:error, :invalid_target}
    end

    test "rejects a relative URI (no scheme)" do
      assert ResourceIndicator.validate("/api/a") == {:error, :invalid_target}
      assert ResourceIndicator.validate("api.example.com") == {:error, :invalid_target}
    end

    test "rejects a URI carrying a fragment (RFC 8707 §2.1)" do
      assert ResourceIndicator.validate("https://api.example.com/a#frag") ==
               {:error, :invalid_target}
    end

    test "rejects malformed percent-encoding" do
      assert ResourceIndicator.validate("https://api.example.com/%ZZ") ==
               {:error, :invalid_target}
    end

    test "rejects when any member of an array is invalid" do
      assert ResourceIndicator.validate(["https://ok.example.com", "not a uri"]) ==
               {:error, :invalid_target}
    end

    test "rejects a non-binary / non-list shape" do
      assert ResourceIndicator.validate(123) == {:error, :invalid_target}
      assert ResourceIndicator.validate([123]) == {:error, :invalid_target}
    end
  end

  describe "authorize/2" do
    test "passes when every requested resource is in the allowlist" do
      allowed = ["https://api.example.com/a", "https://api.example.com/b"]

      assert ResourceIndicator.authorize(["https://api.example.com/a"], allowed) ==
               {:ok, ["https://api.example.com/a"]}

      assert ResourceIndicator.authorize(
               ["https://api.example.com/a", "https://api.example.com/b"],
               allowed
             ) == {:ok, ["https://api.example.com/a", "https://api.example.com/b"]}
    end

    test "rejects a resource the server does not serve (invalid_target)" do
      assert ResourceIndicator.authorize(
               ["https://evil.example.com"],
               ["https://api.example.com/a"]
             ) == {:error, :invalid_target}
    end

    test "an empty request is trivially authorized" do
      assert ResourceIndicator.authorize([], ["https://api.example.com/a"]) == {:ok, []}
    end
  end
end
