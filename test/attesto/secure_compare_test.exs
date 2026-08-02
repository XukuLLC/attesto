defmodule Attesto.SecureCompareTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.SecureCompare

  test "equal binaries compare true" do
    assert SecureCompare.equal?("abc123", "abc123")
    assert SecureCompare.equal?("", "")
  end

  test "different binaries of the same length compare false" do
    refute SecureCompare.equal?("abc123", "abc124")
  end

  test "binaries of different lengths compare false (no raise)" do
    refute SecureCompare.equal?("abc", "abcd")
    refute SecureCompare.equal?("abcd", "abc")
  end

  test "non-binary operands compare false" do
    refute SecureCompare.equal?("abc", nil)
    refute SecureCompare.equal?(:abc, "abc")
    refute SecureCompare.equal?(123, 123)
  end

  describe "length independence" do
    # A caveat about what these tests can and cannot do.
    #
    # The property at stake is a TIMING one: the comparison must not
    # short-circuit on a length mismatch, because the time to answer would
    # then separate "wrong length" from "right length, wrong bytes". No
    # assertion below detects that. All of them pass against the
    # short-circuiting implementation this replaced, which was verified by
    # reverting it and re-running. A wall-clock assertion would be the only
    # test that fails on the old code, and a timing assertion on a shared CI
    # runner is a flake generator, not a guard.
    #
    # So these pin the BEHAVIOUR the fix must preserve, not the fix itself:
    # that hashing both operands still answers exactly "are these identical",
    # including the cases a careless implementation gets wrong - a prefix
    # compared against the value it prefixes, one side hashed but not the
    # other, an empty operand. The timing property is held by construction
    # (both operands become 32-byte digests before comparison) and by the
    # moduledoc that explains why, which is where a future change would have
    # to argue with it.
    test "wildly different lengths still compare false without raising" do
      refute SecureCompare.equal?("a", String.duplicate("a", 100_000))
      refute SecureCompare.equal?(String.duplicate("a", 100_000), "a")
      refute SecureCompare.equal?("", "a")
      refute SecureCompare.equal?("a", "")
    end

    test "equality holds for variable-length values, not only fixed-size digests" do
      secret = "s_" <> String.duplicate("x", 137)

      assert SecureCompare.equal?(secret, secret)
      refute SecureCompare.equal?(secret, secret <> "y")
      refute SecureCompare.equal?(secret, String.replace_suffix(secret, "x", "y"))
    end

    test "a prefix is not equal to the value it prefixes" do
      # The classic short-circuit bug: comparing only up to the shorter length.
      refute SecureCompare.equal?("abc", "abcdef")
      refute SecureCompare.equal?("abcdef", "abc")
    end

    # `:crypto.hash_equals/2` raises on unequal sizes, so the implementation
    # has to guarantee equal-size operands itself. Pin that it never escapes.
    test "never raises, whatever the sizes" do
      for {a, b} <- [{"", "x"}, {"x", ""}, {"ab", "abcdefghij"}, {String.duplicate("q", 4097), "q"}] do
        assert is_boolean(SecureCompare.equal?(a, b))
      end
    end
  end
end
