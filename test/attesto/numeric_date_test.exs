defmodule Attesto.NumericDateTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.NumericDate

  @now 1_700_000_000

  describe "fetch/3" do
    test "distinguishes required and optional missing claims" do
      assert {:error, :missing} = NumericDate.fetch(%{}, "exp", required: true)
      assert :missing = NumericDate.fetch(%{}, "exp", required: false)
    end

    test "validates integer and non-negative policy" do
      assert {:ok, @now} = NumericDate.fetch(%{"iat" => @now}, "iat")
      assert {:ok, -1} = NumericDate.fetch(%{"exp" => -1}, "exp", non_negative: false)
      assert {:error, :invalid} = NumericDate.fetch(%{"iat" => -1}, "iat")
      assert {:error, :invalid} = NumericDate.fetch(%{"iat" => 1.5}, "iat")
      assert {:error, :invalid} = NumericDate.fetch(%{"iat" => "now"}, "iat")
    end

    test "reports malformed optional values for either caller policy" do
      result = NumericDate.fetch(%{"exp" => "later"}, "exp", required: false)

      assert {:error, :invalid} = result
      assert {:error, :invalid_claims} = fail_closed(result)
      assert :ok = permissive_optional(result)
    end
  end

  describe "comparison primitives" do
    test "expiry is strict at the leeway boundary" do
      refute NumericDate.not_expired?(@now, @now, leeway: 0)
      assert NumericDate.not_expired?(@now + 1, @now, leeway: 0)
      assert NumericDate.not_expired?(@now - 30, @now, leeway: 60)
      refute NumericDate.not_expired?(@now - 60, @now, leeway: 60)
    end

    test "not-before accepts the exact skew boundary and rejects one second beyond" do
      assert NumericDate.not_before_reached?(@now + 60, @now, skew: 60)
      refute NumericDate.not_before_reached?(@now + 61, @now, skew: 60)
    end

    test "freshness accepts both exact age boundaries" do
      assert :ok = NumericDate.fresh?(@now + 60, @now, future_skew: 60, max_age: 300)
      assert :ok = NumericDate.fresh?(@now - 300, @now, future_skew: 60, max_age: 300)
      assert :future = NumericDate.fresh?(@now + 61, @now, future_skew: 60, max_age: 300)
      assert :stale = NumericDate.fresh?(@now - 301, @now, future_skew: 60, max_age: 300)
    end

    test "lifetime accepts the configured maximum" do
      assert NumericDate.within_lifetime?(@now + 300, @now, 300)
      refute NumericDate.within_lifetime?(@now + 301, @now, 300)
    end
  end

  describe "now/2" do
    test "accepts integer and DateTime overrides" do
      datetime = DateTime.from_unix!(@now, :second)

      assert NumericDate.now(now: @now) == @now
      assert NumericDate.now(now: datetime) == @now
    end

    test "preserves explicit live-clock defaults and invalid override policy" do
      assert is_integer(NumericDate.now([], default: :datetime))
      assert is_integer(NumericDate.now([], default: :system))
      assert is_integer(NumericDate.now([now: :invalid], default: :system, invalid_override: :fallback))

      assert_raise ArgumentError, fn ->
        NumericDate.now(now: :invalid)
      end
    end
  end

  defp fail_closed({:error, :invalid}), do: {:error, :invalid_claims}
  defp fail_closed(other), do: other

  defp permissive_optional({:error, :invalid}), do: :ok
  defp permissive_optional(other), do: other
end
