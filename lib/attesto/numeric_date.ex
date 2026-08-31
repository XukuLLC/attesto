defmodule Attesto.NumericDate do
  @moduledoc """
  Value-level helpers for JWT NumericDate comparisons and Unix-second clocks.

  This module deliberately does not choose protocol policy. Callers provide
  requiredness, non-negative validation, leeway, future skew, and maximum age,
  then map the result to their own error atom.
  """

  @type fetch_result :: {:ok, integer()} | :missing | {:error, :missing | :invalid}
  @type freshness_result :: :ok | :future | :stale | :invalid

  @doc """
  Fetch a NumericDate claim from `claims`.

  Missing optional claims return `:missing`; missing required claims return
  `{:error, :missing}`. A present value that is not an integer, or is negative
  when `non_negative: true`, returns `{:error, :invalid}`.
  """
  @spec fetch(map(), term(), keyword()) :: fetch_result()
  def fetch(claims, key, opts \\ []) when is_map(claims) and is_list(opts) do
    case Map.fetch(claims, key) do
      {:ok, value} ->
        if valid?(value, opts), do: {:ok, value}, else: {:error, :invalid}

      :error ->
        if Keyword.get(opts, :required, true), do: {:error, :missing}, else: :missing
    end
  end

  @doc "Return whether `value` is an integer NumericDate for the selected policy."
  @spec valid?(term(), keyword()) :: boolean()
  def valid?(value, opts \\ []) when is_list(opts) do
    is_integer(value) and
      (not Keyword.get(opts, :non_negative, true) or value >= 0)
  end

  @doc "Return whether an expiry remains strictly beyond `now - leeway`."
  @spec not_expired?(term(), term(), keyword()) :: boolean()
  def not_expired?(exp, now, opts \\ [])

  def not_expired?(exp, now, opts) when is_integer(exp) and is_integer(now) and is_list(opts) do
    exp > now - Keyword.get(opts, :leeway, 0)
  end

  def not_expired?(_exp, _now, _opts), do: false

  @doc "Return whether a not-before NumericDate has been reached."
  @spec not_before_reached?(term(), term(), keyword()) :: boolean()
  def not_before_reached?(nbf, now, opts \\ [])

  def not_before_reached?(nbf, now, opts) when is_integer(nbf) and is_integer(now) and is_list(opts) do
    nbf <= now + Keyword.get(opts, :skew, 0)
  end

  def not_before_reached?(_nbf, _now, _opts), do: false

  @doc """
  Classify an issued-at value against a future-skew and maximum-age window.

  Boundary values are accepted: `iat == now + future_skew` and
  `iat == now - max_age` both return `:ok`.
  """
  @spec fresh?(term(), term(), keyword()) :: freshness_result()
  def fresh?(iat, now, opts \\ [])

  def fresh?(iat, now, opts) when is_integer(iat) and is_integer(now) and is_list(opts) do
    future_skew = Keyword.get(opts, :future_skew, 60)
    max_age = Keyword.get(opts, :max_age, 300)

    cond do
      iat > now + future_skew -> :future
      iat < now - max_age -> :stale
      true -> :ok
    end
  end

  def fresh?(_iat, _now, _opts), do: :invalid

  @doc "Return whether `finish` is no more than `max_seconds` after `start`."
  @spec within_lifetime?(term(), term(), term()) :: boolean()
  def within_lifetime?(finish, start, max_seconds)
      when is_integer(finish) and is_integer(start) and is_integer(max_seconds) do
    finish <= start + max_seconds
  end

  def within_lifetime?(_finish, _start, _max_seconds), do: false

  @doc """
  Resolve a positive lifetime option that may only shorten `default`.

  A missing, non-positive, non-integer, or longer requested lifetime falls
  back to the supplied default.
  """
  @spec bounded_lifetime(keyword(), atom(), pos_integer()) :: pos_integer()
  def bounded_lifetime(opts, key, default) when is_list(opts) and is_integer(default) and default > 0 do
    case Keyword.get(opts, key) do
      n when is_integer(n) and n > 0 and n <= default -> n
      _ -> default
    end
  end

  @doc """
  Resolve a Unix-second clock from options.

  `default: :datetime | :system` preserves the caller's original live-clock
  source. `invalid_override: :raise | :fallback` preserves whether an invalid
  `:now` override raised or silently used that live clock.
  """
  @spec now(keyword(), keyword()) :: integer()
  def now(opts, policy \\ []) when is_list(opts) and is_list(policy) do
    default = Keyword.get(policy, :default, :datetime)
    invalid_override = Keyword.get(policy, :invalid_override, :raise)

    case Keyword.get(opts, :now) do
      nil -> live_now(default)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      _invalid -> invalid_now(invalid_override, default)
    end
  end

  @doc """
  Resolve a Unix-second clock and reject negative values.

  Stateful grant transitions use this boundary so a malformed clock cannot
  produce a record with an invalid expiry or reach a mutating store callback.
  """
  @spec non_negative_now!(keyword(), keyword()) :: non_neg_integer()
  def non_negative_now!(opts, policy \\ []) when is_list(opts) and is_list(policy) do
    case now(opts, policy) do
      value when is_integer(value) and value >= 0 -> value
      _negative -> raise ArgumentError, ":now must be a non-negative NumericDate"
    end
  end

  defp invalid_now(:fallback, default), do: live_now(default)

  defp invalid_now(:raise, _default), do: raise(ArgumentError, "invalid :now override; expected a DateTime or integer")

  defp invalid_now(other, _default), do: raise(ArgumentError, "invalid NumericDate invalid_override: #{inspect(other)}")

  defp live_now(:datetime), do: DateTime.utc_now() |> DateTime.to_unix(:second)
  defp live_now(:system), do: System.system_time(:second)
end
