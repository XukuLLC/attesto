defmodule Attesto.SecureCompare do
  @moduledoc """
  Constant-time comparison of two binaries.

  Used wherever an attacker-controlled value is checked against a secret
  or a derived digest (a DPoP `ath`, a PKCE challenge) and a
  short-circuiting `==` would leak information through timing.
  """

  @doc """
  Returns `true` iff `a` and `b` are byte-identical, comparing in
  constant time **regardless of their lengths**.

  `:crypto.hash_equals/2` requires equal-length inputs, so a length guard
  is unavoidable somewhere. Guarding with `byte_size(a) == byte_size(b)`
  before it would short-circuit, and the time to answer would then
  separate "wrong length" from "right length, wrong bytes". Comparing
  fixed-size digests of the operands removes that: both inputs are hashed
  to 32 bytes, so the comparison is over equal lengths by construction and
  its duration carries nothing about the inputs.

  Every call site inside this library already guarantees fixed-length
  operands before calling (`Attesto.PKCE.verify/3` gates on
  `Attesto.Thumbprint.valid?/1`, which requires an exact byte size), so
  this is not a fix for a leak in Attesto's own use. It is here because
  this function is public, its name is an unconditional promise, and a
  host comparing a variable-length value of its own should get the
  property the name claims rather than one contingent on validating shape
  first.

  The final byte comparison runs only when the digests already match, so
  it cannot leak: reaching it means the caller supplied either the correct
  value or a SHA-256 collision. It is there so a collision cannot be
  reported as equality.
  """
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash_equals(:crypto.hash(:sha256, a), :crypto.hash(:sha256, b)) and a == b
  end

  def equal?(_, _), do: false
end
