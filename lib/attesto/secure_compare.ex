defmodule Attesto.SecureCompare do
  @moduledoc """
  Result-independent comparison of two binaries.

  Used wherever an attacker-controlled value is checked against a secret
  or a derived digest (a DPoP `ath`, a PKCE challenge) and a
  short-circuiting `==` would leak information through timing.

  "Result-independent" rather than "constant-time": how long `equal?/2`
  takes does not depend on HOW the operands differ - whether the length was
  wrong, or a prefix matched - but it does depend on their total size, since
  both are hashed. See `equal?/2` for what that does and does not withhold.
  """

  @doc """
  Returns `true` iff `a` and `b` are byte-identical, without the
  *comparison* revealing whether they were the same length.

  `:crypto.hash_equals/2` requires equal-length inputs, so a length guard
  is unavoidable somewhere. Guarding with `byte_size(a) == byte_size(b)`
  before it short-circuits, and the time to answer then separates "wrong
  length" from "right length, wrong bytes" - a distinction that tells an
  attacker probing a secret when to stop varying length and start varying
  content. Hashing both operands to 32 bytes removes it: the comparison is
  over equal lengths by construction and takes the same path either way.

  ## What this does not do

  It is **not** constant-time in the total size of its inputs. SHA-256
  reads every byte, so a call with two 100 KB operands takes materially
  longer than one with two 1-byte operands. What is withheld is the
  *result-dependent* signal - whether a guess was the right length, or
  matched to some prefix - not the fact that a large value was compared.
  A caller who needs the size itself hidden must pad or cap before calling.

  Callers should still validate shape first where they can, and most here
  do: `Attesto.PKCE.verify/3` gates on `Attesto.Thumbprint.valid?/1`,
  which requires an exact byte size, so its operands are fixed-length
  before this is reached. `Attesto.DPoP`'s `ath` comparison does not - the
  presented value is an arbitrary-length claim from the proof - which is
  precisely the case that benefits.

  The final byte comparison runs only when the digests already match, which
  IS a result-dependent branch - an equal pair does that extra work and an
  unequal pair does not. It is deliberate and it leaks nothing useful:
  reaching it means the caller already supplied the correct value (or a
  SHA-256 collision), so the timing difference separates "right" from
  "wrong", which the answer itself already reveals. What is withheld is the
  distinction among WRONG inputs - the one an attacker probes with.
  """
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash_equals(:crypto.hash(:sha256, a), :crypto.hash(:sha256, b)) and a == b
  end

  def equal?(_, _), do: false
end
