defmodule Attesto.PreAuthorizedCodeStore do
  @moduledoc """
  Storage seam for OID4VCI pre-authorized codes.

  `Attesto.PreAuthorizedCode` generates and validates a pre-authorized code,
  but it never decides where the code lives. A host implements this behaviour
  over whatever store fits (Postgres, Redis, ETS);
  `Attesto.PreAuthorizedCodeStore.ETS` is a ready single-node implementation.

  ## The single-use contract

  `take/1` MUST be atomic: it returns the record for `code_hash` and removes it
  in one indivisible step, so two concurrent redemptions of the same
  pre-authorized code cannot both succeed. A store that let `take/1` race would
  let a captured code be replayed. A SQL implementation uses
  `DELETE ... WHERE code_hash = $1 RETURNING ...`; an ETS implementation uses
  `:ets.take/2`.

  The code is consumed by `take/1` even if `Attesto.PreAuthorizedCode` then
  rejects the redemption because it is expired or the presented PIN is wrong.
  A failed validation therefore burns the code and denies repeated attempts
  against a captured code.

  ## Record fields

  A stored record contains:

    * `:code_hash` - the `Attesto.Secret.hash/1` of the code (the key).
    * `:data` - the bound issuance context.
    * `:expires_at` - absolute expiry, unix seconds.
  """

  @type entry :: %{code_hash: binary(), data: map(), expires_at: integer()}

  @doc "Persist a pre-authorized code record."
  @callback put(entry()) :: :ok

  @doc """
  Atomically fetch and delete the record for `code_hash`.

  MUST be a single indivisible operation to preserve the single-use guarantee.
  Returns `{:ok, entry}` when the code existed and was unredeemed, and `:error`
  when no such code exists. The latter includes an already-redeemed code.
  """
  @callback take(code_hash :: binary()) :: {:ok, entry()} | :error

  @doc "Read the entry for `code_hash` without consuming it."
  @callback get(code_hash :: binary()) :: {:ok, entry()} | :error

  @optional_callbacks get: 1
end
