defmodule Attesto.CodeStore do
  @moduledoc """
  Storage seam for authorization codes.

  `Attesto.AuthorizationCode` is pure: it generates a code, hashes it, and
  validates a redemption, but it never decides *where* the code lives.
  That is this behaviour. A host implements it over whatever store fits
  (Postgres, Redis, ETS); `Attesto.CodeStore.ETS` is a ready single-node
  implementation.

  ## The single-use contract (load-bearing)

  `take/1` MUST be atomic: it returns the record for `code_hash` **and
  removes it** in one indivisible step, so two concurrent redemptions of
  the same code cannot both succeed. Authorization codes are single-use
  (RFC 6749 §4.1.2); a store that let `take/1` race would let a captured
  code be replayed. A SQL implementation uses
  `DELETE ... WHERE code_hash = $1 RETURNING ...`; an ETS implementation
  uses `:ets.take/2`.

  The code is consumed by `take/1` even if `Attesto.AuthorizationCode`
  then rejects the redemption (wrong redirect URI, failed PKCE): a code
  that has been presented once is spent, which denies an attacker repeated
  validation attempts against a stolen code.

  ## Optional reuse tracking (additive, fail-safe)

  The single-use contract above stops a code being redeemed twice, but on
  its own it cannot tell a *replay of an already-redeemed code* apart from
  a *never-issued code*: once `take/1` has removed the row, a second
  presentation looks identical to garbage. The OAuth 2.0 Security BCP
  §4.13 (and RFC 6749 §4.1.2) say more: when a code is presented a second
  time the AS SHOULD revoke the tokens already issued from the first
  redemption, because a second presentation is an attack signal (the code
  leaked). Acting on that signal requires remembering which family, if any,
  the first redemption spawned.

  A store MAY opt into this by implementing the OPTIONAL `mark_consumed/2`
  callback and extending `take/1` to return `{:error, :consumed, meta}`
  for a code that was already redeemed. This is purely additive:

    * A store that does NOT implement reuse tracking keeps `take/1`'s
      original `{:ok, entry} | :error` contract. `Attesto.AuthorizationCode`
      treats a re-presented (now absent) code as `:invalid_grant`, exactly
      as before. Single use is unaffected.
    * A store that DOES implement reuse tracking calls `mark_consumed/2`
      when a redemption succeeds, recording the `code_hash` together with
      `meta` (the `family_id`/`subject` for that redemption). The family is
      `nil` for `finalize/3` no-refresh flows and is the exact issued family
      only for `issue_refresh_and_finalize/6`. A later
      `take/1` of the same hash then returns `{:error, :consumed, meta}`,
      and `Attesto.AuthorizationCode.redeem/4` surfaces
      `{:error, {:reuse, meta}}` so the caller can revoke the family.

  Fail-safe means: the absence of reuse tracking never makes the system
  *less* safe than single use already guarantees; it only forgoes the
  extra descendant-revocation signal. A store therefore implements the
  callback only when it can persist the consumed marker durably enough to
  be useful (a single-redemption window is already closed by `take/1`
  whether or not the marker survives).

  ## Record shape

  A stored record is a map with:

    * `:code_hash` - the `Attesto.Secret.hash/1` of the code (the key).
    * `:data` - the opaque grant context the host round-trips
      (client, redirect URI, scope, PKCE challenge, optional DPoP
      thumbprint, subject, and any host claims).
    * `:expires_at` - absolute expiry, unix seconds. The store MAY evict
      expired records, but `Attesto.AuthorizationCode` re-checks expiry
      after `take/1`, so eviction timing is not security-critical.
  """

  @type code_hash :: String.t()

  @typedoc """
  Reuse metadata recorded at the first redemption and replayed to a later
  `take/1` of the same `code_hash`. Opaque to `Attesto.CodeStore`; carried
  through `Attesto.AuthorizationCode.redeem/4` to the caller. Conventionally
  holds `:family_id` and `:subject`; the family is `nil` for a no-refresh
  `finalize/3` marker and non-nil only when the refresh composition captured
  an actually issued family.
  """
  @type consumed_meta :: map()

  @type entry :: %{
          required(:code_hash) => code_hash(),
          required(:data) => map(),
          required(:expires_at) => integer()
        }

  @doc "Persist a code record."
  @callback put(entry()) :: :ok

  @doc """
  Atomically fetch and delete the record for `code_hash`.

  MUST be a single indivisible operation to preserve single use. Returns:

    * `{:ok, record}` - the code existed and was unredeemed; it is now
      removed. This is the primary path every store implements.
    * `:error` - no such code (never issued, expired-and-evicted, or - for
      a store WITHOUT reuse tracking - already redeemed). Treated as
      `:invalid_grant` by `Attesto.AuthorizationCode.redeem/4`.
    * `{:error, :consumed, meta}` - OPTIONAL, only for a store that
      implements `mark_consumed/2`: the code was already successfully
      redeemed once. `meta` is the value passed to `mark_consumed/2` at
      that first redemption (carrying the `family_id`/`subject`, with a nil
      family for no-refresh finalization). This is the code-reuse attack
      signal (OAuth 2.0 Security BCP §4.13); the
      redeemer surfaces it so the caller can revoke descendants.

  A store that does not track reuse never returns the third form, so the
  contract stays `{:ok, entry} | :error` for it and reuse tracking is
  purely additive.
  """
  @callback take(code_hash()) :: {:ok, entry()} | :error | {:error, :consumed, consumed_meta()}

  @doc """
  OPTIONAL. Record that `code_hash` was successfully redeemed and spawned
  the family described by `meta`, so a later `take/1` of the same hash can
  report `{:error, :consumed, meta}`.

  Implemented only by stores that support code-reuse detection (OAuth 2.0
  Security BCP §4.13 / RFC 6749 §4.1.2). `Attesto.AuthorizationCode` calls
  it exactly once, after a redemption fully validates, with `meta` carrying
  that redemption's `:family_id` and `:subject` (or a nil family when
  `finalize/3` is used for a no-refresh flow). A store that does not
  implement this callback simply omits it from the behaviour; the redeemer
  detects its absence (`function_exported?/3`) and skips the call, leaving
  single-use behaviour unchanged.

  Returns `:ok`. The marker SHOULD persist at least as long as the code's
  original lifetime would have remained useful; a store MAY key it by
  `code_hash` alongside the consumed-token bookkeeping it already keeps.
  """
  @callback mark_consumed(code_hash(), consumed_meta()) :: :ok

  @doc """
  OPTIONAL. Read the entry for `code_hash` WITHOUT consuming it (unlike
  `take/1`). Returns `{:ok, entry}` when a code with that hash is stored, else
  `:error`.

  Used for read-only pre-checks at the token endpoint - e.g. surfacing a
  holder-of-key (DPoP) requirement for a sender-constrained code (RFC 9449 §10 /
  FAPI2) before the client-authentication failure, WITHOUT burning the
  single-use code. A store that does not implement it is detected via
  `function_exported?/3` and the pre-check is skipped (single-use behaviour and
  the normal error are unchanged).
  """
  @callback get(code_hash()) :: {:ok, entry()} | :error

  @optional_callbacks mark_consumed: 2, get: 1
end
