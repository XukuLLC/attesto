defmodule Attesto.RefreshStore do
  @moduledoc """
  Storage seam for refresh tokens, with the atomic primitive that makes
  reuse detection possible.

  `Attesto.RefreshToken` is pure rotation logic; this behaviour is where
  refresh tokens live and how they are consumed. `Attesto.RefreshStore.ETS`
  is a ready single-node implementation; a production host implements it
  over its database.

  ## The `rotate/4` contract (load-bearing)

  Refresh-token rotation (RFC 6749 §10.4, OAuth 2.0 Security BCP) requires
  detecting when an *already-rotated* (consumed) token is presented again.
  That can be captured-token reuse, or it can be an immediate retry after the
  client lost the first response. Distinguishing them requires the consumed
  record's timestamp and complete successor state. The parent claim, child
  insert, and retry-state write MUST therefore be one atomic family-level
  transaction. Splitting those mutations lets a simultaneous retry observe a
  consumed parent before its successor exists and can revoke a healthy family.

  It returns:

    * `{:ok, parent, child}` - the parent existed and was unconsumed; the transaction
      atomically marked it consumed, stored its exact successor state, and
      inserted the unconsumed child. Both records are snapshots returned by
      that transaction: `parent` is the committed post-parent and
      MUST carry `consumed: true`, the exact `consumed_at` supplied in
      `opts[:now]`, and successor state logically equal to the argument;
      `child` MUST be the exact newly committed child. Returning both snapshots
      avoids a racy post-commit read after another request has already rotated
      the child.
    * `{:reuse, record}` - the token existed but was **already** consumed.
      The caller MUST apply the same fixed-window successor recovery checks as
      any other consumed-token read. A complete matching retry may receive the
      original successor; otherwise the family is revoked. The record carries
      `consumed_at`, `successor`, and the `family_id` needed for that decision.
    * `{:error, :family_revoked}` - family revocation won the serialization
      race; neither parent nor child was changed by this call.
    * `{:error, :retry_state_unavailable}` - credential-equivalent retry state
      could not be protected before the transaction; no rotation mutation was
      committed.
    * `{:error, :token_conflict}` - the proposed child's random token hash
      already exists; no rotation mutation was committed, so the caller may
      retry with a newly generated child.
    * `{:error, :family_integrity_error}` - a child already occupies the
      proposed `(family_id, generation)`. The store MUST atomically and
      stickily revoke the family before returning this result.
    * `{:error, :invalid_rotation}` - the proposed child or successor state
      violates this contract; no rotation mutation was committed.
    * `{:error, :expired}` - the parent was expired at `opts[:now]`; no
      rotation mutation was committed.
    * `:error` - no such parent token.

  A SQL implementation locks or otherwise serializes the family against
  `revoke_family/1`, locks the parent row, then conditionally updates the
  parent and inserts the child in one transaction. A blocked loser MUST read
  the post-commit parent, including the winner's complete successor state. A
  database transaction without family-level serialization against revocation
  is insufficient: revocation and rotation could otherwise commit a live
  child in a revoked family.

  ## Record contract

  Every adapter MUST enforce these invariants on records it persists and
  returns. The outer fields are:

    * `:token_hash` - the non-empty `Attesto.Secret.hash/1` of the plaintext
      token (the lookup key); plaintext tokens never belong in a record.
    * `:family_id` - a non-empty identifier grouping every descendant, revoked
      together on reuse.
    * `:generation` - a non-negative integer. Initial issuance is exactly
      generation `0`; every child is exactly its parent's generation plus one,
      and each `(family_id, generation)` pair is unique.
    * `:data` - the canonical context below; adapters MUST preserve all keys
      and values exactly through `get/1` and rotation.
    * `:expires_at` - an absolute non-negative Unix-second expiry. A consumed
      parent cannot be used for retry after this boundary, even if its
      persisted successor retry deadline is later; stores may retain the
      expired row for replay detection until that deadline.
    * `:consumed` - a boolean. An unconsumed record has `consumed_at: nil` and
      `successor: nil`; a consumed record has a non-negative integer
      `consumed_at` strictly before `expires_at` and the committed successor
      state.
    * `:successor` - `nil` before rotation, or the complete credential-
      equivalent retry bundle for the immediately issued successor, or the
      non-secret strict-mode tombstone `%{retry_until: now, recoverable: false}`.

  `:data` is a map with exactly these required atom keys (additional host
  claims belong inside `:claims`, not beside these keys):

    * `:subject` - a non-empty string.
    * `:scope` and `:resource` - lists of non-empty strings; either may be
      empty, and rotation may only narrow them.
    * `:client_id` and `:dpop_jkt` - a non-empty client ID or DPoP thumbprint,
      respectively, or `nil` when unbound.
    * `:acr` - a non-empty authentication-context string or `nil`.
    * `:auth_time` - a non-negative Unix second or `nil`.
    * `:claims` - a map of opaque host claims.

  The canonical context is also exposed as `stored_context/0` for adapter
  specifications. A positive-grace successor bundle contains the plaintext
  `:token`, matching child `:generation` and `:context`, and a
  `:retry_until` strictly before the child expiry; persistent adapters MUST
  protect and redact that credential as described below.
  """

  @type token_hash :: String.t()
  @type family_id :: String.t()

  @type stored_context :: %{
          required(:subject) => String.t(),
          required(:scope) => [String.t()],
          required(:resource) => [String.t()],
          required(:client_id) => String.t() | nil,
          required(:dpop_jkt) => String.t() | nil,
          required(:acr) => String.t() | nil,
          required(:auth_time) => non_neg_integer() | nil,
          required(:claims) => map()
        }

  @type entry :: %{
          required(:token_hash) => token_hash(),
          required(:family_id) => family_id(),
          required(:generation) => non_neg_integer(),
          required(:data) => stored_context(),
          required(:expires_at) => integer(),
          required(:consumed) => boolean(),
          optional(:consumed_at) => integer() | nil,
          optional(:successor) => map() | nil
        }

  @doc """
  Persist a new (unconsumed) refresh-token record.

  Returns `{:error, :family_revoked}` if the record's `family_id` has been
  revoked (see `revoke_family/1`), or `{:error, :conflict}` if its token hash
  or `(family_id, generation)` already exists. The row MUST NOT be stored in
  either case. Revocation is sticky - it rejects later inserts, not just the
  rows present at revoke time.
  """
  @callback insert(entry()) :: :ok | {:error, :family_revoked | :conflict}

  @doc """
  Non-consuming read of the record for `token_hash`, or `:error` if
  absent. Used to validate a rotation (expiry, DPoP binding) and to detect
  a replayed already-consumed token BEFORE the atomic `rotate/4` transition
  it, so a recoverable validation failure does not burn the token.

  Reads MUST be linearizable with `rotate/4` and `revoke_family/1`, including
  read-your-writes immediately after a successful rotation. Do not serve this
  callback from an eventually consistent replica: stale child or parent state
  can turn a valid retry into family revocation or incorrectly treat an
  already-consumed successor as live.
  """
  @callback get(token_hash()) :: {:ok, entry()} | :error

  @doc """
  Atomically rotate a parent into one child, serialized against family
  revocation. `child` MUST be an unconsumed record in the same family at
  `parent.generation + 1`, with its final hash, canonical `data` context, and
  expiry. `successor`
  is either the complete retry bundle (`:token`, `:generation`, `:context`,
  `:retry_until`) or `%{retry_until: now, recoverable: false}` for strict mode.

  A complete retry bundle contains a live plaintext credential. Persistent
  stores MUST protect it with authenticated encryption at rest using stable
  key material available to every serving node and deployment through the
  retry deadline. It MUST be bound against tampering to the parent/family,
  generation, context, and deadline; it MUST never be logged; and it MUST be
  irreversibly redacted promptly after the deadline.

  Any child insert, retry-state protection, constraint, or write failure MUST
  roll back the entire transition. Success means the complete transaction is
  durably committed. A timeout or callback exception has ambiguous commit
  status, so callers will fail closed and attempt family revocation.
  """
  @callback rotate(token_hash(), child :: entry(), successor :: map(), keyword()) ::
              {:ok, parent :: entry(), child :: entry()}
              | {:reuse, entry()}
              | {:error,
                 :family_revoked
                 | :retry_state_unavailable
                 | :token_conflict
                 | :family_integrity_error
                 | :invalid_rotation
                 | :expired}
              | :error

  @doc """
  Revoke a token family: remove every token in `family_id` AND mark the
  family revoked so a subsequent `insert/1` for it is refused (sticky
  revocation; see `insert/1`). The marker MUST remain effective for the
  lifetime of the store, including after every token row has expired; clearing
  it can resurrect an imported or long-lived family. An implementation with a
  host-configured retention bound MUST fail closed after that bound rather
  than accept a later insert for the family. Idempotent - revoking an
  already-revoked or unknown family is a no-op `:ok`.
  """
  @callback revoke_family(family_id()) :: :ok
end
