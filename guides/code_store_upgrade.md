# Upgrading a custom authorization-code store

A host must implement the complete `Attesto.CodeStore` behaviour. Reuse tracking
and access-token linkage are required. Call `Attesto.CodeStore.validate!/1` to
check callback coverage before serving requests.

| Previous callback or extension | Replacement |
| --- | --- |
| `put/1` | `c:Attesto.CodeStore.put/1`: insert only; never overwrite an existing hash |
| `get/1` | `c:Attesto.CodeStore.read/1`: return explicit state, immutable data, expiry, redemption and one revocation flag |
| `take/1` | `c:Attesto.CodeStore.claim/1`: atomically change live to claimed; return `:ok` or `:error` |
| `mark_consumed/2` | `c:Attesto.CodeStore.finish/2`: atomically record redemption and return concurrent revocation |
| `pending_revoked?/1` | Removed: finish returns one revocation flag in its atomic transition |
| `delete_unconsumed/1` | `c:Attesto.CodeStore.delete_unclaimed/1`: one atomic batch deletes matching live codes and flags matching claimed grants revoked |
| `record_access_token_for_code/3` | Same name, required; link once, preserving any revocation |
| `revoke_access_token_for_code/1` | Same name, required; idempotent, including before linkage |
| `revoke_family_access_tokens/1` | Same name, required; select by the finished redemption's family |
| `access_token_revoked?/1` | Same name, required; read without writes, checking token expiry |
| Ecto's family-based `record_access_token/3` | Removed: use the unique code hash for linkage |

`read/1` returns `{:ok, snapshot}` or `:error`. A snapshot has `:code_hash`,
`:data`, `:expires_at`, `:state`, `:redemption`, and `:revoked`. The states are `:live`, `:claimed`, and `:redeemed`.
`:redemption` is nil until finish, then contains `:family_id`, `:subject`, and
`:replay_retain_until`. Retain the canonical nine-field grant data unchanged;
its family provenance must not become the redemption's family linkage.

Every read is non-writing. Each write is one atomic transition. A failed
claim or replay flag writes nothing; core rereads and compares before taking
further action, at most three rereads before raising a store contract violation. Neither replay flagging nor finishing revokes a refresh family itself.
Finish returns `{:ok, revoked?}`, or
`:error` unless the code was claimed. Core uses this flag to revoke the
linked access token and, for refresh composition, the actual issued family.

Retain claimed codes for at least 300 seconds after claim. Cleanup can then
remove them only after code expiry and when no unexpired access token is linked.
If finish returns `:error`, core revokes the newly issued refresh family and
access-token link and returns `{:error, :invalid_grant}` without tokens.
Retain redeemed rows through code and linked token expiry. An authoritative
bundled refresh table permits cleanup after the last unexpired family member
disappears. Otherwise use the family deadline, retaining indefinitely only when
an external refresh store supplies no deadline. Cleanup must never reopen a
claimed code. SQL transitions lock code rows before refresh-family rows.

Redemption now compares client, redirect URI, PKCE when challenged,
and DPoP when bound in every state, before writing. A refusal leaves all store
state untouched. A verifier presented for a code issued without a challenge fails PKCE comparison.
The client-id opt-out on authorization-code redemption is removed: every
presentation must identify the bound client. Expiry is checked only before claiming a live code. Matching claimed or redeemed
presentations trigger reuse containment even after code expiry. Every endpoint refusal remains `invalid_grant`.

Reuse revocation deliberately departs from the literal wording of RFC 6749
§4.1.2: it requires a matching presentation, so possession of a code alone
cannot revoke another client's tokens.

For the bundled PostgreSQL store, apply the additive
`--upgrade 4.19` migration before rolling nodes; see
attesto_phoenix's migration guide. Old nodes continue to spend failed
presentations and revoke on non-matching replays until the roll completes.
Both sweepers use the same five-minute claim reservation and refresh-family
liveness rules; a missing code is unknown and cannot finish successfully. Original family provenance overwritten by an old writer
cannot be recovered. Custom database stores must likewise retain all previous columns and their
meaning, use one shared atomic claim predicate, and share replay markers and
retention across versions. Add nullable or defaulted columns first; remove old
columns only in a later release after all writers have stopped using them.
The bundled store also writes the previous pending revocation marker, so a
flag conservatively denies an already linked access token during issuance.
