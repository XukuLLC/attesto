# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.14.0] - 2026-08-12

SIOPv2 DID Subject Syntax support for connection-free DID methods. Self-issued
ID Tokens can now bind their subject and signature directly to a `did:jwk` or
`did:key` verification method without an issuer JWKS or network resolution.

### Added

- `Attesto.Siop.verify/2` now supports SIOPv2 Decentralized Identifier Subject
  Syntax for connection-free `did:jwk` and `did:key` subjects. Verification
  requires the method-defined protected `kid`, rejects a simultaneous
  `sub_jwk`, resolves the holder public key locally, enforces the JWK's
  signature usage and algorithm metadata, verifies the signature, and requires
  `iss == sub`. Network-backed and unsupported DID methods continue to fail
  closed.

## [1.13.0] - 2026-08-11

Hardening of the ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`)
assertion verifier. Pairs with `attesto_phoenix` 2.12.0, which enforces the
signed `resource` and `cnf.jkt` constraints at the token endpoint; that
package now requires this release (`>= 1.13.0`).

### Security

- ID-JAG verification now validates a present `scope`, `resource`, and `cnf`
  instead of allowing a malformed optional authorization constraint to be
  treated as absent. A signed constraint that could not be parsed previously
  degraded to "absent", erasing the IdP's ceiling; it now fails closed. An
  empty `scope` is rejected rather than read as an unbounded one.
- **Mixed confirmation methods are rejected.** A `cnf` carrying `jkt`
  alongside any other member (for example an `x5t#S256` certificate
  thumbprint) previously matched on `jkt` alone, silently dropping the second
  constraint — an IdP that required both DPoP *and* mTLS possession got an
  assertion enforced as DPoP-only. Only a single-member `cnf.jkt` is accepted.
- `jti` is bounded (256 bytes) before it can reach a host replay store, so
  unbounded IdP-controlled input never becomes a store key.

### Changed

- **Potentially breaking**: an ID-JAG carrying `authorization_details`
  (RFC 9396) is now rejected with `:invalid_claims`. This verifier has no
  policy engine for their typed constraints, and ignoring a signed constraint
  would silently promote a narrowly-scoped assertion to broader scope-only
  authority. Fail closed until the constraints can be enforced end to end.
  Trusted IdPs that mint ID-JAGs including `authorization_details` must stop
  doing so, or pin `attesto ~> 1.12.2` until they can.
- An RFC 7800 confirmation claim using a method other than DPoP `jkt` is
  likewise rejected rather than treated as an unbound (bearer) assertion.

## [1.12.2] - 2026-08-11

Second-round hardening from a review-of-the-fixes pass, a dedicated sweep of the
shared crypto/infra primitives (never a prior review front), and fuzzing of the
SD-JWT / mdoc / status-list parsers. mdoc and status-list parsing came through
fuzzing fully clean.

### Security

- **`Attesto.Did` did:jwk DoS**: `resolve/2` now rejects an oversized
  presenter-controlled RSA key on the raw map (via `SigningAlg.rsa_params_ok?`)
  BEFORE `JOSE.JWK.from_map/1` bignum-decodes it — a ~256 KB modulus previously
  pinned a scheduler for ~3s per unauthenticated request. (did:jwk resolution is
  not yet wired to an HTTP endpoint, so this was latent.)
- **`Attesto.SdJwtVc.issue/2` registered-claim integrity**: subject claims are
  string-keyed before merging the registered claims, so an atom-keyed collision
  (e.g. `claims: %{cnf: ...}`) can no longer emit a duplicate JSON member and let
  a last-wins verifier bind to the wrong holder key. Matches `Attesto.JwtVc`.
### Fixed

- `Attesto.SdJwt.verify/3` and `Attesto.CredentialProof.verify_jwt/2` now fail
  closed (`{:error, _}`) on a malformed host-supplied `jwks` / `accepted_algs`
  (nil, non-list) instead of raising, honoring their documented contract
  (found by fuzzing).
- `Attesto.Store.ETS` `:direct` reset now clears every table the store owns, not
  just the primary — a store adding `extra_tables:` on the default reset mode
  would previously leave those rows intact.

### Documentation

- `Attesto.Did` did:web resolver: explicit SSRF warning (the fetch URL is
  presenter-controlled — allow-list before dereferencing).
- `Attesto.Mdoc`: clarified that document-type binding requires
  `:expected_doc_type` (threaded via `Attesto.VpToken`'s `:query_constraints`).

## [1.12.1] - 2026-08-10

### Fixed

- `Attesto.PreAuthorizedCodeStore.ETS.reset/0` (test-facing) now routes through
  the owner process (`reset: :server`), so it works on the `:protected` table
  introduced in 1.12.0. In 1.12.0 the macro-provided direct
  `:ets.delete_all_objects/1` raised `insufficient access rights` when a
  downstream test suite called `reset/0`. Production is unaffected (reset is
  test-only).

## [1.12.0] - 2026-08-10

Wallet-surface security-hardening release from a 6-front adversarial sweep of
the EU-wallet code (SD-JWT/SD-JWT VC, mdoc/COSE, OID4VP verifier, OID4VCI
issuer, OpenID Federation/DID/SIOPv2/attestation) plus an ecosystem-CVE and
per-spec security-considerations cross-check. The cryptographic surface was
found solid; the fixes close policy-enforcement gaps.

### Security

- **Status List Token freshness**: `Attesto.StatusList.verify/3` now rejects an
  expired token (`exp` present and past, 60s clock-skew leeway). `exp` remains
  optional per draft-ietf-oauth-status-list §11.5, so a no-exp token does not
  expire. Previously a stale/expired list verified indefinitely, letting a
  revoked credential read VALID.
- **SD-JWT VC registered claims**: `Attesto.SdJwtVc.issue/2` never makes
  registered claims (`iss`/`vct`/`cnf`/`status`/`iat`/`exp`/`nbf`/`sub`)
  selectively disclosable, closing a holder-binding / revocation-reference strip
  where a holder could remove `cnf` and present as a bearer credential.
- **SD-JWT disclosure DoS**: `Attesto.SdJwt` caps presentation byte-length and
  disclosure count before any base64/JSON decode work.
- **Pre-authorized code store isolation**: the reference ETS store now uses a
  `:protected` table (owner-only writes, single-use `take` preserved), matching
  the credential-offer store, so a co-resident BEAM process cannot forge a
  redeemable grant.
- **OpenID Federation trust marks**: added `Attesto.Federation.TrustMark.verify/3`
  for real signature/`iss`/`sub`/`typ`/`exp` verification;
  `validate_trust_marks/1` is documented as structural-only.

### Fixed

- `Attesto.PresentationSession` `create_attrs` type now lists `:query_constraints`
  (a latent dialyzer contract mismatch for `attesto_phoenix`).

## [1.11.0] - 2026-08-10

Second security-hardening release, from two further adversarial audit rounds
(under-covered flows + implementation-level classes) and three cross-model code
reviews. Focused on denial-of-service resource-exhaustion classes and OID4VP
verification correctness.

### Security

- **RSA verification-key parameter bounds (DoS).** `Attesto.SigningAlg.rsa_params_ok?/1`
  rejects an RSA verification key whose modulus exceeds 8192 bits or whose public
  exponent is not an odd integer in `3..65537`, evaluated on the RAW base64url
  `n`/`e` before any bignum decode. Without it, an attacker-supplied key with a
  multi-hundred-KB exponent pins a scheduler in `modexp` for seconds. Wired at
  every gate that admits an untrusted key: `Attesto.Key.verification_jwk/2`,
  `Attesto.JWS.verification_candidates/2` (via `map_candidate!`), the SD-JWT
  holder Key Binding path (`Attesto.SdJwt`), and `Attesto.JwtVc`'s `cnf` parse.
- **OID4VP format binding + query-ID requirement.** `Attesto.VpToken.verify/2`
  now (a) binds each presentation to the DCQL-requested *format* — a validly
  signed `dc+sd-jwt` credential can no longer satisfy an `mso_mdoc` query
  (`:format_mismatch`) — and (b) treats every query id that carries a constraint
  as required, so a wallet cannot return a credential under a different id to
  dodge the type/claim binding. `constraints_from_dcql/1` accepts atom- or
  string-keyed queries. (Completes the DCQL binding introduced in 1.10.0.)
- **Token Status List decompression-bomb bound.** `Attesto.StatusList` inflates
  the status bitstring through a capped `:zlib.safeInflate` loop (16 MiB ceiling,
  `:status_list_too_large`) instead of `:zlib.uncompress/1`, so a signed zlib
  bomb from a compromised status issuer cannot expand to gigabytes.
- **CBOR/mdoc parse-amplification bound.** `Attesto.Mdoc` and `Attesto.Cose`
  reject CBOR input over 1 MiB before decoding, bounding the deep-nesting
  amplification the decoder would otherwise turn into heap ahead of any signature
  check.
- **Nonce single-use + store ceilings.** `Attesto.CNonceStore` gains a required
  atomic `consume/1` (single-use OID4VCI c_nonces; see attesto_phoenix). The
  `Attesto.CNonceStore.ETS` and `Attesto.DPoP.NonceStore.ETS` stores bound table
  growth from their unauthenticated endpoints with an O(1) best-effort ceiling.

### Changed (breaking)

- `Attesto.CNonceStore` requires the `consume/1` callback. The bundled ETS store
  implements it; custom stores must add it (a store that cannot single-use a
  nonce must not be used for issuance).
- `Attesto.VpToken.verify/2`: a query id present in `:query_constraints` is now
  required in the response even if absent from `:expected_query_ids`.

## [1.10.0] - 2026-08-10

Security-hardening release from an adversarial audit against four public
vulnerability classes (broken tenant/authorization isolation, `alg:none` /
decrypt-then-verify signature bypass, DPoP session theft, and unbounded-batch
DoS). The audit found the JWT-verification and DPoP surfaces already
fail-closed; the fixes below close authorization-isolation seams and add
defense-in-depth.

### Security

- **Credential-offer id is now generated by the library.**
  `Attesto.CredentialOffer.store_by_reference/3` mints the by-reference offer id
  with a 256-bit CSPRNG (`Attesto.Secret.generate/0`) and stores it, so a host
  can no longer supply a guessable id. The by-reference offer endpoint is
  unauthenticated and a pre-authorized offer embeds a redeemable
  `pre-authorized_code`, so a weak id let an attacker enumerate the endpoint and
  redeem a victim's code. Use this instead of calling the store's `put/1` with a
  self-chosen id. `:ttl` is validated (a positive integer <= 3600 s).
- **OID4VP verified results are single-use.**
  `Attesto.PresentationSession.result/2` now reads the completed result through
  the store's `take/1` and clears it, and the reference store's `get/1` no
  longer returns the result payload at all. The OID4VP `response_code` handed to
  the browser is the session id and transits the address bar, history,
  `Referer`, and logs; reading results once means a captured `response_code` can
  no longer be replayed to re-read the presented claims.
- **Credential Request `proofs` are bounded.**
  `Attesto.CredentialRequest.parse/2` caps the total proofs per request (default
  50, override with `:max_proofs`; validated to a non-negative integer) and
  rejects an over-cap request with `{:error, :too_many_proofs}` before any
  signature is verified, closing an authenticated proof-verification
  amplification-DoS.
- **Key-attestation signer strength parity.** `Attesto.KeyAttestation.verify/2`
  now applies the FAPI RSA-modulus / Edwards-curve strength policy to the
  attestation signer (via `:enforce_fapi_alg_policy`), matching
  `Attesto.ClientAssertion` and `Attesto.WalletAttestation`.
- **Reference stores hardened to `:protected` ETS.** The presentation-session
  and credential-offer ETS tables (which hold plaintext session data / redeemable
  codes) drop `:public`, so a co-resident BEAM process can no longer directly
  `:ets.insert/2` to overwrite a verified result, bypass the atomic
  `pending -> completed` guard, or inject a forged offer.
- **Introspection multi-tenant guidance.** Documented that any deployment where
  more than one client can authenticate to introspection MUST set
  `:introspection_authorize` (without it, one client can introspect another's
  token). No behavior change.

### Changed (breaking)

- `Attesto.PresentationSession.result/2` is now single-use: it consumes the
  completed session, and a second read (or a read of a still-pending/expired
  session) returns `:error`. Hosts that read the result more than once must read
  it once and cache their own outcome.
- `Attesto.PresentationSessionStore` requires the `take/1` callback (moved out of
  `@optional_callbacks`), and `get/1` MUST NOT return a completed session's
  `data.result`. Custom store implementations must provide `take/1`; the bundled
  `Attesto.PresentationSessionStore.ETS` is unaffected.

## [1.9.0] - 2026-08-05

### Added

- **A third redirect-URI matching mode,
  `:exact_allow_loopback_port_including_localhost`**, which applies the RFC 8252
  §7.3 port allowance to the bare hostname `localhost` as well as the
  `127.0.0.1` / `[::1]` literals.

  Native clients exist that register a portless `http://localhost/callback` in
  their client-id metadata document and then bind an ephemeral port. Under
  `:exact_allow_loopback_port` every such request fails
  `redirect_uri_not_registered`: exact comparison fails on the port, and the
  §7.3 exception does not cover the name. Claude Code is one such client, so no
  Attesto deployment could serve it over the loopback flow.

  The literal-IP-only reading remains correct and remains the behavior of
  `:exact_allow_loopback_port` — §7.3's MUST is scoped to "loopback IP redirect
  URIs", and 1.4.1's reconciliation of RFC 9700's wider wording still stands.
  What this adds is the observation that nothing *forbids* a server allowing the
  name, and that §8.3's case against `localhost` is stated entirely in terms of
  what the client does (which interface it binds, its firewall, its host-name
  resolution) — none of which a server changes by refusing the request. The
  residual risk is the combination of two allowances the module already makes
  separately: a registered `localhost` URI is already reachable by exact match,
  and §7.3 port flexibility is already mandated for the IP literals. Permitting
  only that combination is why this is a separate opt-in rather than a change to
  the existing mode.

  **No behavior change unless selected.** `:exact` and
  `:exact_allow_loopback_port` are byte-for-byte as before — `localhost` still
  gets no port flexibility under either, and the existing test asserting that is
  unchanged. `localhost` is a distinct host identity from the IP literals and
  never cross-matches them, and every other constraint is preserved: byte-exact
  `http://` scheme, anchored authority (`localhost.evil.example`,
  `sub.localhost`, `evil-localhost`, `localhost.` and userinfo all stay
  outside), no fragment, exact path and query, and the asymmetric request /
  registered port rule.
## [1.8.1] - 2026-08-03

### Fixed

- **Clean compile for consumers without the optional `:cbor` dependency.**
  `Attesto.VpToken`'s mdoc verification path pattern-matched on `Attesto.Mdoc`,
  which compiles to a raising stub when `:cbor` is absent. Under Elixir 1.19+'s
  set-theoretic type checker the stub types as `none()`, so those clauses were
  reported as unreachable — a warning that surfaced for any downstream app (e.g.
  a Livebook `Mix.install`) that didn't pull `:cbor`. The mdoc verification
  cluster is now gated behind `Code.ensure_loaded?(CBOR)`: with `:cbor` present
  the behavior is unchanged; without it, an mdoc presentation fails closed with
  `{:error, {id, :mdoc_unsupported}}` and SD-JWT VC / `jwt_vc_json` verification
  is unaffected. A dedicated CI job now compiles the library with no optional
  deps present and fails on any such warning.

## [1.8.0] - 2026-08-03

### Added

- **OpenID for Verifiable Credentials (OID4VC / EU digital identity)** — the
  conn-free core of the issuer and verifier roles, targeting the HAIP profile.
  Issue and verify **IETF SD-JWT VC** (`Attesto.SdJwt` / `Attesto.SdJwtVc`),
  **ISO 18013-5 mdoc** (`Attesto.Mdoc`, CBOR + COSE_Sign1), and W3C
  `jwt_vc_json` (`Attesto.JwtVc`), all with holder key binding. OID4VCI issuance
  primitives (`Attesto.CredentialOffer`, `CredentialRequest`, `CredentialResponse`,
  `CredentialProof`, `CredentialIssuerMetadata`, `WalletAttestation`,
  `KeyAttestation`) and OID4VP presentation primitives (`Attesto.PresentationRequest`,
  `VpToken`, `PresentationSession` + store) including DCQL, `direct_post` /
  encrypted `direct_post.jwt` with a per-request ephemeral response-encryption
  key, and the x509 `client_id` schemes. Plus `Attesto.StatusList` (IETF Token
  Status List), `Attesto.Siop` (SIOPv2 Self-Issued ID Token verification for the
  RP role, with `sub_jwk` self-signature, RFC 7638 subject binding, and
  fail-closed nonce/`exp`/`iat`/`nbf` checks), and OpenID Federation support.
- Signed Credential Issuer Metadata (`CredentialIssuerMetadata.signed/2`), the
  `x5c` header and `dc+sd-jwt` typ for SD-JWT VC issuance, and the response-
  encryption-key binding threaded into mdoc `direct_post.jwt` verification —
  the interoperability details exercised while driving the OIDF OID4VCI/OID4VP
  conformance suites green.

## [1.7.0] - 2026-08-02

### Security

- DPoP replay identities are now namespaced by the proof key. `jti` uniqueness
  is only guaranteed per key (RFC 9449 §4.2), so recording the raw `jti` let two
  keys sharing a `jti` collide in the replay store — a cross-client false replay
  and a targeted DoS in which an authenticated attacker pre-burns a victim's
  `jti` under the attacker's own key. `Attesto.DPoP.verify_proof/2` now returns
  `replay_key`, a fixed-length digest of `jkt:jti`, and every replay path (the
  plug, the token endpoint, PAR, device authorization) records THAT.

  **Upgrade note:** the recorded identity's format changed (raw `jti` →
  digest). During a rolling upgrade, old and new nodes write different formats
  to a shared replay store, so a single proof could be accepted once on each
  side within its acceptance window (`max_age + skew`, default ~120s). Drain old
  nodes and wait out one proof lifetime, or briefly stop the world, to close
  that window. A fresh deployment is unaffected.

- A batch of fail-closed / correctness fixes found by a full-surface adversarial
  sweep and two rounds of external review:
  - `Attesto.DPoP` replay TTL now retains the `jti` one second past the
    inclusive freshness boundary, closing a sub-second edge-of-life replay gap.
  - `Attesto.IdentityAssertion` rejects a present non-integer `nbf` instead of
    treating it as absent (`:invalid_claims`).
  - `Attesto.RequestObject` parameter coercion is total: a request-object claim
    that is a list with a non-string member is dropped rather than raising.
  - CIBA signed authentication requests reject an authorization-endpoint
    request object (`typ: oauth-authz-req+jwt`); `typ` comparison follows
    RFC 7515 §4.1.9 for the `application/` prefix.
  - `Attesto.JARM` reserved claims (`iss`/`aud`/`iat`/`exp`) can no longer be
    shadowed by a caller's atom- or charlist-keyed duplicate.
  - `Attesto.SessionState` rejects an OP browser-state secret under 32 bytes and
    a `session_state` salt containing a space or `.`, and serializes the browser
    origin closer to the WHATWG form (lowercase scheme/host, bracketed IPv6).

### Changed

- The `:replay_check` callback and `verify_proof/2`'s `replay_key` carry an
  OPAQUE replay identity (a digest), not the raw `jti`; do not parse it. The
  `[:attesto, :dpop, :replay_detected]` telemetry still carries the raw client
  `jti` for correlation.

- `Attesto.Scope.grants_all?/3` is now linear in the requested-scope count.
  It previously rescanned the granted set and re-split resource wildcards for
  every (required, granted) pair, so a large caller-supplied `scope` value - on
  which RFC 6749 §3.3 places no bound - was a denial-of-service lever: 500,000
  scope tokens took ~20 seconds. Classifying the granted set once and testing
  each required scope against that index in O(1) drops the same input to ~40ms.
  For every proper-list input (the typespec's contract) the result is identical
  to the naive form, pinned by a generated property test; an improper list now
  raises rather than short-circuiting, a louder failure on a value the contract
  already forbids. Surfaced by mining the class behind Keycloak CVE-2026-4634.

## [1.6.0] - 2026-08-01

### Security

- Claim a DPoP proof's `jti` only after the access token has verified.
  `Attesto.Plug.Authenticate` ran `:replay_check` during proof validation, two
  steps before `verify_token`. That callback is check-AND-record — the default
  claims the identifier with `:ets.insert_new/2` in the same step that tests it
  — so an unauthenticated caller wrote a row on every request. A DPoP proof is
  signed by a key the caller generated, so anyone can mint a valid one, pair it
  with any string in the `Authorization` header, and grow an unbounded ETS table
  for the cost of a signature.

  The guarantee is unchanged: the claim still happens before the request is
  served, it is still the same atomic check-and-record, and a replayed `jti` on
  an otherwise-valid request is still refused (RFC 9449 §11.1).

  The authorization-server path needed the same fix, in `attesto_phoenix` — an
  earlier draft of this entry claimed it did not, on the grounds that
  `%Request{}` carries an authenticated client. That is false for a **public
  client** (RFC 6749 §2.1), which presents a `client_id` and no credential, so
  the same unauthenticated write was reachable at the token endpoint. See that
  package's changelog.

- `Attesto.SecureCompare.equal?/2` no longer short-circuits on a length
  mismatch. Both operands are hashed to 32 bytes and those digests are
  compared, so the comparison no longer separates "wrong length" from "right
  length, wrong bytes" — the distinction an attacker probes with. A matching
  pair does one extra byte comparison to rule out a digest collision; that
  branch separates right from wrong, which the answer already reveals.

  `Attesto.PKCE.verify/3` was never exposed - it gates on
  `Attesto.Thumbprint.valid?/1`, which requires an exact byte size - but
  `Attesto.DPoP`'s `ath` comparison takes an arbitrary-length value straight
  from the presented proof, so it was, and it is the caller this most benefits.

  Note what the change does and does not buy: the comparison no longer reveals
  HOW the operands differ, but hashing reads every byte, so its duration still
  depends on their total size.

### Added

- `Attesto.Telemetry` — `:telemetry` events for the refusals that mean someone
  holds a credential they should not:

  | Event | Fires when |
  |---|---|
  | `[:attesto, :refresh_token, :reuse_detected]` | a rotated token is presented again; the family has been revoked |
  | `[:attesto, :dpop, :replay_detected]` | a proof carries an already-recorded `jti` |
  | `[:attesto, :token, :sender_constraint_mismatch]` | a sender-bound token is presented with the wrong proof of possession |

  Previously these returned an atom and nothing else, so a host that wanted to
  alert had to wrap every call site. Metadata carries correlation handles
  (`family_id`, `client_id`, `subject`, `jti`, `binding`, `reason`). No
  credential or digest of one is ever copied into an event, but some handles are
  read out of credentials - `jti` from the proof, `client_id` from the token -
  and `jti` is the client's to choose, so a handler should treat metadata as
  untrusted input. The events are indicators to correlate, not proof of theft. Ordinary failures — expired,
  unknown client, wrong scope — are deliberately not events. Event names and
  metadata keys are public API; see the module docs.

  Adds `:telemetry` as a dependency.

- `Attesto.DPoP.verify_proof/2` now reports the `replay_ttl` it derived, so a
  caller claiming the `jti` itself uses that verification's own acceptance
  window rather than re-deriving the formula.

### Documentation

- `Attesto.DPoP.ReplayCache` now names `AttestoPhoenix.Store.EctoReplayCheck` as
  the shared-store implementation to use on a multi-node deployment. It
  previously described one in the abstract ("e.g. a Postgres-backed cache"),
  which read as an instruction to go and build something the family already
  ships.

## [1.5.0] - 2026-07-28

### Security

- Reject a Client ID Metadata Document whose `redirect_uris` contain a URI that
  RFC 3986 and the WHATWG URL Standard read differently
  (`{:error, :invalid_redirect_uris}`).

  A CIMD document is fetched from a URL the client itself chose, so its
  `redirect_uris` are supplied by the client in a way a host-registered set is
  not. Elixir's `URI` follows RFC 3986 while the browser that receives the
  `Location` follows WHATWG, and the two disagree about some authorities: in
  `https://evil.example\@client.example/cb`, RFC 3986 reads `evil.example\` as
  userinfo and `client.example` as the host, while WHATWG treats the backslash
  as a path separator and navigates to `evil.example`.

  Any check phrased in terms of a *host* or an *origin* — the CIMD draft's
  same-origin tightening, a deployment's origin allow-list — is decided with the
  first parser and enforced by the second, so such a URI could pass the check
  and still send the authorization response off-origin. Refusing the document
  keeps the URI out of the registered set those checks ever run against.

  Byte-exact matching (RFC 6749 §3.1.2.3) was never affected: it compares
  strings, not origins. The RFC 8252 §7.3 loopback exception was never affected
  either, because it anchors on the whole authority rather than the parsed host
  — `http://evil.example\@127.0.0.1/cb` was already refused.

### Added

- `Attesto.RedirectURI.unambiguous?/1`, the predicate behind the above: whether
  every URL parser agrees which origin a URI names. It refuses backslashes,
  userinfo, and C0 controls/whitespace anywhere in the URI. Exposed so a host
  applying its own origin-level policy to a redirect URI can gate on the same
  rule.

  This governs what may be *registered*; it is not a matching mode and does not
  change what `registered?/3` accepts.

### Changed

- The WHATWG parity suite now pins a second invariant alongside the loopback
  one: for every URI `unambiguous?/1` admits, the host RFC 3986 reads and the
  host WHATWG reads are the same string.

## [1.4.1] - 2026-07-28

### Documentation

- Reconcile RFC 9700's wording of the loopback exception with the rule
  `Attesto.RedirectURI` actually implements. RFC 9700 §2.1 and §4.1.3 phrase it
  as applying to "`localhost` redirection URIs of native apps", which reads
  wider than this module's literal-IP-only rule and could be mistaken for a
  conformance gap. Both texts define the exception by reference — "as described
  in Section 7.3 of [RFC8252]" — and §7.3 constructs the URI from the loopback
  IP literal, not the name, so `localhost` there is shorthand for "the loopback
  interface" and §7.3's construction is the normative content.

  No behavior change: 1.4.0 already implements exactly this. A `localhost`
  redirect URI still matches exactly; it just gets no port flexibility.

- State in the README's RFC table where the §7.3 opt-in lives — the core
  defaults to exact RFC 6749 §3.1.2.3 matching and the caller selects
  `:exact_allow_loopback_port` per request — rather than the vaguer "opt-in,
  off by default".

## [1.4.0] - 2026-07-28

### Added

- RFC 8252 §7.3 loopback interface redirection, as an opt-in redirect-URI
  matching mode. `Attesto.AuthorizationRequest.validate/2` accepts
  `:redirect_uri_matching`, which is `:exact` (the RFC 6749 §3.1.2.3 simple
  string comparison) unless a host selects `:exact_allow_loopback_port`. Under
  the exception a native app's loopback redirect URI matches on any port, so an
  ephemeral port bound at runtime need not be registered ahead of time, while
  scheme, host, path, and query still compare exactly. The relaxation is scoped
  to `http://127.0.0.1/...` and `http://[::1]/...`; RFC 8252 §8.3 makes
  `http://localhost/...` unacceptable, and `https`, private-use schemes, and
  every remote host stay exact-match. An unmatched redirect URI is still
  classified `{:direct, :redirect_uri_not_registered}` and is never used as a
  redirect target. The new matching logic lives in `Attesto.RedirectURI`.

  The two sides of the comparison differ in one respect: a port on the
  **request** URI must be decimal `1..65535` or absent, since it names an
  endpoint a browser is about to be redirected to, while the **registered**
  URI's port is discarded and so may be anything — including the conventional
  `:0` placeholder.

  Defaults are unchanged: without the option, redirect matching is
  byte-identical to previous releases. Enabling the exception is incompatible
  with profiles that mandate exact redirect-URI matching, so it must be a
  deliberate deployment decision. Redemption-time `redirect_uri` comparison in
  `Attesto.AuthorizationCode` is unaffected — the code is bound to the URI the
  client actually presented, ephemeral port included, and still matches exactly.

## [1.3.0] - 2026-07-25

### Changed

- Admit compatible JOSE releases through the 1.x line while retaining 1.11.12
  as the minimum security- and runtime-compatible version. This lets hosts use
  newer native cryptographic adapters without another Attesto release.

### Fixed

- Derive OIDC `at_hash` and `c_hash` claims for Ed25519-signed ID Tokens with
  SHA-512 and Ed448-signed ID Tokens with SHAKE256, matching their signature
  primitives and interoperable OIDC validators. Previously EdDSA used SHA-256
  unconditionally, contrary to OIDC's generic hash rule when applied to RFC
  8032. ID Token and logout-token minting now snapshot the signing PEM once so
  algorithm, curve-specific hash, `kid`, and signature cannot straddle a
  keystore rotation. Algorithm selection remains bound to trusted keystore
  metadata and key material; Ed448 uses JOSE's configured Curve448 and SHA3
  backends. The ambiguous keyless `hash_alg/1` and `hash_half_bytes/1` helpers
  remain Ed25519-compatible but are deprecated in favor of key-aware
  `oidc_hash_profile/2` and `oidc_hash/3`. A missing SHAKE256 backend now raises
  a direct configuration error.
- Support RFC 9864's exact `Ed25519` and `Ed448` JOSE identifiers in trusted
  key metadata, signing, verification, ID Token hash profiles, and DPoP while
  retaining legacy `EdDSA` inference for wire compatibility. DPoP discovery
  advertises the new identifiers only when the configured JOSE backend reports
  them available. Default FAPI client-assertion, signed-request-object, and
  CIBA policies accept EdDSA only over a trusted Ed25519 key and accept exact
  Ed25519, never Ed448, and require PS256 RSA moduli to be at least 2048 bits;
  an explicit non-FAPI allowlist can opt into Ed448 or a weaker RSA key, while
  named FAPI policies retain the key gate when their algorithm list is
  narrowed. DPoP rejects RSA proof keys with moduli below 2048 bits for every
  accepted RSASSA and RSA-PSS proof algorithm. FAPI server keystores must also
  provision RSA keys of at least 2048 bits; generic keystore resolution remains
  profile-neutral for backward compatibility.

### Documentation

- Correct the token, ID Token, logout-token, and keystore documentation to
  describe Attesto's existing multi-algorithm support. Signing and verification
  bind RS256, PS256, ES256, ES384, ES512, legacy EdDSA, Ed25519, or Ed448 to
  trusted keystore metadata or the key type and curve; verification never
  learns algorithm policy from a presented JWS header.

## [1.2.5] - 2026-07-17

### Fixed

- Require JOSE 1.11.12 or later on the 1.11 release line. JOSE 1.11.9 and
  1.11.10 cannot encode or decode EC private keys on OTP 28 after OTP changed
  the `ECPrivateKey` version representation. JOSE 1.11.11 fixed EC handling but
  introduced a builtin-JSON regression that encoded Elixir `nil` as the string
  `"nil"`; 1.11.12 is the first release to include both fixes. Attesto's public
  API and runtime policy are unchanged.

## [1.2.4] - 2026-07-16

### Security

- Require JOSE 1.11.9 or later on the 1.11 release line. This excludes releases
  affected by the PBES2 iteration-count denial of service and avoids the
  unintended runtime Dialyxir dependency published in JOSE 1.11.7 and 1.11.8.

## [1.2.3] - 2026-07-16

### Security

- Constrain the optional Plug dependency to advisory-safe patch lines while
  retaining compatibility across Plug 1.16 through 1.20. This prevents package
  resolution from selecting affected releases between otherwise-safe lower and
  upper bounds; Attesto's runtime behavior is unchanged.

## [1.2.2] - 2026-07-16

### Fixed

- Token verification, RFC 7662 introspection, and protected-resource Plug
  authentication can now validate access tokens against an explicit, trusted
  set of RFC 8707 resource audiences without disabling audience checks. The
  Plug policy is configured per protected resource. Scalar audiences must occur
  in the configured set; every member of an array audience must be trusted. The
  default verifier behavior remains unchanged when no trusted set is supplied,
  and malformed policy fails closed.

### Security

- Raise the optional Plug dependency floor to 1.19.5, excluding releases with
  published multipart temp-file exhaustion, nested-parameter quadratic-time
  denial-of-service, and cookie attribute-injection advisories.

## [1.2.1] - 2026-07-08

### Fixed

- `Attesto.Keystore.Static` now labels the signing key's own `kid` with the
  configured `:signing_alg`, so a keystore that signs `PS256` (or any alg other
  than the one inferred from the key type) with a single key no longer needs a
  redundant `:key_algs` entry to verify its **own** tokens. Previously, setting
  `signing_alg: "PS256"` on an RSA key without a matching `:key_algs` map made
  verification infer `RS256` from the key and reject the server's own tokens as
  `:invalid_signature`. An explicit `:key_algs` entry for that `kid` still wins.

## [1.2.0] - 2026-07-08

### Changed

- `Attesto.Config` now raises a **guiding** error when the `:issuer` is not an
  `https` URL (RFC 8414 §2). Instead of a bare rejection, the message points
  developers at [mkcert](https://github.com/FiloSottile/mkcert) to serve a
  locally-trusted certificate so the issuer stays `https` — local development
  never needs to downgrade to plain http. There is deliberately no
  https-disable switch in the library.

## [1.1.0] - 2026-07-07

### Added

- **OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core
  1.0).** New `Attesto.CIBA` primitive - the device grant's async sibling:
  `Attesto.CIBA.Request.validate/3` runs the §7.1 backchannel authentication
  request rules (scope-with-`openid`, exactly-one-hint, ping/push
  `client_notification_token` entropy/length/charset, `binding_message` /
  `user_code` / `requested_expiry` shape) and verifies §7.1.1 **signed
  authentication requests** against the client's registered JWKS (all six
  REQUIRED claims enforced; FAPI-CIBA's 60-minute lifetime bound by default);
  `issue/4` mints a 256-bit `auth_req_id` (only its hash is stored) with the
  §7.3 acknowledgement fields; `approve/4` / `deny/3` record the user's
  decision atomically and return the ping-mode §10.2 notification data;
  `redeem/4` runs the token-endpoint state machine with the exact §11
  vocabulary (`authorization_pending` / `slow_down` / `expired_token` /
  `access_denied` / `invalid_grant`), single-use, expiry-beats-approval,
  client- and DPoP-binding checked before consume. Plus `Attesto.CIBA.Grant`,
  the `Attesto.CIBAStore` behaviour (every transition a single atomic guarded
  operation; the poll interval is frozen into the record at issue time), and
  an ETS reference store.
- `Attesto.RequestObject.verify/3` gains `:require_iat`, `:require_jti`, and
  `:require_client_id_claim` options for the CIBA signed-request profile
  (defaults preserve the RFC 9101 behaviour).
- Discovery (`Attesto.Discovery`) accepts the CIBA Core §4 metadata:
  `backchannel_authentication_endpoint`,
  `backchannel_token_delivery_modes_supported`,
  `backchannel_authentication_request_signing_alg_values_supported`, and
  `backchannel_user_code_parameter_supported`.
- **OpenID Connect Front-Channel Logout 1.0 (OP side).**
  - `Attesto.FrontChannelLogout.logout_uri/3` builds the exact URI an OP
    logout page loads in an iframe for one Relying Party: the registered
    `frontchannel_logout_uri` with `iss` + `sid` query parameters appended
    whenever the session's `sid` is known (both together or neither, §2).
  - `Attesto.LogoutSessionStore` records both logout channels: an entry now
    carries `frontchannel_logout_uri` / `frontchannel_session_required`
    alongside the back-channel fields, and `backchannel_logout_uri` is
    optional — a row exists for any RP that registered at least one logout
    URI.
  - `Attesto.Discovery` accepts the `frontchannel_logout_supported` and
    `frontchannel_logout_session_supported` host members (§3).
- **OpenID Connect Session Management 1.0 (OP side).**
  - `Attesto.SessionState` computes the §3.2 `session_state` value
    (lowercase-hex SHA-256 over `client_id <> " " <> origin <> " " <>
    op_browser_state <> " " <> salt`, dot, salt) plus the browser-form
    `origin/1` of a `redirect_uri` and the salt / OP-browser-state generators
    — the pure computation the OP's authorization response and the
    `check_session_iframe`'s JavaScript recomputation must agree on.
  - `Attesto.Discovery` accepts the `check_session_iframe` host member (§3.3).

## [1.0.0] - 2026-07-04

First stable release; the public API is now under semantic versioning. No
functional change from 0.13.0.

The authorization-server core (tokens, ID tokens, PKCE, DPoP, PAR, discovery,
RP-Initiated and Back-Channel Logout) backs an OpenID Provider that passes the
OpenID Foundation conformance suite for OpenID Connect Core (Basic), FAPI 2.0
Security Profile Final, FAPI 2.0 Message Signing Final, RP-Initiated Logout,
and Back-Channel Logout.

## [0.13.0] - 2026-06-23

### Added

- **OpenID Connect Logout (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).**
  - `Attesto.LogoutToken` mints a signed Back-Channel `logout_token`
    (§2.4): `typ: "logout+jwt"`, the `events` claim
    `{"http://schemas.openid.net/event/backchannel-logout": {}}`, `iss`/`aud`/
    `iat`/`jti`/short-`exp`, at least one of `sub`/`sid`, and never a `nonce`.
  - `Attesto.EndSession` is the conn-free RP-Initiated Logout validator:
    `parse/2` verifies the `id_token_hint`, resolves the Relying Party
    `client_id` (rejecting a `client_id` parameter that disagrees with the
    hint's `aud`), and extracts the session `sub`/`sid`; `confirm_redirect/2`
    honors a `post_logout_redirect_uri` only on an **exact** match against the
    client's registered set and appends `state` — an unregistered or
    unidentifiable return URI is refused (no open redirect).
  - `Attesto.IDToken` gains a `sid` claim (`:sid` mint option, OIDC Back-Channel
    Logout §2.1) and `verify_logout_hint/2`, which validates a hint's signature
    + issuer while **tolerating expiry** and reading the RP from `aud` rather
    than requiring it up front (RP-Initiated Logout §2).
  - `Attesto.LogoutSessionStore` behaviour: the OP-side
    `(sid, client_id) -> backchannel_logout_uri` delivery map, with an atomic
    `take_targets/1` (enumerate-and-delete) so concurrent logouts cannot
    double-deliver.
  - Discovery (`Attesto.Discovery`) gains `end_session_endpoint`,
    `backchannel_logout_supported`, and `backchannel_logout_session_supported`.

## [0.12.0] - 2026-06-23

### Added

- **RFC 8628 Device Authorization Grant.** New `Attesto.DeviceCode` primitive
  (issue + the §3.5 polling state machine: `authorization_pending` / `slow_down`
  / `expired_token` / `access_denied`, expiry-beats-approval, single-use
  consume), `Attesto.DeviceCode.Grant`, the `Attesto.DeviceCodeStore` behaviour
  (every transition a single atomic guarded operation), and an ETS reference
  store. The `user_code` uses an ambiguity-free base-20 alphabet and is
  normalized + charset-validated before any store lookup. `device_authorization_endpoint`
  is now an accepted RFC 8414 metadata field.

## [0.11.0] - 2026-06-22

### Added

- **RFC 9470 Step-Up Authentication Challenge.** New `Attesto.StepUp` +
  `Attesto.StepUp.Requirement` primitive: a requirement is accepted `acr_values`
  and/or a `max_age` freshness bound; `evaluate/3` checks a verified token's
  `acr` / `auth_time` claims (conjunction, fail-closed on absent/malformed) and
  returns the §3 challenge params.
- `Attesto.Token.mint/3` accepts optional `:acr` / `:auth_time`, written as
  access-token claims (the carrier a resource server enforces step-up against).
- `Attesto.RefreshToken` carries the original `acr` / `auth_time` across rotation
  unchanged, so a refresh-minted access token reports the real authentication
  event (`auth_time` is never re-stamped).
- `Attesto.Plug.OAuthError.insufficient_user_authentication/4` (the RFC 9470 §3
  401 challenge) and a `:step_up` option on `Attesto.Plug.Authenticate` that
  enforces a per-route requirement after token verification.
- `acr_values_supported` is now an accepted protected-resource-metadata host
  field (RFC 9728), so a resource server can advertise the `acr` values it can
  demand.

## [0.10.0] - 2026-06-22

### Added

- **RFC 8707 Resource Indicators.** New `Attesto.ResourceIndicator` primitive
  (`validate/1` for §2.1 absolute-URI syntax over the scalar/array `resource`
  parameter; `authorize/2` for §2.2 allow-listing → `:invalid_target`).
- `Attesto.Token.mint/3`'s `:audience` option now accepts a list of resource
  identifiers, written as a JWT `aud` array (a single resource still collapses
  to a string). `Token.verify` already checks array membership, so a resource
  server validates that its own identifier is in `aud`.
- `Attesto.AuthorizationCode` / `Attesto.RefreshToken` bind a `resource` set
  alongside scope; refresh rotation carries it and narrows it subset-only (a
  requested resource outside the granted set is `:invalid_target`).
- `Attesto.AuthorizationRequest` parses and validates the `resource` parameter,
  surfacing a malformed value as a redirectable `invalid_target` error.

## [0.9.0] - 2026-06-21

### Changed

- **`Attesto.Plug.Authenticate` bearer presentation methods are explicit and
  header-only by default.** The new `:bearer_methods` option accepts `:header` /
  `"header"` and `:body` / `"body"`; it defaults to `[:header]`. A resource
  server that intentionally accepts RFC 6750 §2.2 form-body `access_token`
  credentials must opt in with `bearer_methods: [:header, :body]` and advertise
  the matching `bearer_methods_supported` metadata. URI-query bearer tokens
  remain unsupported. DPoP, mTLS, and host-provided `:credential_from_conn`
  fallback credentials are unchanged.

## [0.8.1] - 2026-06-21

### Changed

- **`Attesto.Plug.OAuthError.insufficient_scope/4` now honors the transport
  hooks.** The 403 scope-rejection path threads the same `:send_error`,
  `:www_authenticate`, and `:no_store` options `unauthorized/4` already honored,
  so a resource server can override the 403 response envelope and inject a
  per-conn challenge (e.g. a request-derived RFC 9728 `resource_metadata`
  pointer) on the scope-rejection path, not just the authentication-rejection
  path. The `insufficient_scope` code, 403 status, and the `error_description` /
  `scope` challenge semantics remain owned by the renderer; the default response
  is byte-identical when no hooks are passed.
- **`Attesto.Plug.RequireScopes` now threads those transport hooks** onto both
  the 403 `insufficient_scope` and the 401 `invalid_token` it renders, alongside
  the existing `:resource_metadata` pointer. Previously they were dropped, so a
  host could not override the scope-rejection envelope through this plug.

## [0.8.0] - 2026-06-20

### Added

- **`Attesto.ProtectedResourceMetadata`** — renderer for the RFC 9728 OAuth 2.0
  Protected Resource Metadata document (the resource-server analogue of
  `Attesto.Discovery`). `metadata/2` returns the string-keyed map a resource
  publishes at `/.well-known/oauth-protected-resource`: the REQUIRED `resource`
  identifier (defaulting to `config.audience`, overridable via `:resource`) plus
  the nil-droppable RFC 9728 §2 host fields (`authorization_servers`,
  `jwks_uri`, `scopes_supported`, `bearer_methods_supported`,
  `resource_signing_alg_values_supported`,
  `authorization_details_types_supported`, the `resource_name`/documentation/
  policy/ToS members, `tls_client_certificate_bound_access_tokens`,
  `dpop_bound_access_tokens_required`, `dpop_signing_alg_values_supported`, and
  `signed_metadata`). A present-but-malformed `:resource` (the REQUIRED member)
  fails fast with `ArgumentError`. Conn-free; mounting a serving endpoint is the
  host's concern.
- **RFC 9728 §5.1 `resource_metadata` challenge pointer.**
  `Attesto.Plug.OAuthError.unauthorized/4` and `insufficient_scope/3,4` now
  append a `resource_metadata="<url>"` auth-param to the `WWW-Authenticate`
  challenge when a `:resource_metadata` opt is present, so a client refused with
  401/403 can discover the resource's protected-resource metadata (and thereby
  its authorization server). Threaded through `Attesto.Plug.Authenticate`
  (`:resource_metadata` init opt) and `Attesto.Plug.RequireScopes`
  (`:resource_metadata` init opt). Omitted when unset.

- **`Attesto.Token.mint/3` `:audience` option** — a per-call override for the
  access token's `aud` claim, defaulting to `config.audience`. RFC 8707 §2: when
  a token request carries a `resource` indicator the access token's `aud` MUST
  identify that resource; the host derives the resource identifier and passes it
  here. The override is conn-free and does not mutate `config`, so one issuer can
  mint resource-audienced tokens for one grant without changing `aud` for any
  other. A present-but-malformed override (a `nil`, `""`, list, or other
  non-string) is rejected `{:error, :invalid_audience}` rather than minted, so a
  miswired `resource` cannot produce a malformed `aud`.

- **`Attesto.IdentityAssertion`** — verification for the Identity Assertion JWT
  Authorization Grant (ID-JAG), the resource Authorization Server's half of
  `draft-ietf-oauth-identity-assertion-authz-grant-04` (the grant behind MCP
  Enterprise-Managed Authorization). Conn-free and side-effect-free:
  `verify/3` checks the assertion's signature against a caller-supplied trusted
  issuer JWKS (kid selection, `RS256`/`PS256`/`ES*`/`EdDSA`) and enforces the
  draft's claim rules — JOSE `typ` pinned to `oauth-id-jag+jwt`, `iss` matches
  the trusted issuer (NOT the `client_id`), `aud` is exactly this server's
  issuer (strict single value), the required `iss`/`sub`/`aud`/`client_id`/
  `jti`/`exp`/`iat` claims, `client_id` binding, and `exp`/`iat`/`nbf` skew with
  an optional `:max_lifetime_seconds` bound. `peek_issuer/1` reads the
  unverified `iss` so the caller can select the trusted issuer before verifying.
  The stateful concerns (JWKS fetch/cache, `jti` replay, subject resolution,
  error mapping to RFC 6749 `invalid_grant`) belong to the `attesto_phoenix`
  token layer. Distinct from `private_key_jwt` client auth (RFC 7523 §3) and the
  RFC 8693 token-exchange grant (which runs at the IdP).

## [0.7.2] - 2026-06-16

### Added

- **`c:Attesto.CodeStore.get/1`** (OPTIONAL callback) — read a stored authorization
  code WITHOUT consuming it (unlike `take/1`). Implemented by the bundled
  `Attesto.CodeStore.ETS`. Lets the token endpoint run read-only pre-checks
  (e.g. a holder-of-key requirement) without burning the single-use code.
- **`Attesto.AuthorizationCode.dpop_bound?/2`** — returns whether a stored code
  is bound to a DPoP key (RFC 9449 §10), via the store's non-consuming `get/1`.
  Used to surface a holder-of-key (`invalid_request`/`invalid_dpop_proof`)
  rejection ahead of the client-auth error at the token endpoint (FAPI2
  `ensure-holder-of-key-required`), without consuming the code. Returns `false`
  when the store has no `get/1`, so behaviour is unchanged for stores that
  don't implement it.

## [0.7.1] - 2026-06-14

### Security

- **Refresh-rotation grace no longer replays an already-rotated successor.**
  `RefreshToken.rotate/3`'s within-grace idempotent-retry path returned the
  parent's cached successor without checking it was still the live, unconsumed
  leaf. After `A → B → C`, a replay of the captured parent `A` inside the grace
  window re-issued `B` (and minted a fresh access token from it) instead of
  detecting reuse — suppressing the OAuth 2.0 Security BCP §4.13 captured-token
  signal and forking a live chain. The grace retry now confirms the cached
  successor is still unconsumed; if it has been rotated onward, the replay is
  treated as reuse and the whole family is revoked.

### Added

- **`Attesto.AuthorizationRequest` carries `dpop_jkt`.** The validated request
  now exposes the RFC 9449 §10 `dpop_jkt` parameter, read from the EFFECTIVE
  (post-`request`-object-merge) params — so a signed request object's `dpop_jkt`
  is authoritative and an unsigned outer-query value is ignored when a request
  object is present. (Consumed by `attesto_phoenix`'s authorization endpoint,
  which previously read it from the raw outer query.)

## [0.7.0] - 2026-06-14

### Added

- **`Attesto.ClientIdMetadata` — the pure core of Client ID Metadata Documents
  (CIMD, `draft-ietf-oauth-client-id-metadata-document-01`).** CIMD lets a client
  identify itself with no prior registration by using an HTTPS URL as its
  `client_id`; the authorization server dereferences that URL to a JSON client
  metadata document. This module is the conn-free, HTTP-free half:
  `client_id_url?/1` and `validate_client_id/1` enforce the draft §2 URL grammar
  (https, path required, no fragment/userinfo/dot-segments); `validate_document/2`
  validates a fetched document (the `client_id` must equal the URL, no shared
  symmetric secret / `client_secret_*` auth method, a non-empty `redirect_uris`)
  and normalizes it into the same client shape the RFC 7591 registration path
  produces. The network half (SSRF-guarded fetch, caching) lives in
  `attesto_phoenix`; this module touches no socket and adds no dependency.
- `Attesto.Discovery` advertises the `client_id_metadata_document_supported`
  authorization-server metadata field when the host enables it.

## [0.6.16] - 2026-06-13

### Fixed

- **Authorization-code redemption is now atomic.**
  `Attesto.AuthorizationCode.redeem/4` no longer records the reuse marker
  (`consumed_success`) itself; that moved to the new `finalize/3`, which the
  caller runs ONLY after the full token response is successfully built. So a
  code whose redemption validated but whose downstream issuance then failed (a
  mint or refresh-store fault, a host `build_principal` callback returning the
  subject under the wrong key) is left single-use-spent but NOT reuse-flagged: a
  replay is a clean `invalid_grant` instead of a false reuse attack that revokes
  the family, and a legitimate retry of a transient failure is not mistaken for
  an attack. Previously any post-validation failure permanently bricked the code
  AND marked it a successful redemption.

  **Caller change:** after a successful token response, call
  `AuthorizationCode.finalize/3` to record the reuse marker. The bundled
  `attesto_phoenix` token endpoint (>= 0.7.7) does this. Stores that do not
  implement the optional `mark_consumed/2` are unaffected.

## [0.6.15] - 2026-06-12

### Fixed

- `Attesto.RequestObject` compares the JOSE `typ` header CASE-INSENSITIVELY
  (RFC 7515 §4.1.9 `typ` is a media type; RFC 2045 §5.1 media types are
  case-insensitive). The FAPI 2.0 Message Signing conformance suite signs request
  objects with a randomly-cased typ (e.g. `OautH-auThZ-REQ+jWt`) to exercise
  this; the previous exact-match rejected them as `invalid_typ`, failing the
  Message-Signing happy-flow / user-rejects tests at the PAR endpoint. A wrong
  type is still rejected; an absent `typ` is still governed by `accepted_typ`.

## [0.6.14] - 2026-06-12

### Fixed

- `Attesto.RequestObject.Policy.fapi_message_signing/0` no longer *requires* the
  JOSE `typ` header on signed request objects - it now accepts an absent `typ`
  (`accepted_typ: ["oauth-authz-req+jwt", nil]`) while still rejecting a wrong
  one. FAPI 2.0 Message Signing §5.3.1 ("shall accept that typ") and RFC 9101 §4
  make `typ` RECOMMENDED, not mandatory, and the OpenID FAPI conformance suite
  signs its request objects with no `typ` header - so the previous strict
  pinning rejected every conformant pushed request object and failed the FAPI2
  Message Signing certification at the PAR endpoint. `typ` is still validated for
  the RFC 9101 §10.8 explicit-typing defence when a client does send it.

### Security

- `Attesto.DPoP` now applies the strict canonical-base64url check to the proof's
  JOSE header (no padding, no non-significant trailing bits) that the
  Token/IDToken/ClientAssertion/RequestObject verifiers already apply, so a DPoP
  proof header cannot be presented in a non-canonical/aliased encoding.
  Defense-in-depth (the signature is verified over the real bytes regardless).

## [0.6.13] - 2026-06-04

The FAPI 2.0 Message Signing surface: signed request objects (JAR, §5.3),
signed authorization responses (JARM, §5.4), and token introspection with
signed responses (§5.5). All additions are backward-compatible; behaviour is
unchanged unless a caller opts into the new policy/options.

### Added

- `Attesto.JARM` — JWT Secured Authorization Response Mode (§5.4). Signs an
  authorization response (success: `code`/`state`; error:
  `error`/`error_description`/`state`) into a JWT carrying `iss`/`aud`/`exp`/
  `iat`, using the keystore signing key (algorithm pinned, never `none`).
- `Attesto.Introspection` — OAuth 2.0 Token Introspection (RFC 7662). Access
  tokens are introspected statelessly with the full `Attesto.Token` verifier
  except the sender-binding proof match (the `cnf` is echoed for the resource
  server); refresh tokens are checked against an `Attesto.RefreshStore`
  (active only while unconsumed and unexpired). Never an error — an invalid,
  expired, revoked, or unknown token is reported inactive (no existence
  oracle).
- `Attesto.SignedIntrospection` — the RFC 9701 signed introspection response
  (a JWT with `iss`/`aud`/`iat` and a `token_introspection` claim, JOSE header
  `typ` = `"token-introspection+jwt"`).
- `Attesto.RequestObject.Policy` gains `require_request_object` (false in
  `generic/0`, true in `fapi_message_signing/0`) and
  `require_request_object?/1`. `Attesto.AuthorizationRequest.validate/2` rejects
  a request that carries no signed request object when the policy requires one
  (redirectable `invalid_request`; non-redirectable when the client is
  untrusted, OIDC Core §3.1.2.6).
- `Attesto.AuthorizationRequest` parses and validates `response_mode` (the
  RFC 6749 `query` plus the JARM modes `jwt`/`query.jwt`/`fragment.jwt`/
  `form_post.jwt`); `supported_response_modes/0` exposes the accepted set.
  Trusted redirectable errors carry the requested `response_mode` and the
  `client_id` so the transport can return the error as a JARM JWT.
- `Attesto.Discovery` allowlists the RFC 9101 §10.5 metadata members
  `require_signed_request_object` and
  `request_object_signing_alg_values_supported`.
- `Attesto.SigningAlg.keystore_algs/1` — the unique signing algorithms across a
  keystore's verification keys (shared by the ID Token / JARM / introspection
  signing-algorithm metadata).
- `Attesto.Token.verify/3` accepts `require_confirmation_binding: false` to
  verify a token's signature/claims while skipping only the sender-binding
  proof match (used by introspection); the `cnf` shape is still validated.
- `Attesto.Introspection.introspect/3` accepts an `:authorize` predicate
  `(response -> boolean)` consulted with the active response before it is
  returned (RFC 7662 §4 / RFC 9701 §5: the AS MAY restrict which tokens a
  caller may introspect). A non-`true` return — or a raise — downgrades the
  response to `%{"active" => false}` so a caller not authorized for the token
  learns nothing about it. When omitted, every authenticated caller may
  introspect any token (the single-trust-domain default).
- `Attesto.Introspection` surfaces the RFC 7662 `sub`/`scope`/`client_id`/`cnf`
  members for an active refresh token from the stored record's own data
  contract (`Attesto.RefreshToken` build context), when present, so a resource
  server — and an `:authorize` policy — can decide per refresh token rather than
  allow/deny every refresh token wholesale. A store that does not populate them
  yields the minimal `active`+`exp` response.

### Security

- `Attesto.AuthorizationRequest.validate/2` now judges the OIDC `openid`-scope
  gate for the `require_nonce` policy on the EFFECTIVE (post-merge) request, so
  a direct JAR carrying `scope=openid` only inside the signed request object can
  no longer bypass the host's nonce requirement. A plain OAuth request (no
  `openid` scope) remains un-nonce-constrained.
- `Attesto.RequestObject.verify/3` rejects a signed request object whose `aud`
  is an array containing any non-string member (RFC 7519 §4.1.3), rather than
  accepting it on a single matching member — matching the hardened
  Token/IDToken/JARM audience handling.
- `Attesto.RequestObject.verify/3` rejects a request object that itself carries
  a `request` or `request_uri` claim (RFC 9101 §4 forbids them) instead of
  silently dropping them, so a nested-request smuggle fails closed at the
  verifier.

## [0.6.12] - 2026-06-03

### Added

- `Attesto.RequestObject.Policy` — a data-only JAR verification policy for
  signed authorization request objects (RFC 9101). `generic/0` is the OpenID
  Connect §6.1 baseline (the default: `nbf`/`exp`/`typ` not required);
  `fapi_message_signing/0` is the FAPI 2.0 Message Signing §5.3.1 profile
  (`nbf` required ≤60 min past, `exp` required ≤60 min after `nbf`, JOSE header
  `typ` = `"oauth-authz-req+jwt"`). `Attesto.AuthorizationRequest.validate/2`
  accepts a `:request_object_policy` option (default `%Policy{}`, generic) and
  threads it into `Attesto.RequestObject.verify/3`. An `aud` that is an array
  containing the issuer is already accepted. Behaviour is unchanged unless a
  caller opts into the FAPI profile.

## [0.6.11] - 2026-06-03

### Added

- `:accepted_algs` option on `Attesto.ClientAssertion.verify/5` and
  `Attesto.RequestObject.verify/3` (default `Attesto.SigningAlg.fapi_algs/0`),
  so the accepted client-authentication / request-object signature algorithms
  are caller-supplied policy rather than a hardcoded constant. The default
  preserves current behaviour.
- `Attesto.SigningAlg.default_client_algs/0` as a named helper for the default
  client-presented signature verification policy.
- Strict JAR policy options on `Attesto.RequestObject.verify/3` for the FAPI
  Message Signing 2.0 (§5.3.1) / RFC 9101 profile: `:require_nbf`,
  `:max_nbf_age_seconds`, `:require_exp`, `:max_lifetime_seconds`, and
  `:accepted_typ` (e.g. `"oauth-authz-req+jwt"`). `:require_nbf`/`:require_exp`
  demand a non-negative integer NumericDate (a missing or malformed value
  fails); `:max_lifetime_seconds` requires both `nbf` and `exp` anchors. These
  default to the prior lenient behaviour, so callers opt into strictness with
  explicit policy.

### Fixed

- `Attesto.RequestObject.verify/3` now honours `nbf` as a not-before claim
  (RFC 7519 §4.1.5): a request object with `nbf` in the future is rejected as
  `:not_yet_valid` even in lenient mode (clock skew tolerated).

## [0.6.10] - 2026-06-02

### Changed

- Require a single-valued string `aud` in client-authentication assertions
  (FAPI 2). An array `aud` is now rejected even when it contains an accepted
  value, and the string must match an expected audience exactly.

## [0.6.9] - 2026-06-02

### Changed

- Restrict client-authentication assertions (`private_key_jwt`) and request
  objects to the FAPI 2 signing algorithms PS256, ES256, and EdDSA. Assertions
  or request objects signed with RS256 are now rejected. `Attesto.SigningAlg`
  exposes the permitted set via `fapi_algs/0`. The provider's own token signing
  (`allowed/0`) is unaffected and still admits RS256.

## [0.6.8] - 2026-06-02

### Fixed

- Canonicalize DPoP `htu` URI comparison by ignoring query/fragment,
  normalizing scheme and host case, and treating an explicit HTTPS default port
  as equivalent to an omitted port. Non-HTTPS URIs, host/path mismatches, and
  non-default port mismatches remain rejected.

## [0.6.7] - 2026-06-01

### Fixed

- Accept DPoP proof `iat` values up to 60 seconds ahead of the server clock,
  matching Attesto's JWT verifier clock-skew policy. Proofs remain
  short-lived through `max_age_seconds`, and replay-cache TTLs now cover the
  full acceptance window.

## [0.6.6] - 2026-06-01

### Fixed

- Sign `PS256` JWTs with the RFC 7518 salt length (32 bytes for SHA-256)
  instead of JOSE/OpenSSL's maximum salt length. This makes PS256 access
  tokens and ID Tokens verifiable by strict FAPI/OIDF validators while keeping
  Attesto's key-derived algorithm policy unchanged.
- Treat signed authorization request object parameters as authoritative
  (RFC 9101 §6.3). When a `request` JWT is present, unsigned query parameters
  no longer supplement missing signed parameters such as PKCE inputs.
- Require signed request objects to carry `iss`, matching `client_id`, and a
  configured `aud`, preventing cross-client or cross-issuer replay of otherwise
  valid request objects.
- Reject access-token-shaped payloads during ID Token verification even when the
  access token JOSE `typ` header is intentionally disabled.

## [0.6.5] - 2026-06-01

### Fixed

- Allow an authorization code that was not pre-bound with `dpop_jkt` to be
  redeemed at the token endpoint with a DPoP proof. Codes explicitly bound with
  `dpop_jkt` still require the exact same proof key at redemption. This matches
  FAPI-style DPoP flows where the authorization request does not pre-bind the
  code, but the token endpoint proof sender-constrains the access token being
  minted.

## [0.6.4] - 2026-06-01

### Fixed

- Load keystore modules before checking optional callbacks such as
  `verification_pems/0`, `key_algs/0`, and `signing_alg/0`. Cold modules now
  advertise and use their configured per-key algorithms deterministically
  instead of briefly falling back to inferred RSA `RS256` metadata.

## [0.6.3] - 2026-06-01

### Added

- Allow OAuth authorization-server metadata (RFC 8414) hosts to advertise
  `authorization_response_iss_parameter_supported` and
  `token_endpoint_auth_signing_alg_values_supported`. These are host capability
  declarations; Attesto still drops nil values and ignores unlisted metadata
  keys.

## [0.6.2] - 2026-06-01

### Fixed

- Unsigned OpenID Connect request objects (`request` JWTs with `alg: "none"`)
  are now rejected with the redirectable `request_not_supported` error instead
  of `invalid_request_object`. Attesto still deliberately does not accept
  unsigned request objects; this change makes the unsupported-feature signal
  match OIDC Core §3.1.2.6 and the OpenID conformance suite.

## [0.6.1] - 2026-05-31

### Added

- `Attesto.Test.DPoPVerifier` - a server-side DPoP verification harness for
  host application suites, the counterpart to `Attesto.Test.DPoP`. From a plain
  request description (`method`, `url`, `headers`) it verifies the presented
  DPoP proof and, when `verify_token: true`, the access token, returning
  `{:ok, verified}` or an `{:error, challenge}` map carrying the HTTP status,
  the `WWW-Authenticate` challenge, and an optional `DPoP-Nonce`. It does not
  reimplement RFC 9449: it delegates every decision to the production verifiers
  `Attesto.DPoP.verify_proof/2` and `Attesto.Token.verify/3`, and mirrors the
  resource server's scheme handling (a DPoP-bound token presented as Bearer
  surfaces a `DPoP` challenge, RFC 9449 §7.1; a missing required nonce surfaces
  `use_dpop_nonce`, §8). It depends on neither Plug, Phoenix, nor any HTTP
  client, so it runs from any ExUnit suite.

- `Attesto.Test.DPoP` - DPoP test fixtures for host application suites
  (RFC 9449). Ships under `lib/` so a consumer can call it from its
  `test/` tree without depending on Attesto's own test support.
  `generate_key/1` mints a proof key (EC P-256 / `ES256` by default);
  `mint_access_token/4` mints a DPoP-sender-constrained access token bound
  to that key via `cnf.jkt` (RFC 7800); `proof/4` builds a valid proof JWT
  for a `(htm, htu)` pair, optionally carrying `ath` (RFC 9449 §4.3) and a
  server `nonce` (§8); `invalid_proof/5` builds a proof with a single
  deliberate defect (`:wrong_htm`, `:wrong_htu`, `:missing_ath`,
  `:expired`) for negative tests. Every fixture is built through the same
  primitives the production code uses (`Attesto.Token.mint/3`,
  `Attesto.DPoP.compute_jkt/1`, `Attesto.DPoP.compute_ath/1`,
  `Attesto.SigningAlg.infer/1`, `JOSE.JWS`), and embeds only the proof
  key's public half (RFC 9449 §4.2), so a fixture is correct by
  construction against `Attesto.DPoP.verify_proof/2` and stays in step
  with it.

## [0.6.0]

### Added

- `Attesto.IDToken.mint/3` rounds out the OpenID Connect Core §2 ID Token
  claim set: `auth_time` (REQUIRED when the request asked for it or carried
  `max_age`), `acr`, `amr`, and `azp` are accepted as optional inputs and
  omitted when absent. Arbitrary additional claims requested through the
  OIDC Core §5.5 `claims` parameter or a host userinfo mapping are supplied
  via `:extra_claims`, a string-keyed map merged after the protocol claims.
  The merge is non-overriding: a key colliding with a reserved protocol
  claim (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `azp`, `auth_time`,
  `acr`, `amr`, `at_hash`, `c_hash`) is rejected with
  `:reserved_claim_conflict`, and a non-map or non-string-keyed value with
  `:invalid_extra_claims`. `at_hash`/`c_hash` (OIDC Core §3.1.3.6,
  §3.3.2.11) were already present.
- `Attesto.AuthorizationRequest.validate/2` - `:require_nonce` option (default
  `false`). When `true`, a request with no `nonce` is rejected with a
  redirectable `invalid_request` error (OIDC Core §3.1.2.1); when `false`,
  `nonce` stays OPTIONAL and is carried through unenforced (RFC 6749 keeps the
  `code` flow at SHOULD). The OP policy is the host's, signalled per call.
- Authorization-code reuse detection (OAuth 2.0 Security BCP §4.13 /
  RFC 6749 §4.1.2). `Attesto.AuthorizationCode.issue/3` accepts an
  optional `:family_id` that links a code to the refresh-token family it
  spawns; it rides onto the redeemed `Attesto.AuthorizationCode.Grant`
  (new `:family_id` field). `Attesto.CodeStore` gains an OPTIONAL
  reuse-tracking pair: a `mark_consumed/2` callback and a third `take/1`
  return value `{:error, :consumed, meta}`. When a store implements them,
  `redeem/4` records the spent code's `family_id`/`subject` and surfaces a
  later replay of that code as `{:error, {:reuse, meta}}` so the caller can
  revoke the descendant family. The addition is purely additive and
  fail-safe: a store that does not implement the pair keeps the
  `{:ok, entry} | :error` `take/1` contract and a re-presented code stays
  `{:error, :invalid_grant}`, with single-use atomicity unchanged.
- Refresh-token rotation grace for honest retries. `Attesto.RefreshToken.rotate/3`
  now returns the same successor when the just-consumed parent is immediately
  retried by the same client, DPoP binding, and narrowed scope within
  `:rotation_grace_seconds` (default `10`). Outside that window, or on any
  mismatch, reuse still revokes the whole family. `Attesto.RefreshStore`
  entries now carry `:consumed_at` and `:successor`, and stores may implement
  `remember_successor/3` to support the idempotent retry path.
- `Attesto.Plug.Authenticate` accepts a `:credential_from_conn` fallback hook
  for host-owned credential channels such as first-party cookies. The
  `Authorization` header remains authoritative when present; the callback is
  consulted only when no usable header credential exists.
- `Attesto.Plug.OAuthError` supports transport hooks (`:send_error`,
  `:www_authenticate`, `:no_store`) so hosts can preserve their API error
  envelope while Attesto owns the OAuth status/challenge semantics.

### Changed

- `Attesto.AuthorizationRequest.validate/2` - `prompt` tokens are now validated
  against the fixed OIDC set `{none, login, consent, select_account}`; an unknown
  token is a redirectable `invalid_request` error (OIDC Core §3.1.2.1). The
  parsed list is still exposed for the controller, which enforces semantics such
  as `prompt=none` (the OP MUST NOT show UI).
- `c:Attesto.RefreshStore.consume/2` receives rotation options such as the
  claim timestamp and returns consumed records with enough metadata for
  retry/reuse decisions. This is the intentional 0.6 store-contract change.

### Security

- Closed a JWS signature-malleability gap in the compact-form boundary of
  both `Attesto.Token.verify/3` and `Attesto.IDToken.verify/3`. The boundary
  previously checked each segment against the base64url alphabet only
  (RFC 4648 §5), which accepts a non-canonical final character: the 342-byte
  RS256 signature segment is a partial quantum (342 rem 4 == 2) whose last
  character carries four unused low-order bits, so several distinct
  characters decode to the same signature bytes (RFC 4648 §3.5). JOSE's
  liberal decoder normalises such a variant and verifies it, so a tampered
  serialization that is not byte-identical to the issuer's token was
  accepted. The boundary now requires each segment to round-trip through
  `Base.url_decode64/2` and `Base.url_encode64/2` byte-identically, rejecting
  padding, non-alphabet bytes, and non-zero unused trailing bits in one
  check, before the token reaches JOSE. Canonical unpadded base64url tokens
  are unaffected; the empty signature segment of an `alg:none` token still
  round-trips and is classified `:invalid_signature`.

## [0.5.1]

### Added

- `Attesto.IDToken` - mint and verify OpenID Connect ID Tokens (OIDC Core
  1.0 §2), including `at_hash`/`c_hash` generation, `nonce`, and the
  client-id audience and generic `JWT` `typ` that distinguish an ID Token
  from an RFC 9068 access token. Shares the keystore/`kid`/RS256 path with
  `Attesto.Token`.
- `Attesto.AuthorizationRequest` - protocol-shape validation for the
  authorization endpoint (RFC 6749 §4.1.1, OIDC Core §3.1.2.1, PKCE
  §4.3): `response_type`, `client_id`, exact-match `redirect_uri`,
  scope/`openid` detection, and the PKCE parameters.
- `Attesto.OpenIDDiscovery` - the OpenID Provider Metadata document
  (OIDC Discovery 1.0 §3) served from `/.well-known/openid-configuration`,
  built on top of `Attesto.Discovery`.
- `mix check` alias running formatting, `--warnings-as-errors` compile,
  property tests, and Credo strict in one command.

### Security

- DPoP replay cache: closed a race in the expired-entry re-admission path.
  `Attesto.DPoP.ReplayCache.check_and_record/2` performed a non-atomic
  lookup-then-insert, so at the exact TTL boundary two concurrent callers
  could both re-admit a just-expired `jti` and a proof could be replayed
  more than once. Re-admission is now a single atomic compare-and-delete
  (`:ets.select_delete/2` guarded on expiry) followed by `insert_new/2`, so
  exactly one caller wins and the losers see `:replay`.
- Token verification now enforces canonical compact-JWS form at its own
  boundary. `Attesto.Token.verify/3` and `Attesto.IDToken.verify/3` reject
  any `=` padding or non-base64url byte in a compact segment before the
  token reaches JOSE, refusing to verify a serialization the issuer never
  emitted (JOSE's decoder would otherwise tolerantly normalize trailing
  padding). Unpadded base64url tokens are unaffected.

### Fixed

- Documentation: the authorization-code single-use note now links the
  `Attesto.CodeStore` `take/1` callback with the correct callback
  reference, clearing a docs-build warning.
