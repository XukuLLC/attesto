# CIBA — attesto_phoenix layer design

Design doc for the `attesto_phoenix` (and cert_example) work that sits on top of the
`Attesto.CIBA` core primitive shipped on this branch (`feat/ciba-core`). This stream did
NOT touch attesto_phoenix; this document is the handoff for the stream that owns it.

Target: FAPI-CIBA OP certification (`fapi-ciba-id1-test-plan`, poll + ping variants,
private_key_jwt and mtls client auth), layered on the existing FAPI 2.0 cert wiring.

## 0. What the core already provides (contract recap)

All in `attesto` on this branch — the phoenix layer is HTTP framing + storage + host
callbacks only, following the PAR/Token pattern (NOT RevocationController):

| Core API | Purpose |
|---|---|
| `Attesto.CIBA.Request.validate(client, params, opts)` | §7.1 request-shape rules + §7.1.1 signed-request verification (via `Attesto.RequestObject` with `require_client_id_claim: false, require_exp/iat/nbf/jti: true`, 60-min lifetime bound). `client` is the registered CIBA metadata map: `%{client_id, token_delivery_mode, jwks, request_signing_alg, user_code_parameter}`. |
| `Attesto.CIBA.issue(store, request, %{subject: ...}, opts)` | Mints the 256-bit `auth_req_id` (hash-only storage), returns the §7.3 `%{auth_req_id, expires_in, interval}`. `subject` is REQUIRED — the hint must be resolved first. |
| `Attesto.CIBA.approve(store, auth_req_id, %{subject:, acr:, scope:, claims:, auth_time:}, opts)` / `deny/3` | Atomic pending→approved/denied; both return `%{client_id, delivery_mode, client_notification_token}` — the ping-notification payload data (§10.2 fires on approval AND denial). `approve` enforces subject == issue-time subject (`:subject_mismatch`). |
| `Attesto.CIBA.redeem(store, auth_req_id, %{client_id:, dpop_jkt:}, opts)` | Token-endpoint state machine: `authorization_pending` / `slow_down` / `expired_token` / `access_denied` / `invalid_grant`; single-use consume; expiry beats approval; binding checks before consume. |
| `Attesto.CIBA.lookup(store, auth_req_id)` | Non-consuming view for the auth-device UI / host routing. |
| `Attesto.CIBA.grant_type/0` | `"urn:openid:params:grant-type:ciba"`. |
| `Attesto.CIBA.error_status/1` | §13 HTTP statuses (401 `invalid_client`, 403 `access_denied`, else 400). |
| `Attesto.CIBAStore` behaviour + `Attesto.CIBAStore.ETS` | Storage seam; every transition one atomic guarded op; the poll interval is frozen INTO the record at issue (it is what the client was told). |

Host-emitted errors the core deliberately does not produce (they need the resolved
user): `unknown_user_id`, `expired_login_hint_token`, `missing_user_code`,
`invalid_user_code`. They are in the core's `error()` type and `error_status/1` for
rendering.

## 1. Config additions (`AttestoPhoenix.Config`)

Mirror `device_authorization:` exactly:

```elixir
ciba: [
  enabled: false,
  # advertised + enforced delivery modes; FAPI-CIBA forbids :push
  delivery_modes: [:poll, :ping],
  expires_in_seconds: 120,
  max_expires_in_seconds: 600,
  interval_seconds: 5,
  # FAPI-CIBA: signed authentication requests are mandatory
  require_signed_request: true,
  request_signing_algs: ["PS256", "ES256"],
  binding_message_max_length: 128,
  require_binding_message: false,
  user_code_parameter_supported: false
],
ciba_store: MyApp.EctoCIBAStore,
```

New callback fields (join `:authenticate_device_user` in the struct):

* `:authenticate_ciba_user` — `(request :: Attesto.CIBA.Request.t() -> {:ok, subject} | {:error, :unknown_user_id | :expired_login_hint_token})`.
  Resolves the hint (`{:login_hint, "user@x"}` / `{:login_hint_token, jwt}` /
  `{:id_token_hint, jwt}`) to a subject. For `id_token_hint` the host should verify it
  with `Attesto.IDToken.verify_logout_hint/2`-style leniency (expired ID tokens are
  acceptable hints per CIBA §7.1) and read `sub`. Called BEFORE `issue/4`.
  It is also the place to check `user_code`: if the resolved user has a registered
  secret code and the client sent none → `{:error, :missing_user_code}`; wrong code →
  `{:error, :invalid_user_code}` (compare via `Attesto.SecureCompare`).
* `:notify_ciba_user` — `(auth_req_id, request, subject -> :ok)`. Kicks off the
  out-of-band authentication on the user's device (push notification, in-app prompt…).
  The cert_example implements this as the auto-approval fixture (see §6). Invoked after
  `issue/4` succeeds, OUTSIDE the response path (async — the §7.3 acknowledgement must
  not wait on it).
* `:ciba_ping_http_client` — module implementing the ping delivery behaviour (§4),
  default `AttestoPhoenix.CIBAPing.Req` (mirrors `AttestoPhoenix.BackChannelLogout.Req`).

Client registry: `ClientAuthentication.Result.client` (host client map) must expose the
CIBA registration metadata (CIBA §4): `backchannel_token_delivery_mode`,
`backchannel_client_notification_endpoint`, `backchannel_authentication_request_signing_alg`,
`backchannel_user_code_parameter`, plus the existing `jwks`. The controller maps these
onto the core's `Request.client()` map. A client whose registered mode is not in
`ciba[:delivery_modes]` → `unauthorized_client`. Enabling CIBA adds
`urn:openid:params:grant-type:ciba` to `Config.grant_types_supported/1` (same mechanism
as `device_code`).

## 2. BackchannelAuthenticationController (thin, PAR/Token pattern)

`AttestoPhoenix.Controller.BackchannelAuthenticationController`, `POST` only.
HTTP framing identical to `DeviceAuthorizationController.create/2`, except CIBA is
confidential-clients-only (FAPI-CIBA §5.2.2 — `allow_public: false`):

```
create(conn, params):
  resolve_config → put_no_store → require_enabled → check_https
  → reject_query_credentials
  → ClientAuthentication.authenticate_with_context (private_key_jwt / mtls; allow_public: false)
  → BackchannelAuthentication.request(config, %Request{client, params, ...})   # conn-free AS module
  → 200 json %{auth_req_id, expires_in, interval}  (interval omitted when nil)
  | render_error via OAuthError (status from Attesto.CIBA.error_status/1)
```

New conn-free AS module `AttestoPhoenix.AuthorizationServer.BackchannelAuthentication`
(the analogue of `AuthorizationServer.DeviceAuthorization`):

1. Build the core `client` map from the authenticated client's registration.
2. Strip client-auth params (`client_id`, `client_assertion`, `client_assertion_type`)
   from `params` — the core requires `request` to be alone for signed requests.
3. `Attesto.CIBA.Request.validate(client, params, issuer: config.issuer,
   require_signed_request:, accepted_algs:, ...)`.
4. `request.signed?` false + `require_signed_request` handled by core; ALSO enforce
   `iss == authenticated client_id` is already the core's `issuer:` check.
5. Replay-guard the signed request's `jti` (optional hardening; the core verifies but
   does not track — reuse `EctoReplayCheck`/DPoP replay seam if cheap).
6. `Callback.invoke(config.authenticate_ciba_user, [request])` → subject or
   `unknown_user_id` / `expired_login_hint_token` / `missing_user_code` /
   `invalid_user_code` OAuthError.
7. `Attesto.CIBA.issue(ciba_store, request, %{subject: subject}, expires_in:, ...)`.
8. Async `Callback.invoke(config.notify_ciba_user, [auth_req_id, request, subject])`
   (Task.Supervisor, fire-and-forget; failures logged via EventSink).

Router macro: add `ciba: true` option to `attesto_routes/1` (like `device: true`)
mounting `POST /oauth/bc-authorize` (`@backchannel_authentication_path`, tail from
`Config.backchannel_authentication_tail()`; keep it configurable). No user-facing GET
route — the authentication device is the host's own UI/app, unlike the device grant's
verification page.

## 3. Token endpoint grant

`AttestoPhoenix.AuthorizationServer.Token`: add
`dispatch(%Request{grant_type: "urn:openid:params:grant-type:ciba"})` clause next to the
`@grant_device_code` one:

* Confidential-only (add to `@confidential_only_grants`).
* Params: require `auth_req_id` (string) → `Attesto.CIBA.redeem(store, auth_req_id,
  %{client_id: client.id, dpop_jkt: sender_constraint_jkt}, [])`.
* Error mapping is verbatim (`{:error, atom}` → OAuthError `atom`, HTTP 400, per §11).
* On `{:ok, %Attesto.CIBA.Grant{}}`: mint through the same path as the device grant —
  access token (+ refresh token per policy) with `grant.scope` / `grant.resource` /
  cnf from mtls/DPoP, and an ID Token (scope contains `openid` always) carrying
  `grant.subject`, `grant.acr`, `grant.auth_time` (FAPI-CIBA: `acr` REQUIRED in the ID
  token when the client requested `acr_values`). No `nonce` (CIBA has none); ping/poll
  token responses are plain OIDC token responses (§10.1.1 `at_hash`/`rt_hash` extras
  apply to PUSH only, which we do not implement).

## 4. Ping-mode notification delivery

Behaviour seam mirroring `AttestoPhoenix.BackChannelLogout`:

```elixir
defmodule AttestoPhoenix.CIBAPing do
  @callback post(endpoint :: String.t(), client_notification_token :: String.t(),
                 auth_req_id :: String.t()) :: :ok | {:error, term()}
end
```

Default impl `AttestoPhoenix.CIBAPing.Req`:
`POST {backchannel_client_notification_endpoint}` with headers
`authorization: Bearer <client_notification_token>`, `content-type: application/json`,
body `{"auth_req_id": "..."}`. Expect 200/204.

Semantics locked by the conformance suite (fapi-ciba-id1 ping modules):

* **Do not follow redirects** (`FAPICIBAID1PingNotificationEndpointReturnsRedirectRequest`):
  a 3xx from the notification endpoint is a failure, never followed (SSRF posture).
* **Do not retry on 401/403** (`...Returns401AndRequireServerDoesNotRetry`): the flow
  outcome is unaffected — tokens stay available at the token endpoint; log and move on.
* A response body is ignored (`...ReturnsABody`).
* Timeout short (~5s), TLS verified, and the endpoint URL must be https (validate at
  client registration).
* Delivery is async (Task.Supervisor) and best-effort; §10.2 clients that miss the ping
  may poll (treated as poll mode — the core already enforces the interval for ping
  records).

Trigger points: after `Attesto.CIBA.approve/4` AND `deny/3` return
`{:ok, %{delivery_mode: :ping, client_notification_token: token, client_id: id}}`, the
host looks up the client's registered notification endpoint and calls the seam. This
lives in a small `AttestoPhoenix.AuthorizationServer.CIBADecision` helper the host's
approval UI calls, so hosts don't hand-roll the approve→notify sequence:

```elixir
CIBADecision.approve(config, auth_req_id, %{subject:, acr:, scope:}) # core approve + ping delivery
CIBADecision.deny(config, auth_req_id)
```

Expiry without decision sends NO notification (the client discovers `expired_token` by
polling; ping-on-expiry is optional in §10.2 — skip for v1).

## 5. Ecto store (`AttestoPhoenix.Store.EctoCIBAStore` + `Schema.CIBARequest`)

Mirror `EctoDeviceCodeStore`/`Schema.DeviceCode` (guarded atomic UPDATEs, no
read-modify-write). Migration sketch (`attesto_ciba_requests`):

```elixir
create table(:attesto_ciba_requests, primary_key: false) do
  add :id, :binary_id, primary_key: true
  add :auth_req_id_hash, :string, null: false     # unique index; only the hash
  add :client_id, :string, null: false
  add :delivery_mode, :string, null: false        # poll | ping | push
  add :scope, {:array, :string}, null: false, default: []
  add :acr_values, {:array, :string}, null: false, default: []
  add :binding_message, :string
  add :client_notification_token, :string         # ping/push only (bearer secret — see note)
  add :hint_subject, :string, null: false         # issue-time resolved user (data.subject)
  add :resource, {:array, :string}, null: false, default: []
  add :dpop_jkt, :string
  add :status, :string, null: false, default: "pending"
  add :subject, :string                           # bound at approval
  add :acr, :string
  add :auth_time, :utc_datetime
  add :granted_scope, {:array, :string}           # NULL = "as requested"
  add :granted_claims, :map
  add :interval, :integer, null: false, default: 5
  add :last_polled_at, :utc_datetime
  add :expires_at, :utc_datetime, null: false
  timestamps(updated_at: false, type: :utc_datetime)
end
create unique_index(:attesto_ciba_requests, [:auth_req_id_hash])
create index(:attesto_ciba_requests, [:expires_at])   # sweeper
```

Callback implementations (all single-statement, `RETURNING`-style via
`Repo.update_all(..., select: ...)`):

* `put/1` — insert from the core entry (`from_record/1` spreads `data.*` across
  columns; `to_entry/1` folds back, reconstructing the `data` map — copy the DeviceCode
  bridge pattern).
* `approve/3` — `UPDATE ... SET status='approved', subject=$, acr=$, auth_time=$,
  granted_scope=$, granted_claims=$ WHERE auth_req_id_hash=$ AND status='pending' AND
  expires_at > $now RETURNING *`; on zero rows, one follow-up SELECT to classify
  `:not_found` / `:already_decided` / `:expired`.
* `deny/2` — same with `status='denied'`.
* `poll/2` — `UPDATE ... SET last_polled_at=$now WHERE auth_req_id_hash=$ AND
  (last_polled_at IS NULL OR last_polled_at <= $now - interval) RETURNING *`
  (note: `interval` is the ROW's column — `$now - interval` in SQL); zero rows →
  existence check → `:slow_down` or `:error`.
* `consume/2` — `UPDATE ... SET status='consumed' WHERE auth_req_id_hash=$ AND
  status='approved' AND expires_at > $now RETURNING *`.
* Register with `Store.Sweeper` on `expires_at` like the device-code table.

Note on `client_notification_token`: it is a client-generated bearer secret. v1 stores
it plaintext (parity with how PAR request params are stored; it is single-flow-scoped
and ≤120s-lived). If review wants it hashed, the ping delivery needs it back — so it
would have to be encrypted-at-rest instead (host `Cloak`/`Vault` concern), not hashed.
Flag for the security review.

## 6. cert_example wiring plan

* Register two conformance clients (the suite's "client" and "client2") with:
  `backchannel_token_delivery_mode` (poll for the poll plan run, ping for the ping run),
  `backchannel_client_notification_endpoint` (suite-provided URL, ping run),
  `backchannel_authentication_request_signing_alg: "PS256"` (match suite keys), jwks.
* Config: `ciba: [enabled: true, require_signed_request: true,
  request_signing_algs: ["PS256", "ES256"]]`, `ciba_store: EctoCIBAStore`.
* `authenticate_ciba_user`: resolve `login_hint`/`id_token_hint` against the fixture
  user table (the suite sends the `login_hint` from its test config, e.g. an email; the
  `id_token_hint` is an ID token previously issued by us — verify + read `sub`).
* **Automated approval fixture**: the suite config field `automated_ciba_approval_url`
  (condition `CallAutomatedCibaApprovalEndpoint`) is called as
  `GET <url>?token={auth_req_id}&type={action}` with `action ∈ {allow, deny}` right
  after the backchannel response. Implement a conformance-only endpoint
  `GET /ciba-sim/action?token=...&type=...` that:
  * schedules `CIBADecision.approve/deny` after a ~3s delay (so
    `FAPICIBAID1MultipleCallToTokenEndpoint` observes `authorization_pending` first,
    and immediate-poll tests see pending → slow_down behaviour);
  * `type=allow` → approve as the hint-resolved subject with a fixture `acr`;
    `type=deny` → deny.
  * Also render the manual instruction page path (the suite tells the tester to
    approve/reject by hand when no automated URL is configured) — the automated
    endpoint makes headless runs possible; keep both.
* `FAPICIBAID1AuthReqIdExpired` waits out the lifetime: keep `expires_in` 120s but honor
  `requested_expiry` (core already clamps ≤ 600) — the suite sends a short
  `requested_expiry` for that module. **Do not auto-approve before expiry in that test**:
  the automated endpoint is not called for it, so the 3s-delay fixture is safe.
* Browser/user interaction simulated by the suite: NONE beyond the approval endpoint —
  CIBA has no redirects, so no Selenium/browser config. The ping variant additionally
  requires our ping POST to reach the suite's notification endpoint (it validates the
  Bearer token equals the `client_notification_token` it sent, and resumes the test).

## 7. Conformance plan (what to run)

* Plan: **`fapi-ciba-id1-test-plan`** ("FAPI-CIBA-ID1: Authorization server test").
* Variants (run as separate plans):
  1. `fapi_ciba_profile=plain_fapi`, `client_auth_type=private_key_jwt`, `ciba_mode=poll`
  2. `fapi_ciba_profile=plain_fapi`, `client_auth_type=private_key_jwt`, `ciba_mode=ping`
  3. (optional breadth) `client_auth_type=mtls` × {poll, ping} — unlocks the
     wrong-client-id modules that private_key_jwt can't test; needed for the full cert.
  * `client_registration=static_client` (dynamic later if we certify DCR).
* Certification profile name emitted: **FAPI-CIBA** (plain_fapi). Brazil/ConnectID
  variants are out of scope (they pin mode/auth combos and add `purpose`/CPF hints).
* Key modules to smoke first: `fapi-ciba-id1` (happy path),
  `fapi-ciba-id1-user-rejects-authentication` (deny path),
  `fapi-ciba-id1-multiple-call-to-token-endpoint` (pending/slow_down),
  `fapi-ciba-id1-auth-req-id-expired`, the `ensure-request-object-*` matrix (already
  covered by core tests 1:1 — missing aud/iss/exp/iat/nbf/jti, expired exp, exp 70min,
  nbf future/past, alg none/bad/RS256, signed-by-other-client), the ping notification
  endpoint behaviours (§4), and `ensure-backchannel-authorization-request-without-request-fails`
  (`require_signed_request: true`).
* Per the conformance-runbook memory: after downloading results, parse only the newest
  logs; verify ping-variant green with the real notification round-trip, not a
  cookieless smoke (no browser state involved in CIBA, but the ping callback is the
  analogous false-green trap — confirm the suite log shows our POST).

## 8. Open questions for the phoenix stream

1. `login_hint_token` support: CIBA leaves its format to the deployment; suggest NOT
   advertising/accepting it in v1 (`unknown_user_id` on receipt) — the suite's
   plain_fapi profile uses `login_hint`/`id_token_hint`.
2. Signed-request `jti` replay tracking: worthwhile hardening; reuse the DPoP replay
   seam or skip for v1 (spec does not mandate OP-side tracking).
3. `client_notification_token` at-rest handling (see §5 note).
4. Whether `notify_ciba_user` failures should auto-deny after a timeout (operational
   dead-letter policy; conformance doesn't exercise it).
