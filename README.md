# Attesto

[![Hex.pm](https://img.shields.io/hexpm/v/attesto)](https://hex.pm/packages/attesto)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto)
[![Hex Downloads](https://img.shields.io/hexpm/dt/attesto)](https://hex.pm/packages/attesto)
[![Elixir CI](https://github.com/XukuLLC/attesto/actions/workflows/elixir.yml/badge.svg)](https://github.com/XukuLLC/attesto/actions/workflows/elixir.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/XukuLLC/attesto/blob/main/LICENSE)
[![Elixir](https://img.shields.io/badge/elixir-%E2%89%A5%201.18-purple)](https://elixir-lang.org)
[![OpenID Certified](https://img.shields.io/badge/OpenID-Certified-F78C40)](https://openid.net/certification/certified-openid-connect-implementations/)

A vendor-neutral [OAuth 2.0](https://oauth.net/2/) / [OpenID Connect](https://openid.net/developers/how-connect-works/) engine for Elixir APIs that need modern token security, with first-class support for sender-constrained access tokens: [DPoP](https://datatracker.ietf.org/doc/html/rfc9449) and mutual TLS. It also provides the conn-free protocol pieces for JAR, JARM, token introspection, and FAPI 2.0 Message Signing.

## Certification

[![FAPI 2.0 Certified](https://img.shields.io/badge/FAPI_2.0-Certified-F78C40)](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)
[![FAPI-CIBA Certified](https://img.shields.io/badge/FAPI--CIBA-Certified-F78C40)](https://openid.net/certification/certified-fapi-ciba-openid-providers-profiles/)
[![OpenID Connect Certified](https://img.shields.io/badge/OpenID_Connect-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-profiles/)
[![Logout Profiles Certified](https://img.shields.io/badge/Logout_Profiles-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-for-logout-profiles/)
[![Session Management Certified](https://img.shields.io/badge/Session_Management-Certified-F78C40)](https://openid.net/certification/certified-openid-providers-for-logout-profiles/)
[![Relying Party Certified](https://img.shields.io/badge/Relying_Party-Certified-F78C40)](https://openid.net/certification/certified-openid-relying-parties-profiles/)

<a href="https://openid.net/certification/certified-openid-connect-implementations/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certified" width="180" align="right"></a>

Attesto is [OpenID Certified](https://openid.net/certification/certified-openid-connect-implementations/),
as an authorization server built from `attesto` +
[`attesto_phoenix`](https://github.com/XukuLLC/attesto_phoenix), to:

- **FAPI 2.0 Security Profile Final — OP** and **FAPI 2.0 Message Signing
  Final — OP** ([Financial-grade API](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/))
- **FAPI-CIBA — OP** (Client-Initiated Backchannel Authentication; poll and ping)
- **OpenID Connect Core — Basic OP** and **Config OP**
- **RP-Initiated**, **Back-Channel**, and **Front-Channel Logout — OP**
- **Session Management — OP**

The client side, [`attesto_client`](https://github.com/XukuLLC/attesto_client),
is separately certified as a **Relying Party library** (Basic, Config, and
Dynamic OP profiles).

Certification runs against the OpenID Foundation's conformance suite and the
results are published on the OIDF site. The FAPI 2.0 certifications — bank-grade
sender-constrained ([DPoP](https://datatracker.ietf.org/doc/html/rfc9449) /
mTLS) tokens with signed request objects (JAR) and responses (JARM) — are the
first for an Elixir provider.

## Where it fits

Most Elixir authentication libraries focus on the application session: signing
in with an external provider, managing user accounts, or creating Phoenix
session cookies. Attesto sits on the token side of the boundary: short-lived,
scoped, locally-verifiable OAuth/OIDC tokens for APIs and machine clients.
That matters for everyday APIs as much as specialized high-assurance systems:
as exploit discovery gets cheaper and faster, stolen bearer tokens and
long-lived credentials become weaker defaults.

Use it when you need to:

1. Verify standards-based API tokens in a resource server. Attesto verifies
   JWT access tokens locally by signature, audience, issuer, and optional
   sender constraint. A stolen sender-constrained token is not enough to call
   the API without the holder's DPoP key or client certificate, and no token
   database or introspection call is required for the normal access-token path.

2. Issue tokens from your own authorization server. Attesto provides the
   protocol pieces: JWT access tokens, ID tokens, JWKS/key handling, DPoP,
   mutual-TLS binding, authorization-code helpers, refresh-token rotation,
   signed authorization requests, JARM response JWTs, token introspection,
   scope algebra, and OAuth error/challenge helpers. Machine-to-machine access
   can use OAuth client credentials with short-lived scoped tokens instead of
   long-lived API keys. Transport and persistence remain separate;
   `attesto_phoenix` supplies the Phoenix/Ecto layer.

This is different from session-oriented libraries such as Ueberauth, Assent,
Pow, AshAuthentication, or `mix phx.gen.auth`: those help your application
authenticate users. Attesto helps your application issue or verify OAuth/OIDC
tokens.

Attesto is the engine, not the framework. It mints and verifies JWTs, binds
them to a sender, and validates proofs and scopes. You bring the principals,
the keys, and the policy. It carries no opinion about your identity provider,
your web layer, or your persistence.

If you want a batteries-included Phoenix authorization server, use
[`attesto_phoenix`](https://github.com/XukuLLC/attesto_phoenix) on top of
this package: endpoints, router helpers, and Ecto-backed stores wired together.

To protect a Model Context Protocol (MCP) server as an OAuth resource server,
use [`attesto_mcp`](https://github.com/XukuLLC/attesto_mcp): it reuses Attesto's
token, DPoP, and scope checks as Plug modules and adds the MCP-facing
`WWW-Authenticate` challenge and protected-resource metadata (RFC 9728).

## Contents

- [Certification](#certification)
- [Where it fits](#where-it-fits)
- [Why this library](#why-this-library)
- [Installation](#installation)
- [Usage](#usage)
  - [Configure once](#configure-once)
  - [Mint and verify a token](#mint-and-verify-a-token)
  - [Sender-constrain a token to a DPoP key](#sender-constrain-a-token-to-a-dpop-key)
  - [Authorization request and response JWTs](#authorization-request-and-response-jwts)
  - [Token introspection](#token-introspection)
  - [Match scopes](#match-scopes)
- [What you supply / what's in the box](#what-you-supply--whats-in-the-box)
- [RFC coverage](#rfc-coverage)
- [Plug integration (optional)](#plug-integration-optional)
- [Security telemetry](#security-telemetry)
- [Cluster safety](#cluster-safety)
- [Status](#status)
- [Development](#development)
- [License](#license)

## Why this library

- **Vendor-neutral.** No coupling to Auth0, Okta, Cognito, or any particular IdP. The token shape is yours, and the same issuer can serve several kinds of principal (a machine client, a human session) from one signing key and one verifier.
- **Sender-constrained by design.** DPoP (RFC 9449) and certificate-bound tokens (RFC 8705) are part of the core, with the `cnf` binding matrix enforced on both issue and verify.
- **Short-lived and locally verifiable.** Access tokens are signed JWTs that resource servers can verify without a shared token database. Refresh-token rotation, reuse detection, and revocation hooks cover the stateful parts that should stay stateful.
- **Protocol, not policy.** Attesto selects keys by key ID ([`kid`](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4)), verifies the configured signing algorithms, canonicalises thumbprints, compares in constant time, and rejects replay. Whether a given principal may hold a given scope stays in your application.
- **Pluggable keys.** Use the bundled static keystore (which derives the public half from the private key so the two can never drift), or implement the `Attesto.Keystore` behaviour against your own KMS or rotation story.
- **Cross-language parity.** The test suite verifies Attesto-issued tokens and proofs against a reference implementation in another language, so the wire format is exactly what other ecosystems expect.

## Installation

```elixir
def deps do
  [
    {:attesto, "~> 1.5"}
  ]
end
```

## Usage

### Configure once

Declare the principal kinds your issuer serves, point Attesto at a keystore, and name your issuer and audience.

```elixir
config =
  Attesto.Config.new(
    issuer: "https://api.example.com/",
    audience: "https://api.example.com/",
    keystore: Attesto.Keystore.Static,
    principal_kinds: [
      Attesto.PrincipalKind.new("client", "oc_",
        required_claims: [{"client_id", :non_empty_string}]
      ),
      Attesto.PrincipalKind.new("user", "usr_",
        required_claims: [
          {"act", :non_empty_string},
          {"sid", :non_empty_string},
          {"token_version", :non_neg_integer}
        ]
      )
    ]
  )
```

The `:issuer` must be an `https` URL (RFC 8414 §2), including in development.
Don't downgrade to plain `http` locally — serve a locally-trusted
[mkcert](https://github.com/FiloSottile/mkcert) certificate so `https://localhost`
just works. If you use `attesto_phoenix`, `mix attesto_phoenix.gen.dev_https` and
`AttestoPhoenix.DevTLS.https_opts/1` wire it in one step; see its
[Local HTTPS guide](https://hexdocs.pm/attesto_phoenix/local_https.html).

The static keystore reads its signing key from application config:

```elixir
config :attesto, Attesto.Keystore.Static,
  signing_pem: System.fetch_env!("OAUTH_SIGNING_PRIVATE_KEY_PEM")
```

### Mint and verify a token

```elixir
{:ok, token} =
  Attesto.Token.mint(config, %{
    kind: "client",
    sub: "oc_live_4f2a",
    scopes: ["documents.read", "documents.write"],
    claims: %{"client_id" => "oc_live_4f2a"}
  })

# token.access_token  -> the compact JWS
# token.token_type    -> "Bearer"
# token.expires_in    -> 900
# token.scope         -> "documents.read documents.write"

{:ok, claims} = Attesto.Token.verify(config, token.access_token)
# claims["sub"]   -> "oc_live_4f2a"
# claims["scope"] -> "documents.read documents.write"
```

### Sender-constrain a token to a DPoP key

Pass a JWK thumbprint at issue time, then verify the proof and the binding together on each request.

```elixir
{:ok, token} =
  Attesto.Token.mint(config, principal, dpop_jkt: proof_key_thumbprint)
# token.token_type -> "DPoP"

{:ok, proof} =
  Attesto.DPoP.verify_proof(dpop_proof_jwt,
    http_method: "POST",
    http_uri: "https://api.example.com/documents",
    access_token: token.access_token,
    replay_check: &Attesto.DPoP.ReplayCache.check_and_record/2
  )

{:ok, _claims} =
  Attesto.Token.verify(config, token.access_token, dpop_jkt: proof.jkt)
```

A DPoP- or mTLS-bound token presented without (or with a mismatched) proof is rejected, and a proof presented against a token that is not bound that way is rejected too.

### Authorization request and response JWTs

Attesto verifies signed authorization request objects (JAR / RFC 9101) and can
build signed authorization responses (JARM). Profile policy is explicit data:
the generic defaults stay broadly OpenID-compatible, while
`Attesto.RequestObject.Policy.fapi_message_signing/0` applies the FAPI 2.0
Message Signing request-object rules.

```elixir
policy = Attesto.RequestObject.Policy.fapi_message_signing()

{:ok, request_claims} =
  Attesto.RequestObject.verify(request_jwt, client_jwks,
    [issuer: client_id, audience: config.issuer] ++
      Attesto.RequestObject.Policy.to_verify_opts(policy)
  )

{:ok, response_jwt} =
  Attesto.JARM.response_jwt(config, client_id, %{
    "code" => code,
    "state" => state
  })
```

`Attesto.AuthorizationRequest.validate/2` accepts `:request_object_policy`,
`:request_object_jwks`, and `:request_object_audience` options so a transport
layer can enforce request-object policy while keeping controller code thin.

### Token introspection

`Attesto.Introspection` implements the RFC 7662 active-token decision without
owning an HTTP endpoint. Access tokens are introspected with the same verifier
used by resource servers, except the sender-binding proof match is skipped so
the response can echo `cnf` for the resource server to enforce. Refresh tokens
are active only while present, unconsumed, and unexpired in the configured
`Attesto.RefreshStore`.

```elixir
response =
  Attesto.Introspection.introspect(config, token,
    refresh_store: MyApp.RefreshStore,
    token_type_hint: "access_token"
  )

{:ok, signed_response} =
  Attesto.SignedIntrospection.response_jwt(config, resource_server_id, response)
```

The signed response helper emits the RFC 9701
`application/token-introspection+jwt` payload; the HTTP endpoint and content
negotiation belong to the host or integration layer.

### Match scopes

```elixir
catalog = Attesto.Scope.new_catalog(~w(documents.read documents.write reports.read))

Attesto.Scope.grants?(catalog, ["documents.*"], "documents.write")
# => true

Attesto.Scope.grants_all?(catalog, ["documents.read"], ["documents.write"])
# => false
```

## What you supply / what's in the box

| What you supply | What's in the box |
| --- | --- |
| Principal definitions (`Attesto.PrincipalKind`) | Token issue and verify (`Attesto.Token`) |
| Signing / verification keys, rotation (`Attesto.Keystore`) | JWS signing, `kid` selection, claim validation |
| Authorization policy ("may this principal do X?") | DPoP proof verification + replay protection (`Attesto.DPoP`) |
| HTTP layer, routing, plugs | mTLS certificate-binding checks (`Attesto.MTLS`) |
| Persistence, sessions, IdP integration | Scope grant-form matching (`Attesto.Scope`) |
| Issuer / audience values (`Attesto.Config`) | JAR, JARM, and introspection primitives |
| Client stores, PAR stores, endpoint rendering | Canonical SHA-256 thumbprints (`Attesto.Thumbprint`) |

If a decision depends on your business rules, it is yours. If it is a wire-format or cryptographic check defined by an RFC, it is Attesto's.

## RFC coverage

| RFC | Title | Status |
| --- | --- | --- |
| RFC 7519 | JSON Web Token (JWT) | Supported |
| RFC 7515 | JSON Web Signature (JWS) | Supported |
| RFC 7518 | JSON Web Algorithms (JWA) — the signing/verification alg set behind the JWT/JWS support | Supported (`Attesto.SigningAlg`) |
| RFC 7517 | JSON Web Key (JWK) | Supported |
| RFC 7638 | JWK Thumbprint | Supported |
| RFC 7800 | Proof-of-Possession Key Semantics (`cnf`) | Supported |
| RFC 8705 | Mutual-TLS / Certificate-Bound Access Tokens | Supported |
| RFC 9449 | Demonstrating Proof of Possession (DPoP) | Supported |
| RFC 6749 §4.1 | Authorization-code grant (single-use, PKCE-mandatory) | Supported |
| RFC 6749 §6 / §10.4 | Refresh-token rotation + reuse detection | Supported |
| RFC 6749 §3.3 | Access-token scope | Supported |
| RFC 9700 | OAuth 2.0 Security BCP — the current best-practice hardening (PKCE-everywhere, refresh rotation + reuse detection, registered redirect URIs) | Supported |
| RFC 7523 §4 | JWT-assertion grant (`jwt-bearer`; ID-JAG draft) | Supported |
| RFC 8707 | Resource Indicators (`resource` → token `aud`) | Supported (one or more resources; `Attesto.ResourceIndicator`) |
| RFC 9470 | Step-Up Authentication Challenge (`acr`/`auth_time`) | Supported (`Attesto.StepUp`) |
| RFC 8628 | Device Authorization Grant (`device_code`/`user_code` polling) | Supported (`Attesto.DeviceCode`) |
| CIBA Core 1.0 | Client-Initiated Backchannel Authentication (poll/ping; signed requests per FAPI-CIBA) | Supported (`Attesto.CIBA`) |
| RFC 7636 | Proof Key for Code Exchange (PKCE) | Supported (S256) |
| RFC 8252 §7.3 | OAuth 2.0 for Native Apps — loopback interface redirection (variable port) | Supported (`Attesto.RedirectURI`). The core defaults to exact RFC 6749 §3.1.2.3 matching; the caller opts a request in with `redirect_uri_matching: :exact_allow_loopback_port`. `attesto_phoenix` selects it per client from its `client_native?` mark |
| RFC 8414 | Authorization Server Metadata (discovery) | Supported |
| RFC 9126 | Pushed Authorization Requests (PAR) — the client pushes the auth request to the AS for a one-time `request_uri`, so request params never ride the browser/URL | Supported (discovery advertisement + request-object primitives; the `request_uri` endpoint/store live in `attesto_phoenix`) |
| RFC 9728 | Protected Resource Metadata | Supported |
| CIMD draft | Client ID Metadata Documents (`https`-URL client ids) | Supported |
| RFC 7517 | JSON Web Key Set publication (JWKS endpoint) | Supported |
| RFC 7009 | Token Revocation (refresh-token family) | Supported |
| RFC 9449 §8 | DPoP server-issued nonce | Supported |
| RFC 9068 | JWT access-token `typ: "at+jwt"` header | Supported |
| RFC 9101 | JWT Secured Authorization Request (JAR) | Supported |
| JARM | JWT Secured Authorization Response Mode | Supported |
| RFC 7662 | OAuth 2.0 Token Introspection | Core primitive |
| RFC 9701 | JWT Response for OAuth Token Introspection | Core primitive |
| FAPI 2.0 Message Signing | JAR/JARM/signed introspection primitives | Core primitives |

## Plug integration (optional)

The core is plain functions, but a thin optional Plug layer wires them to
a Phoenix/Plug pipeline so you don't hand-roll header parsing, `htu`
construction, replay enforcement, the mTLS thumbprint handoff, or the
standard error responses:

```elixir
plug Attesto.Plug.Authenticate,
  config: &MyApp.Attesto.config/0,
  replay_check: &MyApp.DPoPReplay.check_and_record/2,
  cert_der: &MyApp.TLS.client_cert_der/1

plug Attesto.Plug.RequireScopes, ["documents.read"]
```

`Authenticate` parses `Authorization: Bearer …` / `DPoP …`, verifies the
DPoP proof and the access token (and the mTLS binding when `:cert_der`
returns a certificate), and assigns the verified claims.
`Attesto.Plug.OAuthError` renders the RFC 6750 / RFC 9449 responses
(`WWW-Authenticate`, `DPoP-Nonce`, `invalid_token`, `invalid_dpop_proof`,
`insufficient_scope`, `use_dpop_nonce`). `Plug` is an optional dependency:
add it only if you use this layer. The token-endpoint grant logic stays
yours - client auth, policy, and store wiring are too host-specific for a
fixed plug.

## Security telemetry

Most refusals are routine — an expired token, an unknown client, a scope
that was not granted. Three are not. Each of these means someone is
holding a credential they should not, and each is emitted as a
[`:telemetry`](https://hexdocs.pm/telemetry) event so it can reach a pager
or a SIEM without wrapping every call site:

| Event | Fires when |
|---|---|
| `[:attesto, :refresh_token, :reuse_detected]` | a rotated refresh token is presented again — **the family has already been revoked**, so this is the only notice that the session ended for a reason |
| `[:attesto, :dpop, :replay_detected]` | a DPoP proof carries a `jti` the replay store already recorded |
| `[:attesto, :token, :sender_constraint_mismatch]` | a DPoP- or mTLS-bound token is presented with the wrong proof of possession |

```elixir
:telemetry.attach_many(
  "attesto-security",
  Attesto.Telemetry.events(),
  &MyApp.Security.handle_event/4,
  nil
)
```

Metadata carries correlation handles — `family_id`, `client_id`,
`subject`, `jti`, `binding`, `reason`. Attesto never derives them from a
credential: no token, code, secret, or assertion is put into an event, in
plaintext or hashed.

That is not the same as the bytes being harmless. `jti` is chosen by the
client and emitted unchanged, and `client_id` / `subject` / `family_id` are
the host's own identifiers, so a handler is writing values it did not
choose — treat metadata as untrusted input wherever it sends it.
`Attesto.Telemetry` documents this in full; event names and metadata keys
are public API.

Routine failures are deliberately **not** events. Emitting them would bury
the three above in traffic that is simply what a healthy authorization
server looks like.

## Cluster safety

The engine is pure and stateless, so it is **cluster-safe by
construction**: the same token/proof verifies to the same result on any
node. All *state* (authorization codes, refresh-token families, seen DPoP
`jti` values, DPoP nonces) lives behind storage behaviours whose contracts
mandate the atomic primitives (atomic `take`, atomic compare-and-set
`consume`, sticky family revocation). Implement those behaviours over a
shared store (Postgres, Redis) and the whole system is cluster-safe — or
take [`attesto_phoenix`](https://hex.pm/packages/attesto_phoenix), which
ships Ecto implementations of all of them (including
`AttestoPhoenix.Store.EctoReplayCheck`, whose unique constraint on `jti`
makes the DPoP record-and-check atomic across nodes) with migrations and
an expiry sweeper.

The bundled ETS reference stores are deliberately **single-node** - a
captured credential would otherwise be replayable once per node. Rather
than fail silently, every ETS store (`CodeStore.ETS`, `RefreshStore.ETS`,
`DPoP.ReplayCache`, `DPoP.NonceStore.ETS`) **refuses to boot on a clustered
BEAM** unless you pass `multi_node_acknowledged?: true`, which forces the
choice: wire a shared store, or explicitly accept the single-node
constraint.

## Status

A stable `1.x` release: the public API follows [semantic versioning](https://semver.org/) — minor and patch releases are backward-compatible and breaking changes wait for a new major version (read the CHANGELOG before upgrading). Implemented and tested: token issue/verify, DPoP, mTLS certificate-bound tokens, scope, keystore, PKCE validation, JWKS publication, OIDC discovery, the authorization-code grant (single-use, optionally DPoP-bound), refresh-token rotation with reuse detection, token revocation (RFC 7009, refresh-token family), Pushed Authorization Request primitives (RFC 9126), Resource Indicators (RFC 8707), signed request-object policy (JAR) and JARM response signing, token introspection and signed introspection response JWTs, Step-Up Authentication challenges (RFC 9470), the JWT-assertion (`jwt-bearer`) grant, the Device Authorization Grant (RFC 8628), Client-Initiated Backchannel Authentication (CIBA; poll/ping, signed requests per FAPI-CIBA), the RP-Initiated / Back-Channel / Front-Channel Logout and Session Management primitives, RFC 9728 protected-resource metadata, Client ID Metadata Document (CIMD) verification, and `:telemetry` events for security-relevant refusals. The stateful grants run against the `Attesto.CodeStore` / `Attesto.RefreshStore` behaviours, with ETS reference implementations included; a production host either takes the Ecto implementations from `attesto_phoenix` or writes its own (the atomic-`take` and atomic-`consume` contracts are documented). Cross-language parity tests check Attesto-issued artifacts against a reference implementation in another language. Pin to `~> 1.5`.

## Development

```sh
mix deps.get
mix test
mix precommit   # format --check-formatted, compile --warnings-as-errors, credo --strict, test
```

The cross-language parity tests drive a reference `joserfc` / `cryptography`
stack in-process via `erlang_python` and run as part of `mix test` (they
self-skip when that Python stack is not installed). Install it with
`pip install joserfc cryptography` against the interpreter `erlang_python`
loads.

## License

MIT, Copyright (c) Neil Berkman. See [LICENSE](LICENSE).
