# @operatum/auth — architecture

`@operatum/auth` is the **app-side authentication SDK** that every
Operatum-built app imports. It is a LIBRARY (zero runtime deps —
`node:crypto` + the global `fetch`; `package.json:2-6`, `:20-22`), not a
service. It runs in the consuming app's process and hands each route the
authenticated caller via `req.operatum`.

**This repo does NOT issue or mint tokens.** RS256 signing and JWKS
publication are the gateway's job (a separate repo, out of scope here).
This SDK is purely the *relying party*: it **verifies** gateway-issued
RS256 JWTs against the gateway's published JWKS (bearer + service modes)
and **reads** gateway-injected `X-Operatum-*` identity headers
(reverse-proxy mode). Everything below is verified against this repo's
source; each load-bearing claim cites the file and lines it was read
from.

It implements the app side of two auth postures the platform supports.
Which one an app uses is pinned in `.operatum/manifest.yaml`
(`auth.mode`); the SDK has one factory per mode and both return the same
adapter shape so route code is mode-agnostic.

Public entry point: `src/index.js` (exports at `src/index.js:1-19`).

---

## The two auth modes

### Mode 1 — Reverse-proxy / header trust (default)

File: `src/header-mode.js`.

The gateway authenticates the user at the edge and **injects**
`X-Operatum-*` identity headers when proxying to the app. The app trusts
them because of **topology, not crypto**: the app port is loopback-only
(`--publish 127.0.0.1::N`) on a per-build docker network, so the gateway
is the only origin that can reach it (trust model documented at
`src/header-mode.js:9-24`). The gateway is expected to strip
client-supplied `X-Operatum-*` headers inbound, closing the spoof vector;
that stripping lives in the gateway repo (external — not verifiable from
here). Outside this topology (local dev, foreign k8s networking) header
mode is unsafe and apps should use bearer mode instead
(`src/header-mode.js:20-24`).

- `createOperatumAuthFromHeaders(opts?)` — factory
  (`src/header-mode.js:227`). Zero config by default: no JWKS, audience,
  cookie, or handoff. Returns
  `{ middleware, requirePerm, requireDepScope, verify }`
  (`src/header-mode.js:355`).
- `readOperatumHeaders(headers, opts?)` — the protocol reader
  (`src/header-mode.js:142`). Validates every field and returns a clean
  identity or `null` on *any* malformed header (no half-authenticated
  states): UUID checks for user/tenant/build ids
  (`src/header-mode.js:154-156`), a present email + a known role
  (`:157`), the `auth-mode` bypass guard (`:162`), and a JSON-array
  `perms` (`:171-175`). It is **vendored** from the gateway's
  `operatum-headers.js` (the SDK can't import gateway code); the wire
  protocol is the contract and both sides are pinned by tests in their
  respective repos (rationale at `src/header-mode.js:126-134`). When
  called with `{ secret }` it additionally REQUIRES a valid, fresh HMAC
  signature over the header set (see *HMAC proof-of-gateway* below) —
  presence alone is then not sufficient (`src/header-mode.js:167-169`).
- The middleware maps the identity onto `req.operatum`
  (`src/header-mode.js:253-265`); a missing/invalid set yields a flat
  `401 { ok:false, error:'unauthenticated', reason:'missing_or_invalid_operatum_headers' }`
  (`src/header-mode.js:301-305`).
- `verify()` is an **inert stub** in this mode — there is no token to
  verify, so it always throws (`src/header-mode.js:347-353`). It exists
  only for shape-parity with bearer mode.

#### HMAC proof-of-gateway (defense-in-depth, OFF by default)

Topology is the primary trust anchor; an HMAC signature is an **optional
second factor** layered on top. It is **dormant unless a per-deploy
shared secret is configured** — `opts.secret`, else
`process.env.OPERATUM_GATEWAY_SIGNING_SECRET`
(resolved at `src/header-mode.js:232`). When present, the middleware
requires a valid signature before it accepts any identity headers
(`src/header-mode.js:248` passes the secret into the reader):

- `verifyOperatumSignature` (`src/header-mode.js:97-117`) recomputes an
  HMAC-SHA256 over a **pinned canonical string** —
  `canonicalStringForSigning` (`src/header-mode.js:87-95`) joins the
  identity headers in the frozen `OPERATUM_HEADER_NAMES` order
  (`src/header-mode.js:76-85`) plus the timestamp — and compares it to
  `x-operatum-signature` with `timingSafeEqual` (`src/header-mode.js:116`).
- Replay is bounded: `x-operatum-timestamp` must be within
  `DEFAULT_SIGNATURE_MAX_AGE_MS` (±5 min) of now (`src/header-mode.js:73`,
  `:106`).
- The provided signature must be exactly 64 hex chars before any buffer
  work, so a non-ASCII value can't make `timingSafeEqual` throw
  (`src/header-mode.js:112`).
- The signer is the gateway's `operatum-headers.js`; the canonical-string
  protocol is **vendored in sync** and pinned by
  `test/header-mode-hmac.test.js`.

When the secret is absent the middleware stays in presence-only mode for
backward-compatible rollout (`src/header-mode.js:248`) — no behaviour
change for existing zero-config callers.

### Mode 2 — Bearer / JWKS verification

Files: `src/middleware.js`, `src/jwt-verify.js`, `src/jwks-cache.js`.

The app verifies a gateway-issued RS256 JWT against the gateway's
published JWKS. Used when the app runs outside the reverse-proxy
topology, or when the manifest declares `auth.mode: bearer`.

- `createOperatumAuth({ jwksUri, expectedAudience, loginUrl, ... })` —
  factory (`src/middleware.js:210`). Returns
  `{ middleware, requirePerm, verify, jwks, mountHandoff }`
  (`src/middleware.js:380`). Requires `jwksUri` + `expectedAudience`
  (`src/middleware.js:218-219`).
- Token sources (first match wins): `Authorization: Bearer`, the
  `operatum.session` cookie, then a `?operatum_token=` query param
  (`extractToken`, `src/middleware.js:182-189`).
- `verifyToken(token, { jwks, expectedAudience, issuer, clockSkewSec })`
  — signature + claim validation (`src/jwt-verify.js:56`). RS256-only
  (`src/jwt-verify.js:77`); requires a `kid` (`:78`); checks `iss`
  (`:97-99`), exact `aud` (`:100-103`), and `exp`/`iat` with skew
  (`:107-112`).
- `JwksCache` (`src/jwks-cache.js:19`) — fetches the configured
  `jwksUri`, caches RSA keys by `kid` for 5 min
  (`DEFAULT_MAX_AGE_MS`, `src/jwks-cache.js:16`, `:45-49`), and
  **refreshes on unknown kid** to ride through gateway key rotations
  (`src/jwt-verify.js:80-86`, `src/jwks-cache.js:56-58`).
- `TokenError` (`src/jwt-verify.js:11-17`) carries a `.code` used as the
  401 `reason`.

### Mode 3 (sub-mode) — Cross-app dependency / service tokens

File: `src/service-mode.js`. Layered *into* header mode.

A direct app→app dep call (container→container, bypassing the gateway
edge) carries only a `Bearer` **service** token, no identity headers, so
the producer must verify it itself (design documented at
`src/service-mode.js:1-22`). Header mode's middleware does this
automatically when this app's build id + a JWKS are resolvable: the
dep-token branch runs when no identity headers matched
(`src/header-mode.js:269-296`), with config assembled by
`resolveServiceConfig` (`src/header-mode.js:363-385`). It is **dormant
unless activated** — `resolveServiceConfig` returns `null` (pure header
mode) when service tokens are disabled or this app's build id / a JWKS
are absent (`src/header-mode.js:364-372`); existing zero-config callers
are unaffected. Disable explicitly with `{ enableServiceTokens: false }`.

`verifyDepToken` (`src/service-mode.js:58`) does, in order: (1) crypto
verify via `verifyToken` with `audiencePrefix: 'operatum-service:'`
(`:65`) and a `role === 'service'` check (`:66`); (2) a same-tenant check
when `ownTenantId` is set (`:72-74`); (3) a `app:dep:<ownBuildId>` scope
grant (`:77-80`); (4) a **fail-closed** revocation callback to the
gateway introspection endpoint when `introspectUrl` is set (`:82-86`;
non-2xx / network error → treated as inactive, `:96-108`).
`requireDepScope({ tool })` (`src/header-mode.js:324-342`) gates routes:
it requires a verified `service` principal (`:327-329`) holding a dep
scope for this app, with an optional per-tool scope (`:331-336`).

---

## The middleware

Both factories expose `middleware()` — a framework-agnostic handler that
populates `req.operatum` then calls `next()`, or rejects. Framework
detection (Express `req.get`/`res.status` vs. Fastify
`req.headers`/`reply.code`) is normalised by small adapters
(`src/middleware.js:39-72`, `src/header-mode.js:192-206`) — added after a
Fastify crash on the Express-only `req.get('host')`
(`src/middleware.js:9-13`).

`requirePerm(perm)` gates a route on a grant in `req.operatum.perms`
(`src/middleware.js:273-283`, `src/header-mode.js:309-319`), assuming
`middleware()` already ran. Service principals carry an empty `perms`
array, so `requirePerm` always 403s them (`src/header-mode.js:282`).

Bearer-only: `mountHandoff(app, opts?)` (`src/middleware.js:317`)
registers `POST /_operatum/auth/handoff`, which verifies the
fragment-delivered token and sets an httpOnly `operatum.session` cookie
(`src/middleware.js:336-377`) with a **transport-aware** `Secure` flag
(`reqIsSecure`, `src/middleware.js:328-334`; applied `:359-362`). On
unauthenticated browser GETs the middleware serves a bootstrap HTML that
runs the same handoff before falling back to a `loginUrl?next=` redirect
(`buildBootstrapHtml`, `src/middleware.js:129-171`; `denyUnauthenticated`,
`:227-244`). The bootstrap serves a 200 HTML page rather than a bare 302
to avoid racing the fragment handoff (rationale, `:104-127`). Overriding
the bootstrap's handoff path is noted **planned/not implemented**
(`src/middleware.js:132-135`).

---

## `req.operatum` shape

Set by header mode at `src/header-mode.js:253-265` and by bearer mode at
`src/middleware.js:252-260`:

```js
{
  userId,    // header: x-operatum-user-id      | bearer: payload.sub
  email,     // header: x-operatum-email        | bearer: payload.email
  tenantId,  // header: x-operatum-tenant-id    | bearer: payload.tenant_id
  appId,     // header: x-operatum-build-id     | bearer: payload.app_id
  role,      // 'admin'|'builder'|'reviewer'|'viewer'
  perms,     // string[]  e.g. ['use'] | ['use','build'] | []
  displayName?, // header mode only, when the gateway sends it
  raw,       // header: the parsed headers      | bearer: the decoded JWT payload
}
```

Service principals (dep tokens) instead carry `principalKind:'service'`,
`role:'service'`, `serviceName`, `scopes`, and `userId/email = null`
(`src/header-mode.js:275-286`).

### No delegation / act-chain in this repo

The ticket asks about a "delegation act-chain (audit-only)". **Verified
against source: this repo has none.** A search of `src/*.js` finds no
delegation, on-behalf-of, actor, or act-chain construct. Every
authenticated request resolves to exactly ONE principal — either a user
identity (`src/header-mode.js:253-265`, `src/middleware.js:252-260`) or a
single service principal (`src/header-mode.js:275-286`) — with no
delegating/acting party recorded on the request.

The only audit-adjacent surface here is `req.operatum.raw`, which mirrors
the parsed headers (header mode) or the decoded JWT payload (bearer mode)
for debugging/introspection (`src/header-mode.js:261-264`,
`src/middleware.js:259`), plus the service token's `scopes` array. Any
act-chain concept, if it exists on the platform, lives in the gateway
(external repo) and is deliberately out of scope for this doc.

---

## The `X-Operatum-*` header contract (CONSUMED in header mode)

Produced by the gateway (external — not verifiable from this repo) and
read by `readOperatumHeaders` (`src/header-mode.js:142-188`). The
inventory this SDK validates:

| Header | Value | Validated at |
| --- | --- | --- |
| `x-operatum-user-id` | UUID | `src/header-mode.js:154` |
| `x-operatum-tenant-id` | UUID | `src/header-mode.js:155` |
| `x-operatum-build-id` | UUID (→ `appId`) | `src/header-mode.js:156` |
| `x-operatum-email` | present, then percent-decoded | `src/header-mode.js:157`, `:179` |
| `x-operatum-role` | one of the 4 roles | `src/header-mode.js:157` |
| `x-operatum-perms` | JSON array string | `src/header-mode.js:171-175` |
| `x-operatum-auth-mode` | must equal `'reverse-proxy'` | `src/header-mode.js:162` |
| `x-operatum-display-name` | percent-encoded, optional | `src/header-mode.js:182-186` |
| `x-operatum-timestamp` | epoch ms, HMAC mode only | `src/header-mode.js:101-106` |
| `x-operatum-signature` | 64 hex chars, HMAC mode only | `src/header-mode.js:102-116` |

`x-operatum-auth-mode` is the **bypass guard**: a request lacking it (or
carrying the legacy `bearer` literal) must NOT authenticate via headers —
that path belongs to the JWT verifier (`src/header-mode.js:158-162`).
Free-text fields (`email`, `display-name`) are percent-decoded because
HTTP/1.1 headers are ASCII-only (`src/header-mode.js:179`, `:182-186`).

## The JWT audience binding (bearer mode)

The gateway is the issuer and mints app tokens with `iss: 'operatum'` and
`aud: operatum-app:<buildId>` (issuance is external — not verifiable from
this repo). The app sets `expectedAudience` to
`operatum-app:${OPERATUM_APP_ID}` and `verifyToken` requires an **exact**
match (`src/jwt-verify.js:100-103`) — so a token minted for app A cannot
authenticate at app B. Service tokens instead use
`aud: operatum-service:<name>`, matched by **prefix** because the name
varies per token (`src/jwt-verify.js:104-106`, `src/service-mode.js:65`).
`verifyToken` enforces exactly one of `expectedAudience` /
`audiencePrefix` (`src/jwt-verify.js:65-70`).

The public verification key is fetched from the configured `jwksUri`
(the app points this at `<gateway>/.well-known/jwks.json`); only RSA keys
with a `kid`, `n`, and `e` are cached (`src/jwks-cache.js:70-73`).
Rotation is handled by the unknown-kid refresh path above.

## Failure reasons

Bearer/handoff `reason` codes surfaced as `401 { ok:false,
error:'unauthenticated', reason:'<code>' }`: `no_token`
(`src/middleware.js:249`) plus the `TokenError.code` values —
`malformed`, `alg_mismatch`, `missing_kid`, `unknown_kid`,
`bad_signature`, `bad_issuer`, `bad_audience`, `expired`, `not_yet_valid`
(`src/jwt-verify.js:73-111`), and the config-time `misconfigured`
(`:64-69`). Header mode returns a single flat reason,
`missing_or_invalid_operatum_headers` (`src/header-mode.js:304`).

---

## EXPOSES (the app's API) vs. CONSUMES (the platform's surface)

**EXPOSES** — what an app imports from `src/index.js` (`src/index.js:1-19`):

- `createOperatumAuthFromHeaders` / `readOperatumHeaders` (header mode)
- `createOperatumAuth` (bearer mode) → `middleware`, `requirePerm`,
  `verify`, `jwks`, `mountHandoff`
- `verifyToken`, `JwksCache`, `TokenError` (low-level bearer primitives)
- `verifyDepToken`, `parseDepScope`, `parseDepToolScope` (service tokens)
- the `req.operatum` identity object on every authenticated request

**CONSUMES** — the platform/gateway surface the SDK depends on (all
external; described here as the contract, not as verified gateway code):

- the gateway-injected `X-Operatum-*` request headers (header mode) +
  the loopback/per-build-network topology that makes them trustworthy
- the gateway JWKS the app points `jwksUri` at (bearer + service modes) —
  fetched via `JwksCache`
- the JWT contract: `iss='operatum'`, RS256, `aud=operatum-app:<buildId>`
  / `operatum-service:<name>`, claims `sub`/`email`/`tenant_id`/`app_id`/
  `role`/`perms`/`scopes` (as read at `src/middleware.js:252-260`,
  `src/service-mode.js:65-93`)
- the gateway service-token introspection endpoint for dep-token
  revocation (`introspectUrl`, `src/service-mode.js:82-86`)
- platform-injected env: `OPERATUM_APP_ID`/`OPERATUM_BUILD_ID`,
  `OPERATUM_GATEWAY_URL`/`OPERATUM_JWKS_URL`, `OPERATUM_TENANT_ID`,
  `OPERATUM_GATEWAY_SIGNING_SECRET` (resolved at
  `src/header-mode.js:232`, `:365-369`, `:376`)
- `.operatum/manifest.yaml` `auth.mode` — must match the chosen factory

---

## Where to start

- `src/index.js` — public API surface
- `src/header-mode.js` — reverse-proxy mode + HMAC + service tokens
- `src/middleware.js` — bearer mode middleware + handoff
- `src/jwt-verify.js` / `src/jwks-cache.js` — JWT crypto + JWKS cache
- `src/service-mode.js` — cross-app dep-token verification
</content>
