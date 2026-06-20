# @operatum/auth — architecture

`@operatum/auth` is the **app-side authentication SDK** that every
Operatum-built app imports. It is a LIBRARY (zero runtime deps —
`node:crypto` + global `fetch`), not a service; it runs in the
consuming app's process and gives each route the authenticated caller
via `req.operatum`.

It implements the app side of two auth postures the platform supports.
Which one an app uses is pinned in `.operatum/manifest.yaml`
(`auth.mode`); the SDK has one factory per mode and both return the same
adapter shape so route code is mode-agnostic.

Public entry point: `src/index.js`.

---

## The two auth modes

### Mode 1 — Reverse-proxy / header trust (default)

File: `src/header-mode.js`.

The gateway authenticates the user at the edge and **injects**
`X-Operatum-*` identity headers when proxying to the app. The app trusts
them because of **topology, not crypto**: the app port is loopback-only
on a per-build docker network, so the gateway is the only origin that
can reach it (`src/header-mode.js:9-24`). The gateway also strips
client-supplied `X-Operatum-*` headers inbound (gateway
`src/lib/operatum-headers.js:32-37`), closing the spoof vector.

- `createOperatumAuthFromHeaders(opts?)` — factory
  (`src/header-mode.js:140`). Zero config: no JWKS, audience, cookie, or
  handoff. Returns `{ middleware, requirePerm, requireDepScope, verify }`
  (`src/header-mode.js:261`).
- `readOperatumHeaders(headers)` — the protocol reader
  (`src/header-mode.js:71`). Validates every field and returns a clean
  identity or `null` on *any* malformed header (no half-authenticated
  states). It is **vendored** from the gateway's `operatum-headers.js`
  (the SDK can't import gateway code); the wire protocol is the contract
  and both sides are pinned by tests (`src/header-mode.js:61-69`).
- The middleware maps the identity onto `req.operatum`
  (`src/header-mode.js:155-172`); a missing/invalid set yields a flat
  `401` (`src/header-mode.js:206-211`).
- `verify()` throws in this mode — there is no token to verify
  (`src/header-mode.js:253-259`).

### Mode 2 — Bearer / JWKS verification

Files: `src/middleware.js`, `src/jwt-verify.js`, `src/jwks-cache.js`.

The app verifies an Operatum-issued RS256 JWT against the gateway's
published JWKS. Used when the app runs outside the reverse-proxy
topology, or when the manifest declares `auth.mode: bearer`.

- `createOperatumAuth({ jwksUri, expectedAudience, loginUrl, ... })` —
  factory (`src/middleware.js:210`). Returns
  `{ middleware, requirePerm, verify, jwks, mountHandoff }`
  (`src/middleware.js:380`). Requires `jwksUri` + `expectedAudience`
  (`src/middleware.js:218-219`).
- `verifyToken(token, { jwks, expectedAudience, issuer, clockSkewSec })`
  — signature + claim validation (`src/jwt-verify.js:56`). RS256-only
  (`src/jwt-verify.js:77`); checks `iss` (`:97`), `aud`
  (`:100-106`), `exp`/`iat` with skew (`:107-112`).
- `JwksCache` (`src/jwks-cache.js:19`) — fetches
  `<gateway>/.well-known/jwks.json`, caches by `kid` for 5 min
  (`:16`), and **refreshes on unknown kid** to ride through gateway key
  rotations (`src/jwt-verify.js:81-86`, `src/jwks-cache.js:43-50`).
- `TokenError` (`src/jwt-verify.js:11`) carries a `.code` used as the
  401 `reason`.

### Mode 3 (sub-mode) — Cross-app dependency / service tokens

File: `src/service-mode.js`. Layered *into* header mode.

A direct app→app dep call (container→container, bypassing the gateway
edge) carries only a `Bearer` **service** token, no identity headers.
The producer must verify it itself (`src/service-mode.js:1-22`). Header
mode's middleware does this automatically when this app's build id + a
JWKS are resolvable (`src/header-mode.js:140-202`, config resolved in
`resolveServiceConfig`, `src/header-mode.js:269-291`).

`verifyDepToken` (`src/service-mode.js:58`) does: (1) crypto verify with
`audiencePrefix: 'operatum-service:'`, role `service`; (2) same-tenant
check; (3) a `app:dep:<ownBuildId>` scope grant; (4) a fail-closed
revocation callback to the gateway introspection endpoint
(`src/service-mode.js:64-94`). `requireDepScope({ tool })`
(`src/header-mode.js:230-248`) gates routes on those scopes.

---

## The middleware

Both factories expose `middleware()` — a framework-agnostic handler that
populates `req.operatum` then calls `next()`, or rejects. Framework
detection (Express `req.get`/`res.status` vs. Fastify
`req.headers`/`reply.code`) is normalised by small adapters
(`src/middleware.js:39-72`, `src/header-mode.js:114-128`) — added after a
Fastify crash on the Express-only `req.get('host')`
(`src/middleware.js:9-13`).

`requirePerm(perm)` gates a route on a grant in `req.operatum.perms`
(`src/middleware.js:273-283`, `src/header-mode.js:215-225`), assuming
`middleware()` already ran.

Bearer-only: `mountHandoff(app, opts?)` (`src/middleware.js:317`)
registers `POST /_operatum/auth/handoff`, which verifies the
fragment-delivered token and sets an httpOnly `operatum.session` cookie
with a **transport-aware** `Secure` flag (`src/middleware.js:328-362`).
On unauthenticated browser GETs the middleware serves a bootstrap HTML
that runs the same handoff before falling back to a `loginUrl?next=`
redirect (`buildBootstrapHtml`, `src/middleware.js:129-171`;
`denyUnauthenticated`, `:227-244`).

---

## `req.operatum` shape

Set by header mode at `src/header-mode.js:159-171` and by bearer mode at
`src/middleware.js:252-260`:

```js
{
  userId,    // header: x-operatum-user-id      | bearer: payload.sub
  email,     // header: x-operatum-email        | bearer: payload.email
  tenantId,  // header: x-operatum-tenant-id    | bearer: payload.tenant_id
  appId,     // header: x-operatum-build-id     | bearer: payload.app_id
  role,      // 'admin'|'builder'|'reviewer'|'viewer'
  perms,     // string[]  e.g. ['use'] | ['use','build'] | []
  displayName?, // header mode only, when sent
  raw,       // header: the parsed headers      | bearer: the decoded JWT payload
}
```

Service principals (dep tokens) instead carry `principalKind:'service'`,
`role:'service'`, `serviceName`, `scopes`, `userId/email = null`
(`src/header-mode.js:181-191`).

---

## The `X-Operatum-*` header contract (CONSUMED in header mode)

Produced by the gateway (`buildOperatumHeaders`,
`gateway/src/lib/operatum-headers.js:79`) and read by
`readOperatumHeaders` (`src/header-mode.js:71`). Both ends pin the same
inventory:

| Header | Value | Validated at |
| --- | --- | --- |
| `x-operatum-user-id` | UUID | `src/header-mode.js:83` |
| `x-operatum-tenant-id` | UUID | `:84` |
| `x-operatum-build-id` | UUID (→ `appId`) | `:85` |
| `x-operatum-email` | percent-encoded, decoded | `:86`, `:101` |
| `x-operatum-display-name` | percent-encoded, optional | `:104-108` |
| `x-operatum-role` | one of the 4 roles | `:86` |
| `x-operatum-perms` | JSON array string | `:93-97` |
| `x-operatum-auth-mode` | must equal `'reverse-proxy'` | `:91` |

`x-operatum-auth-mode` is the **bypass guard**: a request lacking it (or
carrying `bearer`) must NOT authenticate via headers — that path belongs
to the JWT verifier (`src/header-mode.js:87-91`). Free-text fields are
percent-encoded because HTTP/1.1 headers are ASCII-only (rationale:
gateway `src/lib/operatum-headers.js:50-57`).

## The JWT audience binding (bearer mode)

The gateway is the issuer (`signAppLoginToken`,
`gateway/src/auth/jwt.js`) and mints app tokens with
`aud: operatum-app:<buildId>` (`gateway/src/auth/jwt.js:223`),
`iss: 'operatum'`. The app sets `expectedAudience` to
`operatum-app:${OPERATUM_APP_ID}` and `verifyToken` requires an exact
match (`src/jwt-verify.js:100-103`) — so a token minted for app A cannot
authenticate at app B. Service tokens use `aud: operatum-service:<name>`
(`gateway/src/auth/jwt.js:466`), matched by **prefix** because the name
varies per token (`src/jwt-verify.js:104-106`, `src/service-mode.js:65`).

The public verification key is published at
`<gateway>/.well-known/jwks.json`; the private key lives in the
gateway's secret store. Rotation publishes new + previous keys during a
grace window so in-flight tokens keep verifying.

---

## EXPOSES (the app's API) vs. CONSUMES (the platform's surface)

**EXPOSES** — what an app imports from `src/index.js`:

- `createOperatumAuthFromHeaders` / `readOperatumHeaders` (header mode)
- `createOperatumAuth` (bearer mode) → `middleware`, `requirePerm`,
  `verify`, `jwks`, `mountHandoff`
- `verifyToken`, `JwksCache`, `TokenError` (low-level bearer primitives)
- `verifyDepToken`, `parseDepScope`, `parseDepToolScope` (service tokens)
- the `req.operatum` identity object on every authenticated request

**CONSUMES** — the platform/gateway surface the SDK depends on:

- the gateway-injected `X-Operatum-*` request headers (header mode) +
  the loopback/per-build-network topology that makes them trustworthy
- the gateway JWKS at `<gateway>/.well-known/jwks.json` (bearer +
  service modes) — fetched via `JwksCache`
- the JWT contract: `iss='operatum'`, RS256, `aud=operatum-app:<buildId>`
  / `operatum-service:<name>`, claims `sub`/`email`/`tenant_id`/`app_id`/
  `role`/`perms`/`scopes`
- the gateway service-token introspection endpoint
  (`/api/service-tokens/introspect`) for dep-token revocation
- platform-injected env: `OPERATUM_APP_ID`/`OPERATUM_BUILD_ID`,
  `OPERATUM_GATEWAY_URL`/`OPERATUM_JWKS_URL`, `OPERATUM_TENANT_ID`
- `.operatum/manifest.yaml` `auth.mode` — must match the chosen factory

---

## How the scaffold uses it

`gateway/src/lib/scaffold/express-node/src/main.js` is committed into a
build's seed commit and uses header mode: it mounts public routes
(`/healthz`, `/openapi.json`) before the gate, then
`createOperatumAuthFromHeaders()` + `app.use(auth.middleware())`; routes
below the marker get `req.operatum`. The deploy gate validates that the
auth middleware, `/healthz`, and the `PORT` binding are present.

## Where to start

- `src/index.js` — public API surface
- `src/header-mode.js` — reverse-proxy mode + service tokens
- `src/middleware.js` — bearer mode middleware + handoff
- `src/jwt-verify.js` / `src/jwks-cache.js` — JWT crypto + JWKS cache
- `src/service-mode.js` — cross-app dep-token verification
