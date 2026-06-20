# @operatum/auth

App-side authentication SDK for apps built on the Operatum platform.
**Zero runtime dependencies** — only `node:crypto` and the global `fetch`.

Every Operatum-built app imports this package to identify the caller
and gate its routes. It supports the platform's two auth postures:

- **Reverse-proxy (header) mode** — the *default*. The gateway edge
  authenticates the user and injects verified `X-Operatum-*` identity
  headers; the app trusts them by topology. **Zero config.**
- **Bearer (JWT) mode** — the legacy/explicit posture. The app verifies
  an Operatum-issued RS256 JWT against the gateway's published JWKS.

Both factories return the **same object shape**
(`middleware`, `requirePerm`, `verify`) and both populate the same
`req.operatum` identity, so an app can swap one for the other without
touching its route code.

> The auth posture is pinned in `.operatum/manifest.yaml`
> (`auth.mode: reverse-proxy` | `bearer`). The code and the manifest
> must stay in lockstep — a mismatch makes every request 401.

## Install

```bash
npm install @operatum/auth
```

Requires Node 18+ (global `fetch`, `createPublicKey({ format: 'jwk' })`).

---

## Mode 1 — Reverse-proxy / header mode (default)

This is what the platform scaffold uses. The gateway sits in front of
the app, authenticates the user itself, and forwards identity as
`X-Operatum-*` request headers. The app reads them — **no JWKS, no
audience, no login URL, no handoff endpoint.**

```js
import express from 'express';
import { createOperatumAuthFromHeaders } from '@operatum/auth';

const app = express();
app.use(express.json());

// Public routes BEFORE the gate so they aren't 401'd.
app.get('/healthz', (_req, res) => res.json({ ok: true }));

const auth = createOperatumAuthFromHeaders();   // zero config

app.use(auth.middleware());                       // gate everything below

app.get('/me', (req, res) => res.json({ user: req.operatum }));

app.post('/deploy', auth.requirePerm('build'), (req, res) => { /* ... */ });

app.listen(process.env.PORT);
```

**Trust model is topology, not crypto.** The app container publishes
loopback-only (`--publish 127.0.0.1::N`) and joins the per-build docker
network, so the gateway is the only origin that can reach the app's
port. Any `X-Operatum-*` header that arrives therefore came from the
gateway. The gateway strips client-supplied `X-Operatum-*` headers on
the way in, so a browser cannot forge identity. **Outside this topology
(local dev, foreign k8s networking) header mode is unsafe — use bearer
mode instead.**

A request that arrives without valid headers gets a flat
`401 { ok:false, error:'unauthenticated', reason:'missing_or_invalid_operatum_headers' }`.
There is no login redirect or fragment recovery — that's the gateway's
job on the front side.

### Cross-app dependency / service tokens (optional)

When one app calls another directly (container→container, bypassing the
gateway edge), the call carries only a `Bearer` **service** token — no
identity headers. `createOperatumAuthFromHeaders().middleware()` verifies
those automatically when this app's build id + a JWKS are resolvable
(from opts or platform-injected env: `OPERATUM_APP_ID`/`OPERATUM_BUILD_ID`,
`OPERATUM_GATEWAY_URL` or `OPERATUM_JWKS_URL`). Verified service callers
get `req.operatum.principalKind === 'service'`. Gate them with
`auth.requireDepScope()` / `auth.requireDepScope({ tool })`. Disable with
`createOperatumAuthFromHeaders({ enableServiceTokens: false })`.

---

## Mode 2 — Bearer / JWT mode

The app verifies an Operatum-issued RS256 JWT against the gateway's
JWKS. Use this when the app runs *outside* the reverse-proxy topology,
or when the manifest declares `auth.mode: bearer`.

```js
import express from 'express';
import { createOperatumAuth } from '@operatum/auth';

const app = express();

const auth = createOperatumAuth({
  jwksUri: 'https://operatum.example.com/.well-known/jwks.json',
  expectedAudience: `operatum-app:${process.env.OPERATUM_APP_ID}`,
  loginUrl: 'https://operatum.example.com/login', // browser fallback (optional)
});

app.use(auth.middleware());
app.get('/me', (req, res) => res.json({ user: req.operatum }));
app.post('/deploy', auth.requirePerm('build'), (req, res) => { /* ... */ });
app.listen(3000);
```

The middleware verifies the signature against the matching `kid`, then
checks `iss = 'operatum'`, `aud === expectedAudience`, and `exp`/`iat`
(30s clock skew). It rejects any algorithm other than RS256. Key
rotation is handled transparently: an unknown `kid` forces one JWKS
refresh before the token is rejected.

### Token sources (first match wins)

1. `Authorization: Bearer <token>` — for API calls.
2. `operatum.session` cookie — set by the app after the SPA hands off
   the token (see fragment handoff below). Best for SPAs.
3. `?operatum_token=<token>` query string — initial landing only; the
   app should redirect to itself without it.

### Fragment handoff (SPA apps)

The Operatum SPA opens the app with the token in the URL fragment
(`https://your-app/#operatum_token=...`) — fragments never reach the
server, keeping the raw token out of access logs. Mount the handoff
endpoint and POST the fragment on first load:

```js
auth.mountHandoff(app);   // registers POST /_operatum/auth/handoff
```

```js
// client
const m = location.hash.match(/(?:^|&)operatum_token=([^&]+)/);
if (m) {
  await fetch('/_operatum/auth/handoff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ token: decodeURIComponent(m[1]) }),
  });
  history.replaceState(null, '', location.pathname + location.search);
}
```

The endpoint verifies the token and sets an httpOnly `operatum.session`
cookie (transport-aware `Secure` flag; override via
`mountHandoff(app, { cookieSecure, cookieSameSite, path })`). When
unauthenticated browser GETs hit a gated route, the middleware also
serves a tiny bootstrap HTML that runs this same handoff before falling
back to a `loginUrl?next=<url>` redirect.

### Behavior on auth failure (bearer mode)

- Browser requests: serve bootstrap HTML → handoff or redirect to
  `loginUrl?next=<original-url>` (always 401 if no `loginUrl`).
- API requests (`Accept: application/json` or XHR):
  `401 { ok:false, error:'unauthenticated', reason:'<code>' }`.

Reason codes: `no_token`, `malformed`, `alg_mismatch`, `missing_kid`,
`unknown_kid`, `bad_signature`, `bad_issuer`, `bad_audience`, `expired`,
`not_yet_valid`.

---

## `req.operatum` shape (both modes)

```js
{
  userId:   'uuid',              // header mode: x-operatum-user-id | bearer: payload.sub
  email:    'you@operatum.com',
  tenantId: 'uuid',
  appId:    '<buildId>',         // the app this identity is scoped to
  role:     'admin'|'builder'|'reviewer'|'viewer',
  perms:    ['use'] | ['use','build'] | [],
  // displayName present only in header mode when the gateway sends it
  raw:      { /* headers (header mode) | decoded JWT payload (bearer mode) */ },
}
```

Service principals (dep tokens) instead carry
`principalKind:'service'`, `role:'service'`, `serviceName`, `scopes`,
and `userId/email = null`.

## API surface

| Export | Mode | Purpose |
| --- | --- | --- |
| `createOperatumAuthFromHeaders(opts?)` | header | factory → `{ middleware, requirePerm, requireDepScope, verify }` |
| `createOperatumAuth(opts)` | bearer | factory → `{ middleware, requirePerm, verify, jwks, mountHandoff }` |
| `verifyToken(token, opts)` | bearer | low-level JWT verify |
| `JwksCache` | bearer | JWKS fetch + cache |
| `TokenError` | bearer | typed verify error (`.code`) |
| `readOperatumHeaders(headers)` | header | parse/validate `X-Operatum-*` → identity\|null |
| `verifyDepToken` / `parseDepScope` / `parseDepToolScope` | service | dep-token verification helpers |

Works with both Express (`req.get`/`res.status`) and Fastify
(`req.headers`/`reply.code`) — the middleware detects the framework.

See `ARCHITECTURE.md` for the full header contract, the JWT audience
binding, and what this SDK exposes vs. consumes.
