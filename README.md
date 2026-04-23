# @operatum/auth

Verify Operatum-issued JWTs in apps built on the Operatum platform.
Zero runtime dependencies — uses `node:crypto` and global `fetch`.

## What it does

Operatum acts as the Identity Provider for every app it builds. The
Operatum SPA authenticates users (Google SSO or password), mints a
short-lived RS256 JWT scoped to one app, and hands it to the app.
This package is what the app uses to verify that token and identify
the caller.

- Fetches and caches Operatum's JWKS (`/.well-known/jwks.json`).
- Verifies RS256 signatures, rejects any other algorithm.
- Checks `iss`, `aud`, `exp`, `iat` with a small clock skew allowance.
- Handles gateway key rotations transparently (refresh-on-unknown-kid).
- Provides Express middleware that populates `req.operatum`.

## Install

```bash
npm install @operatum/auth
```

## Use

```js
import express from 'express';
import { createOperatumAuth } from '@operatum/auth';

const app = express();

const auth = createOperatumAuth({
  jwksUri: 'https://operatum.example.com/.well-known/jwks.json',
  expectedAudience: `operatum-app:${process.env.OPERATUM_APP_ID}`,
  loginUrl: 'https://operatum.example.com/login', // browser fallback
});

// Every route below this line requires a valid Operatum JWT.
app.use(auth.middleware());

app.get('/me', (req, res) => {
  res.json({ user: req.operatum });
});

// Fine-grained grant gate: only users with the `build` grant can redeploy.
app.post('/deploy', auth.requirePerm('build'), async (req, res) => {
  // ...
});

app.listen(3000);
```

### `req.operatum` shape

```js
{
  userId:   'uuid',              // Operatum user id (payload.sub)
  email:    'you@operatum.com',  // Operatum email
  tenantId: 'uuid',              // Operatum tenant id
  appId:    '<buildId>',         // the app this token was minted for
  role:     'admin'|'builder'|'reviewer'|'viewer',
  perms:    ['use'] | ['use', 'build'] | [],
  raw:      { /* full decoded payload */ },
}
```

## Token handoff patterns

The app receives tokens from the Operatum SPA in one of three ways —
the middleware looks in this order:

1. **`Authorization: Bearer <token>` header** — for API calls. The SPA
   fetches a token via `POST /api/auth/token?app_id=…` and attaches it
   on each request to the app.
2. **`operatum.session` cookie** — the app itself sets this after the
   SPA hands off the token on first open, so browser navigation
   doesn't need to re-attach it. Recommended for SPAs served by the app.
3. **`?operatum_token=<token>` query string** — initial landing only.
   The app should immediately redirect to the same URL without it.

## Behavior on auth failure

- Browser requests (`Accept: text/html`): redirect to
  `loginUrl?next=<original-url>`. The SPA finishes authentication and
  sends the user back.
- API requests (`Accept: application/json` or XHR): `401 JSON`
  `{ ok: false, error: 'unauthenticated', reason: '<code>' }`.

Reason codes: `no_token`, `malformed`, `alg_mismatch`, `missing_kid`,
`unknown_kid`, `bad_signature`, `bad_issuer`, `bad_audience`,
`expired`, `not_yet_valid`.

## Key rotation

The gateway rotates its signing key occasionally. The client handles
this transparently:

1. A request arrives with an unknown `kid`.
2. The JWKS cache forces a refresh.
3. If the new `kid` is now in the JWKS, verification proceeds.
4. If not, the token is rejected with `unknown_kid`.

During the gateway's rotation grace window (default 1 hour), both the
new and previous public keys are published, so in-flight tokens
continue to verify.

## Node version

Requires Node 18+ (global `fetch`, `createPublicKey({ format: 'jwk' })`).
