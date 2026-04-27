# @operatum/auth — architecture

A tiny library (zero runtime deps) that verifies Operatum-issued
JWTs inside apps built on the platform. Apps install it as an
npm package and call one function to authenticate a user.

This is a LIBRARY, not a service. It runs in the consuming app's
process.

## What it solves

Operatum acts as the Identity Provider for every app it builds.
When a user opens an app from the Operatum UI:

1. Operatum SPA authenticates the user (cookie session, Google
   SSO, password).
2. Mints a short-lived RS256 JWT with the app's `build_id` as
   the audience.
3. Redirects the user to the app with the JWT in a one-time URL
   fragment.
4. The app reads the JWT, calls `verifyToken` from this library,
   gets back the user record, sets its own session cookie.

After the initial handshake, the app drives its own session and
the JWT is discarded. Re-auth happens via Operatum if the app's
session expires.

## API

```js
import { verifyToken, getJWKS } from '@operatum/auth';

// At app start, prime the JWKS cache (optional — verifyToken
// fetches lazily otherwise):
await getJWKS({ baseUrl: 'https://operatum.example.com' });

// In a route handler:
const payload = await verifyToken(token, {
  baseUrl: 'https://operatum.example.com',
  expectedAudience: 'operatum-app:<build_id>',
});
// → { sub, email, name, role, tenant_id, ... }
```

## What it does

- Fetches the JWKS from `<baseUrl>/.well-known/jwks.json` (cached
  for 5 min).
- Verifies the JWT signature against the matching kid.
- Validates `iss = 'operatum'`, `aud` matches the app's
  build_id, `exp` not passed.
- Returns the decoded payload.

## What it doesn't do

- No session storage — that's the app's job.
- No refresh — JWTs are short-lived (1h); past expiry the user
  re-auths via Operatum.
- No user lookup beyond what's in the JWT.

## Why a separate package

- Apps shouldn't need to know about Operatum's internal session
  shape — just verify a token and trust the payload.
- Zero deps: works in tiny scratch apps without bloating their
  install size.
- Versioned independently from the gateway — apps can pin a
  known-good auth version.

## Integration with operatum-ui/gateway

The gateway is the issuer (`signAppLoginToken` in
`gateway/src/auth/jwt.js`). The signing key pair lives in the
gateway's secret store; the public key is published at
`<gateway>/.well-known/jwks.json` so this library can fetch it.

## Where to start

- `src/index.js` — public API.
- `src/jwks.js` — JWKS fetch + cache.
- `src/verify.js` — signature + claim validation.
