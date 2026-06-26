/**
 * header-mode.js — read identity from X-Operatum-* request headers.
 *
 * The reverse-proxy SSO mode (operatum-ui stage 8). When the gateway
 * sits in front of an app and authenticates the user itself, it
 * forwards identity as headers rather than as a JWT the app must
 * verify. This module is the app-side reader.
 *
 * Trust model
 * ───────────
 *
 * The headers are trusted because of TOPOLOGY, not crypto:
 *
 *   - the app container binds --publish 127.0.0.1::N (loopback only)
 *   - it joins the per-build docker network operatum-net-<id>-<env>
 *   - the gateway is the only origin that can reach the app's port
 *
 * Therefore: any X-Operatum-* header that arrives at the app came
 * from the gateway. There is no "spoof from outside" attack vector
 * unless the topology guarantee is broken (which would also break
 * every other security assumption — credential injection, secrets,
 * etc.). When apps run OUTSIDE this topology (local dev, k8s with
 * different network rules), this mode is unsafe and apps should
 * use createOperatumAuth (JWT bearer mode) instead.
 *
 * Why this is a SEPARATE export from createOperatumAuth
 * ─────────────────────────────────────────────────────
 *
 * Bearer mode requires jwksUri + expectedAudience + a fetch impl;
 * header mode requires zero config. Mixing them via `mode: '...'`
 * would either ignore irrelevant config (silent footgun) or throw
 * on it (breaking existing callers). A separate factory makes the
 * migration explicit and the wrong-mode-failure mode loud.
 *
 * The returned object has the SAME public shape as
 * createOperatumAuth (middleware, requirePerm, verify*) so call
 * sites can swap the factory and keep everything else.
 *
 * (* verify on header mode is a no-op stub — there's no token to
 * verify; it's exposed only for shape-parity in case an app calls
 * it from a non-middleware context.)
 *
 * What it does NOT mount
 * ──────────────────────
 *
 * No mountHandoff. No bootstrap HTML. No login redirect. The
 * gateway handles all of that on the front side; the app just
 * reads headers off whatever requests reach it. If a request
 * arrives without the headers, the response is a flat 401 — no
 * fragment-token recovery flow because there's nothing for the
 * app to do about it: that's a misrouted request and pretending
 * otherwise would mask infrastructure bugs.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { JwksCache } from './jwks-cache.js';
import { verifyDepToken, parseDepScope, parseDepToolScope } from './service-mode.js';

const ROLES = new Set(['admin', 'builder', 'reviewer', 'viewer']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── HMAC proof-of-gateway (defense-in-depth) ─────────────────────────────────
//
// Vendored in sync with operatum-ui/gateway/src/lib/operatum-headers.js.
// The protocol is the contract; both sides MUST produce identical canonical
// strings for the same header set + timestamp.
//
// The header name ordering in OPERATUM_HEADER_NAMES is pinned — both signer
// (gateway) and verifier (here) iterate this exact sequence.

const OPERATUM_TIMESTAMP_HEADER = 'x-operatum-timestamp';
const OPERATUM_SIGNATURE_HEADER = 'x-operatum-signature';
const DEFAULT_SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000; // ±5 min replay window

// Ordered exactly as in operatum-headers.js — do not reorder.
const OPERATUM_HEADER_NAMES = Object.freeze([
  'x-operatum-user-id',
  'x-operatum-tenant-id',
  'x-operatum-email',
  'x-operatum-display-name',
  'x-operatum-role',
  'x-operatum-build-id',
  'x-operatum-perms',
  'x-operatum-auth-mode',
]);

function canonicalStringForSigning(headers, timestamp) {
  const parts = [];
  for (const name of OPERATUM_HEADER_NAMES) {
    const v = headers[name] ?? headers[name.toUpperCase()];
    if (v != null) parts.push(`${name}=${v}`);
  }
  parts.push(`${OPERATUM_TIMESTAMP_HEADER}=${timestamp}`);
  return parts.join('\n');
}

function verifyOperatumSignature(headers, secret, opts = {}) {
  if (!secret || !headers || typeof headers !== 'object') return false;
  const { maxAgeMs = DEFAULT_SIGNATURE_MAX_AGE_MS, now = Date.now() } = opts;
  const get = (k) => headers[k] ?? headers[k.toUpperCase()];
  const ts = get(OPERATUM_TIMESTAMP_HEADER);
  const provided = get(OPERATUM_SIGNATURE_HEADER);
  if (!ts || !provided) return false;
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return false;
  if (Math.abs(now - tsNum) > maxAgeMs) return false;
  const expected = createHmac('sha256', secret)
    .update(canonicalStringForSigning(headers, ts))
    .digest('hex');
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Read X-Operatum-* headers off a request, validate every field,
 * return a clean identity object — or null on any malformed
 * header (no half-authenticated states).
 *
 * Vendored (not imported) from the gateway's operatum-headers.js
 * because @operatum/auth has zero runtime deps. Drift would break
 * authentication; both implementations are pinned by tests in
 * their respective repos. The protocol is the contract.
 *
 * When `opts.secret` is supplied the reader additionally REQUIRES a valid,
 * fresh HMAC signature (x-operatum-signature + x-operatum-timestamp) and
 * returns null if it is missing or wrong — presence alone is no longer
 * sufficient. Without a secret the behaviour is unchanged (presence-only).
 *
 * @param {Object<string,string>} headers
 * @param {object} [opts]
 * @param {string|Buffer} [opts.secret]  — per-deploy shared secret; enables signature enforcement
 * @param {number} [opts.maxAgeMs]       — replay window (default 5 min)
 * @param {number} [opts.now]            — injectable clock for tests
 */
export function readOperatumHeaders(headers, opts = {}) {
  if (!headers || typeof headers !== 'object') return null;
  const get = (k) => headers[k] ?? headers[k.toUpperCase()];

  const userId   = get('x-operatum-user-id');
  const tenantId = get('x-operatum-tenant-id');
  const email    = get('x-operatum-email');
  const role     = get('x-operatum-role');
  const buildId  = get('x-operatum-build-id');
  const permsRaw = get('x-operatum-perms');
  const authMode = get('x-operatum-auth-mode');

  if (!UUID_RE.test(userId ?? ''))   return null;
  if (!UUID_RE.test(tenantId ?? '')) return null;
  if (!UUID_RE.test(buildId ?? ''))  return null;
  if (!email || !ROLES.has(role))    return null;
  // The auth-mode literal is the bypass-guard. A request that
  // somehow lands here without it (or with the legacy 'bearer'
  // literal) MUST NOT authenticate via headers — that path is
  // for the JWT verifier in createOperatumAuth.
  if (authMode !== 'reverse-proxy')  return null;

  // Cryptographic proof-of-gateway: when a shared secret is configured the
  // signature MUST verify. No half-auth — a missing/forged signature is
  // indistinguishable from any other malformed header set (null).
  if (opts.secret && !verifyOperatumSignature(headers, opts.secret, opts)) {
    return null;
  }

  let perms;
  try {
    perms = JSON.parse(permsRaw ?? '');
    if (!Array.isArray(perms)) return null;
  } catch { return null; }

  const out = {
    userId, tenantId,
    email: decodeURIComponent(email),
    role, buildId, perms, authMode,
  };
  const dn = get('x-operatum-display-name');
  if (dn) {
    try { out.displayName = decodeURIComponent(dn); }
    catch { /* malformed → omit */ }
  }
  return out;
}

// ── framework adapters (mirror middleware.js) ─────────────────

function getHeader(req, name) {
  if (typeof req.get === 'function') {
    const v = req.get(name);
    if (v != null) return v;
  }
  const h = req.headers || {};
  return h[name] || h[name.toLowerCase()] || null;
}

function sendJson(res, status, body) {
  if (typeof res.code === 'function' && typeof res.send === 'function') {
    return res.code(status).send(body);
  }
  return res.status(status).json(body);
}

/**
 * Create a reverse-proxy mode auth adapter. Returns the same shape
 * as createOperatumAuth so call sites can swap one factory for
 * the other and leave the rest of the app alone.
 *
 * No JWKS, no audience, no cookies, no handoff — every config
 * required by JWT mode is absent here, by design.
 *
 * When OPERATUM_GATEWAY_SIGNING_SECRET is set in the environment (injected
 * by the platform at deploy time), the middleware REQUIRES a valid HMAC
 * signature over the X-Operatum-* identity headers. Unsigned or forged
 * identity headers are rejected (null → 401). When the env var is absent
 * the middleware falls back to presence-only mode for backward compatibility
 * during rollout. Pass `opts.secret` to override the env var in tests.
 *
 * @param {object} [opts]
 * @param {string|Buffer} [opts.secret] — signing secret override (default: process.env.OPERATUM_GATEWAY_SIGNING_SECRET)
 * @returns {{middleware, requirePerm, verify}}
 */
export function createOperatumAuthFromHeaders(opts = {}) {
  // Resolve the per-deploy gateway→app HMAC signing secret. The platform
  // injects it as OPERATUM_GATEWAY_SIGNING_SECRET into the app container;
  // opts.secret lets tests supply it directly without touching the env.
  // When neither is present the middleware stays in presence-only mode.
  const signingSecret = opts.secret || process.env.OPERATUM_GATEWAY_SIGNING_SECRET || null;

  // Optional cross-app dependency-token path. A dep call goes container→
  // container (host.docker.internal:<port>) carrying only a Bearer service
  // token — no X-Operatum-* identity headers — so the producer must verify it
  // itself. Activated only when this app's build id + a JWKS are resolvable
  // (from opts or platform-injected env); otherwise this is pure header mode
  // (backward compatible — existing zero-config callers are unaffected).
  const svc = resolveServiceConfig(opts);

  function middleware() {
    return async (req, res, next) => {
      // For Express, headers are normalised lowercase on req.headers.
      // For Fastify too. We pass the headers object (not req) into
      // the read because the read is the protocol contract — nothing
      // framework-specific about it.
      const readOpts = signingSecret ? { secret: signingSecret } : {};
      const identity = readOperatumHeaders(req.headers ?? {}, readOpts);
      if (identity) {
        // appId == buildId; keeping the bearer-mode field name so
        // app code doesn't have to branch on auth mode.
        req.operatum = {
          userId:   identity.userId,
          email:    identity.email,
          tenantId: identity.tenantId,
          appId:    identity.buildId,
          role:     identity.role,
          perms:    identity.perms,
          ...(identity.displayName !== undefined && { displayName: identity.displayName }),
          // raw exposes the headers themselves for debugging; bearer
          // mode exposes the JWT claims — the field names differ but
          // the role (audit + introspection) is the same.
          raw: { ...identity },
        };
        return next();
      }

      // No user identity headers — try a cross-app dependency/service token.
      if (svc) {
        const m = /^Bearer\s+(.+)$/i.exec(getHeader(req, 'authorization') || '');
        if (m) {
          try {
            const p = await verifyDepToken(m[1].trim(), svc);
            req.operatum = {
              principalKind: 'service',
              userId: null,
              email: null,
              tenantId: p.tenantId,
              appId: svc.ownBuildId,
              role: 'service',
              perms: [], // service principals carry no user perms (requirePerm → 403)
              serviceName: p.serviceName,
              scopes: p.scopes,
              raw: { principalKind: 'service', serviceName: p.serviceName, scopes: p.scopes },
            };
            return next();
          } catch (err) {
            // Fall through to 401, but surface the reason for ops — "every dep
            // call suddenly 401s" (bad JWKS, revocation-callback down, clock
            // skew) must be diagnosable. Code/name only; never leak to the body.
            (opts.logger || console).warn?.(
              '[operatum-auth] dep token rejected:', err?.code || err?.name || 'error');
          }
        }
      }

      // No fragment-token recovery, no login redirect. If the gateway is doing
      // its job, this never fires; if it does, it's a misrouted/test/tamper
      // request and should fail closed.
      return sendJson(res, 401, {
        ok: false,
        error: 'unauthenticated',
        reason: 'missing_or_invalid_operatum_headers',
      });
    };
  }

  function requirePerm(perm) {
    return (req, res, next) => {
      if (!req.operatum) {
        return sendJson(res, 401, { ok: false, error: 'unauthenticated' });
      }
      if (!req.operatum.perms.includes(perm)) {
        return sendJson(res, 403, { ok: false, error: `missing '${perm}' permission` });
      }
      return next();
    };
  }

  // Guard a route to a cross-app dependency caller: a verified SERVICE principal
  // holding a dep scope for THIS app. `{ tool }` additionally requires the
  // matching mcp tool scope (a base `app:dep:<id>` grant also satisfies it).
  function requireDepScope({ tool } = {}) {
    return (req, res, next) => {
      const op = req.operatum;
      if (!op || op.principalKind !== 'service') {
        return sendJson(res, 403, { ok: false, error: 'forbidden', reason: 'service_principal_required' });
      }
      const scopes = op.scopes || [];
      if (tool) {
        const hasTool = scopes.some((s) => parseDepScope(s) === op.appId && parseDepToolScope(s) === tool);
        const hasBase = scopes.some((s) => parseDepScope(s) === op.appId && parseDepToolScope(s) === null);
        if (!hasTool && !hasBase) {
          return sendJson(res, 403, { ok: false, error: 'forbidden', reason: `missing dep tool scope '${tool}'` });
        }
      } else if (!scopes.some((s) => parseDepScope(s) === op.appId)) {
        return sendJson(res, 403, { ok: false, error: 'forbidden', reason: 'missing dep scope' });
      }
      return next();
    };
  }

  // Stub for shape parity with createOperatumAuth. There's no
  // token to verify; if an app calls this in header mode, give
  // it back the headers it would have read on a request.
  async function verify() {
    throw new Error(
      'createOperatumAuthFromHeaders: verify() is not meaningful in '
      + 'reverse-proxy mode (no token to verify). Read req.operatum '
      + 'inside a route handler instead.'
    );
  }

  return { middleware, requirePerm, requireDepScope, verify };
}

/**
 * Resolve the optional dep-token verification config from opts + platform env.
 * Returns null (→ pure header mode) when service tokens are explicitly disabled
 * or the required inputs (this app's build id + a JWKS) are absent.
 */
function resolveServiceConfig(opts) {
  if (opts.enableServiceTokens === false) return null;
  const ownBuildId = opts.ownBuildId
    || process.env.OPERATUM_APP_ID || process.env.OPERATUM_BUILD_ID || null;
  const gatewayUrl = opts.gatewayUrl || process.env.OPERATUM_GATEWAY_URL || null;
  const jwksUri = opts.jwksUri || process.env.OPERATUM_JWKS_URL
    || (gatewayUrl ? `${gatewayUrl}/.well-known/jwks.json` : null);
  // Need this app's id and a way to check signatures (a JWKS URL, or an
  // injected jwks instance for tests/embedding); else fall back to header-only.
  if (!ownBuildId || (!jwksUri && !opts.jwks)) return null;
  return {
    ownBuildId,
    // This producer's tenant — used to reject cross-tenant dep tokens (v1).
    ownTenantId: opts.ownTenantId || process.env.OPERATUM_TENANT_ID || null,
    jwks: opts.jwks || new JwksCache({ jwksUri, fetchImpl: opts.fetchImpl }),
    // Revocation callback (immediate revocation). Omitting it (no gatewayUrl)
    // falls back to crypto + scope + the token's own TTL.
    introspectUrl: opts.introspectUrl
      || (gatewayUrl ? `${gatewayUrl}/api/service-tokens/introspect` : null),
    fetchImpl: opts.fetchImpl,
    verifyImpl: opts.verifyImpl,
  };
}

// Expose getHeader for tests that need to check framework-adapter
// behaviour without a full Express/Fastify harness.
export { getHeader as _getHeader };
