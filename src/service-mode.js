/**
 * service-mode.js — producer-side verification of cross-app DEPENDENCY tokens
 * (D2/D3, epic #413).
 *
 * Cross-app dep calls go consumer-container → producer-container directly
 * (host.docker.internal:<port>), NOT through the router/gateway edge. So the
 * PRODUCER must authenticate them itself. A dep token is an Operatum SERVICE
 * token (aud `operatum-service:<name>`, role `service`) carrying a scope
 * `app:dep:<producerBuildId>` (+ `:tool:<name>` for mcp tools), minted in the
 * consumer's tenant at deploy and injected into the consumer's container.
 *
 * The producer verifies it in two steps:
 *   1. LOCAL crypto via the gateway JWKS (fast, no round-trip) — signature, iss,
 *      exp, aud-prefix, role.
 *   2. A scope grant for THIS producer: some scope `app:dep:<ownBuildId>`.
 *   3. A revocation callback to the gateway introspection endpoint (immediate
 *      revocation — the chosen design over the 7-day TTL alone). Fail-CLOSED on
 *      any non-active / network error.
 *
 * Same-tenant only in v1 (the dep token's tenant === the producer's tenant for
 * `dep.tenant: 'same'`). Cross-tenant deps are deferred.
 */

import { TokenError, canonicalAppEnv } from './jwt-verify.js';

// `app:dep:<uuid>` or `app:dep:<uuid>:tool:<name>`. Mirrors the gateway's
// dep-scopes.js (the SDK can't import gateway code).
const DEP_SCOPE_RE =
  /^app:dep:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?::tool:([a-z][a-z0-9_]*))?$/i;

/** @returns {string|null} producer build id encoded in a dep scope, else null. */
export function parseDepScope(scope) {
  const m = DEP_SCOPE_RE.exec(String(scope || ''));
  return m ? m[1] : null;
}

/** @returns {string|null} tool name for a tool-scoped dep scope, else null. */
export function parseDepToolScope(scope) {
  const m = DEP_SCOPE_RE.exec(String(scope || ''));
  return m && m[2] ? m[2] : null;
}

/**
 * Verify a presented dependency/service token for THIS producer.
 *
 * @param {string} token
 * @param {object} opts
 * @param {import('./jwks-cache.js').JwksCache} opts.jwks
 * @param {string} opts.ownBuildId       - this producer's build id
 * @param {string} [opts.introspectUrl]  - gateway introspection endpoint; when
 *                                          set, revocation is enforced (fail-closed)
 * @param {typeof fetch} [opts.fetchImpl=fetch]
 * @param {(t:string, o:object)=>Promise<object>} [opts.verifyImpl] - injectable
 *                                          crypto verify (defaults to verifyToken)
 * @param {string} [opts.ownEnv]         - this producer's environment
 *   (dev|test|main; prod/production = main). When set, the dep token's `env`
 *   claim must name the same environment and an env-less token is refused:
 *   a consumer in env X is deployed against the producer in env X, so its
 *   token must not open the producer's other envs. Unset keeps the old
 *   behaviour (non-platform use).
 * @returns {Promise<{principalKind:'service', serviceName:string|null,
 *                    tenantId:string|null, scopes:string[]}>}
 */
export async function verifyDepToken(token, {
  jwks, ownBuildId, ownTenantId, introspectUrl, fetchImpl, verifyImpl, ownEnv,
} = {}) {
  if (!ownBuildId) throw new TokenError('ownBuildId required', 'misconfigured');
  const wantEnv = typeof ownEnv === 'string' && ownEnv.trim() ? canonicalAppEnv(ownEnv) : undefined;
  if (typeof ownEnv === 'string' && ownEnv.trim() && !wantEnv) {
    throw new TokenError(`unknown app environment ${ownEnv}`, 'misconfigured');
  }
  const verify = verifyImpl || (await import('./jwt-verify.js')).verifyToken;

  // 1. Crypto: signature + iss + exp + aud-prefix.
  const payload = await verify(token, { jwks, audiencePrefix: 'operatum-service:' });
  if (payload.role !== 'service') throw new TokenError('not a service token', 'bad_role');

  // 1b. Tenant isolation (v1 = same-tenant). The dep token must belong to this
  //     producer's tenant. Enforced at mint by the gateway too; checking here
  //     makes the invariant explicit and defends against a future cross-tenant
  //     mint reaching a producer that hasn't opted in.
  if (ownTenantId && String(payload.tenant_id) !== String(ownTenantId)) {
    throw new TokenError('cross-tenant dep token rejected', 'forbidden');
  }

  // 1c. Environment: the token was minted for the producer env the consumer
  //     is deployed against (gateway stamps it). Checked on the claim itself,
  //     whichever verifyImpl ran.
  if (wantEnv) {
    if (payload.env === undefined) throw new TokenError('dep token has no env claim', 'env_missing');
    if (canonicalAppEnv(payload.env) !== wantEnv) {
      throw new TokenError(`dep token is for env ${payload.env}, not ${wantEnv}`, 'env_mismatch');
    }
  }

  // 2. A dep grant for THIS producer (base or tool-scoped both carry the id).
  const scopes = Array.isArray(payload.scopes) ? payload.scopes : [];
  if (!scopes.some((s) => parseDepScope(s) === ownBuildId)) {
    throw new TokenError('token lacks a dep scope for this app', 'forbidden');
  }

  // 3. Revocation callback (fail-closed).
  if (introspectUrl) {
    const active = await introspect(token, introspectUrl, fetchImpl || globalThis.fetch);
    if (!active) throw new TokenError('token inactive or revoked', 'revoked');
  }

  return {
    principalKind: 'service',
    serviceName: payload.sub ? String(payload.sub).replace(/^service:/, '') : null,
    tenantId: payload.tenant_id ?? null,
    scopes,
  };
}

async function introspect(token, url, fetchImpl) {
  try {
    const r = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!r.ok) return false; // non-2xx → treat as inactive (fail-closed)
    const j = await r.json();
    return j && j.active === true;
  } catch {
    return false; // network/parse error → fail-closed (revocation can't be confirmed)
  }
}
