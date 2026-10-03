/**
 * service-mode.test.js — producer-side dep/service token verification (D2/D3).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyDepToken, parseDepScope, parseDepToolScope } from '../src/service-mode.js';
import { createOperatumAuthFromHeaders } from '../src/header-mode.js';

const B = '00000000-0000-0000-0000-0000000000bb';
const okVerify = (over = {}) => async () => ({
  role: 'service', sub: 'service:dep:c→p', tenant_id: 't1', scopes: [`app:dep:${B}`], ...over,
});
const activeFetch = async () => ({ ok: true, json: async () => ({ active: true }) });
const inactiveFetch = async () => ({ ok: true, json: async () => ({ active: false }) });
const errFetch = async () => { throw new Error('net'); };

test('parseDepScope / parseDepToolScope', () => {
  assert.equal(parseDepScope(`app:dep:${B}`), B);
  assert.equal(parseDepScope(`app:dep:${B}:tool:search`), B);
  assert.equal(parseDepScope('router:routes:read'), null);
  assert.equal(parseDepScope('app:dep:not-a-uuid'), null);
  assert.equal(parseDepToolScope(`app:dep:${B}:tool:search`), 'search');
  assert.equal(parseDepToolScope(`app:dep:${B}`), null);
});

test('verifyDepToken: valid → service principal', async () => {
  const p = await verifyDepToken('tok',
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: activeFetch });
  assert.equal(p.principalKind, 'service');
  assert.equal(p.serviceName, 'dep:c→p');
  assert.equal(p.tenantId, 't1');
  assert.deepEqual(p.scopes, [`app:dep:${B}`]);
});

test('verifyDepToken: dep scope is for a DIFFERENT build → forbidden', async () => {
  await assert.rejects(() => verifyDepToken('tok',
    { ownBuildId: 'other-id', jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: activeFetch }),
    /dep scope/);
});

test('verifyDepToken: non-service role → bad_role', async () => {
  await assert.rejects(() => verifyDepToken('tok',
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify({ role: 'admin' }), introspectUrl: 'http://gw/i', fetchImpl: activeFetch }),
    /service token/);
});

test('verifyDepToken: introspect inactive → fail-closed (revoked)', async () => {
  await assert.rejects(() => verifyDepToken('tok',
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: inactiveFetch }),
    /inactive|revoked/);
});

test('verifyDepToken: introspect network error → fail-closed', async () => {
  await assert.rejects(() => verifyDepToken('tok',
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: errFetch }),
    /inactive|revoked/);
});

test('verifyDepToken: no introspectUrl → crypto+scope only (TTL fallback)', async () => {
  const p = await verifyDepToken('tok', { ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
  assert.equal(p.principalKind, 'service');
});

// ── middleware service path ───────────────────────────────────────────────────

function mockRes() {
  return { _s: 200, _b: null, status(s) { this._s = s; return this; }, json(b) { this._b = b; return this; } };
}
async function run(mw, req) {
  const res = mockRes();
  let nexted = false;
  await mw(req, res, () => { nexted = true; });
  return { nexted, res, req };
}

test('middleware: valid dep token → service principal + next() + perms:[]', async () => {
  const auth = createOperatumAuthFromHeaders(
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: activeFetch });
  const { nexted, req } = await run(auth.middleware(), { headers: { authorization: 'Bearer tok' } });
  assert.equal(nexted, true);
  assert.equal(req.operatum.principalKind, 'service');
  assert.equal(req.operatum.role, 'service');
  assert.deepEqual(req.operatum.perms, []);
});

test('middleware: revoked dep token → 401 (fail closed)', async () => {
  const auth = createOperatumAuthFromHeaders(
    { ownBuildId: B, jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: inactiveFetch });
  const { nexted, res } = await run(auth.middleware(), { headers: { authorization: 'Bearer tok' } });
  assert.equal(nexted, false);
  assert.equal(res._s, 401);
});

test('middleware: NO service config → pure header mode (bearer ignored, 401)', async () => {
  const auth = createOperatumAuthFromHeaders(); // no env, no opts → svc=null
  const { nexted, res } = await run(auth.middleware(), { headers: { authorization: 'Bearer tok' } });
  assert.equal(nexted, false);
  assert.equal(res._s, 401);
});

test('requireDepScope: non-service principal → 403', async () => {
  const auth = createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
  const res = mockRes();
  let nexted = false;
  auth.requireDepScope()({ operatum: { principalKind: 'user', appId: B } }, res, () => { nexted = true; });
  assert.equal(nexted, false);
  assert.equal(res._s, 403);
});

test('requireDepScope({tool}): base scope satisfies; missing tool → 403', async () => {
  const auth = createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
  // base app:dep:<B> grants the tool
  let okNext = false;
  auth.requireDepScope({ tool: 'search' })(
    { operatum: { principalKind: 'service', appId: B, scopes: [`app:dep:${B}`] } }, mockRes(), () => { okNext = true; });
  assert.equal(okNext, true);
  // only a DIFFERENT tool scope → 403
  const res = mockRes(); let bad = false;
  auth.requireDepScope({ tool: 'search' })(
    { operatum: { principalKind: 'service', appId: B, scopes: [`app:dep:${B}:tool:other`] } }, res, () => { bad = true; });
  assert.equal(bad, false);
  assert.equal(res._s, 403);
});

test('verifyDepToken: cross-tenant (token tenant != producer tenant) → forbidden', async () => {
  await assert.rejects(() => verifyDepToken('tok',
    { ownBuildId: B, ownTenantId: 't2', jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: activeFetch }),
    /cross-tenant/);
});

test('verifyDepToken: same-tenant passes the tenant check', async () => {
  const p = await verifyDepToken('tok',
    { ownBuildId: B, ownTenantId: 't1', jwks: {}, verifyImpl: okVerify(), introspectUrl: 'http://gw/i', fetchImpl: activeFetch });
  assert.equal(p.principalKind, 'service');
});

// ── Environment binding (gateway stamps env on dep tokens) ──────────────────
// A consumer in env X is deployed against the producer in env X, so a dep
// token minted for the dev consumer must not open the producer's test/main.

test('verifyDepToken: ownEnv binds the token env (dev token refused by the test producer)', async () => {
  const p = await verifyDepToken('tok', { ownBuildId: B, jwks: {}, ownEnv: 'dev', verifyImpl: okVerify({ env: 'dev' }) });
  assert.equal(p.principalKind, 'service', 'positive control');
  await assert.rejects(
    verifyDepToken('tok', { ownBuildId: B, jwks: {}, ownEnv: 'test', verifyImpl: okVerify({ env: 'dev' }) }),
    (e) => e.code === 'env_mismatch');
  await assert.rejects(
    verifyDepToken('tok', { ownBuildId: B, jwks: {}, ownEnv: 'prod', verifyImpl: okVerify() }),
    (e) => e.code === 'env_missing', 'an env-less dep token is refused when the producer knows its env');
  const prod = await verifyDepToken('tok', { ownBuildId: B, jwks: {}, ownEnv: 'prod', verifyImpl: okVerify({ env: 'main' }) });
  assert.equal(prod.principalKind, 'service', 'prod (deployer) = main (gateway)');
  await assert.rejects(
    verifyDepToken('tok', { ownBuildId: B, jwks: {}, ownEnv: 'staging', verifyImpl: okVerify({ env: 'staging' }) }),
    (e) => e.code === 'misconfigured');
});

test('verifyDepToken: no ownEnv (non-platform use) keeps the old behaviour', async () => {
  const p = await verifyDepToken('tok', { ownBuildId: B, jwks: {}, verifyImpl: okVerify({ env: 'dev' }) });
  assert.equal(p.principalKind, 'service');
});

test('middleware: the producer binds dep tokens to OPERATUM_APP_ENV', async () => {
  const prev = process.env.OPERATUM_APP_ENV;
  process.env.OPERATUM_APP_ENV = 'main';
  try {
    const mk = (env) => createOperatumAuthFromHeaders(
      { ownBuildId: B, jwks: {}, verifyImpl: okVerify(env ? { env } : {}) });
    assert.equal((await run(mk('main').middleware(), { headers: { authorization: 'Bearer tok' } })).nexted, true,
      'positive control');
    for (const env of ['dev', 'test', undefined]) {
      const { nexted, res } = await run(mk(env).middleware(), { headers: { authorization: 'Bearer tok' } });
      assert.equal(nexted, false, `env=${env}`);
      assert.equal(res._s, 401);
    }
  } finally {
    if (prev === undefined) delete process.env.OPERATUM_APP_ENV; else process.env.OPERATUM_APP_ENV = prev;
  }
});

test('service mode warns ONCE when OPERATUM_APP_ENV is unset (no silent fail-open)', async () => {
  const { _resetDepEnvWarningForTests } = await import('../src/header-mode.js');
  const prev = process.env.OPERATUM_APP_ENV;
  delete process.env.OPERATUM_APP_ENV;
  const warns = [];
  const origWarn = console.warn;
  console.warn = (...a) => { warns.push(a.join(' ')); };
  try {
    _resetDepEnvWarningForTests();
    createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
    createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
    assert.equal(warns.filter((w) => /OPERATUM_APP_ENV is not set: dependency/.test(w)).length, 1);
    // An env (opt or OPERATUM_APP_ENV) silences it.
    _resetDepEnvWarningForTests(); warns.length = 0;
    createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify(), ownEnv: 'dev' });
    process.env.OPERATUM_APP_ENV = 'main';
    createOperatumAuthFromHeaders({ ownBuildId: B, jwks: {}, verifyImpl: okVerify() });
    assert.equal(warns.length, 0);
    // Pure header mode (no service config) has no dep tokens to bind: no warning.
    delete process.env.OPERATUM_APP_ENV;
    _resetDepEnvWarningForTests();
    createOperatumAuthFromHeaders();
    assert.equal(warns.length, 0);
  } finally {
    console.warn = origWarn;
    if (prev === undefined) delete process.env.OPERATUM_APP_ENV; else process.env.OPERATUM_APP_ENV = prev;
  }
});
