// bearer-env-purpose.test.js — on the BEARER path a token must belong to this
// deployment's environment and must not be a purpose-tagged token minted for
// another verifier.
//
// One build id spans dev/test/main, so the audience (operatum-app:<buildId>)
// alone let a token minted for the dev deployment — which lower-trust dev app
// code holds — open the same app's test/main deployment. And edge session /
// handoff / app-run tokens (purpose-tagged) carry the same audience. Real RS256
// tokens; only the JWKS fetch is stubbed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync, createSign, createPublicKey, createHash,
} from 'node:crypto';
import { createOperatumAuth, verifyToken, canonicalAppEnv, BEARER_PATH_PURPOSES } from '../src/index.js';
import { JwksCache } from '../src/jwks-cache.js';

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const kid = createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
const jwk = { ...createPublicKey({ key: publicKey, format: 'pem' }).export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid };
const fetchImpl = async () => ({ ok: true, status: 200, json: async () => ({ keys: [jwk] }) });

function mint(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: 'operatum', aud: 'operatum-app:b', sub: 'u1', perms: ['use'], iat: now, exp: now + 300, ...extra };
  for (const k of Object.keys(payload)) if (payload[k] === undefined) delete payload[k];
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const s = createSign('RSA-SHA256'); s.update(input); s.end();
  return `${input}.${b64url(s.sign(privateKey))}`;
}

function mockReq(token) {
  return {
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    query: {}, protocol: 'https', originalUrl: '/', get: (h) => (h === 'host' ? 'app.example' : undefined),
  };
}
function mockRes() {
  const st = { status: 200, body: null };
  return {
    status(c) { st.status = c; return this; }, json(b) { st.body = b; return this; },
    type() { return this; }, send(b) { st.body = b; return this; },
    set() { return this; }, setHeader() { return this; }, get() { return undefined; },
    _state: st,
  };
}
async function through(auth, token) {
  const res = mockRes();
  let passed = false;
  await auth.middleware()(mockReq(token), res, () => { passed = true; });
  return passed ? 'pass' : `${res._state.status}:${res._state.body?.reason}`;
}
const authFor = (appEnv, extra = {}) => createOperatumAuth({
  jwksUri: 'x', expectedAudience: 'operatum-app:b', fetchImpl, appEnv, ...extra,
});

test('a DEV token does not open the TEST or MAIN deployment of the same app', async () => {
  const dev = mint({ env: 'dev' });
  assert.equal(await through(authFor('dev'), dev), 'pass', 'positive control: dev opens dev');
  assert.equal(await through(authFor('test'), dev), '401:env_mismatch');
  assert.equal(await through(authFor('prod'), dev), '401:env_mismatch');
});

test('the deployer says "prod", the gateway stamps "main": they match', async () => {
  assert.equal(await through(authFor('prod'), mint({ env: 'main' })), 'pass');
  assert.equal(await through(authFor('production'), mint({ env: 'main' })), 'pass');
  assert.equal(await through(authFor('main'), mint({ env: 'prod' })), 'pass');
});

test('an env-LESS token is refused when the deployment env is known', async () => {
  assert.equal(await through(authFor('dev'), mint()), '401:env_missing');
});

test('an unknown deployment env refuses every token (fail closed)', async () => {
  assert.equal(await through(authFor('staging'), mint({ env: 'dev' })), '401:misconfigured');
});

test('OPERATUM_APP_ENV is the default appEnv', async () => {
  const prev = process.env.OPERATUM_APP_ENV;
  process.env.OPERATUM_APP_ENV = 'test';
  try {
    const auth = createOperatumAuth({ jwksUri: 'x', expectedAudience: 'operatum-app:b', fetchImpl });
    assert.equal(await through(auth, mint({ env: 'test' })), 'pass');
    assert.equal(await through(auth, mint({ env: 'dev' })), '401:env_mismatch');
  } finally {
    if (prev === undefined) delete process.env.OPERATUM_APP_ENV; else process.env.OPERATUM_APP_ENV = prev;
  }
});

test('no appEnv (non-platform use): env is not checked, as before', async () => {
  const prev = process.env.OPERATUM_APP_ENV;
  delete process.env.OPERATUM_APP_ENV;
  try {
    const auth = authFor(undefined);
    assert.equal(await through(auth, mint({ env: 'dev' })), 'pass');
    assert.equal(await through(auth, mint()), 'pass');
  } finally {
    if (prev !== undefined) process.env.OPERATUM_APP_ENV = prev;
  }
});

test('purpose-tagged tokens minted for other verifiers never open a bearer app', async () => {
  for (const purpose of ['public_host_session', 'public_host_handoff', 'app_origin_session',
    'app_origin_handoff', 'app_run_delegated', 'some_future_purpose']) {
    assert.equal(await through(authFor('dev'), mint({ env: 'dev', purpose })), '401:purpose_not_allowed', purpose);
    // …even with no env binding configured.
    assert.equal(await through(authFor(undefined), mint({ env: 'dev', purpose })), '401:purpose_not_allowed', purpose);
  }
  assert.deepEqual([...BEARER_PATH_PURPOSES], [undefined], 'only purpose-less tokens ride the bearer path');
});

test('the handoff (fragment → cookie) applies the same checks', async () => {
  const handlers = new Map();
  const app = { post(p, h) { handlers.set(p, h); } };
  const auth = authFor('main');
  auth.mountHandoff(app);
  const call = async (token) => {
    let status = 200; let body = null; const headers = {};
    await handlers.get('/_operatum/auth/handoff')({ body: { token } }, {
      status(c) { status = c; return this; }, json(b) { body = b; return this; },
      setHeader(k, v) { headers[k] = v; return this; },
    });
    return { status, body, cookie: headers['Set-Cookie'] };
  };
  const bad = await call(mint({ env: 'dev' }));
  assert.equal(bad.status, 401);
  assert.equal(bad.body.reason, 'env_mismatch');
  assert.equal(bad.cookie, undefined, 'no session cookie for a cross-env token');
  const session = await call(mint({ env: 'main', purpose: 'public_host_session' }));
  assert.equal(session.status, 401);
  assert.equal(session.body.reason, 'purpose_not_allowed');
  const ok = await call(mint({ env: 'main' }));
  assert.equal(ok.status, 200, 'positive control');
});

test('verifyToken: options are opt-in (service-mode and direct callers unchanged)', async () => {
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl });
  const p = await verifyToken(mint({ env: 'dev', purpose: 'public_host_session' }), { jwks, expectedAudience: 'operatum-app:b' });
  assert.equal(p.purpose, 'public_host_session');
  assert.equal(canonicalAppEnv('Production'), 'main');
  assert.equal(canonicalAppEnv(''), null);
});
