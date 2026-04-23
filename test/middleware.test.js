import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync, createSign, createPublicKey, createHash,
} from 'node:crypto';
import { createOperatumAuth } from '../src/middleware.js';

function kidOf(pubPem) {
  return createHash('sha256').update(pubPem).digest('hex').slice(0, 16);
}
function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function mintKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const kid = kidOf(publicKey);
  const jwk = { ...createPublicKey({ key: publicKey, format: 'pem' }).export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid };
  return { publicKey, privateKey, kid, jwk };
}
function sign({ privateKey, kid, payload }) {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${b64url(signer.sign(privateKey))}`;
}

// Minimal Express-like request/response doubles.
function mockReq(overrides = {}) {
  return {
    headers: {},
    query: {},
    protocol: 'https',
    originalUrl: '/',
    get: (h) => (h === 'host' ? 'app.example' : undefined),
    ...overrides,
  };
}
function mockRes() {
  const state = { status: 200, headers: {}, body: null, redirectedTo: null };
  return {
    status(code) { state.status = code; return this; },
    json(body) { state.body = body; return this; },
    redirect(url) { state.redirectedTo = url; state.status = 302; return this; },
    set(k, v) { state.headers[k] = v; return this; },
    get(k) { return state.headers[k]; },
    _state: state,
  };
}

function jwksFetch(keys) {
  return async () => ({ ok: true, status: 200, json: async () => ({ keys }) });
}

test('middleware populates req.operatum on a valid Bearer token', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const now = Math.floor(Date.now() / 1000);
  const token = sign({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: {
      iss: 'operatum', aud: 'operatum-app:b', sub: 'u1', email: 'u@operatum.com',
      tenant_id: 't1', app_id: 'b', role: 'builder', perms: ['use', 'build'],
      iat: now, exp: now + 60,
    },
  });
  const req = mockReq({ headers: { authorization: `Bearer ${token}` } });
  const res = mockRes();
  let called = false;
  await auth.middleware()(req, res, () => { called = true; });
  assert.equal(called, true, 'next() must be called on success');
  assert.deepEqual(req.operatum, {
    userId: 'u1', email: 'u@operatum.com', tenantId: 't1', appId: 'b',
    role: 'builder', perms: ['use', 'build'], raw: req.operatum.raw,
  });
});

test('middleware redirects browser requests to loginUrl with next=', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const req = mockReq({ originalUrl: '/dashboard?foo=1', headers: { accept: 'text/html' } });
  const res = mockRes();
  await auth.middleware()(req, res, () => { throw new Error('next should not be called'); });
  assert.equal(res._state.status, 302);
  assert.ok(res._state.redirectedTo.startsWith('https://operatum.example/login?next='));
  assert.ok(res._state.redirectedTo.includes(encodeURIComponent('https://app.example/dashboard?foo=1')));
});

test('middleware returns 401 JSON for API-style requests', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const req = mockReq({ headers: { accept: 'application/json' } });
  const res = mockRes();
  await auth.middleware()(req, res, () => { throw new Error('next should not be called'); });
  assert.equal(res._state.status, 401);
  assert.equal(res._state.body.ok, false);
  assert.equal(res._state.body.reason, 'no_token');
});

test('requirePerm enforces the grant list after middleware runs', async () => {
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([]),
  });
  const req = mockReq();
  req.operatum = { perms: ['use'] };
  const res = mockRes();
  await auth.requirePerm('build')(req, res, () => { throw new Error('next should not be called'); });
  assert.equal(res._state.status, 403);
  assert.match(res._state.body.error, /'build'/);

  req.operatum.perms = ['use', 'build'];
  let called = false;
  auth.requirePerm('build')(req, res, () => { called = true; });
  assert.equal(called, true);
});

test('middleware reads the operatum.session cookie when Authorization is absent', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const now = Math.floor(Date.now() / 1000);
  const token = sign({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: {
      iss: 'operatum', aud: 'operatum-app:b', sub: 'u',
      perms: ['use'], iat: now, exp: now + 60,
    },
  });
  const req = mockReq({ headers: { cookie: `other=x; operatum.session=${token}; more=y` } });
  const res = mockRes();
  let called = false;
  await auth.middleware()(req, res, () => { called = true; });
  assert.equal(called, true);
  assert.equal(req.operatum.userId, 'u');
});
