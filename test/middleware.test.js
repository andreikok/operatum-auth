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
  const state = {
    status: 200, headers: {}, body: null, redirectedTo: null,
    contentType: null,
  };
  return {
    status(code) { state.status = code; return this; },
    json(body) { state.body = body; return this; },
    redirect(url) { state.redirectedTo = url; state.status = 302; return this; },
    type(t) { state.contentType = t; return this; },
    send(body) { state.body = body; return this; },
    set(k, v) { state.headers[k] = v; return this; },
    setHeader(k, v) { state.headers[k] = v; return this; },
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

test('middleware serves bootstrap HTML (not 302) for unauthenticated browser requests', async () => {
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
  // Bootstrap is a 200 HTML, not a 302 — that's the whole point of
  // the fix. A 302 would race the fragment handoff (browser carries
  // the fragment forward, no JS ever runs to consume it).
  assert.equal(res._state.status, 200);
  assert.equal(res._state.contentType, 'html');
  assert.equal(res._state.redirectedTo, null);
  // The bootstrap embeds the SSO URL as a fallback for the no-fragment
  // case — so the redirect target still has to be reachable from
  // the page. Pin both the host and the next= round-trip.
  assert.match(res._state.body, /https:\/\/operatum\.example\/login\?next=/);
  assert.ok(res._state.body.includes(encodeURIComponent('https://app.example/dashboard?foo=1')));
});

test('bootstrap HTML reads the fragment and POSTs to the handoff endpoint', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const req = mockReq({ headers: { accept: 'text/html' } });
  const res = mockRes();
  await auth.middleware()(req, res, () => { throw new Error('next should not be called'); });
  const html = res._state.body;
  // The script must read window.location.hash for operatum_token=...
  assert.match(html, /location\.hash/);
  assert.match(html, /operatum_token=/);
  // It POSTs to the handoff endpoint with credentials so the
  // Set-Cookie response is honored cross-origin (gateway → app).
  assert.match(html, /\/_operatum\/auth\/handoff/);
  assert.match(html, /credentials:\s*'include'/);
  assert.match(html, /method:\s*'POST'/);
  // After successful handoff it MUST strip the fragment from the URL
  // and reload — that's what unblocks the next request to be
  // authenticated by the cookie. Without the reload the cookie is
  // set but the current page never re-runs the middleware.
  assert.match(html, /history\.replaceState/);
  assert.match(html, /location\.reload/);
  // No-fragment branch: location.replace to the SSO URL. Pin the
  // fallback so a future trim doesn't quietly drop it.
  assert.match(html, /location\.replace/);
});

test('bootstrap HTML escapes the SSO URL safely (no script-context break)', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  // A path containing characters that would break naive interpolation
  // (apostrophe, angle brackets) must round-trip safely. JSON.stringify
  // is the contract we rely on — pin that the URL is wrapped in
  // a double-quoted JSON literal, not concatenated into the script
  // body raw.
  const req = mockReq({
    originalUrl: '/items?q=</script><script>alert(1)</script>',
    headers: { accept: 'text/html' },
  });
  const res = mockRes();
  await auth.middleware()(req, res, () => { throw new Error('next should not be called'); });
  // The dangerous chunk must NOT appear unencoded in the response
  // (which would let it execute as a sibling script).
  assert.ok(!res._state.body.includes('</script><script>alert(1)</script>'),
    'dangerous URL chars must be encoded, not pasted raw into the script');
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
