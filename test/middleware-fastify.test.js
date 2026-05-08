// middleware-fastify.test.js — pin Fastify compatibility on the
// auth middleware. Live-reported on 2026-05-07: the
// browser-service app crashed every /v1/* call with
// `TypeError: req.get is not a function` because the middleware
// hardcoded Express's req.get('host'). Fastify requests don't
// have .get(); they expose req.headers + reply.code()+send().

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
function jwksFetch(keys) {
  return async () => ({ ok: true, status: 200, json: async () => ({ keys }) });
}

// Fastify request shape: no .get() method. Headers come from
// req.headers (already lowercased). req.url instead of
// req.originalUrl.
function fastifyReq(overrides = {}) {
  return {
    headers: {},
    query: {},
    protocol: 'https',
    url: '/',
    ...overrides,
  };
}

// Fastify reply shape: .code()+.send() instead of .status()+.json().
// reply.redirect() exists. No .setHeader(); use .header().
function fastifyReply() {
  const state = { status: 200, headers: {}, body: null, redirectedTo: null };
  return {
    code(c) { state.status = c; return this; },
    send(b) { state.body = b; return this; },
    redirect(url) { state.redirectedTo = url; state.status = 302; return this; },
    header(k, v) { state.headers[k] = v; return this; },
    _state: state,
  };
}

test('middleware works with a Fastify-shaped request — populates req.operatum', async () => {
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
  const req = fastifyReq({ headers: { authorization: `Bearer ${token}` } });
  const reply = fastifyReply();
  let called = false;
  await auth.middleware()(req, reply, () => { called = true; });
  assert.equal(called, true, 'next() must be called on a valid bearer (Fastify shape)');
  assert.equal(req.operatum.userId, 'u1');
});

test('middleware returns 401 JSON via reply.code()+send() for Fastify API requests', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  // No bearer + Accept: application/json → JSON 401, not redirect.
  const req = fastifyReq({ headers: { accept: 'application/json' } });
  const reply = fastifyReply();
  await auth.middleware()(req, reply, () => { throw new Error('next should not be called'); });
  assert.equal(reply._state.status, 401);
  assert.equal(reply._state.body.ok, false);
  assert.equal(reply._state.body.reason, 'no_token');
});

test('middleware serves bootstrap HTML to Fastify browser requests via reply.code()+send()', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    loginUrl: 'https://operatum.example/login',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const req = fastifyReq({
    url: '/dashboard?foo=1',
    headers: { accept: 'text/html', host: 'app.example' },
  });
  const reply = fastifyReply();
  await auth.middleware()(req, reply, () => { throw new Error('next should not be called'); });
  // After the bootstrap-HTML fix, the deny path returns 200 HTML
  // (not 302) so the embedded script can consume any fragment-token
  // before the SSO fallback redirect fires. The response shape must
  // hit Fastify's reply.code()+send() (not res.status()+res.send()).
  assert.equal(reply._state.status, 200);
  assert.equal(reply._state.headers['Content-Type'], 'text/html; charset=utf-8',
    'Fastify path uses reply.header() — content-type must be set there');
  assert.equal(reply._state.redirectedTo, null);
  // The fallback SSO URL still has to be embedded in the page (used
  // when there's no fragment-token to consume).
  assert.match(reply._state.body, /https:\/\/operatum\.example\/login\?next=/);
  assert.ok(reply._state.body.includes(encodeURIComponent('https://app.example/dashboard?foo=1')),
    `Fastify bootstrap must include the request's full URL — got ${reply._state.body.slice(0, 200)}`);
});

test('requirePerm denies via reply.code()+send() on Fastify', async () => {
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([]),
  });
  const req = fastifyReq();
  req.operatum = { perms: ['use'] };
  const reply = fastifyReply();
  await auth.requirePerm('build')(req, reply, () => { throw new Error('next should not be called'); });
  assert.equal(reply._state.status, 403);
  assert.match(reply._state.body.error, /'build'/);
});

test('does NOT crash on req.get not being a function — the original Fastify bug', async () => {
  // Pin the regression: live-reported `TypeError: req.get is not a
  // function` on the Web page browser service. The crash short-
  // circuited the handler chain, returning an empty reply that the
  // sidecar surfaced as `fetch failed`. The middleware must never
  // call req.get() unconditionally — see getHeader() in
  // src/middleware.js.
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([]),
  });
  const req = fastifyReq({ headers: { accept: 'application/json' } });
  const reply = fastifyReply();
  // No throw here — the crash would propagate as a TypeError.
  await assert.doesNotReject(
    () => auth.middleware()(req, reply, () => {}),
    /req\.get is not a function/);
  assert.equal(reply._state.status, 401);
});
