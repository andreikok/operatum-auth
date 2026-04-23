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

// Tiny Express-like app for exercising mountHandoff without booting Express.
function fakeApp() {
  const handlers = new Map();
  return {
    post(path, handler) { handlers.set(`POST ${path}`, handler); },
    async call(method, path, req = {}) {
      const h = handlers.get(`${method} ${path}`);
      if (!h) throw new Error(`no handler for ${method} ${path}`);
      const headers = {};
      let status = 200;
      let body = null;
      const res = {
        status(c) { status = c; return this; },
        json(b) { body = b; return this; },
        setHeader(k, v) { headers[k] = v; return this; },
      };
      await h({ body: {}, ...req }, res);
      return { status, headers, body };
    },
  };
}

function jwksFetch(keys) {
  return async () => ({ ok: true, status: 200, json: async () => ({ keys }) });
}

test('mountHandoff: valid token sets operatum.session cookie and returns expires_at', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const app = fakeApp();
  auth.mountHandoff(app);

  const now = Math.floor(Date.now() / 1000);
  const token = sign({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u1', exp: now + 600, iat: now },
  });

  const res = await app.call('POST', '/_operatum/auth/handoff', { body: { token } });
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.expires_at, now + 600);

  const setCookie = res.headers['Set-Cookie'];
  assert.ok(setCookie.includes('operatum.session='), 'session cookie must be set');
  assert.ok(/HttpOnly/.test(setCookie), 'cookie must be httpOnly');
  assert.ok(/SameSite=lax/i.test(setCookie), 'cookie must default to SameSite=Lax');
  assert.ok(/Secure/.test(setCookie), 'cookie must default to Secure');
  assert.ok(/Max-Age=\d+/.test(setCookie), 'cookie must carry Max-Age');
});

test('mountHandoff: rejects missing token with 400', async () => {
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([]),
  });
  const app = fakeApp();
  auth.mountHandoff(app);

  const res = await app.call('POST', '/_operatum/auth/handoff', { body: {} });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'missing_token');
});

test('mountHandoff: rejects a forged token with 401 and a reason code', async () => {
  const kp = mintKeypair();
  const imposter = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const app = fakeApp();
  auth.mountHandoff(app);
  const now = Math.floor(Date.now() / 1000);
  const forged = sign({
    privateKey: imposter.privateKey, kid: kp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u', iat: now, exp: now + 60 },
  });

  const res = await app.call('POST', '/_operatum/auth/handoff', { body: { token: forged } });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'handoff_failed');
  assert.equal(res.body.reason, 'bad_signature');
});

test('mountHandoff: cookieSecure + cookieSameSite options are honored', async () => {
  const kp = mintKeypair();
  const auth = createOperatumAuth({
    jwksUri: 'x',
    expectedAudience: 'operatum-app:b',
    fetchImpl: jwksFetch([kp.jwk]),
  });
  const app = fakeApp();
  auth.mountHandoff(app, { cookieSecure: false, cookieSameSite: 'strict' });

  const now = Math.floor(Date.now() / 1000);
  const token = sign({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u', exp: now + 60, iat: now },
  });
  const res = await app.call('POST', '/_operatum/auth/handoff', { body: { token } });
  const setCookie = res.headers['Set-Cookie'];
  assert.ok(!/Secure/.test(setCookie), 'Secure must be off when cookieSecure: false');
  assert.ok(/SameSite=strict/i.test(setCookie));
});
