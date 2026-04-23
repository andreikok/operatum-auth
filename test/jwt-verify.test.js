import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync, createSign, createPublicKey, createHash,
} from 'node:crypto';
import { verifyToken, TokenError } from '../src/jwt-verify.js';
import { JwksCache } from '../src/jwks-cache.js';

// ── Helpers: mint a keypair + sign a test token (mirrors gateway behaviour) ──

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

function signJwt({ privateKey, kid, payload, alg = 'RS256' }) {
  const header = { alg, typ: 'JWT', kid };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${b64url(signer.sign(privateKey))}`;
}

// Wrap a static JWKS in a fake fetch so JwksCache serves known keys.
function jwksServing(jwks) {
  return async () => ({
    ok: true,
    status: 200,
    json: async () => ({ keys: jwks }),
  });
}

// ── Core happy path ─────────────────────────────────────────────────────────

test('verifyToken round-trips a gateway-style RS256 JWT', async () => {
  const kp = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([kp.jwk]) });
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: {
      iss: 'operatum', aud: 'operatum-app:build-1', sub: 'u1',
      email: 'u@operatum.com', perms: ['use'], iat: now, exp: now + 60,
    },
  });
  const payload = await verifyToken(token, { jwks, expectedAudience: 'operatum-app:build-1' });
  assert.equal(payload.sub, 'u1');
  assert.equal(payload.aud, 'operatum-app:build-1');
});

// ── Negative paths ──────────────────────────────────────────────────────────

test('verifyToken rejects a token signed with a different key', async () => {
  const legit = mintKeypair();
  const imposter = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([legit.jwk]) });
  const now = Math.floor(Date.now() / 1000);
  const badToken = signJwt({
    privateKey: imposter.privateKey, kid: legit.kid, // correct kid, wrong key
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u', iat: now, exp: now + 60 },
  });
  await assert.rejects(
    () => verifyToken(badToken, { jwks, expectedAudience: 'operatum-app:b' }),
    (err) => err instanceof TokenError && err.code === 'bad_signature'
  );
});

test('verifyToken rejects a token for a different audience (cross-app replay)', async () => {
  const kp = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([kp.jwk]) });
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:A', sub: 'u', iat: now, exp: now + 60 },
  });
  await assert.rejects(
    () => verifyToken(token, { jwks, expectedAudience: 'operatum-app:B' }),
    (err) => err instanceof TokenError && err.code === 'bad_audience'
  );
});

test('verifyToken rejects an expired token (outside skew window)', async () => {
  const kp = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([kp.jwk]) });
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    privateKey: kp.privateKey, kid: kp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u', iat: now - 3600, exp: now - 60 },
  });
  await assert.rejects(
    () => verifyToken(token, { jwks, expectedAudience: 'operatum-app:b', clockSkewSec: 5 }),
    (err) => err instanceof TokenError && err.code === 'expired'
  );
});

test('verifyToken rejects non-RS256 algorithms', async () => {
  const kp = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([kp.jwk]) });
  const now = Math.floor(Date.now() / 1000);
  // Forge a header claiming HS256. No valid signature needed — alg check fires first.
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: kp.kid }));
  const payload = b64url(JSON.stringify({ iss: 'operatum', aud: 'operatum-app:b', exp: now + 60 }));
  const badToken = `${header}.${payload}.sig`;
  await assert.rejects(
    () => verifyToken(badToken, { jwks, expectedAudience: 'operatum-app:b' }),
    (err) => err instanceof TokenError && err.code === 'alg_mismatch'
  );
});

test('verifyToken rejects a token with no kid (defends against "alg:none"-style forgeries)', async () => {
  const kp = mintKeypair();
  const jwks = new JwksCache({ jwksUri: 'x', fetchImpl: jwksServing([kp.jwk]) });
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })); // no kid
  const payload = b64url(JSON.stringify({ iss: 'operatum', aud: 'operatum-app:b' }));
  const token = `${header}.${payload}.sig`;
  await assert.rejects(
    () => verifyToken(token, { jwks, expectedAudience: 'operatum-app:b' }),
    (err) => err instanceof TokenError && err.code === 'missing_kid'
  );
});

test('verifyToken accepts a rotated key after JWKS refresh', async () => {
  const oldKp = mintKeypair();
  const newKp = mintKeypair();
  // Start with only the old key published.
  let published = [oldKp.jwk];
  let fetchCount = 0;
  const jwks = new JwksCache({
    jwksUri: 'x',
    fetchImpl: async () => { fetchCount++; return { ok: true, status: 200, json: async () => ({ keys: published }) }; },
  });

  // Prime the cache.
  await jwks.getKey(oldKp.kid);
  assert.equal(fetchCount, 1);

  // Gateway rotates — new key published, old retired.
  published = [newKp.jwk, oldKp.jwk];
  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    privateKey: newKp.privateKey, kid: newKp.kid,
    payload: { iss: 'operatum', aud: 'operatum-app:b', sub: 'u', iat: now, exp: now + 60 },
  });
  // Unknown kid triggers a refresh transparently — token verifies.
  const payload = await verifyToken(token, { jwks, expectedAudience: 'operatum-app:b' });
  assert.equal(payload.sub, 'u');
  assert.ok(fetchCount >= 2, 'a refetch must have happened');
});
