import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JwksCache } from '../src/jwks-cache.js';

function fakeJwksResponse(keys) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ keys }),
  };
}

test('JwksCache fetches on first getKey and caches by kid', async () => {
  let calls = 0;
  const cache = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    fetchImpl: async () => { calls++; return fakeJwksResponse([{ kid: 'A', kty: 'RSA', n: 'x', e: 'AQAB' }]); },
  });
  const hit = await cache.getKey('A');
  assert.equal(hit.kid, 'A');
  assert.equal(calls, 1);

  const again = await cache.getKey('A');
  assert.equal(again.kid, 'A');
  assert.equal(calls, 1, 'second lookup must not refetch while cache is fresh');
});

test('JwksCache forces a refresh when asked for an unknown kid', async () => {
  let calls = 0;
  let responseKeys = [{ kid: 'A', kty: 'RSA', n: 'x', e: 'AQAB' }];
  const cache = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    fetchImpl: async () => { calls++; return fakeJwksResponse(responseKeys); },
  });

  await cache.getKey('A');
  assert.equal(calls, 1);

  // Simulate a gateway rotation — JWKS now publishes B (and maybe A as retired).
  responseKeys = [{ kid: 'B', kty: 'RSA', n: 'y', e: 'AQAB' }];
  // The cache hasn't expired yet, but B is unknown — getKey should refetch.
  const missing = await cache.getKey('B');
  assert.equal(calls, 2, 'unknown kid must trigger a refetch');
  assert.equal(missing.kid, 'B');
});

test('JwksCache maxAgeMs expires the cache', async () => {
  let calls = 0;
  const cache = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    maxAgeMs: 5,
    fetchImpl: async () => { calls++; return fakeJwksResponse([{ kid: 'A', kty: 'RSA', n: 'x', e: 'AQAB' }]); },
  });
  await cache.getKey('A');
  await new Promise(r => setTimeout(r, 25));
  await cache.getKey('A');
  assert.equal(calls, 2, 'second lookup past maxAgeMs must refetch');
});

test('JwksCache rejects non-OK and missing keys[] responses', async () => {
  const cache = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({}) }),
  });
  await assert.rejects(() => cache.getKey('A'), /JWKS fetch failed/);

  const cache2 = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ not_keys: [] }) }),
  });
  await assert.rejects(() => cache2.getKey('A'), /missing keys\[\]/);
});

test('JwksCache coalesces concurrent refreshes', async () => {
  let calls = 0;
  const cache = new JwksCache({
    jwksUri: 'https://example/.well-known/jwks.json',
    fetchImpl: async () => {
      calls++;
      await new Promise(r => setTimeout(r, 20));
      return fakeJwksResponse([{ kid: 'A', kty: 'RSA', n: 'x', e: 'AQAB' }]);
    },
  });
  const [a, b, c] = await Promise.all([cache.getKey('A'), cache.getKey('A'), cache.getKey('A')]);
  assert.equal(a.kid, 'A');
  assert.equal(b.kid, 'A');
  assert.equal(c.kid, 'A');
  assert.equal(calls, 1, 'concurrent first-calls must share a single fetch');
});
