// header-mode.test.js — reverse-proxy mode (stage-8-pr-3).
//
// Two layers:
//   1. readOperatumHeaders pure-function tests — must STAY in
//      lockstep with the gateway's operatum-headers.js. This is
//      the protocol contract; drift breaks authentication.
//   2. Middleware behavioural tests — mock req/res, verify the
//      middleware accepts/rejects correctly and populates
//      req.operatum with the right shape.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  createOperatumAuthFromHeaders, readOperatumHeaders, _getHeader,
} from '../src/header-mode.js';

const UUID_USER  = '00000000-0000-0000-0000-000000000001';
const UUID_TEN   = '00000000-0000-0000-0000-000000000002';
const UUID_BUILD = '00000000-0000-0000-0000-000000000003';

const validHeaders = (overrides = {}) => ({
  'x-operatum-user-id':     UUID_USER,
  'x-operatum-tenant-id':   UUID_TEN,
  'x-operatum-email':       'alice%40example.com',
  'x-operatum-role':        'builder',
  'x-operatum-build-id':    UUID_BUILD,
  'x-operatum-perms':       '["use"]',
  'x-operatum-auth-mode':   'reverse-proxy',
  ...overrides,
});

// Tiny mock res that captures what a middleware sends.
function makeRes() {
  const captured = { status: null, body: null };
  return {
    captured,
    status(code) { captured.status = code; return this; },
    json(body)   { captured.body = body; return this; },
  };
}

describe('readOperatumHeaders — protocol contract (mirror of gateway)', () => {
  test('happy path: returns clean identity object', () => {
    const r = readOperatumHeaders(validHeaders({
      'x-operatum-display-name': 'Alice',
    }));
    assert.deepEqual(r, {
      userId: UUID_USER,
      tenantId: UUID_TEN,
      email: 'alice@example.com',
      role: 'builder',
      buildId: UUID_BUILD,
      perms: ['use'],
      authMode: 'reverse-proxy',
      displayName: 'Alice',
    });
  });

  test('display-name is optional', () => {
    const r = readOperatumHeaders(validHeaders());
    assert.equal('displayName' in r, false);
  });

  test('decodes percent-encoded email + display name', () => {
    const r = readOperatumHeaders(validHeaders({
      'x-operatum-email':       'a%20b%40c.com',
      'x-operatum-display-name': '%C3%81lice',  // Álice
    }));
    assert.equal(r.email, 'a b@c.com');
    assert.equal(r.displayName, 'Álice');
  });

  test('null on bad UUID in any required field', () => {
    for (const field of ['x-operatum-user-id', 'x-operatum-tenant-id', 'x-operatum-build-id']) {
      const h = validHeaders({ [field]: 'not-a-uuid' });
      assert.equal(readOperatumHeaders(h), null,
        `must reject malformed ${field}`);
    }
  });

  test('null on unknown role (allow-list)', () => {
    assert.equal(readOperatumHeaders(validHeaders({ 'x-operatum-role': 'guest' })), null);
    assert.equal(readOperatumHeaders(validHeaders({ 'x-operatum-role': '' })), null);
  });

  test('null when auth-mode missing or wrong (BYPASS GUARD)', () => {
    // The single most security-load-bearing assertion. If a future
    // refactor accidentally accepts requests without auth-mode=
    // reverse-proxy, header-mode could be invoked on legacy bearer
    // requests and validate them without verifying the JWT. Pin
    // this branch hard.
    const noMode = validHeaders();
    delete noMode['x-operatum-auth-mode'];
    assert.equal(readOperatumHeaders(noMode), null);
    assert.equal(readOperatumHeaders(validHeaders({ 'x-operatum-auth-mode': 'bearer' })), null);
    assert.equal(readOperatumHeaders(validHeaders({ 'x-operatum-auth-mode': 'none' })), null);
  });

  test('null on invalid perms JSON or non-array', () => {
    for (const v of ['not json', '{}', '"use"', 'null', '']) {
      assert.equal(readOperatumHeaders(validHeaders({ 'x-operatum-perms': v })), null);
    }
  });

  test('null on null/undefined/non-object input', () => {
    assert.equal(readOperatumHeaders(null), null);
    assert.equal(readOperatumHeaders(undefined), null);
    assert.equal(readOperatumHeaders('headers'), null);
  });

  test('case-insensitive header lookup (HTTP/1.1 stack tolerance)', () => {
    // Some proxies preserve original casing. Build the upper-case
    // form and verify the read still works.
    const upper = {};
    for (const [k, v] of Object.entries(validHeaders())) {
      upper[k.toUpperCase()] = v;
    }
    const r = readOperatumHeaders(upper);
    assert.ok(r, 'must read upper-case headers');
    assert.equal(r.userId, UUID_USER);
  });
});

describe('createOperatumAuthFromHeaders.middleware() — accept paths', () => {
  test('populates req.operatum with the expected shape', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: validHeaders({ 'x-operatum-display-name': 'Alice' }) };
    const res = makeRes();
    let nextCalled = false;
    auth.middleware()(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true, 'next must fire on successful auth');
    assert.equal(res.captured.status, null, 'no error response on success');
    // appId == buildId — bearer-mode parity so app code doesn't branch
    assert.equal(req.operatum.appId, UUID_BUILD);
    assert.equal(req.operatum.userId, UUID_USER);
    assert.equal(req.operatum.tenantId, UUID_TEN);
    assert.equal(req.operatum.email, 'alice@example.com');
    assert.equal(req.operatum.role, 'builder');
    assert.deepEqual(req.operatum.perms, ['use']);
    assert.equal(req.operatum.displayName, 'Alice');
  });

  test('omits displayName from req.operatum when not present', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: validHeaders() };
    const res = makeRes();
    auth.middleware()(req, res, () => {});
    assert.equal('displayName' in req.operatum, false);
  });

  test('handles perms: ["use","build"]', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: validHeaders({ 'x-operatum-perms': '["use","build"]' }) };
    const res = makeRes();
    let nextCalled = false;
    auth.middleware()(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.deepEqual(req.operatum.perms, ['use', 'build']);
  });
});

describe('createOperatumAuthFromHeaders.middleware() — reject paths', () => {
  test('401 when headers are missing entirely', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: {} };
    const res = makeRes();
    let nextCalled = false;
    auth.middleware()(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, false, 'next MUST NOT fire on bad auth');
    assert.equal(res.captured.status, 401);
    assert.equal(res.captured.body.ok, false);
    assert.equal(res.captured.body.error, 'unauthenticated');
    assert.equal(res.captured.body.reason, 'missing_or_invalid_operatum_headers');
  });

  test('401 when auth-mode header is "bearer" (legacy mode bypass guard)', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: validHeaders({ 'x-operatum-auth-mode': 'bearer' }) };
    const res = makeRes();
    auth.middleware()(req, res, () => {
      assert.fail('next must NOT fire when auth-mode is wrong');
    });
    assert.equal(res.captured.status, 401);
  });

  test('401 with NO redirect (no fragment-token recovery in this mode)', () => {
    // Bearer mode redirects browsers to loginUrl on unauth. Header
    // mode does NOT — there's nothing the app can do to recover
    // (the gateway should have authenticated; if it didn't, this
    // is a misrouted request or a topology breach).
    const auth = createOperatumAuthFromHeaders();
    const req = { headers: {} };
    const res = makeRes();
    res.redirect = () => assert.fail('must NOT redirect in header mode');
    auth.middleware()(req, res, () => {});
    assert.equal(res.captured.status, 401);
  });
});

describe('createOperatumAuthFromHeaders.requirePerm() — grant gate', () => {
  test('passes when perm is in req.operatum.perms', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { operatum: { perms: ['use', 'build'] } };
    const res = makeRes();
    let nextCalled = false;
    auth.requirePerm('build')(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.equal(res.captured.status, null);
  });

  test('403 when perm is missing', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = { operatum: { perms: ['use'] } };
    const res = makeRes();
    auth.requirePerm('build')(req, res, () => {
      assert.fail('next must not fire on missing perm');
    });
    assert.equal(res.captured.status, 403);
    assert.match(res.captured.body.error, /missing 'build' permission/);
  });

  test('401 when req.operatum is missing entirely (middleware not run)', () => {
    const auth = createOperatumAuthFromHeaders();
    const req = {};
    const res = makeRes();
    auth.requirePerm('use')(req, res, () => {});
    assert.equal(res.captured.status, 401);
  });
});

describe('createOperatumAuthFromHeaders.verify() — shape stub', () => {
  test('throws explanatory error (no token to verify in this mode)', async () => {
    const auth = createOperatumAuthFromHeaders();
    await assert.rejects(() => auth.verify(),
      /not meaningful in reverse-proxy mode/);
  });
});

describe('returned API shape — drop-in parity with createOperatumAuth', () => {
  test('exposes middleware, requirePerm, verify (same surface)', () => {
    const auth = createOperatumAuthFromHeaders();
    assert.equal(typeof auth.middleware,   'function');
    assert.equal(typeof auth.requirePerm,  'function');
    assert.equal(typeof auth.verify,       'function');
  });

  test('does NOT expose mountHandoff (no fragment-token flow in this mode)', () => {
    // Bearer mode mounts /_operatum/auth/handoff for the SPA's
    // fragment handoff. Header mode has no fragment, no SPA, no
    // cookie — exposing mountHandoff would invite apps to wire it
    // up and then wonder why nothing flows through.
    const auth = createOperatumAuthFromHeaders();
    assert.equal('mountHandoff' in auth, false);
  });

  test('does NOT expose jwks (no JWKS in this mode)', () => {
    const auth = createOperatumAuthFromHeaders();
    assert.equal('jwks' in auth, false);
  });
});

// ── HMAC proof-of-gateway tests ───────────────────────────────────────────────
//
// Helpers that mirror operatum-ui/gateway/src/lib/operatum-headers.js so we
// can produce valid signed header sets for testing without importing the gateway.

const HMAC_HEADER_NAMES = [
  'x-operatum-user-id', 'x-operatum-tenant-id', 'x-operatum-email',
  'x-operatum-display-name', 'x-operatum-role', 'x-operatum-build-id',
  'x-operatum-perms', 'x-operatum-auth-mode',
];

function signHeaders(headers, secret, ts = String(Date.now())) {
  const parts = [];
  for (const name of HMAC_HEADER_NAMES) {
    const v = headers[name];
    if (v != null) parts.push(`${name}=${v}`);
  }
  parts.push(`x-operatum-timestamp=${ts}`);
  const sig = createHmac('sha256', secret).update(parts.join('\n')).digest('hex');
  return { ...headers, 'x-operatum-timestamp': ts, 'x-operatum-signature': sig };
}

const TEST_SECRET = 'test-signing-secret-32-bytes-long!!';
const FIXED_TS = String(Date.now());

describe('readOperatumHeaders — HMAC signature enforcement', () => {
  test('presence-only still works when no secret supplied', () => {
    const r = readOperatumHeaders(validHeaders());
    assert.ok(r, 'presence-only path must still work without a secret');
  });

  test('accepts valid signed headers when secret matches', () => {
    const signed = signHeaders(validHeaders(), TEST_SECRET, FIXED_TS);
    const r = readOperatumHeaders(signed, { secret: TEST_SECRET, now: Number(FIXED_TS) });
    assert.ok(r, 'must accept correctly signed headers');
    assert.equal(r.userId, UUID_USER);
  });

  test('rejects unsigned headers when secret is configured', () => {
    const r = readOperatumHeaders(validHeaders(), { secret: TEST_SECRET, now: Number(FIXED_TS) });
    assert.equal(r, null, 'unsigned headers must be rejected when secret is set');
  });

  test('rejects headers with wrong signature', () => {
    const signed = signHeaders(validHeaders(), 'wrong-secret', FIXED_TS);
    const r = readOperatumHeaders(signed, { secret: TEST_SECRET, now: Number(FIXED_TS) });
    assert.equal(r, null, 'wrong-key signature must be rejected');
  });

  test('rejects stale timestamp (anti-replay)', () => {
    const staleTs = String(Date.now() - 6 * 60 * 1000); // 6 min ago, outside ±5 min window
    const signed = signHeaders(validHeaders(), TEST_SECRET, staleTs);
    const r = readOperatumHeaders(signed, { secret: TEST_SECRET, now: Date.now() });
    assert.equal(r, null, 'stale signature must be rejected');
  });

  test('rejects when signature header is missing', () => {
    const signed = signHeaders(validHeaders(), TEST_SECRET, FIXED_TS);
    delete signed['x-operatum-signature'];
    const r = readOperatumHeaders(signed, { secret: TEST_SECRET, now: Number(FIXED_TS) });
    assert.equal(r, null, 'missing signature must be rejected');
  });

  test('rejects when timestamp header is missing', () => {
    const signed = signHeaders(validHeaders(), TEST_SECRET, FIXED_TS);
    delete signed['x-operatum-timestamp'];
    const r = readOperatumHeaders(signed, { secret: TEST_SECRET, now: Number(FIXED_TS) });
    assert.equal(r, null, 'missing timestamp must be rejected');
  });
});

describe('createOperatumAuthFromHeaders — HMAC enforcement via opts.secret', () => {
  test('accepts valid signed headers when opts.secret matches', () => {
    const auth = createOperatumAuthFromHeaders({ secret: TEST_SECRET });
    const signed = signHeaders(validHeaders(), TEST_SECRET, FIXED_TS);
    const req = { headers: signed };
    const res = makeRes();
    let nextCalled = false;
    // inject clock so the signature isn't stale by test runtime
    // (middleware uses Date.now() internally; we seed a fresh TS above)
    auth.middleware()(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true, 'next must fire for correctly signed headers');
    assert.equal(res.captured.status, null);
  });

  test('rejects unsigned headers when opts.secret is set (fails closed)', () => {
    const auth = createOperatumAuthFromHeaders({ secret: TEST_SECRET });
    const req = { headers: validHeaders() }; // no signature headers
    const res = makeRes();
    auth.middleware()(req, res, () => {
      assert.fail('next must NOT fire for unsigned headers when secret is configured');
    });
    assert.equal(res.captured.status, 401);
    assert.equal(res.captured.body.error, 'unauthenticated');
  });

  test('presence-only when no secret (backward compat)', () => {
    const auth = createOperatumAuthFromHeaders(); // no opts.secret, no env var
    const req = { headers: validHeaders() };
    const res = makeRes();
    let nextCalled = false;
    auth.middleware()(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true, 'presence-only must still work when no secret');
  });
});

describe('framework adapter (_getHeader)', () => {
  // The adapter is shared with bearer-mode middleware.js but is
  // re-exported here for test isolation. Pin both shapes.
  test('Express-shaped req.get() takes precedence', () => {
    const req = {
      get(name) { return name === 'x-foo' ? 'from-get' : null; },
      headers: { 'x-foo': 'from-headers' },
    };
    assert.equal(_getHeader(req, 'x-foo'), 'from-get');
  });

  test('falls back to headers map when req.get is absent (Fastify)', () => {
    const req = { headers: { 'x-foo': 'from-headers' } };
    assert.equal(_getHeader(req, 'x-foo'), 'from-headers');
  });

  test('case-insensitive headers-map lookup', () => {
    const req = { headers: { 'X-FOO': 'shouty' } };
    // Headers map already-lowercased on Node, but Fastify passes
    // through some original-cased ones. Tolerate both.
    assert.equal(_getHeader(req, 'X-FOO'), 'shouty');
  });
});
