/**
 * jwt-verify.js — verify an Operatum-issued RS256 JWT against a JWKS.
 *
 * Zero runtime dependencies: uses node:crypto for signature verification.
 * Supports only RS256 on purpose — apps shouldn't be flexible here. If
 * the gateway ever rotates to a different alg, the client bumps major.
 */

import { createVerify, createPublicKey } from 'node:crypto';

export class TokenError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = 'TokenError';
  }
}

function decodeSegment(seg) {
  // JWT uses base64url without padding; pad back to a multiple of 4.
  const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '==='.slice(0, (4 - b64.length % 4) % 4);
  return Buffer.from(padded, 'base64');
}

function parseSegment(seg) {
  try {
    return JSON.parse(decodeSegment(seg).toString('utf8'));
  } catch {
    throw new TokenError('malformed JWT segment', 'malformed');
  }
}

/**
 * Convert a JWK (RSA) to a Node KeyObject. Deferred to the stdlib via
 * createPublicKey({ format: 'jwk' }) — available on Node 16+.
 */
function jwkToKeyObject(jwk) {
  return createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * Verify the signature + standard claims of an Operatum JWT.
 *
 * @param {string} token
 * @param {object} opts
 * @param {import('./jwks-cache.js').JwksCache} opts.jwks
 * @param {string} opts.expectedAudience   - e.g. `operatum-app:<buildId>`
 * @param {string} [opts.issuer='operatum']
 * @param {number} [opts.clockSkewSec=30]  - seconds of leeway on iat/exp
 * @returns {Promise<object>} the verified payload
 */
export async function verifyToken(token, {
  jwks,
  expectedAudience,
  issuer = 'operatum',
  clockSkewSec = 30,
} = {}) {
  if (!token || typeof token !== 'string') throw new TokenError('missing token', 'missing');
  if (!jwks) throw new TokenError('no JWKS configured', 'misconfigured');
  if (!expectedAudience) throw new TokenError('no expectedAudience configured', 'misconfigured');

  const parts = token.split('.');
  if (parts.length !== 3) throw new TokenError('not a JWT', 'malformed');
  const [headerB64, payloadB64, sigB64] = parts;

  const header = parseSegment(headerB64);
  if (header.alg !== 'RS256') throw new TokenError(`unsupported alg ${header.alg}`, 'alg_mismatch');
  if (!header.kid) throw new TokenError('JWT header missing kid', 'missing_kid');

  // Key lookup — transparent refresh if kid is unknown (rotation).
  let jwk = await jwks.getKey(header.kid);
  if (!jwk) {
    await jwks.refresh();
    jwk = await jwks.getKey(header.kid);
  }
  if (!jwk) throw new TokenError(`unknown kid ${header.kid}`, 'unknown_kid');

  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${headerB64}.${payloadB64}`);
  verifier.end();
  const ok = verifier.verify(jwkToKeyObject(jwk), decodeSegment(sigB64));
  if (!ok) throw new TokenError('signature failed', 'bad_signature');

  const payload = parseSegment(payloadB64);
  const nowSec = Math.floor(Date.now() / 1000);

  if (issuer && payload.iss !== issuer) {
    throw new TokenError(`bad issuer ${payload.iss}`, 'bad_issuer');
  }
  if (payload.aud !== expectedAudience) {
    throw new TokenError(`bad audience ${payload.aud}`, 'bad_audience');
  }
  if (typeof payload.exp !== 'number' || nowSec > payload.exp + clockSkewSec) {
    throw new TokenError('token expired', 'expired');
  }
  if (typeof payload.iat === 'number' && nowSec + clockSkewSec < payload.iat) {
    throw new TokenError('token issued in the future', 'not_yet_valid');
  }

  return payload;
}
