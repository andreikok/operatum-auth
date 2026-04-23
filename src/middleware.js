/**
 * middleware.js — Express middleware that verifies Operatum JWTs and
 * populates req.operatum with the caller's identity + grants.
 *
 * Token sources (first match wins):
 *   1. Authorization: Bearer <token>
 *   2. operatum.session cookie (set by the app itself after the SPA
 *      hands off the token — see README for the handoff pattern)
 *   3. ?operatum_token=<token> query string on an initial landing —
 *      apps should redirect to themselves without it after reading.
 *
 * On failure:
 *   - JSON callers (Accept: application/json, or XHR heuristic): 401 JSON
 *   - Browser callers: 302 redirect to `loginUrl?next=<original URL>`
 */

import { JwksCache } from './jwks-cache.js';
import { verifyToken, TokenError } from './jwt-verify.js';

function readCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function extractToken(req, cookieName) {
  const auth = req.headers.authorization || req.headers.Authorization;
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  const fromCookie = readCookie(req.headers.cookie, cookieName);
  if (fromCookie) return fromCookie;
  if (req.query && typeof req.query.operatum_token === 'string') return req.query.operatum_token;
  return null;
}

function wantsJson(req) {
  const accept = (req.headers.accept || '').toLowerCase();
  if (accept.includes('application/json')) return true;
  if ((req.headers['x-requested-with'] || '').toLowerCase() === 'xmlhttprequest') return true;
  return false;
}

/**
 * Create an Operatum auth adapter.
 *
 * @param {object} opts
 * @param {string} opts.jwksUri             - e.g. https://gateway.operatum.example/.well-known/jwks.json
 * @param {string} opts.expectedAudience    - e.g. `operatum-app:<buildId>`
 * @param {string} [opts.loginUrl]          - SPA URL to redirect unauthenticated browsers to. Omit → always 401.
 * @param {string} [opts.issuer='operatum']
 * @param {string} [opts.cookieName='operatum.session']
 * @param {number} [opts.clockSkewSec=30]
 * @param {typeof fetch} [opts.fetchImpl]
 */
export function createOperatumAuth(opts) {
  const {
    jwksUri, expectedAudience, loginUrl,
    issuer = 'operatum',
    cookieName = 'operatum.session',
    clockSkewSec = 30,
    fetchImpl,
  } = opts || {};
  if (!jwksUri) throw new Error('createOperatumAuth: jwksUri required');
  if (!expectedAudience) throw new Error('createOperatumAuth: expectedAudience required');

  const jwks = new JwksCache({ jwksUri, fetchImpl });

  async function verify(token) {
    return verifyToken(token, { jwks, expectedAudience, issuer, clockSkewSec });
  }

  function denyUnauthenticated(req, res, reason) {
    if (wantsJson(req) || !loginUrl) {
      return res.status(401).json({ ok: false, error: 'unauthenticated', reason });
    }
    const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const sep = loginUrl.includes('?') ? '&' : '?';
    return res.redirect(`${loginUrl}${sep}next=${encodeURIComponent(fullUrl)}`);
  }

  function middleware() {
    return async (req, res, next) => {
      const token = extractToken(req, cookieName);
      if (!token) return denyUnauthenticated(req, res, 'no_token');
      try {
        const payload = await verify(token);
        req.operatum = {
          userId: payload.sub,
          email: payload.email,
          tenantId: payload.tenant_id,
          appId: payload.app_id,
          role: payload.role,
          perms: Array.isArray(payload.perms) ? payload.perms : [],
          raw: payload,
        };
        return next();
      } catch (err) {
        if (err instanceof TokenError) return denyUnauthenticated(req, res, err.code);
        return res.status(500).json({ ok: false, error: 'auth_failed' });
      }
    };
  }

  /**
   * Gate a route on a specific grant type. `perm` ∈ {'use','build'}.
   * Assumes `middleware()` ran earlier and populated req.operatum.
   */
  function requirePerm(perm) {
    return (req, res, next) => {
      if (!req.operatum) {
        return res.status(401).json({ ok: false, error: 'unauthenticated' });
      }
      if (!req.operatum.perms.includes(perm)) {
        return res.status(403).json({ ok: false, error: `missing '${perm}' permission` });
      }
      return next();
    };
  }

  /**
   * Mount POST /_operatum/auth/handoff on the app. The Operatum SPA
   * opens the app with `#operatum_token=<jwt>` in the URL fragment;
   * the app's client-side JS reads the fragment and POSTs
   *
   *   fetch('/_operatum/auth/handoff', {
   *     method: 'POST',
   *     headers: { 'Content-Type': 'application/json' },
   *     credentials: 'include',
   *     body: JSON.stringify({ token })
   *   })
   *
   * on first load. This endpoint verifies the token, sets an httpOnly
   * `operatum.session` cookie scoped to the app's domain, and returns
   * `{ ok: true, expires_at }` so the SPA can wipe the fragment and
   * start behaving normally.
   *
   * Separating the fragment-handoff into a dedicated endpoint keeps the
   * raw token out of any other logs/proxies on the app's side — it only
   * ever appears in one POST body, which Express doesn't log by default.
   *
   * @param {import('express').Application | import('express').Router} app
   * @param {object} [opts]
   * @param {string} [opts.path='/_operatum/auth/handoff']
   * @param {boolean} [opts.cookieSecure=true]   - Set Secure on the cookie
   * @param {string} [opts.cookieSameSite='lax'] - 'lax' | 'strict' | 'none'
   */
  function mountHandoff(app, opts = {}) {
    const {
      path = '/_operatum/auth/handoff',
      cookieSecure = true,
      cookieSameSite = 'lax',
    } = opts;

    app.post(path, async (req, res) => {
      try {
        // Accept both Express's json-parsed body and a raw string (tolerant
        // for apps that haven't wired `express.json()` yet).
        let token = null;
        if (req.body && typeof req.body === 'object' && typeof req.body.token === 'string') {
          token = req.body.token;
        } else if (typeof req.body === 'string') {
          try { token = JSON.parse(req.body).token; } catch { /* fall through */ }
        }
        if (!token) {
          return res.status(400).json({ ok: false, error: 'missing_token' });
        }

        const payload = await verify(token);
        const maxAgeMs = Math.max(0, (payload.exp * 1000) - Date.now());
        const cookieParts = [
          `${cookieName}=${encodeURIComponent(token)}`,
          'Path=/',
          'HttpOnly',
          `SameSite=${cookieSameSite}`,
          `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
        ];
        if (cookieSecure) cookieParts.push('Secure');
        res.setHeader('Set-Cookie', cookieParts.join('; '));
        res.json({ ok: true, expires_at: payload.exp });
      } catch (err) {
        const code = (err && err.code) || 'auth_failed';
        res.status(401).json({ ok: false, error: 'handoff_failed', reason: code });
      }
    });
  }

  return { middleware, requirePerm, verify, jwks, mountHandoff };
}
