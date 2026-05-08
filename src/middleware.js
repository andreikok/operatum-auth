/**
 * middleware.js — framework-agnostic middleware that verifies
 * Operatum JWTs and populates req.operatum with the caller's
 * identity + grants. Works with both Express (req.get / res.status
 * / res.redirect) and Fastify (req.headers / reply.code / reply.send
 * / reply.redirect) — the helpers below detect which framework's
 * shape is on the request and call the right APIs.
 *
 * Live-reported on 2026-05-07: Fastify apps crashed at
 * `req.get('host')` because that's an Express-only method; a Fastify
 * `request` doesn't have it. The agent saw `fetch failed` because
 * the middleware threw → handler chain aborted → empty reply.
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

// ── Framework adapters ────────────────────────────────────────────
//
// Express:  req.get(name) / req.protocol / req.originalUrl
//           res.status(n).json(o)   /   res.redirect(url)
// Fastify:  req.headers[name]      / req.protocol / req.url
//           reply.code(n).send(o)  /   reply.redirect(url)
//
// The middleware must work with either; these helpers normalise
// the lookup so the rest of the file doesn't branch.

function getHeader(req, name) {
  // Express's req.get() is case-insensitive; Fastify exposes the
  // already-lowercased headers map. Try req.get() first, then fall
  // through to the headers map — partial Express mocks that don't
  // implement get() for every name (and Fastify, which lacks get()
  // entirely) get the same answer.
  if (typeof req.get === 'function') {
    const v = req.get(name);
    if (v != null) return v;
  }
  const h = req.headers || {};
  return h[name] || h[name.toLowerCase()] || null;
}

function getOriginalUrl(req) {
  return req.originalUrl || req.url || '/';
}

function sendJson(res, status, body) {
  // Fastify exposes reply.code()+reply.send(); Express exposes
  // res.status()+res.json(). reply.send() of a plain object emits
  // application/json automatically.
  if (typeof res.code === 'function' && typeof res.send === 'function') {
    return res.code(status).send(body);
  }
  return res.status(status).json(body);
}

function sendRedirect(res, url) {
  // Both frameworks expose .redirect(url), but Fastify wants
  // reply.redirect(url, statusCode?) and ignores the body. Stick to
  // the single-arg form so it works on both.
  return res.redirect(url);
}

function sendHtml(res, status, html) {
  // Express: res.status(n).type('html').send(html)
  // Fastify: reply.code(n).type('text/html').send(html)
  if (typeof res.code === 'function' && typeof res.send === 'function') {
    if (typeof res.type === 'function') res.type('text/html');
    else if (typeof res.header === 'function') res.header('Content-Type', 'text/html; charset=utf-8');
    return res.code(status).send(html);
  }
  if (typeof res.status === 'function') {
    res.status(status);
    if (typeof res.type === 'function') res.type('html');
    else res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  }
  // Bare-Node fallback (used in tests with mock res objects).
  res.statusCode = status;
  if (typeof res.setHeader === 'function') res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.end(html);
}

/**
 * Build the bootstrap HTML served on unauthenticated browser GETs.
 *
 * The default Operatum SSO entry mints a JWT and redirects the
 * browser to `<app>/<path>#operatum_token=<jwt>`. The plan is then
 * for the app's client-side JS to read the fragment and POST it to
 * `/_operatum/auth/handoff` (set up by `mountHandoff`) — that sets
 * the cookie that the server-side middleware consumes on subsequent
 * requests.
 *
 * The original middleware behaviour was to 302 unauthenticated
 * browser requests straight to `loginUrl`. That works for SPAs whose
 * index.html is served publicly (the SPA snippet runs and POSTs
 * before the server-side gate fires) — but not for typical Express
 * apps that gate every route, including `/`. The 302 races the
 * fragment: the browser carries the fragment forward across the
 * redirect (RFC 7231 §7.1.2 — empty target fragment inherits), so
 * the user ends up at `gateway/login?next=…#operatum_token=<jwt>`
 * with the fragment intact but no JS ever ran on the app side to
 * process it. Net effect: a redirect loop the operator sees as
 * "Cannot GET /login" with the token still in the URL bar.
 *
 * The bootstrap HTML closes that gap by running on the FIRST
 * unauthenticated render. It reads the fragment, POSTs the token to
 * `/_operatum/auth/handoff` (same endpoint mountHandoff registers),
 * clears the fragment from the URL on success, and reloads — by
 * which point the cookie is set and the middleware lets the request
 * through. When there's no fragment token to consume, it falls back
 * to the same redirect the middleware was doing before.
 *
 * The page is intentionally tiny and self-contained: no external
 * scripts, no styles, no framework. It must work in any browser the
 * gateway minted a token for, including ones that haven't loaded
 * any other resources from this origin yet.
 */
function buildBootstrapHtml(redirectUrl) {
  // The redirect URL is interpolated as a JSON string so it can't
  // break out of the script context. The handoff path is fixed
  // because mountHandoff doesn't expose its configured path back to
  // the middleware — they both default to /_operatum/auth/handoff,
  // and apps that change it via mountHandoff({ path: '...' }) can
  // override the bootstrap path with the same option (planned).
  const handoffPath = '/_operatum/auth/handoff';
  const safeRedirect = JSON.stringify(redirectUrl);
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Signing in…</title></head>
<body>
<p>Signing in…</p>
<script>
(async function() {
  var hash = (location.hash || '').replace(/^#/, '');
  var m = hash.match(/(?:^|&)operatum_token=([^&]+)/);
  if (m) {
    try {
      var token = decodeURIComponent(m[1]);
      var r = await fetch(${JSON.stringify(handoffPath)}, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token: token })
      });
      if (r.ok) {
        // Strip the fragment so the token doesn't survive in the
        // URL bar, then reload — the cookie is set, this request's
        // path is now authenticated, and the middleware lets it
        // through on the second pass.
        history.replaceState(null, '', location.pathname + location.search);
        location.reload();
        return;
      }
    } catch (e) { /* fall through to redirect */ }
  }
  // No fragment-token (or handoff failed) — go to the SSO entry.
  location.replace(${safeRedirect});
})();
</script>
</body></html>`;
}

function readCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function extractToken(req, cookieName) {
  const auth = getHeader(req, 'authorization');
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  const fromCookie = readCookie(getHeader(req, 'cookie'), cookieName);
  if (fromCookie) return fromCookie;
  if (req.query && typeof req.query.operatum_token === 'string') return req.query.operatum_token;
  return null;
}

function wantsJson(req) {
  const accept = (getHeader(req, 'accept') || '').toLowerCase();
  if (accept.includes('application/json')) return true;
  if ((getHeader(req, 'x-requested-with') || '').toLowerCase() === 'xmlhttprequest') return true;
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
      return sendJson(res, 401, { ok: false, error: 'unauthenticated', reason });
    }
    const protocol = req.protocol || 'http';
    const host = getHeader(req, 'host') || '';
    const fullUrl = `${protocol}://${host}${getOriginalUrl(req)}`;
    const sep = loginUrl.includes('?') ? '&' : '?';
    const ssoUrl = `${loginUrl}${sep}next=${encodeURIComponent(fullUrl)}`;
    // Browser unauthenticated GET: serve a bootstrap HTML that reads
    // a fragment-token (if present) and POSTs it to the handoff
    // endpoint, falling back to the SSO redirect otherwise. A bare
    // 302 here would race the fragment-token handoff (the SPA
    // snippet that's supposed to consume the fragment never gets to
    // run because we redirect away first) — see buildBootstrapHtml's
    // doc-comment for the full rationale.
    return sendHtml(res, 200, buildBootstrapHtml(ssoUrl));
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
        return sendJson(res, 500, { ok: false, error: 'auth_failed' });
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
        return sendJson(res, 401, { ok: false, error: 'unauthenticated' });
      }
      if (!req.operatum.perms.includes(perm)) {
        return sendJson(res, 403, { ok: false, error: `missing '${perm}' permission` });
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
          return sendJson(res, 400, { ok: false, error: 'missing_token' });
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
        // Both Express's res.setHeader and Fastify's reply.header /
        // raw.setHeader work; raw is the most universal escape.
        if (typeof res.header === 'function') {
          res.header('Set-Cookie', cookieParts.join('; '));
        } else if (res.raw && typeof res.raw.setHeader === 'function') {
          res.raw.setHeader('Set-Cookie', cookieParts.join('; '));
        } else {
          res.setHeader('Set-Cookie', cookieParts.join('; '));
        }
        sendJson(res, 200, { ok: true, expires_at: payload.exp });
      } catch (err) {
        const code = (err && err.code) || 'auth_failed';
        sendJson(res, 401, { ok: false, error: 'handoff_failed', reason: code });
      }
    });
  }

  return { middleware, requirePerm, verify, jwks, mountHandoff };
}
