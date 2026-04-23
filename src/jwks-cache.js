/**
 * jwks-cache.js — fetch + cache Operatum's JWKS.
 *
 * Apps call the gateway's public /.well-known/jwks.json exactly as often
 * as they need to. Caching keeps the hot verification path off the wire:
 *
 *   - First verification triggers a fetch.
 *   - Subsequent verifications reuse the cache until `maxAgeMs` elapses.
 *   - A verification failure with kid-not-found forces one refresh — the
 *     right behaviour immediately after a gateway key rotation.
 *
 * We do not cache across process restarts. That's fine: a fresh boot
 * does one JWKS fetch, then serves thousands of requests from memory.
 */

const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 5_000;

export class JwksCache {
  /**
   * @param {object} opts
   * @param {string} opts.jwksUri       - Absolute URL to the gateway JWKS.
   * @param {number} [opts.maxAgeMs]    - How long a successful fetch is trusted.
   * @param {number} [opts.timeoutMs]   - Fetch timeout.
   * @param {typeof fetch} [opts.fetchImpl] - Injectable fetch (for tests).
   */
  constructor({ jwksUri, maxAgeMs = DEFAULT_MAX_AGE_MS, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl } = {}) {
    if (!jwksUri) throw new Error('JwksCache: jwksUri is required');
    this.jwksUri = jwksUri;
    this.maxAgeMs = maxAgeMs;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl || (typeof fetch === 'function' ? fetch : null);
    if (!this.fetchImpl) throw new Error('JwksCache: no fetch implementation available (Node 18+ required or inject fetchImpl)');
    this._keysByKid = new Map();
    this._lastFetchAt = 0;
    this._inflight = null;
  }

  /**
   * Resolve a JWK by kid. Triggers a fetch if the cache is cold, stale,
   * or the kid isn't present (grace-window rotation support).
   */
  async getKey(kid) {
    if (!kid) throw new Error('getKey: kid is required');
    if (this._keysByKid.has(kid) && Date.now() - this._lastFetchAt < this.maxAgeMs) {
      return this._keysByKid.get(kid);
    }
    await this._refresh();
    return this._keysByKid.get(kid) || null;
  }

  /**
   * Force a refresh (used by verify() when signature check fails — could
   * mean the gateway rotated and the fresh kid is new).
   */
  async refresh() {
    return this._refresh();
  }

  async _refresh() {
    if (this._inflight) return this._inflight;
    this._inflight = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(this.jwksUri, { signal: controller.signal });
        if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
        const json = await res.json();
        if (!json || !Array.isArray(json.keys)) throw new Error('JWKS missing keys[]');
        const next = new Map();
        for (const k of json.keys) {
          if (k.kid && k.kty === 'RSA' && k.n && k.e) next.set(k.kid, k);
        }
        this._keysByKid = next;
        this._lastFetchAt = Date.now();
      } finally {
        clearTimeout(timer);
        this._inflight = null;
      }
    })();
    return this._inflight;
  }

  /** Snapshot of currently known kids — useful for diagnostics. */
  knownKids() {
    return [...this._keysByKid.keys()];
  }
}
