export { JwksCache } from './jwks-cache.js';
export { verifyToken, TokenError } from './jwt-verify.js';
export { createOperatumAuth } from './middleware.js';
// Stage-8 reverse-proxy mode: drop-in replacement for
// createOperatumAuth that reads identity from X-Operatum-* request
// headers instead of verifying a JWT. Use this when the gateway
// is fronting the app with --network operatum-net + loopback-only
// publishing; the trust anchor is topology, not crypto.
export {
  createOperatumAuthFromHeaders, readOperatumHeaders,
} from './header-mode.js';
// D2/D3 — producer-side cross-app dependency-token verification. A dep call
// arrives container→container with only a Bearer service token; the producer
// verifies it (JWKS crypto + a dep scope for its own build + a revocation
// callback). createOperatumAuthFromHeaders().middleware() handles this
// automatically; these are exposed for direct use + tests.
export {
  verifyDepToken, parseDepScope, parseDepToolScope,
} from './service-mode.js';
