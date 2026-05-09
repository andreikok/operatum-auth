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
