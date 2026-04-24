# operatum-auth — feature audit

**Last audited:** 2026-04-24
**Scope:** the shared JWT / JWKS verification library
(`@operatum/auth`) used by Operatum-built apps to authenticate
requests from the gateway.

Part of a platform-wide review; see `../operatum*/AUDIT.md` for
adjacent services.

---

## Summary

- **Purpose:** JWT verification (RS256 via JWKS) and Express
  middleware for Operatum apps.
- **Maturity:** Production-active. Recent commits (fragment-based
  token handoff). 4 test files. Zero external dependencies — uses
  `node:crypto` and the global `fetch`.

## Declared (and implemented)

- JWKS caching with rotation transparency.
- Express middleware with fine-grained grant gating.
- Three token-handoff patterns: Authorization header, cookie, URL
  fragment.

## Missing / TODO

None observed. The library is small, focused, and well-tested.

## Critical gaps

None.

## Red flags

None. Clean, focused API. Dependency-free means no supply-chain
pressure.

## Remediation priorities

Nothing in the platform-wide roadmap touches this repo.
