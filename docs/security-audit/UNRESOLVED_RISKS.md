# 0 TO 8848 — RESIDUAL & INFRASTRUCTURE RISKS REGISTER

**Project:** 0 TO 8848 — Global Adventure Achievement Platform (`https://0to8848official.com`)  
**Branch:** `security/remediate-bug01-bug10`  

---

## Honest Disclosure of Infrastructure-Dependent Controls

All 10 code-level security and reliability bugs (`BUG-01` through `BUG-10`) are resolved and tested. In accordance with the project's strict non-fabrication policy, the following production cloud infrastructure items remain environment-dependent at deployment time:

1. **External Cloud WORM Object Lock Provisioning (`BUG-09`):**
   - **Code Status:** `src/server/wormArchiveService.ts` implements authenticated `AES-256-GCM` + `HMAC-SHA256` archive bundle creation, tamper-evident recovery verification, failure alerting, and the `WormProviderTransportAdapter` interface.
   - **Runtime Status:** Until an external AWS S3 Object Lock (COMPLIANCE mode) or GCP Bucket Lock credentials/adapter are registered in production environment variables, `getWormReplicationStatus()` and `GET /api/v1/health` honestly report `protectionLevel: "LOCAL_SQLITE_TRIGGER_IMMUTABLE"` and `wormReplicated: false`.
2. **Multi-Instance Distributed Rate Limit Backing Store (`BUG-01`):**
   - **Code Status:** `src/server/auth.ts` implements the pluggable `RateLimitStore` interface (`setLoginRateLimitStore`) and defaults to `BoundedInMemoryRateLimitStore` (`maxEntries = 5000`, LRU + TTL eviction) for single-node deployments.
   - **Runtime Status:** When horizontally scaling across multiple Node.js instances behind a load balancer, operators should inject a Redis-backed `RateLimitStore` implementation and set `TRUST_PROXY=true` only behind the verified load balancer.
3. **Production Secret Injection (`SEC-CRYPTO-001` & `BUG-06`):**
   - **Code Status:** `validateStartupEnvironmentSecurity()` and `initializeProcessHmacKey()` enforce that `AUDIT_HMAC_SECRET_HEX` (at least 256 bits / 64 hex chars) must be provided via secret manager / environment variable when `NODE_ENV=production`.
4. **Phase 17 (Payments) & Phase 18 (Blockchain) Constitutional Locks:**
   - **Status:** Intentionally hard-locked at `HTTP 503` (`HARD_LOCKED_GATE`) per Founder governance directive. Standard digital badges and certificates remain permanently free.
