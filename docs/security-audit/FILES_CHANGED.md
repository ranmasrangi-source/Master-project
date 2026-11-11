# 0 TO 8848 — FILES CHANGED IN MASTER SECURITY REMEDIATION (`BUG-01` TO `BUG-10`)

**Branch:** `security/remediate-bug01-bug10`  
**Baseline Commit (`main`):** `4d5b28a`

---

## Modified & Created Files

| File Path | Change Type | Associated Findings | Purpose of Changes |
| :--- | :--- | :--- | :--- |
| `src/server/auth.ts` | Modified | `BUG-01`, `BUG-02`, `BUG-03` | Added `BoundedInMemoryRateLimitStore`, 3-layer `(account+IP, IP, distributed account)` progressive rate limiting, `resolveTrustedClientIp`, `buildSessionCookieHeader`, `buildClearSessionCookieHeader`, `APPROVED_SCRYPT_POLICY`, `validateScryptHashParameters`, and `needsPasswordRehash`. |
| `src/server/evidenceProcessor.ts` | Modified | `BUG-04`, `BUG-05`, `BUG-10` | Added `decodeAndValidateBase64Payload`, `readBoundedUploadStream`, strict vault path-traversal guard, `fast-xml-parser` GPX validation, `inspectTrackpointBarometricSensor`, `ExifReader` EXIF parsing without current-time substitution, `jpeg-js`/`pngjs` pixel decoding perceptual hash (`computeDecodedImagePerceptualHash`, `computePerceptualHashHammingDistance`), and linear $O(N)$ sliding-window ascent rate calculation (`MAX_GPX_TRACKPOINTS = 50000`). |
| `src/server/wormArchiveService.ts` | Created | `BUG-09` | Implemented honest local vs. external WORM status reporting, `AES-256-GCM` + `HMAC-SHA256` encrypted audit archive bundle creation and recovery verification (`createEncryptedWormArchiveBundle`, `verifyAndRecoverWormArchiveBundle`), pluggable `WormProviderTransportAdapter`, and failure alerting. |
| `src/server/db.ts` | Modified | `BUG-03`, `BUG-06` | Rewrote `isDemoProvisioningAllowed()` as fail-closed, added `validateStartupEnvironmentSecurity()` and `attemptDemoSeedOperationServer()`, blocked demo fixture logins in production (`DEMO_ACCOUNT_FORBIDDEN_IN_PRODUCTION`), and added automatic password rehash on login (`AUTH_PASSWORD_HASH_UPGRADED`). |
| `src/server/apiRouter.ts` | Modified | `BUG-01`, `BUG-02`, `BUG-04`, `BUG-06`, `BUG-09`, `Part 3` | Wired 3-layer login rate limiting, `extractRawSessionToken` for cookie-based session validation and logout revocation, CSRF protection middleware, `15mb` Express JSON limit + `413` error handler, binary stream upload (`application/octet-stream`), `POST /api/v1/admin/demo-seed`, `GET /api/v1/audit/worm-status`, and dynamic runtime verification in `GET /api/v1/health`. |
| `src/domain/bootstrapClientState.ts` | Created | `BUG-08` | Separated production server-synchronized bootstrap state from development-only demo fixtures; prevents failed or offline bootstrap requests from displaying fake demo submissions or certificates. |
| `src/App.tsx` | Modified | `BUG-08` | Initialized `submissions`, `certificates`, and `auditEvents` to `[]` and `verifyLookupId` to `''`; added loading, offline, and server-error retry banners; added null-guards for empty verification queues. |
| `package.json` | Modified | `BUG-07` | Declared `vitest`, `fast-xml-parser`, `exifreader`, `jpeg-js`, `pngjs`, `@types/pngjs` and added `"test"`, `"test:watch"`, `"test:coverage"`, and `"typecheck"` scripts. |
| `package-lock.json` | Created / Updated | `BUG-07` | Locked deterministic dependency tree for reproducible `npm ci` execution in GitHub Actions. |
| `.github/workflows/ci.yml` | Created | `BUG-07` | Added GitHub Actions CI pipeline executing `npm ci`, `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`, and `npm audit --audit-level=high` on push and pull_request. |
| `src/tests/bug01To10Remediation.test.ts` | Created | `BUG-01`..`BUG-10` | Added 27 comprehensive unit and HTTP integration tests verifying all 10 bug remediations and dynamic health checks. |
| `docs/security-audit/*` | Updated | Documentation | Updated `BUG_REGISTER.md`, `P0_P1_REMEDIATION_REPORT.md`, `AUTOMATED_TEST_RESULTS.md`, `FILES_CHANGED.md`, and `UNRESOLVED_RISKS.md`. |
