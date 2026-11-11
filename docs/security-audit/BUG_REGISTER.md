# 0 TO 8848 — MASTER SECURITY BUG REGISTER (P0 & P1)

**Project:** 0 TO 8848 — Global Adventure Achievement Platform (`https://0to8848official.com`)  
**Repository:** `ranmasrangi-source/Master-project`  
**Audit & Remediation Date:** 2026-11-11  

---

## Summary Table

| Bug ID | Severity | Title | Affected Files | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BUG-P0-001** | **P0 — Critical** | Public Credential & Live TOTP Disclosure (`/api/v1/auth/accounts`), Hardcoded Passwords & Predictable MFA Secrets | `src/server/apiRouter.ts`, `src/server/db.ts`, `src/server/auth.ts`, `src/App.tsx` | **FIXED** | `src/tests/securityAuditP0P1.test.ts` (3/3 PASS), `src/tests/foundation.test.ts` |
| **BUG-P0-002** | **P0 — Critical** | Hardcoded Password Salt in Account Seeding (`00112233...` and `ffeeddcc...`) | `src/server/auth.ts`, `src/server/db.ts` | **FIXED** | `src/tests/securityAuditP0P1.test.ts` (2/2 PASS), `src/tests/foundation.test.ts` |
| **BUG-P0-003** | **P0/P1 — Critical/High** | Unauthenticated & Over-Broad `/api/v1/bootstrap` Data Exposure Across Roles | `src/server/apiRouter.ts`, `src/server/db.ts` | **FIXED** | `src/tests/securityAuditP0P1.test.ts` (6/6 PASS across all 7 access tiers) |
| **BUG-P1-004** | **P1 — High** | Missing Ownership & Role Authorization on Appeals, Certificate Privacy, AI Advisory Brief, and Leaderboard User IDs | `src/server/apiRouter.ts`, `src/server/db.ts` | **FIXED** | `src/tests/securityAuditP0P1.test.ts` (4/4 PASS), `src/tests/rbac1680.test.ts` (4/4 PASS) |
| **BUG-P1-005** | **P1 — High** | Hardcoded Default Audit HMAC Key (`DEFAULT_DEV_HMAC_KEY_HEX`) in `cryptoEngine.ts` | `src/server/cryptoEngine.ts`, `src/tests/foundation.test.ts` | **FIXED** | `src/tests/securityAuditP0P1.test.ts`, `src/tests/foundation.test.ts` |
| **BUG-P1-006** | **P1 — High** | Incomplete 2km GPX Residential Masking (`i === 0` / `i === length - 1` Bug) & Missing GPX/EXIF Anti-Spoofing Checks | `src/server/privacyVault.ts`, `src/server/evidenceProcessor.ts`, `src/types/platform.ts` | **FIXED** | `src/tests/securityAuditP0P1.test.ts` (5/5 PASS), `src/tests/foundation.test.ts` |

---

## Detailed Bug Entries

### 1. `BUG-P0-001` — Public Credential & Live TOTP Disclosure
- **Severity:** P0 — Critical
- **Root Cause:**
  1. `src/server/apiRouter.ts` exposed `GET /api/v1/auth/accounts` to any unauthenticated caller, returning `defaultPasswordHint` (which contained the exact cleartext password) and `currentTotpCode` (which generated a live valid 6-digit RFC 6238 TOTP code on the server for every privileged account including `FOUNDER`, `GOVERNANCE_COMMITTEE`, and `VERIFICATION_OFFICER`).
  2. `src/server/db.ts` exported `TEST_ACCOUNTS_CREDENTIAL_INFO` containing hardcoded cleartext passwords and predictable sequential hex MFA secrets (`31323334...`), along with `getTotpCodeForUser()`.
  3. `src/App.tsx` fetched `/api/v1/auth/accounts` on mount, populated a `<select>` dropdown showing live TOTP codes, and auto-filled `loginUsername`, `loginPassword`, and `loginTotp` into the sign-in form.
- **Exact Code Changes:**
  - `src/server/apiRouter.ts`: Replaced `GET /api/v1/auth/accounts` with `apiRouter.all('/auth/accounts', ...)` returning `HTTP 403 PUBLIC_ACCOUNT_DIRECTORY_DISABLED` across all HTTP verbs.
  - `src/server/db.ts`: Deleted `TEST_ACCOUNTS_CREDENTIAL_INFO` and `getTotpCodeForUser()`. Added `isDemoProvisioningAllowed()` (which returns `false` whenever `NODE_ENV === 'production'`), `NON_SENSITIVE_ACCOUNT_PROFILES` (containing zero secrets), and `getTestOnlyAccountCredentials()` (which throws `PRODUCTION_CREDENTIAL_ACCESS_FORBIDDEN` in production and is never exposed over HTTP). Added migration `002_P0_P1_SECURITY_ROTATION` to rotate all account credentials and MFA secrets using `crypto.randomBytes` CSPRNG and revoke existing sessions.
  - `src/server/auth.ts`: Added `generateRandomMfaSecretHex()` (160-bit CSPRNG secret via `crypto.randomBytes(20)`).
  - `src/App.tsx`: Removed `accountsDirectory`, `/api/v1/auth/accounts` fetch, `handleSelectDirectoryAccount`, hardcoded initial password `'Verifier#8848!Dept219'`, and the TOTP-displaying `<select>` element.

---

### 2. `BUG-P0-002` — Hardcoded Password Salt
- **Severity:** P0 — Critical
- **Root Cause:**
  - `src/server/auth.ts` allowed an optional `saltHex` parameter in `hashPasswordScrypt(password, saltHex)`.
  - `src/server/db.ts` passed fixed salts `'00112233445566778899aabbccddeeff'` and `'ffeeddccbbaa99887766554433221100'` when seeding and migrating user accounts, causing identical salts across accounts.
- **Exact Code Changes:**
  - `src/server/auth.ts`: Removed the optional `saltHex` parameter from `hashPasswordScrypt(password: string)`. Every call now unconditionally generates a fresh 128-bit CSPRNG salt (`crypto.randomBytes(16).toString('hex')`) and stores explicit scrypt parameters (`scrypt$16384$8$1$<saltHex>$<derivedHex>`). Added `extractSaltHexFromStoredHash()` to audit salt uniqueness.
  - `src/server/db.ts`: Removed all fixed salt literals and executed migration `002_P0_P1_SECURITY_ROTATION` so every user record in SQLite has a unique 128-bit salt.

---

### 3. `BUG-P0-003` — Bootstrap API Authorization & Data Privacy Leak
- **Severity:** P0/P1 — Critical/High
- **Root Cause:**
  - In `src/server/apiRouter.ts`, `GET /api/v1/bootstrap` loaded all `submissions`, `dualControlApprovals`, and `auditEvents` unconditionally before checking `sessionUser`. Because `if (sessionUser)` only filtered `submissions` when a user was logged in, an unauthenticated request (`sessionUser === null`) bypassed the `if (sessionUser)` block and received the entire `submissions` queue, `dualControlApprovals`, and `auditEvents`!
  - Furthermore, raw `vaultStorageKey`, `applicantInternalActorUuid`, and `holderUserId` were included in returned objects.
- **Exact Code Changes:**
  - `src/server/db.ts` & `src/server/apiRouter.ts`: Implemented `buildScopedBootstrapPayload(sessionUser)`, `sanitizeCertificateForViewer()`, and `sanitizeSubmissionForViewer()` enforcing 7 explicit access tiers (`PUBLIC_INFORMATION`, `REGISTERED_ADVENTURER`, `VERIFICATION_OFFICER`, `APPEAL_REVIEW_TEAM`, `GOVERNANCE_COMMITTEE`, `FOUNDER`, `SPONSOR_ACCOUNT`) before querying sensitive tables.

---

### 4. `BUG-P1-004` — RBAC, Ownership & Separation-of-Duties Gaps
- **Severity:** P1 — High
- **Root Cause:**
  1. `POST /api/v1/submissions/:id/appeal` checked role (`REGISTERED_ADVENTURER`) and submission status (`REJECTED`), but did not verify `sub.applicantUserId === actor.userId`, allowing one adventurer to file an appeal on another adventurer's submission.
  2. `POST/PATCH /api/v1/certificates/:verificationId/privacy` did not verify `cert.holderUserId === actor.userId` (or privacy governance role), allowing any authenticated user to alter another holder's certificate privacy mode.
  3. `POST /api/v1/ai/advisory-brief` was callable without authentication and appended `AI_ADVISORY_BRIEF_GENERATED` events to the immutable audit log.
  4. `GET /api/v1/leaderboards` exposed internal `holderUserId` in public standings.
- **Exact Code Changes:**
  - `src/server/db.ts`: Added `APPEAL_OWNERSHIP_FORBIDDEN` check (`sub.applicantUserId !== params.actor.userId`) in `fileAppealOnSubmissionServer()` and `PRIVACY_UPDATE_FORBIDDEN` check (`!isOwner && !isPrivacyOfficer`) in `updateCertificatePrivacyConsentServer()`.
  - `src/server/apiRouter.ts`: Added `requireAuth` and verification/governance role check (`VERIFICATION_OFFICER`, `SENIOR_VERIFICATION_LEAD`, `APPEAL_OFFICER`, `SECURITY_COMPLIANCE_OFFICER`, `GOVERNANCE_COMMITTEE`, `FOUNDER`) on `POST /api/v1/ai/advisory-brief`. Replaced `holderUserId` in `GET /api/v1/leaderboards` with an opaque SHA-256 derived `standingEntryKey` (`ldr_<12hex>`).

---

### 5. `BUG-P1-005` — Hardcoded Default Audit HMAC Key
- **Severity:** P1 — High
- **Root Cause:**
  - `src/server/cryptoEngine.ts` defined `const DEFAULT_DEV_HMAC_KEY_HEX = '8848f00d9a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef01234567'` in source code.
- **Exact Code Changes:**
  - `src/server/cryptoEngine.ts`: Removed `DEFAULT_DEV_HMAC_KEY_HEX`. Implemented `initializeProcessHmacKey()` which throws `CRYPTO_KEY_MISSING_IN_PRODUCTION` if `AUDIT_HMAC_SECRET_HEX` is unset when `NODE_ENV === 'production'`, and generates a 256-bit CSPRNG runtime key in OS temporary storage (`0o600`) for non-production test/dev runs.

---

### 6. `BUG-P1-006` — Incomplete 2km GPX Coordinate Masking & Telemetry Spoofing Validation
- **Severity:** P1 — High
- **Root Cause:**
  - `src/server/privacyVault.ts`: `maskResidentialTrackpoints()` included `&& i === 0` and `&& i === points.length - 1`, which restricted masking to only the very first and very last trackpoint instead of all trackpoints within 2,000 meters of the start and end coordinates.
  - `src/server/evidenceProcessor.ts`: Lacked WGS84 coordinate/elevation bounds checks, monotonic timestamp checks, velocity/vertical-jump anomaly detection, and EXIF editing software detection.
- **Exact Code Changes:**
  - `src/server/privacyVault.ts`: Removed `&& i === 0` and `&& i === points.length - 1` so all points before the apex within 2,000m of start and all points after the apex within 2,000m of end are stripped.
  - `src/server/evidenceProcessor.ts`: Added WGS84 bounds validation (`GPX_OUT_OF_BOUNDS_COORDINATES`, `GPX_IMPOSSIBLE_ELEVATION`), monotonic timestamp & velocity anomaly detection (`NON_MONOTONIC_BACKWARDS_TIMESTAMP`, `DUPLICATE_TIMESTAMP_ZERO_DELTA`, `TELEPORTATION_VELOCITY_ANOMALY`, `EXTREME_VERTICAL_JUMP_ANOMALY`, `SUSPICIOUS_CREATOR_TAG`), and EXIF editing software detection (`EXIF_EDITING_OR_SYNTHETIC_SOFTWARE_TAG`, `exifTamperingIndicator: true`).
