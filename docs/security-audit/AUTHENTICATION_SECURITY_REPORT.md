# 0 TO 8848 — AUTHENTICATION & CREDENTIAL SECURITY REPORT

**Project:** 0 TO 8848 — Global Adventure Achievement Platform  
**Modules Audited:** `src/server/auth.ts`, `src/server/db.ts`, `src/server/apiRouter.ts`, `src/App.tsx`  

---

## 1. Removal of Public Credential & TOTP Disclosure (`BUG-P0-001`)

### Previous Vulnerability
- `GET /api/v1/auth/accounts` publicly returned an array of demo accounts containing `defaultPasswordHint` (cleartext password) and `currentTotpCode` (live server-computed RFC 6238 TOTP code).
- `src/App.tsx` automatically queried `/api/v1/auth/accounts` and pre-filled credentials and TOTP codes in the browser.

### Remediation Implemented
1. **Endpoint Hard-Blocked:** `apiRouter.all('/auth/accounts', ...)` in `src/server/apiRouter.ts` returns `HTTP 403 Forbidden` with error code `PUBLIC_ACCOUNT_DIRECTORY_DISABLED`.
2. **Hardcoded Passwords & Predictable MFA Secrets Deleted:** `TEST_ACCOUNTS_CREDENTIAL_INFO` and `getTotpCodeForUser()` have been completely removed from `src/server/db.ts`.
3. **Strict Production Guard:** `isDemoProvisioningAllowed()` returns `false` whenever `NODE_ENV === 'production'`. In production, zero demo accounts are seeded and `getTestOnlyAccountCredentials()` throws `PRODUCTION_CREDENTIAL_ACCESS_FORBIDDEN`.
4. **Independent 160-Bit CSPRNG MFA Secrets:** `generateRandomMfaSecretHex()` in `src/server/auth.ts` uses `crypto.randomBytes(20).toString('hex')` so every account possesses a unique 160-bit TOTP secret.
5. **Frontend Sanitized:** `src/App.tsx` uses standard manual inputs for username, password, and 6-digit TOTP code with zero auto-fill or credential enumeration.

---

## 2. Unique 128-Bit CSPRNG Password Salting (`BUG-P0-002`)

### Previous Vulnerability
- `hashPasswordScrypt()` accepted an optional caller-supplied salt, and `src/server/db.ts` passed fixed salts `'00112233445566778899aabbccddeeff'` and `'ffeeddccbbaa99887766554433221100'`.

### Remediation Implemented
1. **Mandatory CSPRNG Salt Generation:** `hashPasswordScrypt(password: string)` in `src/server/auth.ts` generates a fresh 16-byte (128-bit) salt via `crypto.randomBytes(16)` on every invocation.
2. **Explicit Parameter Storage Format:** Stored hashes follow the format:
   ```text
   scrypt$16384$8$1$<32-char-random-salt-hex>$<128-char-derived-key-hex>
   ```
3. **Constant-Time Verification:** `verifyPasswordScrypt()` parses the explicit cost parameters (`N=16384, r=8, p=1`), derives the 64-byte key, and compares digests using `crypto.timingSafeEqual()`.
4. **Database Credential Rotation (`002_P0_P1_SECURITY_ROTATION`):** Rotated all stored user records in SQLite and verified via `getDatabaseCredentialSecurityStats()` that `uniquePasswordSalts === totalUsers` and `uniqueMfaSecrets === totalUsers`.

---

## 3. Session Security, MFA Enforcement & Rate Limiting

- **Privileged Role MFA Gate:** `PRIVILEGED_MFA_ROLES` (`DESTINATION_RESEARCHER`, `VERIFICATION_OFFICER`, `SENIOR_VERIFICATION_LEAD`, `APPEAL_OFFICER`, `SECURITY_COMPLIANCE_OFFICER`, `PLATFORM_SYSADMIN`, `GOVERNANCE_COMMITTEE`, `FOUNDER`) cannot establish a session without passing RFC 6238 HMAC-SHA1 TOTP verification.
- **Hashed Session Tokens:** Raw 256-bit CSPRNG session tokens (`8848_sess_<64hex>`) are never stored in cleartext in SQLite; only `token_sha256_hash` is persisted in `user_sessions`.
- **Brute-Force Lockout:** `checkLoginRateLimit()` and `recordFailedLoginAttempt()` enforce a 15-minute lockout (`HTTP 429 AUTH_RATE_LIMITED`) after 5 failed login attempts.
