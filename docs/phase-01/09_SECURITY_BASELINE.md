# DOC-P01-09 — Security, Authentication & Cryptographic Baseline

## 1. Authentication & Session Security (`SEC-AUTH-001`)
* **Credential Verification:** Passwords are hashed using Node.js `crypto.scryptSync` with per-user 128-bit cryptographic salts and verified using constant-time `crypto.timingSafeEqual`.
* **Multi-Factor Authentication (MFA) for Privileged Roles:** All privileged verification, appeal, security, sysadmin, and governance roles (`VERIFICATION_OFFICER`, `SENIOR_VERIFICATION_LEAD`, `APPEAL_OFFICER`, `SECURITY_COMPLIANCE_OFFICER`, `PLATFORM_SYSADMIN`, `GOVERNANCE_COMMITTEE`, `FOUNDER`) enforce second-factor verification (`mfaVerified: true`) via RFC 6238 HMAC-SHA1/SHA256 TOTP codes before privileged sessions are issued.
* **Server-Side Sessions:** Sessions use 256-bit CSPRNG session tokens (`crypto.randomBytes(32)`), stored hashed (`SHA-256`) in the `user_sessions` database table with strict expiration (`expires_at_utc`), revocation (`revoked_at_utc`), and `HttpOnly; SameSite=Strict` cookie / Bearer token support.
* **Zero Client Role Trust:** Protected API routes resolve the caller's `userId` and `role` exclusively from the validated server-side session record in the database, never from client-supplied request headers or body fields.

---

## 2. Cryptographic Primitives (`SEC-CRYPTO-001` & `SEC-CRYPTO-002`)
1. **Public Verification IDs (`generateNonEnumerableVerificationId`):**
   * Generated exclusively via `crypto.randomBytes(16)` (**128 bits of genuine CSPRNG entropy**), encoded into a 26-character Crockford Base32 string formatted as `8848-V1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXXX`.
   * Database uniqueness is enforced via a `UNIQUE` index on `certificates.verification_id` with automatic collision retry.
2. **Evidence File Integrity (`computeSha256Hex`):**
   * Calculated from actual uploaded file bytes via `crypto.createHash('sha256').update(buffer).digest('hex')` (64 hex characters / 256 bits).
3. **Sequential Audit & Decision Signatures (`computeHmacSha256Hex`):**
   * Calculated via `crypto.createHmac('sha256', secretKey).update(canonicalPayload).digest('hex')` with key-version tracking (`keyVersion: 'v1'`) and verified via constant-time `crypto.timingSafeEqual`.

---

## 3. Database-Enforced Append-Only Audit Log (`SEC-DB-001`)
* Every security-relevant state transition writes a sequential record to `audit_events` inside a database transaction, chaining `previous_event_hmac` $\rightarrow$ `current_event_hmac`.
* SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers (`trg_audit_events_immutable_update`, `trg_audit_events_immutable_delete`) abort any attempt to modify or delete existing audit rows at the database engine level (`RAISE(ABORT, 'WORM_AUDIT_LOG_IMMUTABLE')`).
* Because local SQLite storage is single-node without external cloud object-lock hardware, `wormReplicated` is honestly recorded as `false` (`storageMode: 'LOCAL_SQLITE_TRIGGER_IMMUTABLE'`) until external WORM object storage is provisioned in production.
