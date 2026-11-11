# 0 TO 8848 — FILES CHANGED MANIFEST

**Project:** 0 TO 8848 — Global Adventure Achievement Platform  
**Repository:** `ranmasrangi-source/Master-project`  

---

## 1. Modified Production Source Files

| File Path | Summary of Security Remediations |
| :--- | :--- |
| `/src/types/platform.ts` | Added `gpsTimestampConsistent?: boolean`, `spoofingIndicators?: string[]`, and `exifTamperingIndicator?: boolean` to `EvidenceArtifact['extractedMetadata']`. |
| `/src/server/auth.ts` | Removed optional caller-supplied fixed salt parameter from `hashPasswordScrypt(password: string)`; enforced unique 16-byte (128-bit) CSPRNG salts (`crypto.randomBytes(16)`) with explicit parameter encoding (`scrypt$16384$8$1$<saltHex>$<derivedHex>`); added `extractSaltHexFromStoredHash()` and `generateRandomMfaSecretHex()` (160-bit CSPRNG); added `'DESTINATION_RESEARCHER'` to `PRIVILEGED_MFA_ROLES`. |
| `/src/server/cryptoEngine.ts` | Removed hardcoded `DEFAULT_DEV_HMAC_KEY_HEX`; exported `initializeProcessHmacKey()` enforcing `AUDIT_HMAC_SECRET_HEX` (>= 256 bits) in production (`CRYPTO_KEY_MISSING_IN_PRODUCTION`) and generating a 256-bit CSPRNG runtime key in `os.tmpdir()` (`0o600`) in non-production. |
| `/src/server/privacyVault.ts` | Fixed `maskResidentialTrackpoints()` by removing `&& i === 0` and `&& i === points.length - 1` so all trackpoints before the apex within 2,000m of start and all trackpoints after the apex within 2,000m of end are masked. |
| `/src/server/evidenceProcessor.ts` | Added WGS84 coordinate and elevation bounds checks (`GPX_OUT_OF_BOUNDS_COORDINATES`, `GPX_IMPOSSIBLE_ELEVATION`), monotonic timestamp validation, teleportation velocity and vertical jump anomaly flags, fake GPX creator tag detection, EXIF image editing software detection (`exifTamperingIndicator: true`), and filename `path.basename()` sanitization. |
| `/src/server/db.ts` | Removed `TEST_ACCOUNTS_CREDENTIAL_INFO` and `getTotpCodeForUser()`; added `NON_SENSITIVE_ACCOUNT_PROFILES`, `isDemoProvisioningAllowed()`, `getTestOnlyAccountCredentials()`, `getDatabaseCredentialSecurityStats()`, migration `002_P0_P1_SECURITY_ROTATION`, `buildScopedBootstrapPayload()`, `sanitizeCertificateForViewer()`, `sanitizeSubmissionForViewer()`, applicant ownership check (`APPEAL_OWNERSHIP_FORBIDDEN`) in `fileAppealOnSubmissionServer()`, and holder/privacy-officer check (`PRIVACY_UPDATE_FORBIDDEN`) in `updateCertificatePrivacyConsentServer()`. |
| `/src/server/apiRouter.ts` | Disabled `/api/v1/auth/accounts` across all HTTP methods (`HTTP 403 PUBLIC_ACCOUNT_DIRECTORY_DISABLED`); wired `GET /api/v1/bootstrap` to `buildScopedBootstrapPayload(sessionUser)`; enforced RBAC and ownership on `/destinations/:idOrCode/advance-stage`, `/submissions/:id/appeal`, `/certificates/:verificationId/privacy`, and `/ai/advisory-brief`; redacted `holderUserId` from `/leaderboards`. |
| `/src/App.tsx` | Removed `/api/v1/auth/accounts` fetch, `TestAccountDirectoryEntry`, `accountsDirectory`, `handleSelectDirectoryAccount`, hardcoded initial password `'Verifier#8848!Dept219'`, and the TOTP-displaying `<select>` dropdown. |

---

## 2. Modified & Added Automated Test Files

| File Path | Summary of Changes |
| :--- | :--- |
| `/src/tests/foundation.test.ts` | Updated test helpers to use `getTestOnlyAccountCredentials()`, `initializeProcessHmacKey()`, and verified `masked.removedCount === 3` on 2km residential trackpoint masking. |
| `/src/tests/securityAuditP0P1.test.ts` | **NEW:** Dedicated 20-test P0/P1 security regression suite covering `BUG-P0-001` through `BUG-P1-006`. |

---

## 3. Added Security Audit Documentation (`/docs/security-audit/`)

1. `/docs/security-audit/BUG_REGISTER.md`
2. `/docs/security-audit/P0_P1_REMEDIATION_REPORT.md`
3. `/docs/security-audit/RBAC_TEST_REPORT.md`
4. `/docs/security-audit/AUTHENTICATION_SECURITY_REPORT.md`
5. `/docs/security-audit/BOOTSTRAP_PRIVACY_REPORT.md`
6. `/docs/security-audit/CRYPTOGRAPHY_TEST_REPORT.md`
7. `/docs/security-audit/EVIDENCE_SECURITY_REPORT.md`
8. `/docs/security-audit/AUTOMATED_TEST_RESULTS.md`
9. `/docs/security-audit/FILES_CHANGED.md`
10. `/docs/security-audit/UNRESOLVED_RISKS.md`
