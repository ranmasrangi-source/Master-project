# 0 TO 8848 — BOOTSTRAP API PRIVACY & 7-TIER ACCESS REPORT

**Project:** 0 TO 8848 — Global Adventure Achievement Platform  
**Endpoint Audited:** `GET /api/v1/bootstrap` (`src/server/apiRouter.ts`, `src/server/db.ts`)  

---

## 1. Root Cause of Previous Vulnerability (`BUG-P0-003`)

In the pre-remediation implementation of `GET /api/v1/bootstrap`:
1. `submissions`, `dualControlApprovals`, and `auditEvents` were queried from SQLite unconditionally before checking `sessionUser`.
2. Because the permission filter was wrapped inside `if (sessionUser) { ... }`, an unauthenticated request (`sessionUser === null`) bypassed the block completely and received all achievement submissions, all dual-control governance approvals, and all internal audit events.
3. Returned submission and certificate objects included internal storage paths (`vaultStorageKey`), internal actor UUIDs (`applicantInternalActorUuid`), and internal user IDs (`holderUserId`, `submissionId`).

---

## 2. Remediated 7-Tier Access Architecture (`buildScopedBootstrapPayload`)

`GET /api/v1/bootstrap` now delegates to `buildScopedBootstrapPayload(sessionUser)` in `src/server/db.ts`, which resolves the caller's session token first and strictly scopes all database queries and field projections across 7 explicit access tiers:

| Access Tier | Caller Role(s) | `submissions` Returned | `dualControlApprovals` Returned | `auditEvents` Returned | Certificate & Artifact Redactions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. `PUBLIC_INFORMATION`** | Unauthenticated (`null`) / `PUBLIC_VISITOR` | `[]` (0 records) | `[]` (0 records) | `[]` (0 records) | `holderUserId` & `submissionId` stripped from all certificates |
| **2. `REGISTERED_ADVENTURER`** | `REGISTERED_ADVENTURER`, `VERIFIED_GUIDE`, `ORGANIZATION_ADMIN`, `DESTINATION_PARTNER` | Own submissions only (`applicant_user_id === sessionUser.userId`) | `[]` (0 records) | `[]` (0 records) | `vaultStorageKey` & `applicantInternalActorUuid` stripped; `holderUserId` visible only on own certificates |
| **3. `VERIFICATION_OFFICER`** | `VERIFICATION_OFFICER`, `SENIOR_VERIFICATION_LEAD` | Blind verification queue (`status !== 'APPEALED'`) | `[]` for Officer; `CERTIFICATE_REVOKE` records for Senior Lead | `[]` (0 records) | `applicantDisplayName` masked to `Blind Dossier [Initials]`; `vaultStorageKey`, `applicantInternalActorUuid`, & `appealRecord` stripped |
| **4. `APPEAL_REVIEW_TEAM`** | `APPEAL_OFFICER` | Appealed submissions only (`status === 'APPEALED'`) excluding any submission where caller is in `originalReviewerUserIdsBlocked` | `[]` (0 records) | `[]` (0 records) | `applicantDisplayName` masked to `Blind Appeal Dossier [Initials]`; `vaultStorageKey` & `applicantInternalActorUuid` stripped |
| **5. `GOVERNANCE_COMMITTEE`** | `GOVERNANCE_COMMITTEE`, `SECURITY_COMPLIANCE_OFFICER`, `DESTINATION_RESEARCHER`, `PLATFORM_SYSADMIN` | Scoped per RBAC `ACHIEVEMENT_SUBMISSIONS:READ` | Scoped per RBAC (`GOVERNANCE_COMMITTEE` & `SECURITY_COMPLIANCE_OFFICER`) | Scoped per RBAC `APPEND_ONLY_AUDIT_LOGS:READ` | `vaultStorageKey` stripped from bootstrap list (accessed only via short-TTL signed vault token) |
| **6. `FOUNDER`** | `FOUNDER` | All submissions (with `vaultStorageKey` stripped from list payload) | All dual-control approval records | All append-only audit events | Constitutional & 2P dual-control oversight |
| **7. `SPONSOR_ACCOUNT`** | `SPONSOR_ACCOUNT` | `[]` (0 records — Commercial Firewall) | `[]` (0 records) | `[]` (0 records) | Public certificate view only (`holderUserId` & `submissionId` stripped) |

---

## 3. Automated Test Verification

All 7 access tiers are independently tested in `src/tests/securityAuditP0P1.test.ts` (`BUG-P0-003: Bootstrap API Authorization & 7-Tier Privacy Projection`, 6/6 tests passing).
