# DOC-P01-08 — Privacy Architecture, PII Isolation & Evidence Vault

## 1. Three-Zone Data Isolation & PII Encryption (`SEC-PRIV-001`)
To protect adventurer privacy while preserving immutable verification auditability, the backend database enforces strict data segregation:
1. **Zone 1 — Encrypted User PII Vault (`user_pii_vault` & `user_encryption_keys`):**
   * Stores sensitive personal identifiers (`full_name`, `email`, `nationality`) encrypted at rest using **AES-256-GCM** with a per-user Data Encryption Key (`user_dek`).
   * Referenced across submissions, certificates, and audit events exclusively via an opaque, non-PII `internal_actor_uuid`.
2. **Zone 2 — Private Evidence Vault (`evidence_artifacts` & `.data/vault/`):**
   * Raw GPX/FIT telemetry files, original EXIF photographs, and climbing permits are stored in private server storage, never in public static folders.
   * Access is restricted to the uploading owner and assigned, non-conflicted reviewers via HMAC-signed, short-lived access tokens (`TTL <= 15 minutes`).
3. **Zone 3 — Public Verification & Leaderboard Projection (`certificates`):**
   * Exposes only the holder's explicitly consented display representation (`FULL_VERIFIED_NAME`, `DISPLAY_HANDLE_OR_INITIALS`, or `PRIVATE_CREDENTIAL_HOLDER`), consented completion date precision (`EXACT_DATE`, `MONTH_AND_YEAR_ONLY`, or `YEAR_ONLY`), and opt-in leaderboard flag.

---

## 2. Residential Geofence Coordinate Masking
* Upon GPX track ingestion, the backend telemetry parser automatically masks/trims the first and last **2.0 kilometers** of residential/trailhead approach coordinates when generating reviewer preview projections and metadata summaries, ensuring private home or hotel locations are never exposed.

---

## 3. Account Erasure & Cryptographic Key-Shredding Protocol
* When a credential holder requests account deletion / PII erasure (`POST /api/v1/privacy/erasure`), the server executes a transactional key-shredding operation:
  1. Destroys the holder's `user_dek` key in `user_encryption_keys` and wipes the encrypted ciphertexts in `user_pii_vault`.
  2. Redacts `applicantDisplayName`, `applicantInitials`, `applicantNationality`, and `applicantStory` on all associated `submissions` records.
  3. Transitions all associated `certificates` to `DEACTIVATED_BY_USER_ERASURE`, redacts `holderPublicDisplay` and `holderNationality`, and removes the holder from public leaderboards.
  4. Preserves the `append_only_audit_log` chain intact because audit records store only opaque `internal_actor_uuid` identifiers and never cleartext names or emails.

* **Compliance Note:** Technical key-shredding and PII redaction provide the engineering foundation for privacy rights, while formal GDPR/international legal compliance remains subject to external legal counsel review prior to public launch.
