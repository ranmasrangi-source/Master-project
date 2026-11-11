# 0 TO 8848 — EVIDENCE & ACHIEVEMENT VERIFICATION SECURITY REPORT

**Project:** 0 TO 8848 — Global Adventure Achievement Platform  
**Modules Audited:** `src/server/evidenceProcessor.ts`, `src/server/privacyVault.ts`, `src/server/apiRouter.ts`, `src/server/db.ts`  

---

## 1. Distinction Between File Integrity (SHA-256) and Evidence Authenticity

In compliance with Phase 01 constitutional requirements:
- **Post-Upload File Integrity (`sha256Digest`):** SHA-256 proves only that an uploaded byte stream has not been altered after ingestion and prevents duplicate evidence re-submission across dossiers (`DUPLICATE_EVIDENCE_SHA256` rejection).
- **Evidence Authenticity (`extractedMetadata` & Multi-Modal Cross-Check):** Authenticity is evaluated by parsing telemetry trajectories, barometric channels, monotonic timestamps, velocity/ascent envelopes, EXIF software tags, and mandatory human officer review.

---

## 2. Remediations Implemented (`BUG-P1-006`)

### 2.1 Full 2.0 km Residential GPX Coordinate Masking
- **Previous Bug:** `maskResidentialTrackpoints()` in `src/server/privacyVault.ts` contained `&& i === 0` and `&& i === points.length - 1`, which masked only the first and last point of a track rather than all residential points within the 2,000-meter privacy buffer.
- **Fix:** Removed `&& i === 0` and `&& i === points.length - 1`. Every trackpoint prior to the summit apex within 2,000 meters of the starting coordinate and every trackpoint after the summit apex within 2,000 meters of the ending coordinate is stripped before storage or reviewer projection.
- **Automated Test:** `masks ALL residential start and end GPX trackpoints within 2,000m radius` in `src/tests/securityAuditP0P1.test.ts` verifies that 5 residential points (`0m`, `600m`, `1480m` from start; `1180m`, `0m` from end) are removed while the summit point (`8848m`) is preserved (`removedCount === 5`, `maskedPoints.length === 1`).

### 2.2 GPX Telemetry Bounds & Anti-Spoofing Checks (`parseGpxTelemetryBuffer`)
1. **WGS84 Coordinate & Elevation Bounds:** Rejects any GPX trackpoint with `lat < -90 || lat > 90` or `lon < -180 || lon > 180` (`GPX_OUT_OF_BOUNDS_COORDINATES`) or `ele < -500 || ele > 9500` (`GPX_IMPOSSIBLE_ELEVATION`).
2. **Monotonic Timestamp Enforcement:** Flags backwards timestamps (`NON_MONOTONIC_BACKWARDS_TIMESTAMP`) and duplicate timestamps with non-zero displacement (`DUPLICATE_TIMESTAMP_ZERO_DELTA`), setting `gpsTimestampConsistent: false`.
3. **Physical Velocity & Vertical Jump Anomaly Detection:** Flags segments with horizontal velocity `> 45 m/s` (`TELEPORTATION_VELOCITY_ANOMALY`), vertical jumps `> 2,500 m/hr` (`EXTREME_VERTICAL_JUMP_ANOMALY`), or rolling 15-minute ascent rates exceeding the destination's `maxPlausibleAscentRateMPerHr` (`ENVELOPE_ASCENT_RATE_EXCEEDED`).
4. **Fake GPX Generator Detection:** Flags known spoofing creator tags (`fakegpx`, `gpsjoystick`, `mocklocation`, `spoof`) with `SUSPICIOUS_CREATOR_TAG`.

### 2.3 EXIF Manipulation & Synthetic Software Detection (`parsePhotoExifBuffer`)
- Scans EXIF headers for image editing and synthetic generation software (`Photoshop`, `Lightroom`, `GIMP`, `Affinity Photo`, `Pixelmator`, `Snapseed`, `Midjourney`, `DALL-E`, `Stable Diffusion`, `ExifTool`).
- Sets `exifTamperingIndicator: true` and appends `EXIF_EDITING_OR_SYNTHETIC_SOFTWARE_TAG:<software>` to `spoofingIndicators`.

### 2.4 XXE Blocking, Magic-Byte Validation & Short-TTL Signed Vault URLs
- Blocks XML External Entity (`<!ENTITY`, `SYSTEM`, `PUBLIC`) and malicious PDF directives (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`).
- Enforces file size cap (`10 MB`), sanitizes filenames with `path.basename()`, and requires short-TTL (`300s`) HMAC-signed tokens (`verifySignedEvidenceAccessToken`) bound to `(artifactId, viewerUserId,viewerRole, expiresAtEpochMs)` for private vault access.
