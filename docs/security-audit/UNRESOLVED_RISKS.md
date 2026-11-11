# 0 TO 8848 — UNRESOLVED RISKS & HONEST ARCHITECTURAL BOUNDARIES

**Project:** 0 TO 8848 — Global Adventure Achievement Platform  
**Repository:** `ranmasrangi-source/Master-project`  

---

## 1. Status of Audited P0 & P1 Security Bugs

- **Confirmed P0 Bugs Remaining Open:** **0** (`BUG-P0-001`, `BUG-P0-002`, and `BUG-P0-003` are 100% resolved and verified by automated tests).
- **Confirmed P1 Bugs Remaining Open:** **0** (`BUG-P1-004`, `BUG-P1-005`, and `BUG-P1-006` are 100% resolved and verified by automated tests).

---

## 2. Honest Infrastructure & Environment Boundaries (Non-Fabrication Disclosure)

In strict compliance with the Founder's directive against exaggerating local container capabilities as cloud infrastructure:

1. **Single-Node SQLite vs. Distributed Cloud PostgreSQL & WORM Object Lock:**
   - **Current Implementation:** Persistent storage uses Node's built-in `node:sqlite` (`DatabaseSync`) with WAL mode, `BEGIN IMMEDIATE` transactions, and SQLite `BEFORE UPDATE` / `BEFORE DELETE` immutability triggers (`storageMode: 'LOCAL_SQLITE_TRIGGER_IMMUTABLE'`, `wormReplicated: false`).
   - **Residual Infrastructure Risk:** A privileged OS root user with direct filesystem write access to the SQLite file could replace the database file on disk unless audit checkpoints are replicated to an external Cloud S3/GCS WORM (Write-Once-Read-Many) Object Lock bucket in production deployment.

2. **Hardware GNSS Cryptographic Signing vs. Software GPX Parsing:**
   - **Current Implementation:** `src/server/evidenceProcessor.ts` enforces WGS84 coordinate/elevation bounds, monotonic timestamp progression, velocity/vertical-jump limits, destination ascent-rate envelopes, fake GPX creator tag detection, and EXIF editing software detection.
   - **Residual Domain Risk:** Because consumer GPS devices (Garmin, Suunto, COROS, Apple Watch) export unsigned XML `.gpx` files rather than hardware-signed GNSS NMEA/OSNMA streams, a sophisticated adversary can still craft a synthetic GPX trajectory that obeys physical velocity and ascent-rate equations. This is why **multi-modal corroboration** (summit photography + barometric telemetry + official permit/liaison logs) and **mandatory human Verification Officer review** (dual-review for Tier-A 8,000m peaks) remain non-negotiable in the 0 TO 8848 governance model.

3. **In-Memory Rate Limiter Scope:**
   - **Current Implementation:** `loginAttemptsMap` in `src/server/auth.ts` enforces brute-force lockout (5 failed attempts -> 15-minute lockout) within the Node.js server process.
   - **Residual Infrastructure Risk:** In a multi-instance horizontal deployment behind a load balancer, rate-limiting state should be backed by a shared Redis cluster or edge WAF rate-limiting policy.

4. **Future Phases (Phases 15–21) Intentionally Locked:**
   - Phases 15 (Community Feed), 16 (Verified Guide Marketplace), 17 (Ethical Revenue & Commerce), 18 (Optional Blockchain Anchoring), 19 (Global Multilingual Localization), 20 (SRE Chaos & Load Testing), and 21 (Global Launch Readiness) remain intentionally in `PLANNED` / `LOCKED` status per the 21-Phase Master Roadmap, with `/api/v1/payments/checkout` and `/api/v1/blockchain/mint` hard-locked (`HTTP 503`).
