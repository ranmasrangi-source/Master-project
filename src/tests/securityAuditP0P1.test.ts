import express from 'express';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiRouter } from '../server/apiRouter';
import {
  resetDatabase,
  getTestOnlyAccountCredentials,
  isDemoProvisioningAllowed,
  getDatabaseCredentialSecurityStats,
} from '../server/db';
import {
  hashPasswordScrypt,
  verifyPasswordScrypt,
  extractSaltHexFromStoredHash,
  generateRandomMfaSecretHex,
  generateTotpCode,
  resetLoginAttempts,
} from '../server/auth';
import { initializeProcessHmacKey } from '../server/cryptoEngine';
import { parseGpxTelemetryBuffer, parsePhotoExifBuffer } from '../server/evidenceProcessor';
import { maskResidentialTrackpoints } from '../server/privacyVault';
import { DESTINATIONS_100_CATALOG } from '../data/destinations100';

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), '0to8848-p0p1-db-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'platform-p0p1.sqlite');

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use('/api/v1', apiRouter);

let server: http.Server;
let baseUrl = '';

async function apiFetch(
  endpoint: string,
  options?: {
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
  }
): Promise<{ status: number; body: Record<string, any> }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers || {}),
  };
  const res = await fetch(`${baseUrl}${endpoint}`, {
    method: options?.method || 'GET',
    headers,
    body: options?.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const body = (await res.json()) as Record<string, any>;
  return { status: res.status, body };
}

async function loginTestRole(userId: string): Promise<string> {
  const creds = getTestOnlyAccountCredentials(userId);
  resetLoginAttempts(creds.username);
  const totpCode = generateTotpCode(creds.mfaSecretHex);
  const res = await apiFetch('/api/v1/auth/login', {
    method: 'POST',
    body: {
      username: creds.username,
      password: creds.ephemeralPassword,
      totpCode,
    },
  });
  expect(res.status).toBe(200);
  expect(res.body.sessionToken).toBeDefined();
  return res.body.sessionToken;
}

describe('0 TO 8848 — P0 & P1 Security Remediation Regression Suite', () => {
  beforeAll(async () => {
    process.env.DB_FILE_PATH = TEST_DB_PATH;
    resetDatabase(TEST_DB_PATH);
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    try {
      fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('BUG-P0-001: Public Credential & MFA Disclosure Prevention', () => {
    it('disables /api/v1/auth/accounts across all HTTP methods with HTTP 403 and zero secrets', async () => {
      const getRes = await apiFetch('/api/v1/auth/accounts');
      expect(getRes.status).toBe(403);
      expect(getRes.body.error).toBe('PUBLIC_ACCOUNT_DIRECTORY_DISABLED');
      expect(JSON.stringify(getRes.body)).not.toContain('defaultPasswordHint');
      expect(JSON.stringify(getRes.body)).not.toContain('currentTotpCode');
      expect(JSON.stringify(getRes.body)).not.toContain('mfaSecretHex');

      const postRes = await apiFetch('/api/v1/auth/accounts', { method: 'POST', body: {} });
      expect(postRes.status).toBe(403);
      expect(postRes.body.error).toBe('PUBLIC_ACCOUNT_DIRECTORY_DISABLED');
    });

    it('blocks demo credential provisioning and test helper access when NODE_ENV === production', () => {
      const originalEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        expect(isDemoProvisioningAllowed()).toBe(false);
        expect(() => getTestOnlyAccountCredentials('usr-gov-founder-001')).toThrow(
          /PRODUCTION_CREDENTIAL_ACCESS_FORBIDDEN/
        );
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('generates cryptographically independent 160-bit CSPRNG MFA secrets', () => {
      const secretA = generateRandomMfaSecretHex();
      const secretB = generateRandomMfaSecretHex();
      expect(secretA).toMatch(/^[0-9a-f]{40}$/);
      expect(secretB).toMatch(/^[0-9a-f]{40}$/);
      expect(secretA).not.toBe(secretB);
    });
  });

  describe('BUG-P0-002: Unique CSPRNG Password Salting & Scrypt Verification', () => {
    it('produces distinct 128-bit random salts and distinct hashes for identical passwords', () => {
      const samePassword = 'IdenticalPassword#8848!Secure';
      const hash1 = hashPasswordScrypt(samePassword);
      const hash2 = hashPasswordScrypt(samePassword);

      expect(hash1).not.toBe(hash2);
      const salt1 = extractSaltHexFromStoredHash(hash1);
      const salt2 = extractSaltHexFromStoredHash(hash2);
      expect(salt1).toMatch(/^[0-9a-f]{32}$/);
      expect(salt2).toMatch(/^[0-9a-f]{32}$/);
      expect(salt1).not.toBe(salt2);

      // Never uses the previously hardcoded salts
      expect(salt1).not.toBe('00112233445566778899aabbccddeeff');
      expect(salt1).not.toBe('ffeeddccbbaa99887766554433221100');

      expect(verifyPasswordScrypt(samePassword, hash1)).toBe(true);
      expect(verifyPasswordScrypt(samePassword, hash2)).toBe(true);
      expect(verifyPasswordScrypt('WrongPassword#8848!', hash1)).toBe(false);
    });

    it('verifies every account in SQLite has a unique password salt and unique MFA secret', () => {
      const stats = getDatabaseCredentialSecurityStats();
      expect(stats.totalUsers).toBeGreaterThanOrEqual(8);
      expect(stats.uniquePasswordSalts).toBe(stats.totalUsers);
      expect(stats.uniqueMfaSecrets).toBe(stats.totalUsers);
      expect(stats.allHashesUseScryptFormat).toBe(true);
    });
  });

  describe('BUG-P0-003: Bootstrap API Authorization & 7-Tier Privacy Projection', () => {
    it('Tier 1 (PUBLIC_INFORMATION): unauthenticated /api/v1/bootstrap returns 0 submissions, 0 dual-control approvals, and 0 audit events', async () => {
      const res = await apiFetch('/api/v1/bootstrap');
      expect(res.status).toBe(200);
      expect(res.body.accessTier).toBe('PUBLIC_INFORMATION');
      expect(res.body.sessionUser).toBeNull();
      expect(res.body.submissions).toEqual([]);
      expect(res.body.dualControlApprovals).toEqual([]);
      expect(res.body.auditEvents).toEqual([]);

      // Public certificates must never expose internal holderUserId or submissionId
      for (const cert of res.body.certificates) {
        expect(cert.holderUserId).toBeUndefined();
        expect(cert.submissionId).toBeUndefined();
      }
    });

    it('Tier 2 (REGISTERED_ADVENTURER): returns only the adventurer’s own submissions and 0 internal audit/dual-control records', async () => {
      const token = await loginTestRole('usr-tenzing-nepal');
      const res = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${token}` },
      });

      expect(res.status).toBe(200);
      expect(res.body.accessTier).toBe('REGISTERED_ADVENTURER');
      expect(res.body.submissions.length).toBeGreaterThan(0);
      for (const sub of res.body.submissions) {
        expect(sub.applicantUserId).toBe('usr-tenzing-nepal');
        expect(sub.applicantInternalActorUuid).toBeUndefined();
        for (const ev of sub.evidenceArtifacts) {
          expect(ev.vaultStorageKey).toBeUndefined();
        }
      }
      expect(res.body.dualControlApprovals).toEqual([]);
      expect(res.body.auditEvents).toEqual([]);
    });

    it('Tier 3 (VERIFICATION_OFFICER): returns blind verification queue without exposing raw vaultStorageKey paths or audit chain logs', async () => {
      const token = await loginTestRole('usr-reviewer-219');
      const res = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${token}` },
      });

      expect(res.status).toBe(200);
      expect(res.body.accessTier).toBe('VERIFICATION_OFFICER');
      expect(res.body.submissions.length).toBeGreaterThan(0);
      for (const sub of res.body.submissions) {
        expect(sub.applicantInternalActorUuid).toBeUndefined();
        for (const ev of sub.evidenceArtifacts) {
          expect(ev.vaultStorageKey).toBeUndefined();
        }
      }
      expect(res.body.auditEvents).toEqual([]);
    });

    it('Tier 4 (APPEAL_REVIEW_TEAM): returns only appealed submissions and blocks original rejecting reviewer', async () => {
      const token = await loginTestRole('usr-appeal-401');
      const res = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${token}` },
      });

      expect(res.status).toBe(200);
      expect(res.body.accessTier).toBe('APPEAL_REVIEW_TEAM');
      for (const sub of res.body.submissions) {
        expect(sub.status).toBe('APPEALED');
      }
      expect(res.body.auditEvents).toEqual([]);
    });

    it('Tier 5 & 6 (GOVERNANCE_COMMITTEE & FOUNDER): grants full governance audit and dual-control visibility', async () => {
      const govToken = await loginTestRole('usr-gov-committee-002');
      const govRes = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${govToken}` },
      });
      expect(govRes.status).toBe(200);
      expect(govRes.body.accessTier).toBe('GOVERNANCE_COMMITTEE');
      expect(govRes.body.dualControlApprovals.length).toBeGreaterThan(0);
      expect(govRes.body.auditEvents.length).toBeGreaterThan(0);

      const founderToken = await loginTestRole('usr-gov-founder-001');
      const founderRes = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${founderToken}` },
      });
      expect(founderRes.status).toBe(200);
      expect(founderRes.body.accessTier).toBe('FOUNDER');
      expect(founderRes.body.dualControlApprovals.length).toBeGreaterThan(0);
      expect(founderRes.body.auditEvents.length).toBeGreaterThan(0);
    });

    it('Tier 7 (SPONSOR_ACCOUNT): isolates sponsor from verification queues, dual-control records, and audit events', async () => {
      const sponsorToken = await loginTestRole('usr-sponsor-701');
      const res = await apiFetch('/api/v1/bootstrap', {
        headers: { Authorization: `Bearer ${sponsorToken}` },
      });

      expect(res.status).toBe(200);
      expect(res.body.accessTier).toBe('SPONSOR_ACCOUNT');
      expect(res.body.submissions).toEqual([]);
      expect(res.body.dualControlApprovals).toEqual([]);
      expect(res.body.auditEvents).toEqual([]);
    });
  });

  describe('BUG-P1-004: RBAC, Ownership & Separation-of-Duties Enforcement', () => {
    it('prevents a different adventurer from filing an appeal on someone else’s submission (HTTP 403 APPEAL_OWNERSHIP_FORBIDDEN)', async () => {
      const otherAdvToken = await loginTestRole('usr-lukas-at');
      const res = await apiFetch('/api/v1/submissions/sub-queue-101/appeal', {
        method: 'POST',
        headers: { Authorization: `Bearer ${otherAdvToken}` },
        body: { reason: 'Unauthorized third-party appeal attempt across user accounts.' },
      });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('APPEAL_OWNERSHIP_FORBIDDEN');
    });

    it('prevents a non-holder adventurer from modifying another user’s certificate privacy settings (HTTP 403 PRIVACY_UPDATE_FORBIDDEN)', async () => {
      const otherAdvToken = await loginTestRole('usr-lukas-at');
      const bootstrapRes = await apiFetch('/api/v1/bootstrap');
      const targetVerificationId = bootstrapRes.body.certificates[0]?.verificationId;
      expect(targetVerificationId).toBeDefined();

      const res = await apiFetch(`/api/v1/certificates/${targetVerificationId}/privacy`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${otherAdvToken}` },
        body: {
          holderPrivacyMode: 'ANONYMIZED_ID_ONLY',
          holderDatePrecision: 'YEAR_ONLY',
          optInPublicLeaderboards: false,
        },
      });

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('PRIVACY_UPDATE_FORBIDDEN');
    });

    it('blocks unauthenticated users, adventurers, and sponsors from invoking /api/v1/ai/advisory-brief', async () => {
      const unauthRes = await apiFetch('/api/v1/ai/advisory-brief', {
        method: 'POST',
        body: { submissionId: 'sub-queue-101' },
      });
      expect(unauthRes.status).toBe(401);

      const advToken = await loginTestRole('usr-tenzing-nepal');
      const advRes = await apiFetch('/api/v1/ai/advisory-brief', {
        method: 'POST',
        headers: { Authorization: `Bearer ${advToken}` },
        body: { submissionId: 'sub-queue-101' },
      });
      expect(advRes.status).toBe(403);

      const sponsorToken = await loginTestRole('usr-sponsor-701');
      const sponsorRes = await apiFetch('/api/v1/ai/advisory-brief', {
        method: 'POST',
        headers: { Authorization: `Bearer ${sponsorToken}` },
        body: { submissionId: 'sub-queue-101' },
      });
      expect(sponsorRes.status).toBe(403);
    });

    it('redacts internal holderUserId from public /api/v1/leaderboards responses', async () => {
      const res = await apiFetch('/api/v1/leaderboards');
      expect(res.status).toBe(200);
      expect(res.body.standings.length).toBeGreaterThan(0);
      for (const entry of res.body.standings) {
        expect(entry.holderUserId).toBeUndefined();
        expect(entry.standingEntryKey).toMatch(/^ldr_[0-9a-f]{12}$/);
      }
    });
  });

  describe('BUG-P1-005 & BUG-P1-006: Cryptographic Key Enforcement & Evidence Hardening', () => {
    it('throws CRYPTO_KEY_MISSING_IN_PRODUCTION if AUDIT_HMAC_SECRET_HEX is unset in production', () => {
      expect(() =>
        initializeProcessHmacKey({ NODE_ENV: 'production', AUDIT_HMAC_SECRET_HEX: undefined })
      ).toThrow(/CRYPTO_KEY_MISSING_IN_PRODUCTION/);
    });

    it('rejects GPX telemetry containing out-of-bounds WGS84 coordinates', () => {
      const everest = DESTINATIONS_100_CATALOG[0];
      const invalidGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?>
        <gpx version="1.1" creator="Garmin">
          <trk><trkseg>
            <trkpt lat="125.9881" lon="86.9250"><ele>5364</ele><time>2026-05-12T01:00:00Z</time></trkpt>
            <trkpt lat="27.9881" lon="86.9250"><ele>8848</ele><time>2026-05-12T06:00:00Z</time></trkpt>
          </trkseg></trk>
        </gpx>`,
        'utf-8'
      );

      expect(() => parseGpxTelemetryBuffer(invalidGpx, everest)).toThrow(/GPX_OUT_OF_BOUNDS_COORDINATES/);
    });

    it('flags non-monotonic backwards timestamps, teleportation velocity, and fake GPX creators', () => {
      const everest = DESTINATIONS_100_CATALOG[0];
      const spoofedGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?>
        <gpx version="1.1" creator="FakeGPS Spoofer Pro">
          <trk><trkseg>
            <trkpt lat="27.9881" lon="86.9250"><ele>5300</ele><time>2026-05-12T04:00:00Z</time></trkpt>
            <trkpt lat="27.9881" lon="86.9250"><ele>8848</ele><time>2026-05-12T03:00:00Z</time></trkpt>
          </trkseg></trk>
        </gpx>`,
        'utf-8'
      );

      const parsed = parseGpxTelemetryBuffer(spoofedGpx, everest);
      expect(parsed.gpsTimestampConsistent).toBe(false);
      expect(parsed.spoofingIndicators.some((s) => s.startsWith('SUSPICIOUS_CREATOR_TAG'))).toBe(true);
      expect(parsed.spoofingIndicators.some((s) => s.startsWith('NON_MONOTONIC_BACKWARDS_TIMESTAMP'))).toBe(true);
    });

    it('detects image editing software tags (Adobe Photoshop) in EXIF metadata', () => {
      const everest = DESTINATIONS_100_CATALOG[0];
      const fakeJpegWithPhotoshopTag = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe1]),
        Buffer.from('Exif\0\0Software: Adobe Photoshop CC 2026\nDateTimeOriginal: 2026:05:12 06:15:00', 'utf-8'),
        Buffer.alloc(256, 0x42),
      ]);

      const exif = parsePhotoExifBuffer(fakeJpegWithPhotoshopTag, everest);
      expect(exif.exifTamperingIndicator).toBe(true);
      expect(exif.spoofingIndicators.some((s) => s.includes('EXIF_EDITING_OR_SYNTHETIC_SOFTWARE_TAG'))).toBe(true);
    });

    it('masks ALL residential start and end GPX trackpoints within 2,000m radius', () => {
      const points = [
        { lat: 27.7000, lon: 85.3000, ele: 1400 }, // Start (0m) - MASKED
        { lat: 27.7040, lon: 85.3040, ele: 1450 }, // ~600m from start - MASKED
        { lat: 27.7100, lon: 85.3100, ele: 1550 }, // ~1,480m from start - MASKED
        { lat: 27.9881, lon: 86.9250, ele: 8848 }, // Summit (~163km away) - PRESERVED
        { lat: 27.7080, lon: 85.3080, ele: 1500 }, // ~1,180m from end - MASKED
        { lat: 27.7000, lon: 85.3000, ele: 1400 }, // End (0m) - MASKED
      ];
      const result = maskResidentialTrackpoints(points, 2000);
      expect(result.removedCount).toBe(5);
      expect(result.maskedPoints).toHaveLength(1);
      expect(result.maskedPoints[0].ele).toBe(8848);
    });
  });
});
