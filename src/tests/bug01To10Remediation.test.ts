import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import fs from 'node:fs';
import http from 'http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'crypto';
import jpeg from 'jpeg-js';
import { PNG } from 'pngjs';
import { apiRouter } from '../server/apiRouter';
import {
  BoundedInMemoryRateLimitStore,
  checkLoginRateLimit,
  recordFailedLoginAttempt,
  resetLoginAttempts,
  resolveTrustedClientIp,
  buildSessionCookieHeader,
  buildClearSessionCookieHeader,
  validateScryptHashParameters,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  needsPasswordRehash,
} from '../server/auth';
import {
  MAX_EVIDENCE_FILE_BYTES,
  MAX_GPX_TRACKPOINTS,
  decodeAndValidateBase64Payload,
  parseGpxTelemetryBuffer,
  parsePhotoExifBuffer,
  computeDecodedImagePerceptualHash,
  computePerceptualHashHammingDistance,
} from '../server/evidenceProcessor';
import {
  resetDatabase,
  isDemoProvisioningAllowed,
  validateStartupEnvironmentSecurity,
  attemptDemoSeedOperationServer,
  authenticateUserSession,
  validateSessionToken,
  getTestOnlyAccountCredentials,
  listAuditEvents,
  getDb,
} from '../server/db';
import {
  createInitialLoadingBootstrapState,
  resolveBootstrapSuccessState,
  resolveBootstrapFailureState,
  lookupVerifiedCertificateFromState,
} from '../domain/bootstrapClientState';
import {
  getWormReplicationStatus,
  registerWormTransportAdapter,
  clearWormReplicationAlerts,
  createEncryptedWormArchiveBundle,
  verifyAndRecoverWormArchiveBundle,
  replicateAuditBatchToExternalWorm,
} from '../server/wormArchiveService';
import { DESTINATIONS_100_CATALOG } from '../data/destinations100';

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), '0to8848-bug01to10-db-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'platform-bug01to10.sqlite');

// Helper to create an ephemeral test HTTP server
async function startTestServer() {
  const app = express();
  app.use('/api/v1', apiRouter);
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as { port: number };
  return {
    server,
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// Helper to synthesize a valid decoded PNG buffer
function createTestPngBuffer(
  width: number,
  height: number,
  pixelFn: (x: number, y: number) => [number, number, number]
): Buffer {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (width * y + x) << 2;
      const [r, g, b] = pixelFn(x, y);
      png.data[idx] = r;
      png.data[idx + 1] = g;
      png.data[idx + 2] = b;
      png.data[idx + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}

// Helper to synthesize a valid decoded JPEG buffer
function createTestJpegBuffer(
  width: number,
  height: number,
  pixelFn: (x: number, y: number) => [number, number, number]
): Buffer {
  const frameData = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (width * y + x) * 4;
      const [r, g, b] = pixelFn(x, y);
      frameData[idx] = r;
      frameData[idx + 1] = g;
      frameData[idx + 2] = b;
      frameData[idx + 3] = 255;
    }
  }
  const encoded = jpeg.encode({ data: frameData, width, height }, 90);
  return Buffer.from(encoded.data);
}

describe('0 TO 8848 — MASTER BUG FIX & SECURITY REMEDIATION SUITE (BUG-01 TO BUG-10)', () => {
  beforeAll(() => {
    process.env.DB_FILE_PATH = TEST_DB_PATH;
    resetDatabase(TEST_DB_PATH);
    resetLoginAttempts();
    registerWormTransportAdapter(null);
    clearWormReplicationAlerts();
  });

  afterAll(() => {
    resetLoginAttempts();
    registerWormTransportAdapter(null);
    clearWormReplicationAlerts();
    try {
      fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
    } catch {
      // ignore cleanup error
    }
  });

  // =========================================================================
  // BUG-01: Login Rate Limiting & Anti-DoS / Bounded Store
  // =========================================================================
  describe('BUG-01: Layered Login Rate Limiting, IP Isolation, Progressive Lockout & Bounded Store', () => {
    it('isolates account+IP lockouts so an attacker on IP-A cannot lock out a legitimate user on IP-B', () => {
      const targetUser = 'usr-gov-founder-001';
      const attackerIp = '203.0.113.55';
      const legitimateIp = '198.51.100.12';
      const now = 1_700_000_000_000;

      // Attacker triggers 5 failed attempts from attackerIp
      for (let i = 0; i < 5; i++) {
        recordFailedLoginAttempt(targetUser, attackerIp, now + i * 100);
      }

      // Attacker IP is locked out for targetUser
      const attackerStatus = checkLoginRateLimit(targetUser, attackerIp, now + 1000);
      expect(attackerStatus.allowed).toBe(false);
      expect(attackerStatus.blockedByLayer).toBe('ACCOUNT_AND_IP');
      expect(attackerStatus.retryAfterSeconds).toBeGreaterThan(0);

      // Legitimate user from legitimateIp is STILL ALLOWED to log in!
      const legitStatus = checkLoginRateLimit(targetUser, legitimateIp, now + 1000);
      expect(legitStatus.allowed).toBe(true);
    });

    it('enforces progressive lockout tiers (60s -> 300s -> 900s) and recovery after expiration', () => {
      const targetUser = 'adventurer@example.com';
      const clientIp = '192.0.2.88';
      let clock = 1_700_000_000_000;

      // Tier 1: 5 failures -> 60s lockout
      for (let i = 0; i < 5; i++) {
        recordFailedLoginAttempt(targetUser, clientIp, clock);
      }
      const tier1 = checkLoginRateLimit(targetUser, clientIp, clock + 1000);
      expect(tier1.allowed).toBe(false);
      expect(tier1.retryAfterSeconds).toBeLessThanOrEqual(60);
      expect(tier1.retryAfterSeconds).toBeGreaterThanOrEqual(58);

      // Advance past Tier 1 lockout (61s) — user can attempt again
      clock += 61_000;
      expect(checkLoginRateLimit(targetUser, clientIp, clock).allowed).toBe(true);

      // 4 more failures (9 total) -> Tier 2: 300s (5 min) lockout
      for (let i = 0; i < 4; i++) {
        recordFailedLoginAttempt(targetUser, clientIp, clock);
      }
      const tier2 = checkLoginRateLimit(targetUser, clientIp, clock + 1000);
      expect(tier2.allowed).toBe(false);
      expect(tier2.retryAfterSeconds).toBeGreaterThan(250);
      expect(tier2.retryAfterSeconds).toBeLessThanOrEqual(300);

      // Reset on successful login clears account+IP state
      resetLoginAttempts(targetUser, clientIp);
      expect(checkLoginRateLimit(targetUser, clientIp, clock + 2000).allowed).toBe(true);
    });

    it('enforces per-IP global throttle across multiple accounts and distributed multi-IP account anomaly limit', () => {
      const sprayIp = '203.0.113.99';
      const now = 1_700_000_000_000;

      // Password spraying from a single IP across 20 different accounts
      for (let i = 0; i < 20; i++) {
        recordFailedLoginAttempt(`user-${i}@0to8848.com`, sprayIp, now + i * 50);
      }

      const ipSprayStatus = checkLoginRateLimit('brand-new-user@0to8848.com', sprayIp, now + 2000);
      expect(ipSprayStatus.allowed).toBe(false);
      expect(ipSprayStatus.blockedByLayer).toBe('CLIENT_IP_GLOBAL');

      // Distributed botnet attack against one account from 25 distinct IPs
      const botnetTarget = 'highvalue-climber@0to8848.com';
      for (let i = 0; i < 25; i++) {
        recordFailedLoginAttempt(botnetTarget, `198.18.0.${i + 1}`, now + i * 50);
      }
      const distStatus = checkLoginRateLimit(botnetTarget, '198.18.99.99', now + 2000);
      expect(distStatus.allowed).toBe(false);
      expect(distStatus.blockedByLayer).toBe('DISTRIBUTED_ACCOUNT_PROTECTION');
    });

    it('prevents memory exhaustion with BoundedInMemoryRateLimitStore LRU/TTL eviction', () => {
      const store = new BoundedInMemoryRateLimitStore(50);
      const now = 1_700_000_000_000;
      for (let i = 0; i < 200; i++) {
        store.set(
          `key-${i}`,
          {
            failedCount: 1,
            firstFailedAtMs: now,
            lastFailedAtMs: now,
            lockedUntilMs: 0,
            expiresAtMs: now + 60_000,
          },
          now
        );
      }
      // Never exceeds maxEntries (50)
      expect(store.size()).toBe(50);
      expect(store.get('key-0', now)).toBeUndefined();
      expect(store.get('key-199', now)).toBeDefined();
    });

    it('resolves client IP safely and ignores spoofed X-Forwarded-For unless TRUST_PROXY=true', () => {
      const mockReq = {
        headers: { 'x-forwarded-for': '198.51.100.77, 10.0.0.1' },
        socket: { remoteAddress: '::ffff:10.0.0.5' } as any,
        ip: '10.0.0.5',
      };

      expect(resolveTrustedClientIp(mockReq, { TRUST_PROXY: 'false' })).toBe('10.0.0.5');
      expect(resolveTrustedClientIp(mockReq, { TRUST_PROXY: 'true' })).toBe('198.51.100.77');
    });
  });

  // =========================================================================
  // BUG-02: Session Cookie Security, Cookie-Based Logout & CSRF Protection
  // =========================================================================
  describe('BUG-02: Session Cookie Security Flags, Cookie-Based Logout Revocation & CSRF Protection', () => {
    it('sets Secure; HttpOnly; SameSite=Strict in production/HTTPS and omits Secure on plain HTTP dev', () => {
      const prodCookie = buildSessionCookieHeader('tok-123', {
        isProduction: true,
        isHttps: false,
      });
      expect(prodCookie).toContain('0to8848_session=tok-123');
      expect(prodCookie).toContain('HttpOnly');
      expect(prodCookie).toContain('SameSite=Strict');
      expect(prodCookie).toContain('Path=/');
      expect(prodCookie).toContain('Max-Age=28800');
      expect(prodCookie).toContain('Secure');

      const devCookie = buildSessionCookieHeader('tok-dev', {
        isProduction: false,
        isHttps: false,
      });
      expect(devCookie).toContain('HttpOnly');
      expect(devCookie).toContain('SameSite=Strict');
      expect(devCookie).not.toContain('Secure');

      const clearProdCookie = buildClearSessionCookieHeader({
        isProduction: true,
        isHttps: true,
      });
      expect(clearProdCookie).toContain('0to8848_session=');
      expect(clearProdCookie).toContain('Max-Age=0');
      expect(clearProdCookie).toContain('Secure');
    });

    it('revokes session in database on cookie-only POST /api/v1/auth/logout and rejects revoked cookie reuse', async () => {
      const { baseUrl, close } = await startTestServer();
      try {
        const adv = getTestOnlyAccountCredentials('usr-tenzing-nepal');
        const authSession = authenticateUserSession({
          usernameOrUserId: adv.username,
          password: adv.ephemeralPassword,
        });
        expect(validateSessionToken(authSession.sessionToken)).not.toBeNull();

        // Logout using ONLY the Cookie header (no Authorization Bearer header)
        const logoutRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `0to8848_session=${encodeURIComponent(authSession.sessionToken)}`,
          },
          body: JSON.stringify({}),
        });
        expect(logoutRes.status).toBe(200);
        const logoutData = await logoutRes.json();
        expect(logoutData.revoked).toBe(true);
        expect(logoutRes.headers.get('set-cookie')).toContain('Max-Age=0');

        // Verify token is revoked in database
        expect(validateSessionToken(authSession.sessionToken)).toBeNull();

        // Attempt to reuse the revoked cookie on a protected endpoint
        const meRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
          headers: {
            Cookie: `0to8848_session=${encodeURIComponent(authSession.sessionToken)}`,
          },
        });
        expect(meRes.status).toBe(401);
      } finally {
        await close();
      }
    });

    it('blocks cross-origin and simple form-encoded CSRF state-changing requests when using cookie auth', async () => {
      const { baseUrl, close } = await startTestServer();
      try {
        const adv = getTestOnlyAccountCredentials('usr-tenzing-nepal');
        const authSession = authenticateUserSession({
          usernameOrUserId: adv.username,
          password: adv.ephemeralPassword,
        });

        // 1. Cross-origin Origin header with session cookie -> 403 CSRF_ORIGIN_MISMATCH
        const crossOriginRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: 'https://evil-attacker.example.com',
            Cookie: `0to8848_session=${encodeURIComponent(authSession.sessionToken)}`,
          },
          body: JSON.stringify({}),
        });
        expect(crossOriginRes.status).toBe(403);
        const crossOriginBody = await crossOriginRes.json();
        expect(crossOriginBody.error).toBe('CSRF_ORIGIN_MISMATCH');

        // 2. HTML form-encoded POST with session cookie -> 403 CSRF_FORM_ENCODING_BLOCKED
        const formCsrfRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Cookie: `0to8848_session=${encodeURIComponent(authSession.sessionToken)}`,
          },
          body: 'confirm=true',
        });
        expect(formCsrfRes.status).toBe(403);
        const formCsrfBody = await formCsrfRes.json();
        expect(formCsrfBody.error).toBe('CSRF_FORM_ENCODING_BLOCKED');
      } finally {
        await close();
      }
    });
  });

  // =========================================================================
  // BUG-03: Scrypt Parameter Validation & Safe Legacy Rehash
  // =========================================================================
  describe('BUG-03: Scrypt Parameter Validation, DoS Memory Cap & Legacy Hash Auto-Upgrade', () => {
    it('verifies valid scrypt hashes and rejects malformed, non-power-of-two, negative, or excessive memory parameters', () => {
      const validHash = hashPasswordScrypt('Everest-8848-Test!');
      expect(verifyPasswordScrypt('Everest-8848-Test!', validHash)).toBe(true);
      expect(verifyPasswordScrypt('Wrong-Password', validHash)).toBe(false);
      expect(needsPasswordRehash(validHash)).toBe(false);

      const saltHex = crypto.randomBytes(16).toString('hex');
      const keyHex = crypto.randomBytes(64).toString('hex');

      // Non-power-of-two N (e.g. N=20000)
      const nonPow2 = `scrypt$20000$8$1$${saltHex}$${keyHex}`;
      expect(validateScryptHashParameters(nonPow2).valid).toBe(false);
      expect(verifyPasswordScrypt('Everest-8848-Test!', nonPow2)).toBe(false);

      // Excessive memory parameters (N=65536, r=16, p=2 -> 256 MiB > 32 MiB cap)
      const excessiveMem = `scrypt$65536$16$2$${saltHex}$${keyHex}`;
      const memCheck = validateScryptHashParameters(excessiveMem);
      expect(memCheck.valid).toBe(false);
      expect(memCheck.reason).toBe('SCRYPT_MEMORY_LIMIT_EXCEEDED');
      expect(verifyPasswordScrypt('Everest-8848-Test!', excessiveMem)).toBe(false);

      // Negative or non-integer parameters
      expect(verifyPasswordScrypt('Everest-8848-Test!', `scrypt$-16384$8$1$${saltHex}$${keyHex}`)).toBe(false);
      expect(verifyPasswordScrypt('Everest-8848-Test!', `scrypt$abc$8$1$${saltHex}$${keyHex}`)).toBe(false);

      // Malformed / short salt or key
      expect(verifyPasswordScrypt('Everest-8848-Test!', `scrypt$16384$8$1$deadbeef$${keyHex}`)).toBe(false);
    });

    it('supports legacy saltHex:keyHex format and automatically rehashes to approved scrypt policy on login', () => {
      const adv = getTestOnlyAccountCredentials('usr-lukas-at');
      const salt = crypto.randomBytes(16);
      const derived = crypto.scryptSync(adv.ephemeralPassword, salt, 64, {
        N: 16384,
        r: 8,
        p: 1,
      });
      const legacyStoredHash = `${salt.toString('hex')}:${derived.toString('hex')}`;

      const validation = validateScryptHashParameters(legacyStoredHash);
      expect(validation.valid).toBe(true);
      expect(validation.params?.isLegacyFormat).toBe(true);
      expect(needsPasswordRehash(legacyStoredHash)).toBe(true);
      expect(verifyPasswordScrypt(adv.ephemeralPassword, legacyStoredHash)).toBe(true);

      // Temporarily store legacy format in DB for usr-lukas-at and verify login upgrades it
      const db = getDb();
      db.prepare('UPDATE users SET password_hash = ? WHERE user_id = ?').run(
        legacyStoredHash,
        adv.userId
      );

      const loginResult = authenticateUserSession({
        usernameOrUserId: adv.username,
        password: adv.ephemeralPassword,
      });
      expect(loginResult.passwordRehashed).toBe(true);

      const updatedRow = db
        .prepare('SELECT password_hash FROM users WHERE user_id = ?')
        .get(adv.userId) as { password_hash: string };
      expect(updatedRow.password_hash.startsWith('scrypt$16384$8$1$')).toBe(true);
      expect(needsPasswordRehash(updatedRow.password_hash)).toBe(false);
    });
  });

  // =========================================================================
  // BUG-04: Evidence Upload Size Mismatch, Base64 Validation & Binary Streaming
  // =========================================================================
  describe('BUG-04: Evidence Upload Size Enforcement (10 MiB Binary), Base64 Pre-Validation & Binary Streaming', () => {
    it('accepts valid 6 MiB binary evidence via Base64 JSON (which previously failed under 8mb Express limit)', () => {
      // 6 MiB JPEG buffer -> ~8.0 MiB Base64 string
      const sixMibBuffer = Buffer.alloc(6 * 1024 * 1024, 0x41);
      sixMibBuffer[0] = 0xff;
      sixMibBuffer[1] = 0xd8;
      sixMibBuffer[2] = 0xff;
      sixMibBuffer[3] = 0xe0;

      const b64 = sixMibBuffer.toString('base64');
      const decoded = decodeAndValidateBase64Payload(b64, MAX_EVIDENCE_FILE_BYTES);
      expect(decoded.byteLength).toBe(6 * 1024 * 1024);
    });

    it('rejects oversized Base64 payloads (> 10 MiB binary) before allocation and rejects malformed Base64', () => {
      const oversizedBase64 = 'A'.repeat(Math.ceil((11 * 1024 * 1024 * 4) / 3));
      expect(() =>
        decodeAndValidateBase64Payload(oversizedBase64, MAX_EVIDENCE_FILE_BYTES)
      ).toThrow(/FILE_SIZE_LIMIT_EXCEEDED/);

      expect(() =>
        decodeAndValidateBase64Payload('NOT_VALID_BASE64!!!@@@###', MAX_EVIDENCE_FILE_BYTES)
      ).toThrow(/MALFORMED_BASE64_PAYLOAD/);
    });

    it('supports binary streaming upload (application/octet-stream) and rejects spoofed MIME magic bytes', async () => {
      const { baseUrl, close } = await startTestServer();
      try {
        const adv = getTestOnlyAccountCredentials('usr-tenzing-nepal');
        const authSession = authenticateUserSession({
          usernameOrUserId: adv.username,
          password: adv.ephemeralPassword,
        });
        const randSalt = Math.floor(Math.random() * 200);
        const pngBuffer = createTestPngBuffer(16, 16, (x, y) => [
          (x * 13 + randSalt) % 255,
          (y * 17 + 11) % 255,
          99,
        ]);

        // Valid binary stream upload
        const streamRes = await fetch(`${baseUrl}/api/v1/evidence/upload`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${authSession.sessionToken}`,
            'Content-Type': 'application/octet-stream',
            'x-file-name': 'summit_ridge_stream.png',
            'x-artifact-type': 'RAW_EXIF_PHOTO',
            'x-destination-id': 'dest-001',
          },
          body: new Uint8Array(pngBuffer),
        });
        expect(streamRes.status).toBe(201);
        const streamJson = await streamRes.json();
        expect(streamJson.artifact.sha256PostUploadDigest).toBe(
          crypto.createHash('sha256').update(pngBuffer).digest('hex')
        );

        // Spoofed magic bytes (claiming RAW_EXIF_PHOTO for plain text) -> 400
        const spoofRes = await fetch(`${baseUrl}/api/v1/evidence/upload`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${authSession.sessionToken}`,
            'Content-Type': 'application/octet-stream',
            'x-file-name': 'spoofed.jpg',
            'x-artifact-type': 'RAW_EXIF_PHOTO',
            'x-destination-id': 'dest-001',
          },
          body: new Uint8Array(Buffer.from('Not a real JPEG or PNG image at all', 'utf8')),
        });
        expect(spoofRes.status).toBe(400);
        const spoofBody = await spoofRes.json();
        expect(spoofBody.error).toBe('EVIDENCE_VALIDATION_FAILED');
      } finally {
        await close();
      }
    });
  });

  // =========================================================================
  // BUG-05 & BUG-10: GPX / EXIF Evidence Authenticity, Perceptual Hashing & Sliding-Window Speed
  // =========================================================================
  describe('BUG-05 & BUG-10: Structured GPX/EXIF Forensics, Real Perceptual Hash & Linear GPX Performance', () => {
    const everestDest = DESTINATIONS_100_CATALOG[0]; // Mount Everest (8848m)

    it('rejects malformed XML and XXE entity declarations', () => {
      const malformedGpx = Buffer.from(
        `<?xml version="1.0"?><gpx><trk><trkseg><trkpt lat="27.9881" lon="86.9250"><ele>8848</trkpt></trkseg></gpx>`,
        'utf8'
      );
      expect(() => parseGpxTelemetryBuffer(malformedGpx, everestDest)).toThrow(
        /MALFORMED_GPX_XML/
      );

      const xxeGpx = Buffer.from(
        `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><gpx>&xxe;</gpx>`,
        'utf8'
      );
      expect(() => parseGpxTelemetryBuffer(xxeGpx, everestDest)).toThrow(
        /XXE_PAYLOAD_DETECTED_AND_BLOCKED/
      );
    });

    it('flags missing trackpoint <time> tags instead of fabricating sequential timestamps', () => {
      const missingTimeGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?>
        <gpx version="1.1" creator="Garmin Fenix 7">
          <trk><trkseg>
            <trkpt lat="27.9880" lon="86.9249"><ele>8840</ele></trkpt>
            <trkpt lat="27.9881" lon="86.9250"><ele>8848</ele></trkpt>
          </trkseg></trk>
        </gpx>`,
        'utf8'
      );
      const res = parseGpxTelemetryBuffer(missingTimeGpx, everestDest);
      expect(res.spoofingIndicators.some((s) => s.startsWith('MISSING_TRACKPOINT_TIMESTAMPS'))).toBe(true);
      expect(res.gpsTimestampConsistent).toBe(false);
      expect(res.captureTimestampUtc).toBe('TIMESTAMP_MISSING');
    });

    it('does NOT mark barometricChannelDetected=true merely from Garmin/Suunto creator strings without pressure telemetry', () => {
      const brandOnlyGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?>
        <gpx version="1.1" creator="Garmin Fenix 7X Pro Sapphire Solar">
          <trk><trkseg>
            <trkpt lat="27.9880" lon="86.9249"><ele>8840</ele><time>2025-05-15T04:00:00Z</time></trkpt>
            <trkpt lat="27.9881" lon="86.9250"><ele>8848</ele><time>2025-05-15T04:15:00Z</time></trkpt>
          </trkseg></trk>
        </gpx>`,
        'utf8'
      );
      const brandOnlyRes = parseGpxTelemetryBuffer(brandOnlyGpx, everestDest);
      expect(brandOnlyRes.barometricChannelDetected).toBe(false);

      const genuineBaroGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?>
        <gpx version="1.1" creator="Garmin Fenix 7X">
          <trk><trkseg>
            <trkpt lat="27.9880" lon="86.9249">
              <ele>8840</ele>
              <time>2025-05-15T04:00:00Z</time>
              <extensions><gpxtpx:TrackPointExtension><gpxtpx:pressure>335.2</gpxtpx:pressure></gpxtpx:TrackPointExtension></extensions>
            </trkpt>
            <trkpt lat="27.9881" lon="86.9250">
              <ele>8848</ele>
              <time>2025-05-15T04:15:00Z</time>
              <extensions><gpxtpx:TrackPointExtension><gpxtpx:pressure>334.8</gpxtpx:pressure></gpxtpx:TrackPointExtension></extensions>
            </trkpt>
          </trkseg></trk>
        </gpx>`,
        'utf8'
      );
      const genuineBaroRes = parseGpxTelemetryBuffer(genuineBaroGpx, everestDest);
      expect(genuineBaroRes.barometricChannelDetected).toBe(true);
    });

    it('rejects excessive trackpoints (> maxTrackpoints) and processes 5,000 trackpoints in < 800ms (BUG-10)', () => {
      // 1. Exceed custom maxTrackpoints limit (e.g., 10)
      const twelvePtsXml = Array.from({ length: 12 }, (_, i) => {
        const iso = new Date(1_747_280_000_000 + i * 60_000).toISOString();
        return `<trkpt lat="27.9881" lon="86.9250"><ele>${8000 + i}</ele><time>${iso}</time></trkpt>`;
      }).join('\n');
      expect(() =>
        parseGpxTelemetryBuffer(
          Buffer.from(`<gpx><trk><trkseg>${twelvePtsXml}</trkseg></trk></gpx>`, 'utf8'),
          everestDest,
          { maxTrackpoints: 10 }
        )
      ).toThrow(/GPX_MAX_TRACKPOINTS_EXCEEDED/);

      // 2. Benchmark 5,000 trackpoints with sliding-window O(N) algorithm
      const n = 5000;
      const baseTime = 1_747_280_000_000;
      const ptsXml = Array.from({ length: n }, (_, i) => {
        const iso = new Date(baseTime + i * 10_000).toISOString();
        const ele = 8000 + Math.round((i / n) * 848);
        return `<trkpt lat="27.9881" lon="86.9250"><ele>${ele}</ele><time>${iso}</time></trkpt>`;
      }).join('');
      const largeGpx = Buffer.from(
        `<?xml version="1.0" encoding="UTF-8"?><gpx version="1.1"><trk><trkseg>${ptsXml}</trkseg></trk></gpx>`,
        'utf8'
      );

      const t0 = Date.now();
      const perfRes = parseGpxTelemetryBuffer(largeGpx, everestDest);
      const elapsedMs = Date.now() - t0;

      expect(perfRes.trackpointCount).toBe(5000);
      expect(perfRes.recordedMaxElevationM).toBe(8848);
      expect(elapsedMs).toBeLessThan(800);
      expect(MAX_GPX_TRACKPOINTS).toBe(50000);
    });

    it('reports EXIF_TIMESTAMP_MISSING when JPEG lacks EXIF DateTimeOriginal instead of substituting current time', () => {
      const bareJpeg = createTestJpegBuffer(16, 16, (x, y) => [x * 12, y * 12, 80]);
      const exifMeta = parsePhotoExifBuffer(bareJpeg, everestDest);
      expect(exifMeta.captureTimestampUtc).toBe('EXIF_TIMESTAMP_MISSING');
      expect(exifMeta.deviceModel).toBe('EXIF_CAMERA_MODEL_MISSING');
      expect(exifMeta.spoofingIndicators).toContain('MISSING_EXIF_CAPTURE_TIMESTAMP');
    });

    it('computes decoded pixel luminance perceptual hashes (pHash) and detects near-duplicate images across re-encoding', () => {
      // Image A: horizontal gradient in PNG
      const gradientPngA = createTestPngBuffer(32, 32, (x, y) => [x * 7, y * 3, 100]);
      // Image A2: same horizontal gradient with slight brightness tweak (+2) encoded as JPEG
      const gradientJpegA2 = createTestJpegBuffer(32, 32, (x, y) => [
        Math.min(255, x * 7 + 2),
        Math.min(255, y * 3 + 2),
        102,
      ]);
      // Image B: high-contrast top-vs-bottom split pattern in PNG
      const patternPngB = createTestPngBuffer(32, 32, (x, y) =>
        x < 16 ? [250, 250, 250] : [10, 10, 10]
      );

      const resA = computeDecodedImagePerceptualHash(gradientPngA);
      const resA2 = computeDecodedImagePerceptualHash(gradientJpegA2);
      const resB = computeDecodedImagePerceptualHash(patternPngB);

      expect(resA.decodedPixels).toBe(true);
      expect(resA2.decodedPixels).toBe(true);
      expect(resB.decodedPixels).toBe(true);
      expect(resA.perceptualHash).toMatch(/^pHash:[0-9a-f]{16}$/);
      expect(resA2.perceptualHash).toMatch(/^pHash:[0-9a-f]{16}$/);
      expect(resB.perceptualHash).toMatch(/^pHash:[0-9a-f]{16}$/);

      // Near-duplicate re-encoded gradient images have very small Hamming distance (<= 8 bits)
      const distNearDup = computePerceptualHashHammingDistance(
        resA.perceptualHash,
        resA2.perceptualHash
      );
      expect(distNearDup).toBeLessThanOrEqual(8);

      // Completely different visual patterns have high Hamming distance
      const distDifferent = computePerceptualHashHammingDistance(
        resA.perceptualHash,
        resB.perceptualHash
      );
      expect(distDifferent).toBeGreaterThan(10);
    });
  });

  // =========================================================================
  // BUG-06: Fail-Closed Production Demo Provisioning Guard
  // =========================================================================
  describe('BUG-06: Fail-Closed Demo Provisioning Guard & Production Demo Lockout', () => {
    it('fails closed when NODE_ENV is missing, production (even with flag=true), or development without explicit flag', () => {
      // Missing NODE_ENV -> false
      expect(isDemoProvisioningAllowed({ NODE_ENV: undefined, ENABLE_DEV_DEMO_PROVISIONING: 'true' })).toBe(false);
      expect(isDemoProvisioningAllowed({ NODE_ENV: '', ENABLE_DEV_DEMO_PROVISIONING: 'true' })).toBe(false);

      // Production with ENABLE_DEV_DEMO_PROVISIONING=true -> false (hard blocked!)
      expect(
        isDemoProvisioningAllowed({ NODE_ENV: 'production', ENABLE_DEV_DEMO_PROVISIONING: 'true' })
      ).toBe(false);
      const startupSec = validateStartupEnvironmentSecurity({
        NODE_ENV: 'production',
        ENABLE_DEV_DEMO_PROVISIONING: 'true',
      });
      expect(startupSec.safe).toBe(false);
      expect(startupSec.demoProvisioningAllowed).toBe(false);
      expect(startupSec.criticalViolations.some((v) => v.startsWith('DANGEROUS_CONFIG_BLOCKED'))).toBe(true);

      // Development without explicit flag -> false
      expect(
        isDemoProvisioningAllowed({ NODE_ENV: 'development', ENABLE_DEV_DEMO_PROVISIONING: undefined })
      ).toBe(false);
      expect(
        isDemoProvisioningAllowed({ NODE_ENV: 'development', ENABLE_DEV_DEMO_PROVISIONING: 'false' })
      ).toBe(false);

      // Development WITH explicit flag -> true
      expect(
        isDemoProvisioningAllowed({ NODE_ENV: 'development', ENABLE_DEV_DEMO_PROVISIONING: 'true' })
      ).toBe(true);
    });

    it('rejects demo seed operations and blocks demo accounts from logging in when NODE_ENV=production', () => {
      const prevNodeEnv = process.env.NODE_ENV;
      const prevDemoFlag = process.env.ENABLE_DEV_DEMO_PROVISIONING;
      try {
        process.env.NODE_ENV = 'production';
        process.env.ENABLE_DEV_DEMO_PROVISIONING = 'true';

        // 1. Demo seed attempt in production throws DEMO_SEED_FORBIDDEN_IN_PRODUCTION and audits
        expect(() =>
          attemptDemoSeedOperationServer('act-uuid-founder-001', 'FOUNDER')
        ).toThrow(/DEMO_SEED_FORBIDDEN_IN_PRODUCTION/);

        // 2. Demo account authentication in production throws DEMO_ACCOUNT_FORBIDDEN_IN_PRODUCTION and audits
        expect(() =>
          authenticateUserSession({
            usernameOrUserId: 'usr-gov-founder-001',
            password: 'any-password',
            totpCode: '000000',
          })
        ).toThrow(/DEMO_ACCOUNT_FORBIDDEN_IN_PRODUCTION/);

        const events = listAuditEvents();
        expect(events.some((e) => e.actionType === 'SECURITY_DEMO_SEED_REJECTED')).toBe(true);
        expect(events.some((e) => e.actionType === 'SECURITY_DEMO_AUTH_BLOCKED_IN_PRODUCTION')).toBe(true);
      } finally {
        process.env.NODE_ENV = prevNodeEnv;
        process.env.ENABLE_DEV_DEMO_PROVISIONING = prevDemoFlag;
      }
    });
  });

  // =========================================================================
  // BUG-08: Frontend Bootstrap Failure & Production vs Demo State Separation
  // =========================================================================
  describe('BUG-08: Frontend Bootstrap State Separation & Non-Deceptive Error Handling', () => {
    it('initializes with empty loading state and never falls back to demo fixtures on failure in production', () => {
      const initial = createInitialLoadingBootstrapState();
      expect(initial.status).toBe('LOADING');
      expect(initial.submissions).toEqual([]);
      expect(initial.certificates).toEqual([]);
      expect(initial.isDevDemoFixture).toBe(false);

      // Online API failure in production -> ERROR state, empty data, isDevDemoFixture = false
      const prodErrorState = resolveBootstrapFailureState({
        errorMessage: 'HTTP 502 Bad Gateway',
        isOffline: false,
        isProduction: true,
        explicitDevDemoModeRequested: true,
      });
      expect(prodErrorState.status).toBe('ERROR');
      expect(prodErrorState.submissions).toEqual([]);
      expect(prodErrorState.certificates).toEqual([]);
      expect(prodErrorState.isDevDemoFixture).toBe(false);

      // Offline failure -> OFFLINE_ERROR state, empty data
      const offlineState = resolveBootstrapFailureState({
        errorMessage: 'Failed to fetch',
        isOffline: true,
        isProduction: true,
      });
      expect(offlineState.status).toBe('OFFLINE_ERROR');
      expect(offlineState.submissions).toEqual([]);
    });

    it('clearly distinguishes empty lookup, verified match, and non-existent verification ID', () => {
      const readyState = resolveBootstrapSuccessState({
        submissions: [],
        certificates: [
          {
            verificationId: '8848-V1-TEST-0001-AAAA-BBBB-CCCC-000001',
            submissionId: 'SUB-01',
            destinationId: 'dest-001',
            destinationCode: 'NEP-8848-001',
            destinationNameEn: 'Mount Everest',
            verifiedElevationM: 8848,
            routeName: 'South Col',
            verificationTrack: 'STANDARD_CURRENT',
            holderUserId: 'usr-tenzing-nepal',
            holderInternalActorUuid: 'act-uuid-01',
            holderPublicDisplay: 'Mingma Dorjee Sherpa',
            holderNationality: 'Nepal',
            holderPrivacyMode: 'FULL_NAME',
            holderDatePrecision: 'EXACT_DATE',
            publicCompletionDateDisplay: '2026-05-19',
            issuedAtUtc: '2026-05-22T10:00:00Z',
            status: 'ACTIVE_VERIFIED',
            reviewingOfficerCodes: ['REV-OFFICER-104', 'REV-OFFICER-219'],
            cryptographicRecordHash: 'abc1234',
            optInPublicLeaderboards: true,
          },
        ],
        auditEvents: [],
      });

      expect(lookupVerifiedCertificateFromState(readyState, '')).toBeNull();
      expect(
        lookupVerifiedCertificateFromState(readyState, '8848-V1-TEST-0001-AAAA-BBBB-CCCC-000001')
      ).not.toBeNull();
      expect(
        lookupVerifiedCertificateFromState(readyState, '8848-V1-NON-EXISTENT')
      ).toBeNull();
    });
  });

  // =========================================================================
  // BUG-09: Audit Log Tamper-Evident Chain & External WORM Replication Honesty
  // =========================================================================
  describe('BUG-09: Honest Local Audit Immutability Disclosure, Encrypted WORM Archive & Failure Alerting', () => {
    const wormKey32 = crypto.randomBytes(32);

    it('accurately reports LOCAL_SQLITE_TRIGGER_IMMUTABLE when no external WORM adapter is configured', () => {
      const status = getWormReplicationStatus();
      expect(status.protectionLevel).toBe('LOCAL_SQLITE_TRIGGER_IMMUTABLE');
      expect(status.wormReplicated).toBe(false);
      expect(status.status).toBe('LOCAL_ONLY_WORM_UNCONFIGURED');
      expect(status.honestDisclosure).toContain('external cloud WORM Object Lock is not currently connected');
    });

    it('creates AES-256-GCM encrypted + HMAC-signed WORM archive bundles and detects any tampering on recovery', () => {
      const events = listAuditEvents();
      const bundle = createEncryptedWormArchiveBundle(events, wormKey32);
      expect(bundle.bundleId).toMatch(/^worm-bundle-/);
      expect(bundle.eventCount).toBe(events.length);

      // Verify & recover intact bundle
      const recovered = verifyAndRecoverWormArchiveBundle(bundle, wormKey32);
      expect(recovered.valid).toBe(true);
      expect(recovered.recoveredEvents.length).toBe(events.length);

      // Tamper with ciphertextBase64 -> verification fails
      const tamperedBundle = {
        ...bundle,
        ciphertextBase64: 'AAAA' + bundle.ciphertextBase64.slice(4),
      };
      const tamperedCheck = verifyAndRecoverWormArchiveBundle(tamperedBundle, wormKey32);
      expect(tamperedCheck.valid).toBe(false);
    });

    it('alerts on external WORM replication adapter failures and succeeds when healthy adapter is registered', async () => {
      const events = listAuditEvents();

      // 1. Register failing external WORM adapter
      registerWormTransportAdapter({
        providerName: 'AWS_S3_OBJECT_LOCK',
        putImmutableObject: async () => {
          throw new Error('S3 Object Lock endpoint unreachable');
        },
        getImmutableObject: async () => null,
      });

      const failRes = await replicateAuditBatchToExternalWorm(events, wormKey32);
      expect(failRes.wormReplicated).toBe(false);
      expect(failRes.status).toBe('REPLICATION_FAILED');
      expect(failRes.errorReason).toContain('S3 Object Lock endpoint unreachable');
      expect(failRes.alertTriggered).toBe(true);

      const degradedStatus = getWormReplicationStatus();
      expect(degradedStatus.wormReplicated).toBe(false);
      expect(degradedStatus.recentAlertsCount).toBeGreaterThanOrEqual(1);

      // 2. Register healthy external WORM adapter
      registerWormTransportAdapter({
        providerName: 'AWS_S3_OBJECT_LOCK',
        putImmutableObject: async (bundle) => ({
          verified: true,
          externalObjectId: `s3://0to8848-worm/${bundle.bundleId}`,
          versionId: 'v-lock-001',
          retainedUntilUtc: bundle.retainUntilUtc,
        }),
        getImmutableObject: async () => null,
      });

      const okRes = await replicateAuditBatchToExternalWorm(events, wormKey32);
      expect(okRes.wormReplicated).toBe(true);
      expect(okRes.status).toBe('REPLICATED_AND_VERIFIED');
      expect(okRes.externalObjectId).toContain('s3://0to8848-worm/');

      const healthyStatus = getWormReplicationStatus();
      expect(healthyStatus.protectionLevel).toBe('EXTERNAL_WORM_OBJECT_LOCK_VERIFIED');
      expect(healthyStatus.wormReplicated).toBe(true);
    });

    it('exposes honest WORM status and dynamic health check via /api/v1/health and /api/v1/audit/worm-status', async () => {
      registerWormTransportAdapter(null);
      clearWormReplicationAlerts();
      const { baseUrl, close } = await startTestServer();
      try {
        const healthRes = await fetch(`${baseUrl}/api/v1/health`);
        expect(healthRes.status).toBe(200);
        const healthBody = await healthRes.json();
        expect(healthBody.status).toBe('OK');
        expect(healthBody.auditProtectionLevel).toBe('LOCAL_SQLITE_TRIGGER_IMMUTABLE');
        expect(healthBody.wormReplicated).toBe(false);
        expect(healthBody.catalogCount).toBe(100);
        expect(healthBody.phasesCount).toBe(21);

        const wormRes = await fetch(`${baseUrl}/api/v1/audit/worm-status`);
        expect(wormRes.status).toBe(200);
        const wormBody = await wormRes.json();
        expect(wormBody.protectionLevel).toBe('LOCAL_SQLITE_TRIGGER_IMMUTABLE');
      } finally {
        await close();
      }
    });
  });
});
