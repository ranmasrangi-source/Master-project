import express from 'express';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DESTINATIONS_100_CATALOG } from '../data/destinations100';
import { MASTER_21_PHASES } from '../data/governanceAndPhases';
import {
  DEMO_ACTOR_PROFILES,
  runAutomatedFiveSignalCoiCheck,
} from '../domain/verificationEngine';
import { apiRouter } from '../server/apiRouter';
import {
  generateTotpCode,
  hashPasswordScrypt,
  resetLoginAttempts,
  verifyPasswordScrypt,
  verifyTotpCode,
} from '../server/auth';
import {
  computeAuditEventHmac,
  computeHmacSha256Hex,
  computeSha256Hex,
  configureKeyRing,
  createSignedEvidenceAccessToken,
  generateNonEnumerableVerificationId,
  initializeProcessHmacKey,
  verifyAuditChainIntegrity,
  verifyHmacTimingSafe,
  verifySignedEvidenceAccessToken,
} from '../server/cryptoEngine';
import {
  advanceDestinationStageServer,
  appendAuditEvent,
  authenticateUserSession,
  createSubmissionServer,
  executeCryptographicErasureServer,
  executeDualControlCertificateRevocationServer,
  executeHumanReviewDecisionServer,
  getCertificateByVerificationId,
  getDb,
  getDestinationByIdOrCode,
  getSubmissionById,
  getTestOnlyAccountCredentials,
  listAuditEvents,
  resetDatabase,
} from '../server/db';
import {
  assertNoXxeOrMaliciousDirectives,
  parseGpxTelemetryBuffer,
  parsePhotoExifBuffer,
  validateEvidenceFileMagicBytes,
} from '../server/evidenceProcessor';
import {
  decryptPiiWithUserDek,
  encryptPiiWithUserDek,
  generateUserDekHex,
  maskResidentialTrackpoints,
} from '../server/privacyVault';
import { AppendOnlyAuditEvent } from '../types/platform';

const TEST_DB_DIR = fs.mkdtempSync(path.join(os.tmpdir(), '0to8848-test-db-'));
const TEST_DB_PATH = path.join(TEST_DB_DIR, 'platform-test.sqlite');

const app = express();
app.use('/api/v1', apiRouter);

let server: http.Server;
let baseUrl: string = '';

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
});

describe('Stage A: Catalog Honesty & 21-Phase Evidence-Based Status Verification', () => {
  it('ensures all 100 destinations in static source start at 1_PROPOSED and UNPUBLISHED_DRAFT before DB Dual-Control transitions', () => {
    expect(DESTINATIONS_100_CATALOG).toHaveLength(100);
    for (const dest of DESTINATIONS_100_CATALOG) {
      expect(dest.researchStage).toBe('1_PROPOSED');
      expect(dest.elevationCitationVerified).toBe(false);
      expect(dest.publicationStatus).toBe('UNPUBLISHED_DRAFT');
    }
  });

  it('ensures all 21 master phases use honest evidence-based status values', () => {
    expect(MASTER_21_PHASES).toHaveLength(21);
    const allowedStatuses = new Set([
      'NOT_STARTED',
      'DOCUMENTED',
      'DESIGNED',
      'PARTIALLY_IMPLEMENTED',
      'IMPLEMENTED',
      'TESTED',
      'ACCEPTED',
      'HARD_LOCKED_GATE',
    ]);
    for (const phase of MASTER_21_PHASES) {
      expect(allowedStatuses.has(phase.status)).toBe(true);
    }
  });
});

describe('SEC-CRYPTO-001: 128-bit CSPRNG Verification IDs & Collision Handling', () => {
  it('generates 128-bit CSPRNG Verification IDs matching 8848-V1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXXX', () => {
    const id = generateNonEnumerableVerificationId();
    expect(id).toMatch(
      /^8848-V1-[0-9A-TV-Z]{4}-[0-9A-TV-Z]{4}-[0-9A-TV-Z]{4}-[0-9A-TV-Z]{4}-[0-9A-TV-Z]{4}-[0-9A-TV-Z]{6}$/
    );
  });

  it('produces zero collisions across 2,000 generated IDs and retries deterministically on simulated database collision', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const id = generateNonEnumerableVerificationId((candidate) => seen.has(candidate));
      expect(seen.has(id)).toBe(false);
      seen.add(id);
    }
    expect(seen.size).toBe(2000);

    // Simulate a collision on the first 2 attempts
    let attempts = 0;
    const retriedId = generateNonEnumerableVerificationId(() => {
      attempts += 1;
      return attempts <= 2;
    });
    expect(attempts).toBe(3);
    expect(retriedId.startsWith('8848-V1-')).toBe(true);
  });
});

describe('SEC-CRYPTO-002: Genuine NIST SHA-256 & RFC 4231 HMAC-SHA256 Vector Suite', () => {
  it('passes official NIST FIPS 180-4 SHA-256 known test vectors', () => {
    // Vector 1: Empty string ""
    expect(computeSha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    // Vector 2: "abc"
    expect(computeSha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    // Vector 3: 448-bit multi-block message
    expect(
      computeSha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('passes official IETF RFC 4231 HMAC-SHA256 known test vectors (Cases 1, 2, and 3) and supports key rotation', () => {
    // RFC 4231 Test Case 1
    const key1 = Buffer.alloc(20, 0x0b);
    const data1 = Buffer.from('Hi There', 'utf8');
    expect(computeHmacSha256Hex(data1, key1)).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    );

    // RFC 4231 Test Case 2 ("Jefe")
    const key2 = Buffer.from('Jefe', 'utf8');
    const data2 = Buffer.from('what do ya want for nothing?', 'utf8');
    const expectedCase2 =
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843';
    expect(computeHmacSha256Hex(data2, key2)).toBe(expectedCase2);
    expect(verifyHmacTimingSafe(data2, expectedCase2, key2)).toBe(true);
    expect(
      verifyHmacTimingSafe(
        data2,
        '00dcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        key2
      )
    ).toBe(false);

    // RFC 4231 Test Case 3
    const key3 = Buffer.alloc(20, 0xaa);
    const data3 = Buffer.alloc(50, 0xdd);
    expect(computeHmacSha256Hex(data3, key3)).toBe(
      '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'
    );

    // Key Rotation verification (32+ byte key)
    configureKeyRing(
      'v2',
      Buffer.from('rotated-production-secret-key-2026-v2-32bytes!', 'utf8')
    );
    const sigV2 = computeAuditEventHmac(
      {
        sequenceNumber: 1,
        eventId: 'AUD-8848-0001',
        timestampUtc: '2026-11-11T00:00:00.000Z',
        actorInternalUuid: 'usr-test',
        actorRole: 'FOUNDER',
        actionType: 'KEY_ROTATION_TEST',
        targetEntityType: 'SYSTEM',
        targetEntityId: 'SYS-1',
        summary: 'Key rotation verification',
        previousEventHmac:
          '0000000000000000000000000000000000000000000000000000000000000000',
      },
      'v2'
    );
    expect(sigV2.keyVersion).toBe('v2');
    expect(sigV2.hmac).toHaveLength(64);
    configureKeyRing('v1', initializeProcessHmacKey());
  });
});

describe('SEC-DB-001 & SEC-CRYPTO-002: Audit-Chain Tamper Detection & SQLite Immutability Triggers', () => {
  it('verifies intact HMAC-SHA256 audit chain and detects payload or chain tampering', () => {
    const events = listAuditEvents();
    expect(events.length).toBeGreaterThanOrEqual(3);
    const integrity = verifyAuditChainIntegrity(events);
    expect(integrity.valid).toBe(true);

    // Honest WORM reporting check
    for (const evt of events) {
      expect(evt.wormReplicated).toBe(false);
      expect(evt.storageMode).toBe('LOCAL_SQLITE_TRIGGER_IMMUTABLE');
    }

    // Simulate tampered summary on event #2 in memory
    const chronological = [...events].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    const tamperedCopy: AppendOnlyAuditEvent[] = chronological.map((e, idx) =>
      idx === 1 ? { ...e, summary: 'FORGED_SUMMARY_ATTACK' } : { ...e }
    );
    const tamperResult = verifyAuditChainIntegrity(tamperedCopy);
    expect(tamperResult.valid).toBe(false);
    expect(tamperResult.brokenAtSequenceNumber).toBe(2);
    expect(tamperResult.failureReason).toContain('HMAC-SHA256 signature verification failed');
  });

  it('blocks SQL UPDATE and DELETE on audit_events via database triggers', () => {
    const db = getDb();
    expect(() => {
      db.prepare(`UPDATE audit_events SET summary = 'TAMPERED' WHERE sequence_number = 1`).run();
    }).toThrow(/WORM_AUDIT_LOG_IMMUTABLE/);

    expect(() => {
      db.prepare(`DELETE FROM audit_events WHERE sequence_number = 1`).run();
    }).toThrow(/WORM_AUDIT_LOG_IMMUTABLE/);
  });

  it('maintains sequential integrity across concurrent database writes', async () => {
    const beforeCount = listAuditEvents().length;
    await Promise.all(
      Array.from({ length: 10 }, (_, idx) =>
        Promise.resolve().then(() =>
          appendAuditEvent({
            actorInternalUuid: `usr-concurrent-${idx}`,
            actorRole: 'SECURITY_COMPLIANCE_OFFICER',
            actionType: 'CONCURRENT_WRITE_TEST',
            targetEntityType: 'AUDIT_TEST',
            targetEntityId: `TEST-${idx}`,
            summary: `Concurrent audit write #${idx}`,
          })
        )
      )
    );
    const afterEvents = listAuditEvents();
    expect(afterEvents.length).toBe(beforeCount + 10);
    expect(verifyAuditChainIntegrity(afterEvents).valid).toBe(true);
  });
});

describe('5-Signal COI Engine & Appeal Tribunal Independence Suite', () => {
  it('blocks self-review, guide COI, organization COI, and shared expedition roster COI', () => {
    const sub101 = getSubmissionById('sub-queue-101')!;
    const conflictedOfficer = DEMO_ACTOR_PROFILES['actor-reviewer-conflicted-guide'];
    const coiRes = runAutomatedFiveSignalCoiCheck(conflictedOfficer, sub101, false);
    expect(coiRes.overallPassed).toBe(false);
    expect(coiRes.blockingReason).toBeDefined();

    // Self-review test
    const selfActor = {
      ...DEMO_ACTOR_PROFILES['actor-reviewer-independent-219'],
      userId: sub101.applicantUserId,
    };
    const selfRes = runAutomatedFiveSignalCoiCheck(selfActor, sub101, false);
    expect(selfRes.overallPassed).toBe(false);
    expect(selfRes.blockingReason).toContain(
      'Reviewers can never verify or approve their own achievement submissions'
    );

    // Independent Officer 219 passes all 5 signals on sub-queue-101
    const cleanOfficer = DEMO_ACTOR_PROFILES['actor-reviewer-independent-219'];
    const cleanRes = runAutomatedFiveSignalCoiCheck(cleanOfficer, sub101, false);
    expect(cleanRes.overallPassed).toBe(true);
  });

  it('blocks original rejecting reviewer from adjudicating an appeal on the same submission', () => {
    const sub103 = getSubmissionById('sub-queue-103')!;
    expect(sub103.status).toBe('APPEALED');

    // Officer 104 was the original rejecting reviewer on sub-queue-103
    const originalReviewerAsAppeal = {
      ...DEMO_ACTOR_PROFILES['actor-reviewer-104'],
      role: 'APPEAL_OFFICER' as const,
    };
    const blockedAppealCheck = runAutomatedFiveSignalCoiCheck(
      originalReviewerAsAppeal,
      sub103,
      true
    );
    expect(blockedAppealCheck.overallPassed).toBe(false);
    expect(blockedAppealCheck.blockingReason).toContain(
      'Original decision-maker is strictly prohibited'
    );

    // Independent Appeal Officer 401 passes all 5 signals
    const appealOfficer401 = DEMO_ACTOR_PROFILES['actor-appeal-officer-401'];
    const validAppealCheck = runAutomatedFiveSignalCoiCheck(
      appealOfficer401,
      sub103,
      true
    );
    expect(validAppealCheck.overallPassed).toBe(true);
  });
});

describe('SEC-AUTH-001: Authentication, Scrypt Password Hashing, TOTP MFA, Sessions & Rate Limiting', () => {
  it('hashes and verifies passwords with scrypt and validates RFC 6238 TOTP MFA codes', () => {
    const hash = hashPasswordScrypt('MyStrongAlpineSecret!8848');
    expect(verifyPasswordScrypt('MyStrongAlpineSecret!8848', hash)).toBe(true);
    expect(verifyPasswordScrypt('WrongPassword', hash)).toBe(false);

    const secretHex = '4142434445464748495041424344454647484950';
    const nowMs = 1762840000000;
    const code = generateTotpCode(secretHex, nowMs);
    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotpCode(secretHex, code, nowMs)).toBe(true);
    expect(verifyTotpCode(secretHex, '000000', nowMs)).toBe(false);
  });

  it('requires TOTP MFA for privileged roles, issues CSPRNG sessions, and enforces brute-force rate limiting', async () => {
    const verifierAcct = getTestOnlyAccountCredentials('usr-reviewer-219');
    resetLoginAttempts(`login:${verifierAcct.username.toLowerCase()}`);

    // Privileged role login WITHOUT TOTP must fail with 401 MFA_VERIFICATION_FAILED
    const noMfaRes = await apiFetch('/api/v1/auth/login', {
      method: 'POST',
      body: {
        username: verifierAcct.username,
        password: verifierAcct.ephemeralPassword,
      },
    });
    expect(noMfaRes.status).toBe(401);
    expect(noMfaRes.body.error).toBe('MFA_VERIFICATION_FAILED');

    // Privileged role login WITH valid TOTP succeeds
    const validTotp = generateTotpCode(verifierAcct.mfaSecretHex);
    const loginRes = await apiFetch('/api/v1/auth/login', {
      method: 'POST',
      body: {
        username: verifierAcct.username,
        password: verifierAcct.ephemeralPassword,
        totpCode: validTotp,
      },
    });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body.sessionToken).toMatch(/^sess_8848_[0-9a-f]{64}$/);
    expect(loginRes.body.user.role).toBe('VERIFICATION_OFFICER');
    expect(loginRes.body.user.mfaVerified).toBe(true);

    // Brute-force rate limiting check after 5 failed attempts
    const advAcct = getTestOnlyAccountCredentials('usr-lukas-at');
    resetLoginAttempts(`login:${advAcct.username.toLowerCase()}`);
    for (let i = 0; i < 5; i++) {
      await apiFetch('/api/v1/auth/login', {
        method: 'POST',
        body: {
          username: advAcct.username,
          password: 'WrongPassword123',
        },
      });
    }
    const rateLimitedRes = await apiFetch('/api/v1/auth/login', {
      method: 'POST',
      body: {
        username: advAcct.username,
        password: advAcct.ephemeralPassword,
      },
    });
    expect(rateLimitedRes.status).toBe(429);
    expect(rateLimitedRes.body.error).toBe('AUTH_RATE_LIMITED');
    resetLoginAttempts(`login:${advAcct.username.toLowerCase()}`);
  });
});

describe('SEC-GOV-001 & SEC-GOV-003: Backend Destination Governance & Two-Person (2P) Dual-Control', () => {
  it('allows Researcher to advance Stages 1 -> 2 -> 3, blocks Researcher from Stage 4, and enforces Two-Person (2P) distinct principals for Stages 4 and 5', () => {
    const resAcct = getTestOnlyAccountCredentials('usr-researcher-501');
    const founderAcct = getTestOnlyAccountCredentials('usr-gov-founder-001');
    const committeeAcct = getTestOnlyAccountCredentials('usr-gov-committee-002');

    const researcherSession = authenticateUserSession({
      usernameOrUserId: resAcct.username,
      password: resAcct.ephemeralPassword,
      totpCode: generateTotpCode(resAcct.mfaSecretHex),
    });
    const founderSession = authenticateUserSession({
      usernameOrUserId: founderAcct.username,
      password: founderAcct.ephemeralPassword,
      totpCode: generateTotpCode(founderAcct.mfaSecretHex),
    });
    const committeeSession = authenticateUserSession({
      usernameOrUserId: committeeAcct.username,
      password: committeeAcct.ephemeralPassword,
      totpCode: generateTotpCode(committeeAcct.mfaSecretHex),
    });

    // Advance dest-002 (K2) from 1_PROPOSED -> 2_UNDER_RESEARCH -> 3_RESEARCH_COMPLETED
    const s2 = advanceDestinationStageServer({
      actor: researcherSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(s2.destination.researchStage).toBe('2_UNDER_RESEARCH');
    const s3 = advanceDestinationStageServer({
      actor: researcherSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(s3.destination.researchStage).toBe('3_RESEARCH_COMPLETED');

    // Researcher blocked from Stage 4
    expect(() =>
      advanceDestinationStageServer({
        actor: researcherSession.user,
        destinationIdOrCode: 'dest-002',
      })
    ).toThrow(/RBAC_STAGE_GOVERNANCE_DENIED/);

    // Principal 1 (Founder) initiates Stage 4 approval -> DUAL_CONTROL_PENDING_SECOND_SIGNATURE
    const p1Stage4 = advanceDestinationStageServer({
      actor: founderSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(p1Stage4.status).toBe('DUAL_CONTROL_PENDING_SECOND_SIGNATURE');
    expect(p1Stage4.destination.researchStage).toBe('3_RESEARCH_COMPLETED');

    // Principal 1 (Founder) attempting to co-sign their own request MUST be rejected
    expect(() =>
      advanceDestinationStageServer({
        actor: founderSession.user,
        destinationIdOrCode: 'dest-002',
      })
    ).toThrow(/DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN/);

    // Principal 2 (Governance Committee) co-signs -> transitions to 4_REVIEWED_AND_APPROVED
    const p2Stage4 = advanceDestinationStageServer({
      actor: committeeSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(p2Stage4.status).toBe('STAGE_ADVANCED');
    expect(p2Stage4.destination.researchStage).toBe('4_REVIEWED_AND_APPROVED');

    // Stage 5 publication also requires 2 distinct principals
    const p1Stage5 = advanceDestinationStageServer({
      actor: committeeSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(p1Stage5.status).toBe('DUAL_CONTROL_PENDING_SECOND_SIGNATURE');
    const p2Stage5 = advanceDestinationStageServer({
      actor: founderSession.user,
      destinationIdOrCode: 'dest-002',
    });
    expect(p2Stage5.status).toBe('STAGE_ADVANCED');
    expect(p2Stage5.destination.researchStage).toBe('5_PUBLISHED');
    expect(p2Stage5.destination.publicationStatus).toBe('PUBLISHED');
  });

  it('enforces Two-Person (2P) Dual-Control on Certificate Revocation', () => {
    const founderAcct = getTestOnlyAccountCredentials('usr-gov-founder-001');
    const leadAcct = getTestOnlyAccountCredentials('usr-senior-lead-301');

    const founderSession = authenticateUserSession({
      usernameOrUserId: founderAcct.username,
      password: founderAcct.ephemeralPassword,
      totpCode: generateTotpCode(founderAcct.mfaSecretHex),
    });
    const seniorLeadSession = authenticateUserSession({
      usernameOrUserId: leadAcct.username,
      password: leadAcct.ephemeralPassword,
      totpCode: generateTotpCode(leadAcct.mfaSecretHex),
    });

    const certId = '8848-V1-4T8H-2W9C-L5V1-8M3J-7R4K-9P';
    const step1 = executeDualControlCertificateRevocationServer({
      actor: founderSession.user,
      verificationId: certId,
      reason: 'Audit test revocation',
    });
    expect(step1.status).toBe('DUAL_CONTROL_PENDING_SECOND_SIGNATURE');
    expect(step1.certificate.status).toBe('VALID');

    // Same principal cannot self-cosign revocation
    expect(() =>
      executeDualControlCertificateRevocationServer({
        actor: founderSession.user,
        verificationId: certId,
        reason: 'Audit test revocation',
      })
    ).toThrow(/DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN/);

    // Second distinct principal co-signs -> REVOKED
    const step2 = executeDualControlCertificateRevocationServer({
      actor: seniorLeadSession.user,
      verificationId: certId,
      reason: 'Audit test revocation',
    });
    expect(step2.status).toBe('REVOCATION_EXECUTED');
    expect(step2.certificate.status).toBe('REVOKED');
    expect(step2.certificate.optInPublicLeaderboards).toBe(false);
  });
});

describe('SEC-GOV-002: Server-Side Human Verification, Tier-A Dual Review, Split-Decision Escalation & Appeals', () => {
  it('completes Tier-A Dual-Review on sub-queue-101 with 2nd independent officer and issues free 128-bit CSPRNG certificate', () => {
    const officer219Acct = getTestOnlyAccountCredentials('usr-reviewer-219');
    const officer219Session = authenticateUserSession({
      usernameOrUserId: officer219Acct.username,
      password: officer219Acct.ephemeralPassword,
      totpCode: generateTotpCode(officer219Acct.mfaSecretHex),
    });

    const result = executeHumanReviewDecisionServer({
      actor: officer219Session.user,
      submissionId: 'sub-queue-101',
      decision: 'APPROVE',
      humanRationale:
        'Second independent Tier-A review complete: Barometric channel and summit EXIF solar azimuth corroborated.',
      coiHumanAttestationSigned: true,
    });

    expect(result.submission.status).toBe('APPROVED');
    expect(result.issuedCertificate).toBeDefined();
    expect(result.issuedCertificate!.verificationId).toMatch(/^8848-V1-/);
  });

  it('escalates split decisions (1 APPROVE + 1 REJECT) on Tier-A submissions to ESCALATED_SPLIT_DECISION', () => {
    const advAcct = getTestOnlyAccountCredentials('usr-tenzing-nepal');
    const officer219Acct = getTestOnlyAccountCredentials('usr-reviewer-219');
    const officer104Acct = getTestOnlyAccountCredentials('usr-reviewer-104');

    const adventurerSession = authenticateUserSession({
      usernameOrUserId: advAcct.username,
      password: advAcct.ephemeralPassword,
    });
    const officer219Session = authenticateUserSession({
      usernameOrUserId: officer219Acct.username,
      password: officer219Acct.ephemeralPassword,
      totpCode: generateTotpCode(officer219Acct.mfaSecretHex),
    });
    const officer104Session = authenticateUserSession({
      usernameOrUserId: officer104Acct.username,
      password: officer104Acct.ephemeralPassword,
      totpCode: generateTotpCode(officer104Acct.mfaSecretHex),
    });

    const newSub = createSubmissionServer({
      applicant: adventurerSession.user,
      destinationId: 'dest-001', // Everest (Tier-A Dual Review required)
      verificationTrack: 'STANDARD_DIGITAL',
      applicantDisplayName: 'Split Vote Test Climber',
      applicantNationality: 'Nepal (NP)',
      completionDateUtc: '2026-10-20T06:00:00Z',
      applicantStory: 'South Col ascent.',
      truthfulnessDeclarationSigned: true,
      privacyConsent: {
        publicIdentityMode: 'FULL_VERIFIED_NAME',
        publicDatePrecision: 'EXACT_DATE',
        optInPublicLeaderboards: true,
      },
      inlineArtifacts: [
        {
          id: `art-split-${Date.now()}`,
          type: 'GPX_TELEMETRY',
          fileName: 'everest_split_test.gpx',
          sha256PostUploadDigest: computeSha256Hex(`everest-split-${Date.now()}`),
          uploadedAtUtc: new Date().toISOString(),
          extractedMetadata: {
            recordedMaxElevationM: 8848.5,
            distanceSummitedFromApexM: 6,
            rolling15mMaxAscentMPerHr: 210,
            residentialStartEndMasked: true,
          },
        },
      ],
    });

    const rev1 = executeHumanReviewDecisionServer({
      actor: officer219Session.user,
      submissionId: newSub.id,
      decision: 'APPROVE',
      humanRationale: 'First reviewer approves telemetry.',
      coiHumanAttestationSigned: true,
    });
    expect(rev1.submission.status).toBe('AWAITING_SECOND_REVIEW');

    const rev2 = executeHumanReviewDecisionServer({
      actor: officer104Session.user,
      submissionId: newSub.id,
      decision: 'REJECT',
      humanRationale: 'Second reviewer notes barometric calibration gap.',
      coiHumanAttestationSigned: true,
    });
    expect(rev2.submission.status).toBe('ESCALATED_SPLIT_DECISION');
    expect(rev2.issuedCertificate).toBeUndefined();
  });
});

describe('SEC-EVID-001: GPX/EXIF/PDF Parser Security, XXE Rejection, Duplicate SHA-256 & Signed Vault URLs', () => {
  it('parses valid GPX telemetry, computes real SHA-256, and masks residential start/end trackpoints within 2km', () => {
    const dest009 = getDestinationByIdOrCode('dest-009')!;
    const sampleGpx = `<?xml version="1.0" encoding="UTF-8"?>
      <gpx version="1.1" creator="Garmin Fenix 7X Pro">
        <trk><name>Ama Dablam Ascent</name><trkseg>
          <trkpt lat="27.8000" lon="86.8000"><ele>4600</ele><time>2026-11-04T01:00:00Z</time></trkpt>
          <trkpt lat="27.8010" lon="86.8010"><ele>4650</ele><time>2026-11-04T01:20:00Z</time></trkpt>
          <trkpt lat="27.8500" lon="86.8500"><ele>6100</ele><time>2026-11-04T04:00:00Z</time></trkpt>
          <trkpt lat="${dest009.coordinates.lat}" lon="${dest009.coordinates.lng}"><ele>6811.8</ele><time>2026-11-04T06:30:00Z</time><extensions><power>baro_hpa_420</power></extensions></trkpt>
          <trkpt lat="27.8002" lon="86.8001"><ele>4605</ele><time>2026-11-04T11:00:00Z</time></trkpt>
        </trkseg></trk>
      </gpx>`;
    const buf = Buffer.from(sampleGpx, 'utf8');
    validateEvidenceFileMagicBytes(buf, 'GPX_TELEMETRY', 'ascent.gpx');
    const parsed = parseGpxTelemetryBuffer(buf, dest009);
    expect(parsed.trackpointCount).toBe(5);
    expect(parsed.recordedMaxElevationM).toBeCloseTo(6811.8, 1);
    expect(parsed.distanceSummitedFromApexM).toBeLessThan(15);
    expect(parsed.barometricChannelDetected).toBe(true);
    expect(parsed.residentialStartEndMasked).toBe(true);
    expect(parsed.maskedResidentialTrackpointsCount).toBeGreaterThanOrEqual(2);
  });

  it('rejects XML External Entity (XXE) payloads and malicious PDF /JavaScript directives', () => {
    const xxePayload = Buffer.from(
      `<?xml version="1.0"?>
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <gpx><trk><name>&xxe;</name></trk></gpx>`,
      'utf8'
    );
    expect(() => assertNoXxeOrMaliciousDirectives(xxePayload, 'evil.gpx')).toThrow(
      /XXE_PAYLOAD_DETECTED_AND_BLOCKED/
    );

    const maliciousPdf = Buffer.from(
      '%PDF-1.7\n1 0 obj\n<< /JavaScript (app.alert(1)) >>\nendobj',
      'utf8'
    );
    expect(() =>
      validateEvidenceFileMagicBytes(maliciousPdf, 'OFFICIAL_PERMIT_DOC', 'permit.pdf')
    ).toThrow(/MALICIOUS_PDF_DIRECTIVE_BLOCKED/);
  });

  it('validates JPEG/PNG magic bytes and rejects duplicate SHA-256 evidence uploads via /api/v1/evidence/upload', async () => {
    const dest009 = getDestinationByIdOrCode('dest-009')!;
    const jpegBuf = Buffer.from([
      0xff,
      0xd8,
      0xff,
      0xe1,
      0x00,
      0x10,
      0x45,
      0x78,
      0x69,
      0x66,
      0x00,
      0x00,
      ...Buffer.from('Sony ILCE-7RM5 2026:11:04 06:32:10', 'utf8'),
      0xff,
      0xd9,
    ]);
    const exif = parsePhotoExifBuffer(jpegBuf, dest009);
    expect(exif.deviceModel).toContain('Sony ILCE-7RM5');
    expect(exif.captureTimestampUtc).toBe('2026-11-04T06:32:10Z');

    // Login as Registered Adventurer
    const advAcct = getTestOnlyAccountCredentials('usr-tenzing-nepal');
    const loginRes = await apiFetch('/api/v1/auth/login', {
      method: 'POST',
      body: {
        username: advAcct.username,
        password: advAcct.ephemeralPassword,
      },
    });
    const token = loginRes.body.sessionToken;

    const upload1 = await apiFetch('/api/v1/evidence/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: {
        fileName: 'summit_photo.jpg',
        artifactType: 'RAW_EXIF_PHOTO',
        destinationId: 'dest-009',
        contentBase64: jpegBuf.toString('base64'),
      },
    });
    expect(upload1.status).toBe(201);
    expect(upload1.body.artifact.sha256PostUploadDigest).toBe(computeSha256Hex(jpegBuf));

    // Uploading identical bytes again must be rejected with 409 DUPLICATE_EVIDENCE
    const upload2 = await apiFetch('/api/v1/evidence/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: {
        fileName: 'summit_photo_copy.jpg',
        artifactType: 'RAW_EXIF_PHOTO',
        destinationId: 'dest-009',
        contentBase64: jpegBuf.toString('base64'),
      },
    });
    expect(upload2.status).toBe(409);
    expect(upload2.body.error).toBe('DUPLICATE_EVIDENCE');
  });

  it('enforces short-TTL HMAC-signed Private Vault tokens and blocks unauthorized or wrong-viewer access', () => {
    const signed = createSignedEvidenceAccessToken({
      artifactId: 'art-101-gpx',
      submissionId: 'sub-queue-101',
      viewerUserId: 'usr-reviewer-219',
      ttlSeconds: 60,
    });
    const verified = verifySignedEvidenceAccessToken(
      signed.token,
      'art-101-gpx',
      'usr-reviewer-219'
    );
    expect(verified.valid).toBe(true);

    // Wrong artifact ID rejected
    const wrongArtifact = verifySignedEvidenceAccessToken(
      signed.token,
      'art-101-photo',
      'usr-reviewer-219'
    );
    expect(wrongArtifact.valid).toBe(false);

    // Wrong viewerUserId rejected
    const wrongViewer = verifySignedEvidenceAccessToken(
      signed.token,
      'art-101-gpx',
      'usr-sponsor-701'
    );
    expect(wrongViewer.valid).toBe(false);
  });
});

describe('SEC-PRIV-001: AES-256-GCM PII Vault, Key-Shredding Erasure & Coordinate Masking', () => {
  it('encrypts PII with per-user AES-256-GCM DEK and renders ciphertext permanently undecryptable after key-shredding erasure', () => {
    const dek = generateUserDekHex();
    const encrypted = encryptPiiWithUserDek(
      JSON.stringify({ fullName: 'Pasang Dawa Sherpa', passport: 'NP-998877' }),
      dek
    );
    const decryptedBefore = decryptPiiWithUserDek(encrypted, dek);
    expect(decryptedBefore).toContain('Pasang Dawa Sherpa');

    // Shred key (NULL)
    const decryptedAfter = decryptPiiWithUserDek(encrypted, null);
    expect(decryptedAfter).toBeNull();

    // Execute full database key-shredding erasure for usr-pasangnya-01 via Founder/Compliance
    const founderAcct = getTestOnlyAccountCredentials('usr-gov-founder-001');
    const founderSession = authenticateUserSession({
      usernameOrUserId: founderAcct.username,
      password: founderAcct.ephemeralPassword,
      totpCode: generateTotpCode(founderAcct.mfaSecretHex),
    });

    const erasureResult = executeCryptographicErasureServer({
      actor: founderSession.user,
      targetUserId: 'usr-pasangnya-01',
    });
    expect(erasureResult.shreddedUserId).toBe('usr-pasangnya-01');
    expect(erasureResult.decryptedPiiAfterShred).toBeNull();
    expect(erasureResult.deactivatedCertificatesCount).toBeGreaterThanOrEqual(1);

    const certAfter = getCertificateByVerificationId(
      '8848-V1-9K4M-7P2X-Q8R5-3N6W-5T8B-2M'
    );
    expect(certAfter?.status).toBe('DEACTIVATED_BY_USER_ERASURE');
    expect(certAfter?.optInPublicLeaderboards).toBe(false);

    // Audit chain remains 100% valid after GDPR key-shredding erasure
    expect(verifyAuditChainIntegrity(listAuditEvents()).valid).toBe(true);
  });

  it('masks GPX points within 2.0 km of start and end coordinates while preserving summit trackpoints', () => {
    const pts = [
      { lat: 27.7000, lon: 85.3000, ele: 1400 },
      { lat: 27.7050, lon: 85.3050, ele: 1450 },
      { lat: 27.8000, lon: 86.1000, ele: 4200 },
      { lat: 27.9881, lon: 86.9250, ele: 8848.86 }, // summit (>150km away)
      { lat: 27.7002, lon: 85.3001, ele: 1405 }, // end
    ];
    const masked = maskResidentialTrackpoints(pts, 2000);
    expect(masked.removedCount).toBe(3);
    expect(masked.residentialStartEndMasked).toBe(true);
    expect(masked.maskedPoints.some((p) => p.ele === 8848.86)).toBe(true);
  });
});

describe('Stage D: Phase 17 Payment & Phase 18 Blockchain Hard-Lock Regression Suite', () => {
  it('returns HTTP 503 for POST /api/v1/payments/checkout and POST /api/v1/blockchain/mint', async () => {
    const payRes = await apiFetch('/api/v1/payments/checkout', {
      method: 'POST',
      body: {},
    });
    expect(payRes.status).toBe(503);
    expect(payRes.body.code).toBe('PHASE_17_HARD_LOCK');

    const mintRes = await apiFetch('/api/v1/blockchain/mint', {
      method: 'POST',
      body: {},
    });
    expect(mintRes.status).toBe(503);
    expect(mintRes.body.code).toBe('PHASE_18_HARD_LOCK');
  });
});
