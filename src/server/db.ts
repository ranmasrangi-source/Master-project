import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DESTINATIONS_100_CATALOG } from '../data/destinations100';
import {
  evaluateRbacPermission,
  INITIAL_SUBMISSIONS_QUEUE,
  INITIAL_VERIFIED_CERTIFICATES,
} from '../data/governanceAndPhases';
import {
  DEMO_ACTOR_PROFILES,
  runAutomatedFiveSignalCoiCheck,
} from '../domain/verificationEngine';
import {
  AchievementSubmission,
  AppendOnlyAuditEvent,
  AuthenticatedSessionUser,
  DestinationRecord,
  DualControlApprovalRecord,
  EvidenceArtifact,
  HumanReviewDecisionRecord,
  PublicCertificateRecord,
  ResearchStage,
  SubmissionStatus,
  UserRole,
} from '../types/platform';
import {
  extractSaltHexFromStoredHash,
  generateRandomMfaSecretHex,
  generateSessionTokenPair,
  hashPasswordScrypt,
  hashSessionToken,
  roleRequiresMfa,
  verifyPasswordScrypt,
  verifyTotpCode,
} from './auth';
import {
  computeAuditEventHmac,
  computeHmacSha256Hex,
  computeSha256Hex,
  generateNonEnumerableVerificationId,
  verifyAuditChainIntegrity,
} from './cryptoEngine';
import {
  decryptPiiWithUserDek,
  encryptPiiWithUserDek,
  formatConsentedPublicDate,
  formatConsentedPublicIdentity,
  generateUserDekHex,
} from './privacyVault';

let dbInstance: DatabaseSync | null = null;
let currentDbPath: string = '';

/**
 * BUG-P0-001 Remediation:
 * Demo/test account provisioning is strictly prohibited in production (NODE_ENV === 'production').
 * Even if an environment flag is set accidentally, production unconditionally disables demo provisioning.
 */
export function isDemoProvisioningAllowed(): boolean {
  if (process.env.NODE_ENV === 'production') {
    return false;
  }
  return (
    process.env.NODE_ENV === 'test' ||
    Boolean(process.env.VITEST) ||
    process.env.ENABLE_DEV_DEMO_PROVISIONING !== 'false'
  );
}

export interface NonSensitiveAccountDirectoryProfile {
  userId: string;
  username: string;
  role: UserRole;
  officerCode: string;
  displayName: string;
}

/**
 * Non-sensitive identity templates for non-production test/dev seeding.
 * Contains ZERO hardcoded passwords, password hints, or MFA secrets.
 */
export const NON_SENSITIVE_ACCOUNT_PROFILES: Record<
  string,
  NonSensitiveAccountDirectoryProfile
> = {
  'usr-tenzing-nepal': {
    userId: 'usr-tenzing-nepal',
    username: 'tenzing.adventurer',
    role: 'REGISTERED_ADVENTURER',
    officerCode: 'ADV-NP-001',
    displayName: 'Mingma Dorjee Sherpa (Adventurer)',
  },
  'usr-lukas-at': {
    userId: 'usr-lukas-at',
    username: 'lukas.adventurer',
    role: 'REGISTERED_ADVENTURER',
    officerCode: 'ADV-AT-003',
    displayName: 'Lukas Hofer (Adventurer)',
  },
  'usr-reviewer-219': {
    userId: 'usr-reviewer-219',
    username: 'pemba.verifier',
    role: 'VERIFICATION_OFFICER',
    officerCode: 'REV-OFFICER-219',
    displayName: 'Dr. Pemba Sherpa (Independent Verification Officer)',
  },
  'usr-reviewer-104': {
    userId: 'usr-reviewer-104',
    username: 'kilian.verifier',
    role: 'VERIFICATION_OFFICER',
    officerCode: 'REV-OFFICER-104',
    displayName: 'Kilian Vance (Verification Officer — Reviewed Sub 101 & 103)',
  },
  'usr-senior-lead-301': {
    userId: 'usr-senior-lead-301',
    username: 'ang.seniorlead',
    role: 'SENIOR_VERIFICATION_LEAD',
    officerCode: 'REV-LEAD-301',
    displayName: 'Ang Phurba Sherpa (Senior Verification Lead)',
  },
  'usr-guide-conflict-demo': {
    userId: 'usr-guide-conflict-demo',
    username: 'dawa.conflicted',
    role: 'VERIFICATION_OFFICER',
    officerCode: 'REV-OFFICER-399',
    displayName: 'Dawa Geljen (Reviewer with Guide/Roster COI on Sub 101)',
  },
  'usr-appeal-401': {
    userId: 'usr-appeal-401',
    username: 'ananya.appeal',
    role: 'APPEAL_OFFICER',
    officerCode: 'APL-TRIBUNAL-401',
    displayName: 'Justice Ananya Adhikari (Independent Appeal Officer)',
  },
  'usr-gov-founder-001': {
    userId: 'usr-gov-founder-001',
    username: 'founder.governance',
    role: 'FOUNDER',
    officerCode: 'GOV-FOUNDER-001',
    displayName: 'Platform Founder (Dual-Control Principal 1)',
  },
  'usr-gov-committee-002': {
    userId: 'usr-gov-committee-002',
    username: 'chair.governance',
    role: 'GOVERNANCE_COMMITTEE',
    officerCode: 'GOV-COMMITTEE-002',
    displayName: 'Governance Committee Chair (Dual-Control Principal 2)',
  },
  'usr-researcher-501': {
    userId: 'usr-researcher-501',
    username: 'suman.researcher',
    role: 'DESTINATION_RESEARCHER',
    officerCode: 'RES-CARTO-501',
    displayName: 'Suman Thapa (Destination Geodetic Researcher)',
  },
  'usr-sponsor-701': {
    userId: 'usr-sponsor-701',
    username: 'brand.sponsor',
    role: 'SPONSOR_ACCOUNT',
    officerCode: 'SPN-BRAND-701',
    displayName: 'Alpine Gear Sponsor Account (Commercial Firewall Restricted)',
  },
  'usr-security-601': {
    userId: 'usr-security-601',
    username: 'compliance.officer',
    role: 'SECURITY_COMPLIANCE_OFFICER',
    officerCode: 'SEC-COMP-601',
    displayName: 'Nima Tamang (Security & Compliance Officer)',
  },
};

interface EphemeralTestCredentialEntry extends NonSensitiveAccountDirectoryProfile {
  ephemeralPassword: string;
  mfaSecretHex: string;
}

const ephemeralTestCredentialsMap = new Map<string, EphemeralTestCredentialEntry>();

/**
 * Strictly non-production helper for automated Vitest suites to retrieve
 * CSPRNG-generated ephemeral credentials for seeded test accounts.
 * Throws immediately if called in production. Never exposed via any HTTP API.
 */
export function getTestOnlyAccountCredentials(
  userId: string
): EphemeralTestCredentialEntry {
  if (!isDemoProvisioningAllowed()) {
    throw new Error(
      'PRODUCTION_CREDENTIAL_ACCESS_FORBIDDEN: Demo/test credential provisioning is disabled in production.'
    );
  }
  getDb(); // Ensure DB and ephemeral credentials are initialized
  const entry = ephemeralTestCredentialsMap.get(userId);
  if (!entry) {
    throw new Error(`TEST_ACCOUNT_NOT_FOUND: ${userId}`);
  }
  return entry;
}

export function getDb(customPath?: string): DatabaseSync {
  const targetPath =
    customPath ||
    process.env.DB_FILE_PATH ||
    path.resolve(process.cwd(), '.data', '0to8848.sqlite');

  if (dbInstance && currentDbPath === targetPath) {
    return dbInstance;
  }

  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // ignore close error
    }
  }

  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const db = new DatabaseSync(targetPath);
  dbInstance = db;
  currentDbPath = targetPath;

  initializeSchemaAndSeed(db);
  return db;
}

export function resetDatabase(customPath?: string): DatabaseSync {
  const targetPath =
    customPath ||
    process.env.DB_FILE_PATH ||
    path.resolve(process.cwd(), '.data', '0to8848.sqlite');

  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // ignore
    }
    dbInstance = null;
  }

  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
  const walPath = `${targetPath}-wal`;
  const shmPath = `${targetPath}-shm`;
  if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);

  return getDb(targetPath);
}

/**
 * Helper to execute an atomic SQLite transaction (`BEGIN IMMEDIATE` ... `COMMIT` / `ROLLBACK`).
 */
export function runInTransaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE TRANSACTION;');
  try {
    const result = fn();
    db.exec('COMMIT;');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK;');
    } catch {
      // ignore rollback error
    }
    throw err;
  }
}

function initializeSchemaAndSeed(db: DatabaseSync): void {
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA synchronous = NORMAL;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at_utc TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      internal_actor_uuid TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      officer_code TEXT NOT NULL,
      display_label TEXT NOT NULL,
      organization_id TEXT,
      expedition_roster_group_code TEXT,
      guide_for_user_ids_json TEXT NOT NULL DEFAULT '[]',
      mfa_secret_hex TEXT NOT NULL,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      is_erased INTEGER NOT NULL DEFAULT 0,
      created_at_utc TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_encryption_keys (
      user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
      user_dek_hex TEXT,
      created_at_utc TEXT NOT NULL,
      shredded_at_utc TEXT
    );

    CREATE TABLE IF NOT EXISTS user_pii_vault (
      user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
      encrypted_full_name_json TEXT,
      encrypted_email_json TEXT,
      encrypted_nationality_json TEXT,
      updated_at_utc TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id TEXT PRIMARY KEY,
      token_sha256_hash TEXT NOT NULL UNIQUE,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      mfa_verified INTEGER NOT NULL DEFAULT 0,
      created_at_utc TEXT NOT NULL,
      expires_at_utc TEXT NOT NULL,
      revoked_at_utc TEXT
    );

    CREATE TABLE IF NOT EXISTS destinations (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      research_stage TEXT NOT NULL,
      publication_status TEXT NOT NULL,
      elevation_citation_verified INTEGER NOT NULL DEFAULT 0,
      record_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS dual_control_approvals (
      approval_id TEXT PRIMARY KEY,
      operation_type TEXT NOT NULL,
      target_entity_id TEXT NOT NULL,
      initiator_user_id TEXT NOT NULL REFERENCES users(user_id),
      initiator_officer_code TEXT NOT NULL,
      initiator_role TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL,
      cosigner_user_id TEXT REFERENCES users(user_id),
      cosigner_officer_code TEXT,
      cosigner_role TEXT,
      created_at_utc TEXT NOT NULL,
      expires_at_utc TEXT NOT NULL,
      resolved_at_utc TEXT
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      submission_code TEXT NOT NULL UNIQUE,
      applicant_user_id TEXT NOT NULL REFERENCES users(user_id),
      destination_id TEXT NOT NULL REFERENCES destinations(id),
      status TEXT NOT NULL,
      requires_dual_human_review INTEGER NOT NULL DEFAULT 0,
      issued_certificate_id TEXT,
      submitted_at_utc TEXT NOT NULL,
      record_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence_artifacts (
      id TEXT PRIMARY KEY,
      submission_id TEXT REFERENCES submissions(id) ON DELETE CASCADE,
      uploader_user_id TEXT NOT NULL REFERENCES users(user_id),
      artifact_type TEXT NOT NULL,
      file_name TEXT NOT NULL,
      sha256_digest TEXT NOT NULL UNIQUE,
      perceptual_hash TEXT,
      vault_storage_key TEXT,
      uploaded_at_utc TEXT NOT NULL,
      artifact_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS human_reviews (
      review_id TEXT PRIMARY KEY,
      submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
      reviewer_user_id TEXT NOT NULL REFERENCES users(user_id),
      reviewer_officer_code TEXT NOT NULL,
      reviewer_role TEXT NOT NULL,
      decision TEXT NOT NULL,
      human_rationale TEXT NOT NULL,
      decided_at_utc TEXT NOT NULL,
      decision_hmac_signature TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS certificates (
      verification_id TEXT PRIMARY KEY,
      submission_id TEXT NOT NULL UNIQUE REFERENCES submissions(id),
      holder_user_id TEXT NOT NULL REFERENCES users(user_id),
      destination_id TEXT NOT NULL REFERENCES destinations(id),
      status TEXT NOT NULL,
      opt_in_public_leaderboards INTEGER NOT NULL DEFAULT 1,
      issued_at_utc TEXT NOT NULL,
      record_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      sequence_number INTEGER PRIMARY KEY,
      event_id TEXT NOT NULL UNIQUE,
      timestamp_utc TEXT NOT NULL,
      actor_internal_uuid TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action_type TEXT NOT NULL,
      target_entity_type TEXT NOT NULL,
      target_entity_id TEXT NOT NULL,
      summary TEXT NOT NULL,
      previous_event_hmac TEXT NOT NULL,
      current_event_hmac TEXT NOT NULL,
      key_version TEXT NOT NULL DEFAULT 'v1',
      worm_replicated INTEGER NOT NULL DEFAULT 0,
      storage_mode TEXT NOT NULL DEFAULT 'LOCAL_SQLITE_TRIGGER_IMMUTABLE'
    );

    CREATE TRIGGER IF NOT EXISTS trg_audit_events_immutable_update
    BEFORE UPDATE ON audit_events
    BEGIN
      SELECT RAISE(ABORT, 'WORM_AUDIT_LOG_IMMUTABLE: UPDATE prohibited on audit_events');
    END;

    CREATE TRIGGER IF NOT EXISTS trg_audit_events_immutable_delete
    BEFORE DELETE ON audit_events
    BEGIN
      SELECT RAISE(ABORT, 'WORM_AUDIT_LOG_IMMUTABLE: DELETE prohibited on audit_events');
    END;
  `);

  const checkMigration001 = db
    .prepare('SELECT version FROM schema_migrations WHERE version = ?')
    .get('001_FOUNDATION_RECOVERY');

  const checkMigration002 = db
    .prepare('SELECT version FROM schema_migrations WHERE version = ?')
    .get('002_P0_P1_SECURITY_ROTATION');

  if (checkMigration001 && checkMigration002) {
    return;
  }

  // If 001 was already applied on an existing SQLite file, execute 002 security rotation
  if (checkMigration001 && !checkMigration002) {
    runInTransaction(db, () => {
      const nowUtc = new Date().toISOString();
      const existingUsers = db
        .prepare('SELECT user_id, username, role, officer_code, display_label FROM users')
        .all() as Record<string, unknown>[];

      const updateCredsStmt = db.prepare(`
        UPDATE users
        SET password_hash = ?, mfa_secret_hex = ?, mfa_enabled = ?
        WHERE user_id = ?
      `);

      for (const u of existingUsers) {
        const uid = String(u.user_id);
        const role = String(u.role) as UserRole;
        const rotatedPassword = `Rot#${crypto.randomBytes(16).toString('base64url')}!8848`;
        const rotatedHash = hashPasswordScrypt(rotatedPassword);
        const rotatedMfaHex = generateRandomMfaSecretHex();
        const mfaEnabled = roleRequiresMfa(role) ? 1 : 0;

        updateCredsStmt.run(rotatedHash, rotatedMfaHex, mfaEnabled, uid);

        if (isDemoProvisioningAllowed()) {
          ephemeralTestCredentialsMap.set(uid, {
            userId: uid,
            username: String(u.username),
            role,
            officerCode: String(u.officer_code),
            displayName: String(u.display_label),
            ephemeralPassword: rotatedPassword,
            mfaSecretHex: rotatedMfaHex,
          });
        }
      }

      // Ensure usr-security-601 exists if migrating from 001
      const hasSecOfficer = db
        .prepare('SELECT 1 FROM users WHERE user_id = ?')
        .get('usr-security-601');
      if (!hasSecOfficer && isDemoProvisioningAllowed()) {
        const secProfile = NON_SENSITIVE_ACCOUNT_PROFILES['usr-security-601'];
        const secPassword = `Rot#${crypto.randomBytes(16).toString('base64url')}!8848`;
        const secHash = hashPasswordScrypt(secPassword);
        const secMfa = generateRandomMfaSecretHex();
        db.prepare(`
          INSERT INTO users (
            user_id, internal_actor_uuid, username, password_hash, role, officer_code,
            display_label, organization_id, expedition_roster_group_code,
            guide_for_user_ids_json, mfa_secret_hex, mfa_enabled, is_erased, created_at_utc
          ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, '[]', ?, 1, 0, ?)
        `).run(
          secProfile.userId,
          'act-uuid-sec-601',
          secProfile.username,
          secHash,
          secProfile.role,
          secProfile.officerCode,
          secProfile.displayName,
          secMfa,
          nowUtc
        );
        ephemeralTestCredentialsMap.set(secProfile.userId, {
          ...secProfile,
          ephemeralPassword: secPassword,
          mfaSecretHex: secMfa,
        });
      }

      // Revoke all pre-rotation sessions
      db.prepare(
        'UPDATE user_sessions SET revoked_at_utc = ? WHERE revoked_at_utc IS NULL'
      ).run(nowUtc);

      db.prepare(
        'INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)'
      ).run('002_P0_P1_SECURITY_ROTATION', nowUtc);
    });
    return;
  }

  runInTransaction(db, () => {
    const nowUtc = '2026-11-11T00:00:00Z';

    // 1. Seed Users, Encryption Keys & AES-256-GCM PII Vault
    // Every account receives a unique 128-bit CSPRNG password salt and a unique 160-bit CSPRNG MFA secret.
    const additionalCertificateHolders = [
      {
        userId: 'usr-pasangnya-01',
        internalUuid: 'act-uuid-pasangnya-01',
        username: 'pasang.adventurer',
        fullName: 'Pasang Dawa Sherpa',
        nationality: 'Nepal (NP)',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-NP-010',
      },
      {
        userId: 'usr-elena-02',
        internalUuid: 'act-uuid-elena-02',
        username: 'elena.adventurer',
        fullName: 'Elena Rostova',
        nationality: 'Switzerland (CH)',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-CH-011',
      },
      {
        userId: 'usr-aarav-03',
        internalUuid: 'act-uuid-aarav-03',
        username: 'aarav.adventurer',
        fullName: 'Aarav Kumar Gurung',
        nationality: 'Nepal (NP)',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-NP-012',
      },
      {
        userId: 'usr-mateo-04',
        internalUuid: 'act-uuid-mateo-04',
        username: 'mateo.adventurer',
        fullName: 'Mateo Valdés',
        nationality: 'Argentina (AR)',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-AR-013',
      },
      {
        userId: 'usr-claire-fr',
        internalUuid: 'act-uuid-claire-002',
        username: 'claire.adventurer',
        fullName: 'Claire Moreau',
        nationality: 'France (FR)',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-FR-014',
      },
      {
        userId: 'usr-redacted-99',
        internalUuid: 'act-uuid-redacted-99',
        username: 'redacted.holder',
        fullName: 'Revoked Claimant',
        nationality: 'Redacted',
        role: 'REGISTERED_ADVENTURER' as UserRole,
        officerCode: 'ADV-XX-099',
      },
    ];

    const insertUserStmt = db.prepare(`
      INSERT INTO users (
        user_id, internal_actor_uuid, username, password_hash, role, officer_code,
        display_label, organization_id, expedition_roster_group_code,
        guide_for_user_ids_json, mfa_secret_hex, mfa_enabled, is_erased, created_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    `);

    const insertKeyStmt = db.prepare(`
      INSERT INTO user_encryption_keys (user_id, user_dek_hex, created_at_utc, shredded_at_utc)
      VALUES (?, ?, ?, NULL)
    `);

    const insertPiiStmt = db.prepare(`
      INSERT INTO user_pii_vault (
        user_id, encrypted_full_name_json, encrypted_email_json, encrypted_nationality_json, updated_at_utc
      ) VALUES (?, ?, ?, ?, ?)
    `);

    for (const acc of Object.values(NON_SENSITIVE_ACCOUNT_PROFILES)) {
      const demoProfile = Object.values(DEMO_ACTOR_PROFILES).find(
        (p) => p.userId === acc.userId
      );
      const internalUuid =
        demoProfile?.internalActorUuid || `act-uuid-${acc.userId}`;
      const generatedPassword = `Eph#${crypto.randomBytes(16).toString('base64url')}!8848`;
      const pwdHash = hashPasswordScrypt(generatedPassword);
      const uniqueMfaSecretHex = generateRandomMfaSecretHex();
      const mfaEnabled = roleRequiresMfa(acc.role) ? 1 : 0;

      insertUserStmt.run(
        acc.userId,
        internalUuid,
        acc.username,
        pwdHash,
        acc.role,
        acc.officerCode,
        acc.displayName,
        demoProfile?.organizationId || null,
        demoProfile?.expeditionRosterGroupCode || null,
        JSON.stringify(demoProfile?.isGuideForUserIds || []),
        uniqueMfaSecretHex,
        mfaEnabled,
        nowUtc
      );

      if (isDemoProvisioningAllowed()) {
        ephemeralTestCredentialsMap.set(acc.userId, {
          ...acc,
          ephemeralPassword: generatedPassword,
          mfaSecretHex: uniqueMfaSecretHex,
        });
      }

      const dekHex = generateUserDekHex();
      insertKeyStmt.run(acc.userId, dekHex, nowUtc);
      insertPiiStmt.run(
        acc.userId,
        JSON.stringify(encryptPiiWithUserDek(acc.displayName, dekHex)),
        JSON.stringify(
          encryptPiiWithUserDek(`${acc.username}@0to8848official.com`, dekHex)
        ),
        JSON.stringify(encryptPiiWithUserDek('Nepal (NP)', dekHex)),
        nowUtc
      );
    }

    for (const holder of additionalCertificateHolders) {
      const generatedHolderPass = `Eph#${crypto.randomBytes(16).toString('base64url')}!8848`;
      const pwdHash = hashPasswordScrypt(generatedHolderPass);
      const uniqueHolderMfaHex = generateRandomMfaSecretHex();
      insertUserStmt.run(
        holder.userId,
        holder.internalUuid,
        holder.username,
        pwdHash,
        holder.role,
        holder.officerCode,
        holder.fullName,
        null,
        null,
        '[]',
        uniqueHolderMfaHex,
        0,
        nowUtc
      );
      if (isDemoProvisioningAllowed()) {
        ephemeralTestCredentialsMap.set(holder.userId, {
          userId: holder.userId,
          username: holder.username,
          role: holder.role,
          officerCode: holder.officerCode,
          displayName: holder.fullName,
          ephemeralPassword: generatedHolderPass,
          mfaSecretHex: uniqueHolderMfaHex,
        });
      }
      const dekHex = generateUserDekHex();
      insertKeyStmt.run(holder.userId, dekHex, nowUtc);
      insertPiiStmt.run(
        holder.userId,
        JSON.stringify(encryptPiiWithUserDek(holder.fullName, dekHex)),
        JSON.stringify(
          encryptPiiWithUserDek(`${holder.username}@0to8848official.com`, dekHex)
        ),
        JSON.stringify(encryptPiiWithUserDek(holder.nationality, dekHex)),
        nowUtc
      );
    }

    // 2. Insert all 100 Destinations at '1_PROPOSED' baseline
    const insertDestStmt = db.prepare(`
      INSERT INTO destinations (
        id, code, research_stage, publication_status, elevation_citation_verified, record_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const dest of DESTINATIONS_100_CATALOG) {
      insertDestStmt.run(
        dest.id,
        dest.code,
        dest.researchStage,
        dest.publicationStatus,
        dest.elevationCitationVerified ? 1 : 0,
        JSON.stringify(dest)
      );
    }

    // 3. Audited Dual-Control (2P) Publication for the 7 Initial Verification Anchor Destinations
    // Every published destination has an explicit Dual-Control approval record (FOUNDER + GOVERNANCE_COMMITTEE)
    const initialPublishedAnchorIds = [
      'dest-001', // Mount Everest
      'dest-009', // Ama Dablam
      'dest-011', // Imja Tse (Island Peak)
      'dest-014', // Annapurna Circuit
      'dest-035', // Mont Blanc
      'dest-037', // Matterhorn
      'dest-081', // Mount Kilimanjaro
    ];

    const insertDualControlStmt = db.prepare(`
      INSERT INTO dual_control_approvals (
        approval_id, operation_type, target_entity_id, initiator_user_id,
        initiator_officer_code, initiator_role, reason, status,
        cosigner_user_id, cosigner_officer_code, cosigner_role,
        created_at_utc, expires_at_utc, resolved_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'EXECUTED', ?, ?, ?, ?, ?, ?)
    `);

    const updateDestStmt = db.prepare(`
      UPDATE destinations
      SET research_stage = '5_PUBLISHED',
          publication_status = 'PUBLISHED',
          elevation_citation_verified = 1,
          record_json = ?
      WHERE id = ?
    `);

    for (let i = 0; i < initialPublishedAnchorIds.length; i++) {
      const destId = initialPublishedAnchorIds[i];
      const baseDest = DESTINATIONS_100_CATALOG.find((d) => d.id === destId)!;
      const publishedDest: DestinationRecord = {
        ...baseDest,
        researchStage: '5_PUBLISHED',
        publicationStatus: 'PUBLISHED',
        elevationCitationVerified: true,
      };
      updateDestStmt.run(JSON.stringify(publishedDest), destId);

      insertDualControlStmt.run(
        `dca-seed-pub-${i + 1}`,
        'DESTINATION_STAGE_5_PUBLISH',
        baseDest.code,
        'usr-gov-founder-001',
        'GOV-FOUNDER-001',
        'FOUNDER',
        `Verified official geodetic survey citation (${baseDest.elevationReferenceSource}) and route safety envelope.`,
        'usr-gov-committee-002',
        'GOV-COMMITTEE-002',
        'GOVERNANCE_COMMITTEE',
        nowUtc,
        '2026-11-14T00:00:00Z',
        nowUtc
      );
    }

    // 4. Seed Historical Submissions for Initial Certificates + Active Submissions Queue
    const insertSubStmt = db.prepare(`
      INSERT INTO submissions (
        id, submission_code, applicant_user_id, destination_id, status,
        requires_dual_human_review, issued_certificate_id, submitted_at_utc, record_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertArtifactStmt = db.prepare(`
      INSERT INTO evidence_artifacts (
        id, submission_id, uploader_user_id, artifact_type, file_name,
        sha256_digest, perceptual_hash, vault_storage_key, uploaded_at_utc, artifact_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertReviewStmt = db.prepare(`
      INSERT INTO human_reviews (
        review_id, submission_id, reviewer_user_id, reviewer_officer_code,
        reviewer_role, decision, human_rationale, decided_at_utc, decision_hmac_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertCertStmt = db.prepare(`
      INSERT INTO certificates (
        verification_id, submission_id, holder_user_id, destination_id,
        status, opt_in_public_leaderboards, issued_at_utc, record_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Create backing approved/revoked submissions for INITIAL_VERIFIED_CERTIFICATES so FK integrity is 100% enforced
    for (const cert of INITIAL_VERIFIED_CERTIFICATES) {
      const backingSub: AchievementSubmission = {
        id: cert.submissionId,
        submissionCode: `SUB-HIST-${cert.destinationCode}`,
        applicantUserId: cert.holderUserId,
        applicantInternalActorUuid: cert.holderInternalActorUuid,
        applicantDisplayName: cert.holderPublicDisplay,
        applicantInitials: 'V. H.',
        applicantNationality: cert.holderNationality,
        destinationId: cert.destinationId,
        destinationName: cert.destinationNameEn,
        destinationElevationM: cert.verifiedElevationM,
        destinationTier: 'TIER_A_EXPEDITION',
        routeName: cert.routeName,
        verificationTrack: cert.verificationTrack,
        completionDateUtc: `${cert.publicCompletionDateDisplay.slice(0, 10)}T06:00:00Z`,
        applicantStory: 'Verified ascent dossier archived in Private Evidence Vault.',
        truthfulnessDeclarationSigned: true,
        privacyConsent: {
          publicIdentityMode: cert.holderPrivacyMode,
          publicDatePrecision: cert.holderDatePrecision || 'EXACT_DATE',
          optInPublicLeaderboards: cert.optInPublicLeaderboards,
        },
        evidenceArtifacts: [],
        advisoryAiAssessment: {
          modelId: 'gemini-3-flash-preview (Server-Side Advisory Only)',
          generatedAtUtc: cert.issuedAtUtc,
          advisoryRiskLevel: 'LOW',
          kinematicConsistencyNote: 'Verified against destination envelope.',
          exifForensicNote: 'Verified camera EXIF headers.',
          duplicateCheckNote: 'Unique SHA-256 digest.',
          disclaimer: 'ADVISORY AI ANALYSIS ONLY.',
        },
        status: cert.status === 'REVOKED' ? 'REVOKED' : 'APPROVED',
        requiresDualHumanReview: true,
        humanReviews: [],
        issuedCertificateId: cert.verificationId,
        submittedAtUtc: cert.issuedAtUtc,
      };

      insertSubStmt.run(
        backingSub.id,
        backingSub.submissionCode,
        backingSub.applicantUserId,
        backingSub.destinationId,
        backingSub.status,
        1,
        cert.verificationId,
        backingSub.submittedAtUtc,
        JSON.stringify(backingSub)
      );

      insertCertStmt.run(
        cert.verificationId,
        cert.submissionId,
        cert.holderUserId,
        cert.destinationId,
        cert.status,
        cert.optInPublicLeaderboards ? 1 : 0,
        cert.issuedAtUtc,
        JSON.stringify(cert)
      );
    }

    // Seed Active Queue Submissions (101, 102, 103)
    for (const sub of INITIAL_SUBMISSIONS_QUEUE) {
      insertSubStmt.run(
        sub.id,
        sub.submissionCode,
        sub.applicantUserId,
        sub.destinationId,
        sub.status,
        sub.requiresDualHumanReview ? 1 : 0,
        sub.issuedCertificateId || null,
        sub.submittedAtUtc,
        JSON.stringify(sub)
      );

      for (const art of sub.evidenceArtifacts) {
        insertArtifactStmt.run(
          art.id,
          sub.id,
          sub.applicantUserId,
          art.type,
          art.fileName,
          art.sha256PostUploadDigest,
          art.perceptualHash || null,
          art.vaultStorageKey || null,
          art.uploadedAtUtc,
          JSON.stringify(art)
        );
      }

      for (const rev of sub.humanReviews) {
        insertReviewStmt.run(
          rev.reviewId,
          sub.id,
          rev.reviewerUserId,
          rev.reviewerOfficerCode,
          rev.reviewerRole,
          rev.decision,
          rev.humanRationale,
          rev.decidedAtUtc,
          rev.decisionHmacSignature
        );
      }
    }

    // 5. Seed Genesis Audit Events using Genuine RFC 4231 HMAC-SHA256 Chaining
    appendAuditEventInternal(db, {
      actorInternalUuid: 'act-uuid-founder-001',
      actorRole: 'FOUNDER',
      actionType: 'CONSTITUTIONAL_BASELINE_AND_100_DESTINATIONS_INITIALIZED',
      targetEntityType: 'SYSTEM_CONSTITUTION',
      targetEntityId: 'DOC-P01-01',
      summary:
        'Initialized 100 destinations at 1_PROPOSED baseline and locked 12 Non-Negotiable Principles (PAYMENTS_ENABLED=false, BLOCKCHAIN_MINTING_ENABLED=false).',
      timestampUtc: '2026-11-11T00:01:00Z',
    });

    appendAuditEventInternal(db, {
      actorInternalUuid: 'act-uuid-gov-002',
      actorRole: 'GOVERNANCE_COMMITTEE',
      actionType: 'ANCHOR_DESTINATIONS_DUAL_CONTROL_PUBLISHED',
      targetEntityType: 'DUAL_CONTROL_APPROVAL',
      targetEntityId: 'dca-seed-pub-1..7',
      summary:
        'Executed Dual-Control (2P: GOV-FOUNDER-001 + GOV-COMMITTEE-002) verification and Stage 5 publication for 7 foundational anchor destinations.',
      timestampUtc: '2026-11-11T00:05:00Z',
    });

    appendAuditEventInternal(db, {
      actorInternalUuid: 'act-uuid-rev-104',
      actorRole: 'VERIFICATION_OFFICER',
      actionType: 'TIER_A_FIRST_HUMAN_APPROVAL',
      targetEntityType: 'ACHIEVEMENT_SUBMISSION',
      targetEntityId: 'SUB-2026-8848-101',
      summary:
        'Completed 5-Signal COI check and COI attestation; recorded first human approval on Mount Everest submission SUB-2026-8848-101. Awaiting second independent officer concurrence.',
      timestampUtc: '2026-11-11T00:15:00Z',
    });

    db.prepare(
      'INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)'
    ).run('001_FOUNDATION_RECOVERY', nowUtc);
    db.prepare(
      'INSERT INTO schema_migrations (version, applied_at_utc) VALUES (?, ?)'
    ).run('002_P0_P1_SECURITY_ROTATION', nowUtc);
  });
}

function appendAuditEventInternal(
  db: DatabaseSync,
  params: {
    actorInternalUuid: string;
    actorRole: UserRole;
    actionType: string;
    targetEntityType: string;
    targetEntityId: string;
    summary: string;
    timestampUtc?: string;
  }
): AppendOnlyAuditEvent {
  const lastRow = db
    .prepare(
      'SELECT sequence_number, current_event_hmac FROM audit_events ORDER BY sequence_number DESC LIMIT 1'
    )
    .get() as { sequence_number: number; current_event_hmac: string } | undefined;

  const sequenceNumber = lastRow ? Number(lastRow.sequence_number) + 1 : 1;
  const previousEventHmac = lastRow
    ? String(lastRow.current_event_hmac)
    : '0000000000000000000000000000000000000000000000000000000000000000';
  const eventId = `AUD-8848-${String(sequenceNumber).padStart(4, '0')}`;
  const timestampUtc = params.timestampUtc || new Date().toISOString();

  const { hmac: currentEventHmac, keyVersion } = computeAuditEventHmac({
    sequenceNumber,
    eventId,
    timestampUtc,
    actorInternalUuid: params.actorInternalUuid,
    actorRole: params.actorRole,
    actionType: params.actionType,
    targetEntityType: params.targetEntityType,
    targetEntityId: params.targetEntityId,
    summary: params.summary,
    previousEventHmac,
  });

  const wormReplicated = process.env.CLOUD_WORM_ENABLED === 'true';
  const storageMode = wormReplicated
    ? 'CLOUD_WORM_OBJECT_LOCK'
    : 'LOCAL_SQLITE_TRIGGER_IMMUTABLE';

  db.prepare(`
    INSERT INTO audit_events (
      sequence_number, event_id, timestamp_utc, actor_internal_uuid, actor_role,
      action_type, target_entity_type, target_entity_id, summary,
      previous_event_hmac, current_event_hmac, key_version, worm_replicated, storage_mode
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    sequenceNumber,
    eventId,
    timestampUtc,
    params.actorInternalUuid,
    params.actorRole,
    params.actionType,
    params.targetEntityType,
    params.targetEntityId,
    params.summary,
    previousEventHmac,
    currentEventHmac,
    keyVersion,
    wormReplicated ? 1 : 0,
    storageMode
  );

  return {
    sequenceNumber,
    eventId,
    timestampUtc,
    actorInternalUuid: params.actorInternalUuid,
    actorRole: params.actorRole,
    actionType: params.actionType,
    targetEntityType: params.targetEntityType,
    targetEntityId: params.targetEntityId,
    summary: params.summary,
    previousEventHmac,
    currentEventHmac,
    keyVersion,
    wormReplicated,
    storageMode,
  };
}

export function appendAuditEvent(params: {
  actorInternalUuid: string;
  actorRole: UserRole;
  actionType: string;
  targetEntityType: string;
  targetEntityId: string;
  summary: string;
  timestampUtc?: string;
}): AppendOnlyAuditEvent {
  const db = getDb();
  return runInTransaction(db, () => appendAuditEventInternal(db, params));
}

export function listAuditEvents(): AppendOnlyAuditEvent[] {
  const db = getDb();
  const rows = db
    .prepare('SELECT * FROM audit_events ORDER BY sequence_number DESC')
    .all() as Record<string, unknown>[];

  return rows.map((r) => ({
    sequenceNumber: Number(r.sequence_number),
    eventId: String(r.event_id),
    timestampUtc: String(r.timestamp_utc),
    actorInternalUuid: String(r.actor_internal_uuid),
    actorRole: String(r.actor_role) as UserRole,
    actionType: String(r.action_type),
    targetEntityType: String(r.target_entity_type),
    targetEntityId: String(r.target_entity_id),
    summary: String(r.summary),
    previousEventHmac: String(r.previous_event_hmac),
    currentEventHmac: String(r.current_event_hmac),
    keyVersion: String(r.key_version || 'v1'),
    wormReplicated: Boolean(r.worm_replicated),
    storageMode: String(
      r.storage_mode || 'LOCAL_SQLITE_TRIGGER_IMMUTABLE'
    ) as AppendOnlyAuditEvent['storageMode'],
  }));
}

export function listDestinations(): DestinationRecord[] {
  const db = getDb();
  const rows = db
    .prepare('SELECT record_json FROM destinations ORDER BY code ASC')
    .all() as { record_json: string }[];
  return rows.map((r) => JSON.parse(r.record_json) as DestinationRecord);
}

export function getDestinationByIdOrCode(idOrCode: string): DestinationRecord | null {
  const db = getDb();
  const row = db
    .prepare(
      'SELECT record_json FROM destinations WHERE LOWER(id) = LOWER(?) OR LOWER(code) = LOWER(?)'
    )
    .get(idOrCode, idOrCode) as { record_json: string } | undefined;
  return row ? (JSON.parse(row.record_json) as DestinationRecord) : null;
}

export function listSubmissions(forCallerRole?: UserRole): AchievementSubmission[] {
  const db = getDb();
  const rows = db
    .prepare('SELECT record_json FROM submissions ORDER BY submitted_at_utc DESC')
    .all() as { record_json: string }[];

  const parsed = rows.map((r) => JSON.parse(r.record_json) as AchievementSubmission);

  // Blind Reviewer Projection: If caller is VERIFICATION_OFFICER or SENIOR_VERIFICATION_LEAD,
  // mask applicant full name to applicantInitials + opaque code so reviews are blind to identity & commercial tier
  if (
    forCallerRole === 'VERIFICATION_OFFICER' ||
    forCallerRole === 'SENIOR_VERIFICATION_LEAD'
  ) {
    return parsed.map((s) => ({
      ...s,
      applicantDisplayName: `Blind Dossier [${s.applicantInitials}]`,
    }));
  }
  return parsed;
}

export function getSubmissionById(id: string): AchievementSubmission | null {
  const db = getDb();
  const row = db
    .prepare('SELECT record_json FROM submissions WHERE id = ? OR submission_code = ?')
    .get(id, id) as { record_json: string } | undefined;
  return row ? (JSON.parse(row.record_json) as AchievementSubmission) : null;
}

export function listCertificates(): PublicCertificateRecord[] {
  const db = getDb();
  const rows = db
    .prepare('SELECT record_json FROM certificates ORDER BY issued_at_utc DESC')
    .all() as { record_json: string }[];
  return rows.map((r) => JSON.parse(r.record_json) as PublicCertificateRecord);
}

export function getCertificateByVerificationId(
  verificationId: string
): PublicCertificateRecord | null {
  const db = getDb();
  const row = db
    .prepare(
      'SELECT record_json FROM certificates WHERE LOWER(verification_id) = LOWER(?)'
    )
    .get(verificationId.trim()) as { record_json: string } | undefined;
  return row ? (JSON.parse(row.record_json) as PublicCertificateRecord) : null;
}

export function listDualControlApprovals(): DualControlApprovalRecord[] {
  const db = getDb();
  const rows = db
    .prepare('SELECT * FROM dual_control_approvals ORDER BY created_at_utc DESC')
    .all() as Record<string, unknown>[];

  return rows.map((r) => ({
    approvalId: String(r.approval_id),
    operationType: String(
      r.operation_type
    ) as DualControlApprovalRecord['operationType'],
    targetEntityId: String(r.target_entity_id),
    initiatorUserId: String(r.initiator_user_id),
    initiatorOfficerCode: String(r.initiator_officer_code),
    initiatorRole: String(r.initiator_role) as UserRole,
    reason: String(r.reason),
    status: String(r.status) as DualControlApprovalRecord['status'],
    cosignerUserId: r.cosigner_user_id ? String(r.cosigner_user_id) : undefined,
    cosignerOfficerCode: r.cosigner_officer_code
      ? String(r.cosigner_officer_code)
      : undefined,
    cosignerRole: r.cosigner_role ? (String(r.cosigner_role) as UserRole) : undefined,
    createdAtUtc: String(r.created_at_utc),
    expiresAtUtc: String(r.expires_at_utc),
    resolvedAtUtc: r.resolved_at_utc ? String(r.resolved_at_utc) : undefined,
  }));
}

/**
 * SEC-AUTH-001:
 * Authenticates a user with password + MFA verification (mandatory for privileged roles)
 * and persists a CSPRNG session token in user_sessions.
 */
export function authenticateUserSession(params: {
  usernameOrUserId: string;
  password: string;
  totpCode?: string;
}): {
  sessionToken: string;
  user: AuthenticatedSessionUser;
} {
  const db = getDb();
  const row = db
    .prepare(
      'SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(user_id) = LOWER(?)'
    )
    .get(params.usernameOrUserId.trim(), params.usernameOrUserId.trim()) as
    | Record<string, unknown>
    | undefined;

  if (!row || Boolean(row.is_erased)) {
    throw new Error('AUTH_INVALID_CREDENTIALS: Invalid username or password.');
  }

  const storedHash = String(row.password_hash);
  if (!verifyPasswordScrypt(params.password, storedHash)) {
    throw new Error('AUTH_INVALID_CREDENTIALS: Invalid username or password.');
  }

  const role = String(row.role) as UserRole;
  const mfaRequired = roleRequiresMfa(role) || Boolean(row.mfa_enabled);
  const mfaSecretHex = String(row.mfa_secret_hex);

  if (mfaRequired) {
    if (!params.totpCode) {
      throw new Error(
        `MFA_REQUIRED_FOR_PRIVILEGED_ROLE: Role (${role}) requires a 6-digit RFC 6238 TOTP MFA code.`
      );
    }
    if (!verifyTotpCode(mfaSecretHex, params.totpCode)) {
      throw new Error('MFA_INVALID_CODE: Provided 6-digit TOTP MFA code is invalid.');
    }
  }

  const { rawSessionToken, tokenSha256Hash, expiresAtUtc } =
    generateSessionTokenPair(8);
  const sessionId = `sess-${Date.now()}-${tokenSha256Hash.slice(0, 8)}`;
  const nowUtc = new Date().toISOString();

  runInTransaction(db, () => {
    db.prepare(`
      INSERT INTO user_sessions (
        session_id, token_sha256_hash, user_id, mfa_verified, created_at_utc, expires_at_utc, revoked_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, NULL)
    `).run(
      sessionId,
      tokenSha256Hash,
      String(row.user_id),
      mfaRequired ? 1 : 0,
      nowUtc,
      expiresAtUtc
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: String(row.internal_actor_uuid),
      actorRole: role,
      actionType: 'AUTH_SESSION_ESTABLISHED',
      targetEntityType: 'USER_SESSION',
      targetEntityId: sessionId,
      summary: `Authenticated session established for ${String(row.officer_code)} (${role}) with MFA=${mfaRequired ? 'VERIFIED' : 'STANDARD'}.`,
    });
  });

  return {
    sessionToken: rawSessionToken,
    user: {
      userId: String(row.user_id),
      internalActorUuid: String(row.internal_actor_uuid),
      username: String(row.username),
      officerCode: String(row.officer_code),
      displayName: String(row.display_label),
      role,
      organizationId: row.organization_id ? String(row.organization_id) : undefined,
      expeditionRosterGroupCode: row.expedition_roster_group_code
        ? String(row.expedition_roster_group_code)
        : undefined,
      isGuideForUserIds: JSON.parse(String(row.guide_for_user_ids_json || '[]')),
      mfaRequired,
      mfaVerified: mfaRequired,
      sessionExpiresAtUtc: expiresAtUtc,
    },
  };
}

export function validateSessionToken(
  rawSessionToken: string | undefined | null
): AuthenticatedSessionUser | null {
  if (!rawSessionToken) return null;
  const db = getDb();
  const tokenHash = hashSessionToken(rawSessionToken.trim());

  const row = db
    .prepare(`
      SELECT
        s.session_id, s.mfa_verified, s.expires_at_utc, s.revoked_at_utc,
        u.user_id, u.internal_actor_uuid, u.username, u.role, u.officer_code,
        u.display_label, u.organization_id, u.expedition_roster_group_code,
        u.guide_for_user_ids_json, u.mfa_enabled, u.is_erased
      FROM user_sessions s
      JOIN users u ON u.user_id = s.user_id
      WHERE s.token_sha256_hash = ?
    `)
    .get(tokenHash) as Record<string, unknown> | undefined;

  if (!row) return null;
  if (row.revoked_at_utc) return null;
  if (Boolean(row.is_erased)) return null;

  const expiresAtMs = Date.parse(String(row.expires_at_utc));
  if (!Number.isFinite(expiresAtMs) || Date.now() > expiresAtMs) {
    return null;
  }

  const role = String(row.role) as UserRole;
  const mfaRequired = roleRequiresMfa(role) || Boolean(row.mfa_enabled);
  const mfaVerified = Boolean(row.mfa_verified);

  if (mfaRequired && !mfaVerified) {
    return null;
  }

  return {
    userId: String(row.user_id),
    internalActorUuid: String(row.internal_actor_uuid),
    username: String(row.username),
    officerCode: String(row.officer_code),
    displayName: String(row.display_label),
    role,
    organizationId: row.organization_id ? String(row.organization_id) : undefined,
    expeditionRosterGroupCode: row.expedition_roster_group_code
      ? String(row.expedition_roster_group_code)
      : undefined,
    isGuideForUserIds: JSON.parse(String(row.guide_for_user_ids_json || '[]')),
    mfaRequired,
    mfaVerified,
    sessionExpiresAtUtc: String(row.expires_at_utc),
  };
}

export function revokeSessionToken(rawSessionToken: string): boolean {
  const db = getDb();
  const tokenHash = hashSessionToken(rawSessionToken.trim());
  const nowUtc = new Date().toISOString();
  const result = db
    .prepare(
      'UPDATE user_sessions SET revoked_at_utc = ? WHERE token_sha256_hash = ? AND revoked_at_utc IS NULL'
    )
    .run(nowUtc, tokenHash);
  return result.changes > 0;
}

/**
 * BUG-P0-002 Audit Helper:
 * Returns stored password salt metadata and MFA secret uniqueness stats for automated security tests
 * without exposing raw secrets in production.
 */
export function getDatabaseCredentialSecurityStats(): {
  totalUsers: number;
  uniquePasswordSalts: number;
  uniqueMfaSecrets: number;
  allHashesUseScryptFormat: boolean;
} {
  const db = getDb();
  const rows = db
    .prepare('SELECT password_hash, mfa_secret_hex FROM users')
    .all() as { password_hash: string; mfa_secret_hex: string }[];

  const salts = new Set<string>();
  const mfaSecrets = new Set<string>();
  let allHashesUseScryptFormat = true;

  for (const r of rows) {
    if (!r.password_hash.startsWith('scrypt$16384$8$1$')) {
      allHashesUseScryptFormat = false;
    }
    const saltHex = extractSaltHexFromStoredHash(r.password_hash);
    if (saltHex && saltHex.length >= 32) {
      salts.add(saltHex);
    }
    if (r.mfa_secret_hex && r.mfa_secret_hex.length >= 40) {
      mfaSecrets.add(r.mfa_secret_hex);
    }
  }

  return {
    totalUsers: rows.length,
    uniquePasswordSalts: salts.size,
    uniqueMfaSecrets: mfaSecrets.size,
    allHashesUseScryptFormat,
  };
}

/**
 * BUG-P0-003 Remediation:
 * Sanitizes a certificate record for public / non-owner consumption so internal
 * holderUserId, holderInternalActorUuid, and submissionId are never leaked.
 */
export function sanitizeCertificateForViewer(
  cert: PublicCertificateRecord,
  viewer: AuthenticatedSessionUser | null
): Partial<PublicCertificateRecord> & { verificationId: string } {
  const isOwnerOrGovernance =
    viewer !== null &&
    (viewer.userId === cert.holderUserId ||
      ['FOUNDER', 'GOVERNANCE_COMMITTEE', 'SECURITY_COMPLIANCE_OFFICER'].includes(
        viewer.role
      ));

  return {
    verificationId: cert.verificationId,
    holderPublicDisplay: cert.holderPublicDisplay,
    holderPrivacyMode: cert.holderPrivacyMode,
    holderDatePrecision: cert.holderDatePrecision,
    holderNationality: cert.holderNationality,
    destinationId: cert.destinationId,
    destinationCode: cert.destinationCode,
    destinationNameEn: cert.destinationNameEn,
    destinationNameNe: cert.destinationNameNe,
    verifiedElevationM: cert.verifiedElevationM,
    verifiedElevationFt: cert.verifiedElevationFt,
    elevationSourceCitation: cert.elevationSourceCitation,
    routeName: cert.routeName,
    verificationTrack: cert.verificationTrack,
    publicCompletionDateDisplay: cert.publicCompletionDateDisplay,
    issuedAtUtc: cert.issuedAtUtc,
    status: cert.status,
    revocationOrCorrectionNote: cert.revocationOrCorrectionNote,
    reviewingOfficersCodes: cert.reviewingOfficersCodes,
    badgeCode: cert.badgeCode,
    certificateIntegrityDigest: cert.certificateIntegrityDigest,
    optInPublicLeaderboards: cert.optInPublicLeaderboards,
    ...(isOwnerOrGovernance ? { holderUserId: cert.holderUserId } : {}),
  };
}

/**
 * Strips raw vaultStorageKey and internal actor UUIDs from a submission before returning via API.
 */
export function sanitizeSubmissionForViewer(
  sub: AchievementSubmission,
  viewer: AuthenticatedSessionUser
): AchievementSubmission {
  const sanitizedArtifacts: EvidenceArtifact[] = sub.evidenceArtifacts.map(
    (art) => {
      const { vaultStorageKey: _omittedVaultKey, ...safeArt } = art;
      return safeArt;
    }
  );

  // Blind Reviewer Projection for VERIFICATION_OFFICER and SENIOR_VERIFICATION_LEAD
  if (
    viewer.role === 'VERIFICATION_OFFICER' ||
    viewer.role === 'SENIOR_VERIFICATION_LEAD'
  ) {
    return {
      ...sub,
      applicantInternalActorUuid: undefined,
      applicantDisplayName: `Blind Dossier [${sub.applicantInitials}]`,
      evidenceArtifacts: sanitizedArtifacts,
      appealRecord: undefined,
    };
  }

  // Independent Appeal Review Team Projection
  if (viewer.role === 'APPEAL_OFFICER') {
    return {
      ...sub,
      applicantInternalActorUuid: undefined,
      applicantDisplayName: `Blind Appeal Dossier [${sub.applicantInitials}]`,
      evidenceArtifacts: sanitizedArtifacts,
    };
  }

  // Adventurer / Owner or Governance Projection
  return {
    ...sub,
    applicantInternalActorUuid: undefined,
    evidenceArtifacts: sanitizedArtifacts,
  };
}

export type BootstrapAccessTier =
  | 'PUBLIC_INFORMATION'
  | 'REGISTERED_ADVENTURER'
  | 'VERIFICATION_OFFICER'
  | 'APPEAL_REVIEW_TEAM'
  | 'GOVERNANCE_COMMITTEE'
  | 'FOUNDER'
  | 'SPONSOR_ACCOUNT';

/**
 * BUG-P0-003 Remediation:
 * Enforces authentication and role-based access tier scoping BEFORE querying
 * sensitive tables (submissions, dual_control_approvals, audit_events).
 * Separates access into 7 explicit tiers:
 * 1. PUBLIC_INFORMATION (unauthenticated / PUBLIC_VISITOR)
 * 2. REGISTERED_ADVENTURER (own submissions only, zero internal audit/dual-control)
 * 3. VERIFICATION_OFFICER (blind verification queue, zero appeal/internal PII)
 * 4. APPEAL_REVIEW_TEAM (disputed appeal queue only, original reviewer blocked)
 * 5. GOVERNANCE_COMMITTEE (dual-control & audit oversight)
 * 6. FOUNDER (constitutional & dual-control oversight)
 * 7. SPONSOR_ACCOUNT (strict commercial firewall — zero submissions, audit, or dual-control)
 */
export function buildScopedBootstrapPayload(
  sessionUser: AuthenticatedSessionUser | null
): {
  accessTier: BootstrapAccessTier;
  sessionUser: AuthenticatedSessionUser | null;
  destinations: DestinationRecord[];
  submissions: AchievementSubmission[];
  certificates: Array<Partial<PublicCertificateRecord> & { verificationId: string }>;
  dualControlApprovals: DualControlApprovalRecord[];
  auditEvents: AppendOnlyAuditEvent[];
  auditChainStatus: { valid: boolean; checkedCount: number };
} {
  const destinations = listDestinations();
  const rawCertificates = listCertificates();
  const sanitizedCertificates = rawCertificates.map((c) =>
    sanitizeCertificateForViewer(c, sessionUser)
  );

  // Verify audit chain integrity on server without exposing raw audit event records to unauthorized callers
  const allAuditEventsInternal = listAuditEvents();
  const chainCheck = verifyAuditChainIntegrity(allAuditEventsInternal);
  const auditChainStatus = {
    valid: chainCheck.valid,
    checkedCount: chainCheck.checkedCount,
  };

  // Tier 1: Unauthenticated or PUBLIC_VISITOR -> Strictly Public Information Only
  if (!sessionUser || sessionUser.role === 'PUBLIC_VISITOR') {
    return {
      accessTier: 'PUBLIC_INFORMATION',
      sessionUser: null,
      destinations,
      submissions: [],
      certificates: sanitizedCertificates,
      dualControlApprovals: [],
      auditEvents: [],
      auditChainStatus,
    };
  }

  // Tier 7: SPONSOR_ACCOUNT -> Strictly isolated by Commercial Sponsor Firewall
  if (sessionUser.role === 'SPONSOR_ACCOUNT') {
    return {
      accessTier: 'SPONSOR_ACCOUNT',
      sessionUser,
      destinations,
      submissions: [],
      certificates: sanitizedCertificates,
      dualControlApprovals: [],
      auditEvents: [],
      auditChainStatus,
    };
  }

  // Tier 2: REGISTERED_ADVENTURER (and guide/partner/member accounts) -> Own submissions only
  if (
    [
      'REGISTERED_ADVENTURER',
      'PREMIUM_MEMBER_FUTURE',
      'VERIFIED_GUIDE',
      'ORGANIZATION_ADMIN',
      'DESTINATION_PARTNER',
    ].includes(sessionUser.role)
  ) {
    const db = getDb();
    const ownRows = db
      .prepare(
        'SELECT record_json FROM submissions WHERE applicant_user_id = ? ORDER BY submitted_at_utc DESC'
      )
      .all(sessionUser.userId) as { record_json: string }[];
    const ownSubmissions = ownRows
      .map((r) => JSON.parse(r.record_json) as AchievementSubmission)
      .map((s) => sanitizeSubmissionForViewer(s, sessionUser));

    return {
      accessTier: 'REGISTERED_ADVENTURER',
      sessionUser,
      destinations,
      submissions: ownSubmissions,
      certificates: sanitizedCertificates,
      dualControlApprovals: [],
      auditEvents: [],
      auditChainStatus,
    };
  }

  // Tier 3: VERIFICATION_OFFICER & SENIOR_VERIFICATION_LEAD -> Blind Verification Queue
  if (
    sessionUser.role === 'VERIFICATION_OFFICER' ||
    sessionUser.role === 'SENIOR_VERIFICATION_LEAD'
  ) {
    const db = getDb();
    const queueRows = db
      .prepare(
        "SELECT record_json FROM submissions WHERE status != 'APPEALED' ORDER BY submitted_at_utc DESC"
      )
      .all() as { record_json: string }[];
    const blindQueue = queueRows
      .map((r) => JSON.parse(r.record_json) as AchievementSubmission)
      .map((s) => sanitizeSubmissionForViewer(s, sessionUser));

    const canReadAudit = evaluateRbacPermission(
      sessionUser.role,
      'APPEND_ONLY_AUDIT_LOGS',
      'READ'
    ).allowed;

    const dualControlForLead =
      sessionUser.role === 'SENIOR_VERIFICATION_LEAD'
        ? listDualControlApprovals().filter(
            (d) => d.operationType === 'CERTIFICATE_REVOKE'
          )
        : [];

    return {
      accessTier: 'VERIFICATION_OFFICER',
      sessionUser,
      destinations,
      submissions: blindQueue,
      certificates: sanitizedCertificates,
      dualControlApprovals: dualControlForLead,
      auditEvents: canReadAudit ? allAuditEventsInternal : [],
      auditChainStatus,
    };
  }

  // Tier 4: APPEAL_OFFICER (Independent Appeal Review Team) -> Appealed Dossiers Only (COI Filtered)
  if (sessionUser.role === 'APPEAL_OFFICER') {
    const db = getDb();
    const appealRows = db
      .prepare(
        "SELECT record_json FROM submissions WHERE status = 'APPEALED' ORDER BY submitted_at_utc DESC"
      )
      .all() as { record_json: string }[];
    const appealQueue = appealRows
      .map((r) => JSON.parse(r.record_json) as AchievementSubmission)
      .filter(
        (s) =>
          !s.appealRecord?.originalReviewerUserIdsBlocked.includes(
            sessionUser.userId
          )
      )
      .map((s) => sanitizeSubmissionForViewer(s, sessionUser));

    return {
      accessTier: 'APPEAL_REVIEW_TEAM',
      sessionUser,
      destinations,
      submissions: appealQueue,
      certificates: sanitizedCertificates,
      dualControlApprovals: [],
      auditEvents: [],
      auditChainStatus,
    };
  }

  // Tier 5: GOVERNANCE_COMMITTEE (and Security/Compliance / Researcher / Sysadmin)
  if (sessionUser.role !== 'FOUNDER') {
    const canReadSubs = evaluateRbacPermission(
      sessionUser.role,
      'ACHIEVEMENT_SUBMISSIONS',
      'READ'
    ).allowed;
    const canReadAudit = evaluateRbacPermission(
      sessionUser.role,
      'APPEND_ONLY_AUDIT_LOGS',
      'READ'
    ).allowed;
    const canReadDualControl = [
      'GOVERNANCE_COMMITTEE',
      'SECURITY_COMPLIANCE_OFFICER',
    ].includes(sessionUser.role);

    const govSubmissions = canReadSubs
      ? listSubmissions(sessionUser.role).map((s) =>
          sanitizeSubmissionForViewer(s, sessionUser)
        )
      : [];

    return {
      accessTier: 'GOVERNANCE_COMMITTEE',
      sessionUser,
      destinations,
      submissions: govSubmissions,
      certificates: sanitizedCertificates,
      dualControlApprovals: canReadDualControl ? listDualControlApprovals() : [],
      auditEvents: canReadAudit ? allAuditEventsInternal : [],
      auditChainStatus,
    };
  }

  // Tier 6: FOUNDER -> Constitutional & Dual-Control Oversight
  const founderSubmissions = listSubmissions(sessionUser.role).map((s) =>
    sanitizeSubmissionForViewer(s, sessionUser)
  );
  return {
    accessTier: 'FOUNDER',
    sessionUser,
    destinations,
    submissions: founderSubmissions,
    certificates: sanitizedCertificates,
    dualControlApprovals: listDualControlApprovals(),
    auditEvents: allAuditEventsInternal,
    auditChainStatus,
  };
}

/**
 * SEC-GOV-001 & SEC-GOV-003:
 * Server-side 5-stage destination transition with mandatory Two-Person (2P) Dual-Control
 * enforcement for Stage 4 (4_REVIEWED_AND_APPROVED) and Stage 5 (5_PUBLISHED).
 */
export function advanceDestinationStageServer(params: {
  actor: AuthenticatedSessionUser;
  destinationIdOrCode: string;
  reason?: string;
}): {
  status: 'STAGE_ADVANCED' | 'DUAL_CONTROL_PENDING_SECOND_SIGNATURE';
  destination: DestinationRecord;
  dualControlRecord?: DualControlApprovalRecord;
} {
  const db = getDb();
  return runInTransaction(db, () => {
    const dest = getDestinationByIdOrCode(params.destinationIdOrCode);
    if (!dest) {
      throw new Error(`DESTINATION_NOT_FOUND: ${params.destinationIdOrCode}`);
    }

    const stageOrder: ResearchStage[] = [
      '1_PROPOSED',
      '2_UNDER_RESEARCH',
      '3_RESEARCH_COMPLETED',
      '4_REVIEWED_AND_APPROVED',
      '5_PUBLISHED',
    ];
    const currentIndex = stageOrder.indexOf(dest.researchStage);
    if (currentIndex >= stageOrder.length - 1) {
      throw new Error('DESTINATION_ALREADY_PUBLISHED: Destination is already at Stage 5.');
    }

    const nextStage = stageOrder[currentIndex + 1];

    // Stages 2 & 3: Require DESTINATION_RESEARCHER, GOVERNANCE_COMMITTEE, or FOUNDER
    if (
      nextStage === '2_UNDER_RESEARCH' ||
      nextStage === '3_RESEARCH_COMPLETED'
    ) {
      if (
        !['DESTINATION_RESEARCHER', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
          params.actor.role
        )
      ) {
        throw new Error(
          `RBAC_STAGE_RESEARCH_DENIED: Role (${params.actor.role}) is not authorized to advance research stages 1–3.`
        );
      }

      const updated: DestinationRecord = {
        ...dest,
        researchStage: nextStage,
        elevationCitationVerified: false,
        publicationStatus: 'UNPUBLISHED_DRAFT',
      };

      db.prepare(`
        UPDATE destinations
        SET research_stage = ?, publication_status = 'UNPUBLISHED_DRAFT',
            elevation_citation_verified = 0, record_json = ?
        WHERE id = ?
      `).run(nextStage, JSON.stringify(updated), dest.id);

      appendAuditEventInternal(db, {
        actorInternalUuid: params.actor.internalActorUuid,
        actorRole: params.actor.role,
        actionType: 'DESTINATION_RESEARCH_STAGE_ADVANCED',
        targetEntityType: 'DESTINATION_RECORD',
        targetEntityId: dest.code,
        summary: `Officer ${params.actor.officerCode} advanced ${dest.code} from ${dest.researchStage} to ${nextStage}.`,
      });

      return {
        status: 'STAGE_ADVANCED',
        destination: updated,
      };
    }

    // Stages 4 & 5: Require Dual-Control (2P) by GOVERNANCE_COMMITTEE / FOUNDER
    if (
      params.actor.role !== 'FOUNDER' &&
      params.actor.role !== 'GOVERNANCE_COMMITTEE'
    ) {
      throw new Error(
        `RBAC_STAGE_GOVERNANCE_DENIED: Role (${params.actor.role}) cannot approve Stage 4 or publish Stage 5 destinations.`
      );
    }

    const operationType: DualControlApprovalRecord['operationType'] =
      nextStage === '4_REVIEWED_AND_APPROVED'
        ? 'DESTINATION_STAGE_4_APPROVE'
        : 'DESTINATION_STAGE_5_PUBLISH';

    // Check if there is an existing non-expired PENDING_SECOND_APPROVAL for this destination & stage
    const existingPending = db
      .prepare(`
        SELECT * FROM dual_control_approvals
        WHERE operation_type = ? AND target_entity_id = ? AND status = 'PENDING_SECOND_APPROVAL'
        ORDER BY created_at_utc DESC LIMIT 1
      `)
      .get(operationType, dest.code) as Record<string, unknown> | undefined;

    const nowUtc = new Date().toISOString();

    if (!existingPending) {
      const approvalId = `dca-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const expiresAtUtc = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
      const reason =
        params.reason ||
        `Dual-Control initiation to advance ${dest.code} to ${nextStage}.`;

      db.prepare(`
        INSERT INTO dual_control_approvals (
          approval_id, operation_type, target_entity_id, initiator_user_id,
          initiator_officer_code, initiator_role, reason, status,
          cosigner_user_id, cosigner_officer_code, cosigner_role,
          created_at_utc, expires_at_utc, resolved_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING_SECOND_APPROVAL', NULL, NULL, NULL, ?, ?, NULL)
      `).run(
        approvalId,
        operationType,
        dest.code,
        params.actor.userId,
        params.actor.officerCode,
        params.actor.role,
        reason,
        nowUtc,
        expiresAtUtc
      );

      appendAuditEventInternal(db, {
        actorInternalUuid: params.actor.internalActorUuid,
        actorRole: params.actor.role,
        actionType: `${operationType}_INITIATED_1_OF_2`,
        targetEntityType: 'DUAL_CONTROL_APPROVAL',
        targetEntityId: approvalId,
        summary: `Principal 1 (${params.actor.officerCode}) initiated Dual-Control (${operationType}) for ${dest.code}. Awaiting distinct second principal signature.`,
      });

      return {
        status: 'DUAL_CONTROL_PENDING_SECOND_SIGNATURE',
        destination: dest,
        dualControlRecord: {
          approvalId,
          operationType,
          targetEntityId: dest.code,
          initiatorUserId: params.actor.userId,
          initiatorOfficerCode: params.actor.officerCode,
          initiatorRole: params.actor.role,
          reason,
          status: 'PENDING_SECOND_APPROVAL',
          createdAtUtc: nowUtc,
          expiresAtUtc,
        },
      };
    }

    // Enforce Two-Person Rule: Second signer MUST be a distinct userId
    if (String(existingPending.initiator_user_id) === params.actor.userId) {
      throw new Error(
        `DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN: Principal (${params.actor.officerCode}) initiated this request and cannot self-cosign. A second distinct governance principal is required.`
      );
    }

    const approvalId = String(existingPending.approval_id);
    db.prepare(`
      UPDATE dual_control_approvals
      SET status = 'EXECUTED',
          cosigner_user_id = ?,
          cosigner_officer_code = ?,
          cosigner_role = ?,
          resolved_at_utc = ?
      WHERE approval_id = ?
    `).run(
      params.actor.userId,
      params.actor.officerCode,
      params.actor.role,
      nowUtc,
      approvalId
    );

    const updatedDest: DestinationRecord = {
      ...dest,
      researchStage: nextStage,
      elevationCitationVerified: true,
      publicationStatus: nextStage === '5_PUBLISHED' ? 'PUBLISHED' : 'UNPUBLISHED_DRAFT',
    };

    db.prepare(`
      UPDATE destinations
      SET research_stage = ?,
          publication_status = ?,
          elevation_citation_verified = 1,
          record_json = ?
      WHERE id = ?
    `).run(
      nextStage,
      updatedDest.publicationStatus,
      JSON.stringify(updatedDest),
      dest.id
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: `${operationType}_EXECUTED_2_OF_2`,
      targetEntityType: 'DESTINATION_RECORD',
      targetEntityId: dest.code,
      summary: `Principal 2 (${params.actor.officerCode}) co-signed Dual-Control approval ${approvalId}. ${dest.code} transitioned to ${nextStage}.`,
    });

    return {
      status: 'STAGE_ADVANCED',
      destination: updatedDest,
      dualControlRecord: {
        approvalId,
        operationType,
        targetEntityId: dest.code,
        initiatorUserId: String(existingPending.initiator_user_id),
        initiatorOfficerCode: String(existingPending.initiator_officer_code),
        initiatorRole: String(existingPending.initiator_role) as UserRole,
        reason: String(existingPending.reason),
        status: 'EXECUTED',
        cosignerUserId: params.actor.userId,
        cosignerOfficerCode: params.actor.officerCode,
        cosignerRole: params.actor.role,
        createdAtUtc: String(existingPending.created_at_utc),
        expiresAtUtc: String(existingPending.expires_at_utc),
        resolvedAtUtc: nowUtc,
      },
    };
  });
}

/**
 * SEC-EVID-001 & SEC-GOV-002:
 * Registers a newly uploaded evidence artifact in the database and checks for duplicate SHA-256 digests.
 */
export function saveUploadedEvidenceArtifact(
  uploader: AuthenticatedSessionUser,
  artifact: EvidenceArtifact,
  submissionId?: string
): EvidenceArtifact {
  const db = getDb();
  return runInTransaction(db, () => {
    const duplicate = db
      .prepare('SELECT id, file_name FROM evidence_artifacts WHERE sha256_digest = ?')
      .get(artifact.sha256PostUploadDigest) as
      | { id: string; file_name: string }
      | undefined;

    if (duplicate) {
      throw new Error(
        `DUPLICATE_EVIDENCE_SHA256_DETECTED: An evidence artifact with SHA-256 digest ${artifact.sha256PostUploadDigest} already exists (${duplicate.id} / ${duplicate.file_name}). Recycled evidence is prohibited.`
      );
    }

    db.prepare(`
      INSERT INTO evidence_artifacts (
        id, submission_id, uploader_user_id, artifact_type, file_name,
        sha256_digest, perceptual_hash, vault_storage_key, uploaded_at_utc, artifact_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      artifact.id,
      submissionId || null,
      uploader.userId,
      artifact.type,
      artifact.fileName,
      artifact.sha256PostUploadDigest,
      artifact.perceptualHash || null,
      artifact.vaultStorageKey || null,
      artifact.uploadedAtUtc,
      JSON.stringify(artifact)
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: uploader.internalActorUuid,
      actorRole: uploader.role,
      actionType: 'PRIVATE_EVIDENCE_ARTIFACT_INGESTED',
      targetEntityType: 'EVIDENCE_ARTIFACT',
      targetEntityId: artifact.id,
      summary: `Ingested ${artifact.type} (${artifact.fileName}, SHA-256: ${artifact.sha256PostUploadDigest.slice(0, 16)}...) into Private Vault.`,
    });

    return artifact;
  });
}

export function getEvidenceArtifactById(artifactId: string): {
  artifact: EvidenceArtifact;
  submissionId: string | null;
  uploaderUserId: string;
} | null {
  const db = getDb();
  const row = db
    .prepare(
      'SELECT submission_id, uploader_user_id, artifact_json FROM evidence_artifacts WHERE id = ?'
    )
    .get(artifactId) as
    | {
        submission_id: string | null;
        uploader_user_id: string;
        artifact_json: string;
      }
    | undefined;

  if (!row) return null;
  return {
    artifact: JSON.parse(row.artifact_json) as EvidenceArtifact,
    submissionId: row.submission_id,
    uploaderUserId: row.uploader_user_id,
  };
}

/**
 * SEC-GOV-002 & SEC-EVID-001:
 * Creates a persistent achievement submission on the server, validating that the target
 * destination is Stage 5 Published, truthfulness declaration is signed, and COI fields are preserved.
 */
export function createSubmissionServer(params: {
  applicant: AuthenticatedSessionUser;
  destinationId: string;
  verificationTrack: AchievementSubmission['verificationTrack'];
  applicantDisplayName: string;
  applicantNationality: string;
  completionDateUtc: string;
  applicantStory: string;
  truthfulnessDeclarationSigned: boolean;
  guidedByUserId?: string;
  organizationId?: string;
  expeditionRosterGroupCode?: string;
  privacyConsent: AchievementSubmission['privacyConsent'];
  evidenceArtifactIds?: string[];
  inlineArtifacts?: EvidenceArtifact[];
}): AchievementSubmission {
  const db = getDb();
  return runInTransaction(db, () => {
    if (!params.truthfulnessDeclarationSigned) {
      throw new Error(
        'TRUTHFULNESS_DECLARATION_REQUIRED: Applicant must sign the Truthfulness & Anti-Fraud Declaration.'
      );
    }

    const dest = getDestinationByIdOrCode(params.destinationId);
    if (!dest) {
      throw new Error(`DESTINATION_NOT_FOUND: ${params.destinationId}`);
    }
    if (dest.researchStage !== '5_PUBLISHED') {
      throw new Error(
        `DESTINATION_NOT_PUBLISHED: ${dest.code} is currently at ${dest.researchStage} and cannot accept achievement submissions until Stage 5.`
      );
    }

    const countRow = db
      .prepare('SELECT COUNT(*) as cnt FROM submissions')
      .get() as { cnt: number };
    const seq = Number(countRow.cnt) + 101;
    const subId = `sub-queue-${seq}-${Date.now().toString(36).slice(-4)}`;
    const subCode = `SUB-2026-8848-${seq}`;

    const attachedArtifacts: EvidenceArtifact[] = [];
    if (params.evidenceArtifactIds && params.evidenceArtifactIds.length > 0) {
      for (const artId of params.evidenceArtifactIds) {
        const found = getEvidenceArtifactById(artId);
        if (!found) {
          throw new Error(`EVIDENCE_ARTIFACT_NOT_FOUND: ${artId}`);
        }
        attachedArtifacts.push(found.artifact);
      }
    }
    if (params.inlineArtifacts && params.inlineArtifacts.length > 0) {
      for (const inlineArt of params.inlineArtifacts) {
        const duplicate = db
          .prepare('SELECT id FROM evidence_artifacts WHERE sha256_digest = ?')
          .get(inlineArt.sha256PostUploadDigest);
        if (duplicate) {
          throw new Error(
            `DUPLICATE_EVIDENCE_SHA256_DETECTED: Artifact hash ${inlineArt.sha256PostUploadDigest} already exists.`
          );
        }
        attachedArtifacts.push(inlineArt);
      }
    }

    if (attachedArtifacts.length === 0) {
      throw new Error(
        'EVIDENCE_REQUIRED: At least one verified evidence artifact must be attached to create a submission.'
      );
    }

    const initials = params.applicantDisplayName
      .trim()
      .split(/\s+/)
      .map((p) => `${p[0]?.toUpperCase() || 'A'}.`)
      .join(' ');

    const nowUtc = new Date().toISOString();
    const requiresDualHumanReview =
      dest.tier === 'TIER_A_EXPEDITION' ||
      dest.elevationM >= 8000 ||
      params.verificationTrack === 'HISTORICAL_DOCUMENTARY';

    const newSub: AchievementSubmission = {
      id: subId,
      submissionCode: subCode,
      applicantUserId: params.applicant.userId,
      applicantInternalActorUuid: params.applicant.internalActorUuid,
      applicantDisplayName: params.applicantDisplayName.trim(),
      applicantInitials: initials,
      applicantNationality: params.applicantNationality.trim(),
      destinationId: dest.id,
      destinationName: dest.officialNameEn,
      destinationElevationM: dest.elevationM,
      destinationTier: dest.tier,
      routeName: dest.canonicalRouteName,
      verificationTrack: params.verificationTrack,
      completionDateUtc: params.completionDateUtc,
      expeditionRosterGroupCode:
        params.expeditionRosterGroupCode ||
        params.applicant.expeditionRosterGroupCode,
      guidedByUserId: params.guidedByUserId,
      organizationId: params.organizationId || params.applicant.organizationId,
      applicantStory: params.applicantStory,
      truthfulnessDeclarationSigned: true,
      privacyConsent: params.privacyConsent,
      evidenceArtifacts: attachedArtifacts,
      advisoryAiAssessment: {
        modelId: 'gemini-3-flash-preview (Server-Side Advisory Only)',
        generatedAtUtc: nowUtc,
        advisoryRiskLevel: 'LOW',
        kinematicConsistencyNote:
          'Post-upload SHA-256 byte digest locked. Ready for human officer telemetry & EXIF corroboration.',
        exifForensicNote: 'Private Vault evidence isolated under short-TTL access.',
        duplicateCheckNote: 'Unique SHA-256 digest verified across evidence table.',
        disclaimer:
          'ADVISORY AI ANALYSIS ONLY — AI has zero permission to approve or reject achievements.',
      },
      status: 'UNDER_REVIEW',
      requiresDualHumanReview,
      humanReviews: [],
      submittedAtUtc: nowUtc,
    };

    db.prepare(`
      INSERT INTO submissions (
        id, submission_code, applicant_user_id, destination_id, status,
        requires_dual_human_review, issued_certificate_id, submitted_at_utc, record_json
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
    `).run(
      newSub.id,
      newSub.submissionCode,
      newSub.applicantUserId,
      newSub.destinationId,
      newSub.status,
      newSub.requiresDualHumanReview ? 1 : 0,
      newSub.submittedAtUtc,
      JSON.stringify(newSub)
    );

    for (const art of attachedArtifacts) {
      const existingArt = db
        .prepare('SELECT id FROM evidence_artifacts WHERE id = ?')
        .get(art.id);
      if (existingArt) {
        db.prepare(
          'UPDATE evidence_artifacts SET submission_id = ? WHERE id = ?'
        ).run(newSub.id, art.id);
      } else {
        db.prepare(`
          INSERT INTO evidence_artifacts (
            id, submission_id, uploader_user_id, artifact_type, file_name,
            sha256_digest, perceptual_hash, vault_storage_key, uploaded_at_utc, artifact_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          art.id,
          newSub.id,
          params.applicant.userId,
          art.type,
          art.fileName,
          art.sha256PostUploadDigest,
          art.perceptualHash || null,
          art.vaultStorageKey || null,
          art.uploadedAtUtc,
          JSON.stringify(art)
        );
      }
    }

    appendAuditEventInternal(db, {
      actorInternalUuid: params.applicant.internalActorUuid,
      actorRole: params.applicant.role,
      actionType: 'ACHIEVEMENT_DOSSIER_SUBMITTED',
      targetEntityType: 'ACHIEVEMENT_SUBMISSION',
      targetEntityId: newSub.submissionCode,
      summary: `Submitted ${newSub.verificationTrack} dossier ${newSub.submissionCode} for ${dest.code} (${dest.elevationM}m) with ${attachedArtifacts.length} locked evidence artifact(s).`,
    });

    return newSub;
  });
}

/**
 * SEC-GOV-002, SEC-VERIF-002 & SEC-VERIF-003:
 * Server-side Human Verification & Appeal Tribunal Decision execution.
 * Enforces:
 * - Role boundary (VERIFICATION_OFFICER / SENIOR_VERIFICATION_LEAD vs APPEAL_OFFICER)
 * - 5-Signal Automated COI Check
 * - Signed Human COI Attestation
 * - Tier-A Dual Review (2P) & Split-Decision Escalation (ESCALATED_SPLIT_DECISION)
 * - REQUEST_ADDITIONAL_EVIDENCE workflow
 * - Automatic Free Certificate Issuance with 128-bit CSPRNG Verification ID upon human approval
 */
export function executeHumanReviewDecisionServer(params: {
  actor: AuthenticatedSessionUser;
  submissionId: string;
  decision: HumanReviewDecisionRecord['decision'];
  humanRationale: string;
  coiHumanAttestationSigned: boolean;
  reasonCode?: string;
}): {
  submission: AchievementSubmission;
  issuedCertificate?: PublicCertificateRecord;
} {
  const db = getDb();
  return runInTransaction(db, () => {
    const sub = getSubmissionById(params.submissionId);
    if (!sub) {
      throw new Error(`SUBMISSION_NOT_FOUND: ${params.submissionId}`);
    }

    if (!params.coiHumanAttestationSigned) {
      throw new Error(
        'COI_ATTESTATION_REQUIRED: Officer must sign the Conflict-of-Interest & Blind Review Attestation.'
      );
    }

    if (!params.humanRationale || params.humanRationale.trim().length < 10) {
      throw new Error(
        'RATIONALE_REQUIRED: Human verification rationale must be at least 10 characters.'
      );
    }

    const isAppeal = sub.status === 'APPEALED';

    if (!isAppeal) {
      if (
        params.actor.role !== 'VERIFICATION_OFFICER' &&
        params.actor.role !== 'SENIOR_VERIFICATION_LEAD'
      ) {
        throw new Error(
          `FIREWALL_VERIFICATION_INDEPENDENCE: Role (${params.actor.role}) is prohibited from making verification decisions.`
        );
      }
      if (
        sub.status === 'ESCALATED_SPLIT_DECISION' &&
        params.actor.role !== 'SENIOR_VERIFICATION_LEAD'
      ) {
        throw new Error(
          'ESCALATED_SPLIT_REQUIRES_SENIOR_LEAD: Only a non-conflicted SENIOR_VERIFICATION_LEAD may arbitrate an ESCALATED_SPLIT_DECISION.'
        );
      }
    } else {
      if (params.actor.role !== 'APPEAL_OFFICER') {
        throw new Error(
          `FIREWALL_APPEAL_INDEPENDENCE: Role (${params.actor.role}) cannot adjudicate appeals. Only members of the Independent Appeal Review Team may resolve disputed decisions.`
        );
      }
    }

    const coiCheck = runAutomatedFiveSignalCoiCheck(
      {
        userId: params.actor.userId,
        internalActorUuid: params.actor.internalActorUuid,
        officerCode: params.actor.officerCode,
        displayName: params.actor.displayName,
        role: params.actor.role,
        organizationId: params.actor.organizationId,
        expeditionRosterGroupCode: params.actor.expeditionRosterGroupCode,
        isGuideForUserIds: params.actor.isGuideForUserIds,
      },
      sub,
      isAppeal
    );

    if (!coiCheck.overallPassed) {
      appendAuditEventInternal(db, {
        actorInternalUuid: params.actor.internalActorUuid,
        actorRole: params.actor.role,
        actionType: 'COI_VIOLATION_ATTEMPT_BLOCKED',
        targetEntityType: 'ACHIEVEMENT_SUBMISSION',
        targetEntityId: sub.submissionCode,
        summary: `5-Signal COI Blocker prevented ${params.actor.officerCode} from deciding ${sub.submissionCode}: ${coiCheck.blockingReason}`,
      });
      throw new Error(`COI_BLOCKED: ${coiCheck.blockingReason}`);
    }

    const nowUtc = new Date().toISOString();
    const decisionHmac = computeHmacSha256Hex(
      `${sub.id}|${params.actor.userId}|${params.decision}|${params.humanRationale.trim()}|${nowUtc}`
    );

    const reviewRecord: HumanReviewDecisionRecord = {
      reviewId: `rev-${Date.now()}-${decisionHmac.slice(0, 6)}`,
      reviewerUserId: params.actor.userId,
      reviewerOfficerCode: params.actor.officerCode,
      reviewerRole: params.actor.role as HumanReviewDecisionRecord['reviewerRole'],
      coiAutomatedCheckPassed: true,
      coiHumanAttestationSigned: true,
      decision: params.decision,
      reasonCode: params.reasonCode,
      humanRationale: params.humanRationale.trim(),
      decidedAtUtc: nowUtc,
      decisionHmacSignature: decisionHmac,
    };

    db.prepare(`
      INSERT INTO human_reviews (
        review_id, submission_id, reviewer_user_id, reviewer_officer_code,
        reviewer_role, decision, human_rationale, decided_at_utc, decision_hmac_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      reviewRecord.reviewId,
      sub.id,
      reviewRecord.reviewerUserId,
      reviewRecord.reviewerOfficerCode,
      reviewRecord.reviewerRole,
      reviewRecord.decision,
      reviewRecord.humanRationale,
      reviewRecord.decidedAtUtc,
      reviewRecord.decisionHmacSignature
    );

    const updatedReviews = [...sub.humanReviews, reviewRecord];
    let nextStatus: SubmissionStatus = sub.status;
    let newlyIssuedCert: PublicCertificateRecord | undefined;

    if (params.decision === 'REQUEST_ADDITIONAL_EVIDENCE') {
      nextStatus = 'ADDITIONAL_EVIDENCE_REQUESTED';
    } else if (isAppeal) {
      if (params.decision === 'OVERTURN_AND_APPROVE') {
        nextStatus = 'APPROVED';
      } else if (params.decision === 'UPHOLD_REJECTION' || params.decision === 'REJECT') {
        nextStatus = 'REJECTED';
      } else {
        throw new Error(`Invalid appeal decision verb: ${params.decision}`);
      }
    } else if (sub.status === 'ESCALATED_SPLIT_DECISION') {
      // Binding arbitration by SENIOR_VERIFICATION_LEAD
      nextStatus = params.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    } else if (!sub.requiresDualHumanReview) {
      nextStatus = params.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    } else {
      // Tier-A Dual Independent Human Review state machine
      if (updatedReviews.length === 1) {
        nextStatus = 'AWAITING_SECOND_REVIEW';
      } else {
        const approvals = updatedReviews.filter((r) => r.decision === 'APPROVE').length;
        const rejections = updatedReviews.filter((r) => r.decision === 'REJECT').length;
        if (approvals >= 2 && rejections === 0) {
          nextStatus = 'APPROVED';
        } else if (rejections >= 2 && approvals === 0) {
          nextStatus = 'REJECTED';
        } else {
          // 1 APPROVE and 1 REJECT -> Escalate to Senior Verification Lead
          nextStatus = 'ESCALATED_SPLIT_DECISION';
        }
      }
    }

    if (nextStatus === 'APPROVED') {
      const dest = getDestinationByIdOrCode(sub.destinationId)!;
      const verificationId = generateNonEnumerableVerificationId((candidate) => {
        const exists = db
          .prepare('SELECT 1 FROM certificates WHERE verification_id = ?')
          .get(candidate);
        return Boolean(exists);
      });

      const publicNameDisplay = formatConsentedPublicIdentity({
        fullName: sub.applicantDisplayName,
        initials: sub.applicantInitials,
        identityMode: sub.privacyConsent.publicIdentityMode,
      });

      const publicDateDisplay = formatConsentedPublicDate(
        sub.completionDateUtc,
        sub.privacyConsent.publicDatePrecision
      );

      const certDigest = computeSha256Hex(
        `${verificationId}|${sub.id}|${dest.code}|${dest.elevationM}|${nowUtc}|${decisionHmac}`
      );

      newlyIssuedCert = {
        verificationId,
        submissionId: sub.id,
        holderUserId: sub.applicantUserId,
        holderInternalActorUuid: sub.applicantInternalActorUuid,
        holderPublicDisplay: publicNameDisplay,
        holderPrivacyMode: sub.privacyConsent.publicIdentityMode,
        holderDatePrecision: sub.privacyConsent.publicDatePrecision,
        holderNationality: sub.applicantNationality,
        destinationId: dest.id,
        destinationCode: dest.code,
        destinationNameEn: dest.officialNameEn,
        destinationNameNe: dest.officialNameNe,
        verifiedElevationM: dest.elevationM,
        verifiedElevationFt: dest.elevationFt,
        elevationSourceCitation: dest.elevationReferenceSource,
        routeName: sub.routeName,
        verificationTrack: sub.verificationTrack,
        publicCompletionDateDisplay: publicDateDisplay,
        issuedAtUtc: nowUtc,
        status: 'VALID',
        reviewingOfficersCodes: updatedReviews.map((r) => r.reviewerOfficerCode),
        badgeCode: dest.badgeIdentity.badgeCode,
        certificateIntegrityDigest: certDigest,
        optInPublicLeaderboards: sub.privacyConsent.optInPublicLeaderboards,
      };

      db.prepare(`
        INSERT INTO certificates (
          verification_id, submission_id, holder_user_id, destination_id,
          status, opt_in_public_leaderboards, issued_at_utc, record_json
        ) VALUES (?, ?, ?, ?, 'VALID', ?, ?, ?)
      `).run(
        newlyIssuedCert.verificationId,
        newlyIssuedCert.submissionId,
        newlyIssuedCert.holderUserId,
        newlyIssuedCert.destinationId,
        newlyIssuedCert.optInPublicLeaderboards ? 1 : 0,
        newlyIssuedCert.issuedAtUtc,
        JSON.stringify(newlyIssuedCert)
      );
    }

    const updatedSub: AchievementSubmission = {
      ...sub,
      status: nextStatus,
      humanReviews: updatedReviews,
      appealRecord:
        isAppeal && sub.appealRecord
          ? {
              ...sub.appealRecord,
              appealResolution: reviewRecord,
            }
          : sub.appealRecord,
      issuedCertificateId: newlyIssuedCert
        ? newlyIssuedCert.verificationId
        : sub.issuedCertificateId,
    };

    db.prepare(`
      UPDATE submissions
      SET status = ?, issued_certificate_id = ?, record_json = ?
      WHERE id = ?
    `).run(
      updatedSub.status,
      updatedSub.issuedCertificateId || null,
      JSON.stringify(updatedSub),
      updatedSub.id
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: `HUMAN_REVIEW_${params.decision}`,
      targetEntityType: 'ACHIEVEMENT_SUBMISSION',
      targetEntityId: sub.submissionCode,
      summary: `Officer ${params.actor.officerCode} recorded ${params.decision} on ${sub.submissionCode} -> Status: ${nextStatus}.${
        newlyIssuedCert
          ? ` Free Certificate Issued: ${newlyIssuedCert.verificationId}`
          : ''
      }`,
    });

    return {
      submission: updatedSub,
      issuedCertificate: newlyIssuedCert,
    };
  });
}

/**
 * SEC-VERIF-003:
 * Allows an applicant to file an appeal on a REJECTED submission, automatically
 * populating originalReviewerUserIdsBlocked from all prior humanReviews.
 */
export function fileAppealOnSubmissionServer(params: {
  actor: AuthenticatedSessionUser;
  submissionId: string;
  appellantGrounds: string;
  supplementaryEvidenceSummary: string;
}): AchievementSubmission {
  const db = getDb();
  return runInTransaction(db, () => {
    const sub = getSubmissionById(params.submissionId);
    if (!sub) {
      throw new Error(`SUBMISSION_NOT_FOUND: ${params.submissionId}`);
    }
    if (sub.applicantUserId !== params.actor.userId) {
      throw new Error(
        'APPEAL_OWNERSHIP_FORBIDDEN: Only the original applicant who submitted this dossier may file an appeal.'
      );
    }
    if (sub.status !== 'REJECTED') {
      throw new Error(
        `APPEAL_INVALID_STATUS: Only REJECTED submissions may be appealed (current status: ${sub.status}).`
      );
    }
    if (!params.appellantGrounds || params.appellantGrounds.trim().length < 10) {
      throw new Error('APPEAL_GROUNDS_REQUIRED: Appellant grounds must be provided.');
    }

    const blockedReviewerIds = Array.from(
      new Set(sub.humanReviews.map((r) => r.reviewerUserId))
    );
    const nowUtc = new Date().toISOString();
    const appealId = `APL-2026-8848-${Date.now().toString(36).toUpperCase()}`;

    const updatedSub: AchievementSubmission = {
      ...sub,
      status: 'APPEALED',
      appealRecord: {
        appealId,
        filedAtUtc: nowUtc,
        appellantGrounds: params.appellantGrounds.trim(),
        supplementaryEvidenceSummary: params.supplementaryEvidenceSummary.trim(),
        originalReviewerUserIdsBlocked: blockedReviewerIds,
      },
    };

    db.prepare(`
      UPDATE submissions SET status = 'APPEALED', record_json = ? WHERE id = ?
    `).run(JSON.stringify(updatedSub), sub.id);

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: 'INDEPENDENT_APPEAL_FILED',
      targetEntityType: 'APPEAL_RECORD',
      targetEntityId: appealId,
      summary: `Filed appeal ${appealId} on ${sub.submissionCode}. Original reviewers hard-blocked from tribunal: [${blockedReviewerIds.join(', ')}].`,
    });

    return updatedSub;
  });
}

/**
 * SEC-GOV-003:
 * Two-Person (2P) Dual-Control Certificate Revocation.
 * Requires two distinct principals across SENIOR_VERIFICATION_LEAD, GOVERNANCE_COMMITTEE, and FOUNDER.
 */
export function executeDualControlCertificateRevocationServer(params: {
  actor: AuthenticatedSessionUser;
  verificationId: string;
  reason: string;
}): {
  status: 'REVOCATION_EXECUTED' | 'DUAL_CONTROL_PENDING_SECOND_SIGNATURE';
  certificate: PublicCertificateRecord;
  dualControlRecord: DualControlApprovalRecord;
} {
  const db = getDb();
  return runInTransaction(db, () => {
    if (
      !['SENIOR_VERIFICATION_LEAD', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
        params.actor.role
      )
    ) {
      throw new Error(
        `CERT_REVOKE_DENIED: Role (${params.actor.role}) is not authorized to initiate or co-sign certificate revocation.`
      );
    }

    const cert = getCertificateByVerificationId(params.verificationId);
    if (!cert) {
      throw new Error(`CERTIFICATE_NOT_FOUND: ${params.verificationId}`);
    }
    if (cert.status === 'REVOKED') {
      throw new Error('CERTIFICATE_ALREADY_REVOKED: Certificate is already revoked.');
    }

    const existingPending = db
      .prepare(`
        SELECT * FROM dual_control_approvals
        WHERE operation_type = 'CERTIFICATE_REVOKE'
          AND target_entity_id = ?
          AND status = 'PENDING_SECOND_APPROVAL'
        ORDER BY created_at_utc DESC LIMIT 1
      `)
      .get(cert.verificationId) as Record<string, unknown> | undefined;

    const nowUtc = new Date().toISOString();

    if (!existingPending) {
      const approvalId = `dca-rev-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const expiresAtUtc = new Date(Date.now() + 72 * 3600 * 1000).toISOString();
      const reason =
        params.reason?.trim() ||
        'Post-issuance forensic audit initiated under Dual-Control governance.';

      db.prepare(`
        INSERT INTO dual_control_approvals (
          approval_id, operation_type, target_entity_id, initiator_user_id,
          initiator_officer_code, initiator_role, reason, status,
          cosigner_user_id, cosigner_officer_code, cosigner_role,
          created_at_utc, expires_at_utc, resolved_at_utc
        ) VALUES (?, 'CERTIFICATE_REVOKE', ?, ?, ?, ?, ?, 'PENDING_SECOND_APPROVAL', NULL, NULL, NULL, ?, ?, NULL)
      `).run(
        approvalId,
        cert.verificationId,
        params.actor.userId,
        params.actor.officerCode,
        params.actor.role,
        reason,
        nowUtc,
        expiresAtUtc
      );

      appendAuditEventInternal(db, {
        actorInternalUuid: params.actor.internalActorUuid,
        actorRole: params.actor.role,
        actionType: 'CERTIFICATE_REVOKE_INITIATED_1_OF_2',
        targetEntityType: 'PUBLIC_CERTIFICATE',
        targetEntityId: cert.verificationId,
        summary: `Principal 1 (${params.actor.officerCode}) initiated Dual-Control revocation (${approvalId}) on certificate ${cert.verificationId}. Awaiting distinct second principal signature.`,
      });

      return {
        status: 'DUAL_CONTROL_PENDING_SECOND_SIGNATURE',
        certificate: cert,
        dualControlRecord: {
          approvalId,
          operationType: 'CERTIFICATE_REVOKE',
          targetEntityId: cert.verificationId,
          initiatorUserId: params.actor.userId,
          initiatorOfficerCode: params.actor.officerCode,
          initiatorRole: params.actor.role,
          reason,
          status: 'PENDING_SECOND_APPROVAL',
          createdAtUtc: nowUtc,
          expiresAtUtc,
        },
      };
    }

    if (String(existingPending.initiator_user_id) === params.actor.userId) {
      throw new Error(
        `DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN: Principal (${params.actor.officerCode}) initiated this revocation and cannot self-cosign. A second distinct authorized principal is required.`
      );
    }

    const approvalId = String(existingPending.approval_id);
    db.prepare(`
      UPDATE dual_control_approvals
      SET status = 'EXECUTED',
          cosigner_user_id = ?,
          cosigner_officer_code = ?,
          cosigner_role = ?,
          resolved_at_utc = ?
      WHERE approval_id = ?
    `).run(
      params.actor.userId,
      params.actor.officerCode,
      params.actor.role,
      nowUtc,
      approvalId
    );

    const updatedCert: PublicCertificateRecord = {
      ...cert,
      status: 'REVOKED',
      optInPublicLeaderboards: false,
      revocationOrCorrectionNote: `REVOKED under Dual-Control Resolution (${approvalId}: ${String(
        existingPending.initiator_officer_code
      )} + ${params.actor.officerCode}): ${String(existingPending.reason)}`,
    };

    db.prepare(`
      UPDATE certificates
      SET status = 'REVOKED', opt_in_public_leaderboards = 0, record_json = ?
      WHERE verification_id = ?
    `).run(JSON.stringify(updatedCert), cert.verificationId);

    db.prepare(`
      UPDATE submissions SET status = 'REVOKED' WHERE id = ?
    `).run(cert.submissionId);

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: 'CERTIFICATE_REVOKE_EXECUTED_2_OF_2',
      targetEntityType: 'PUBLIC_CERTIFICATE',
      targetEntityId: cert.verificationId,
      summary: `Principal 2 (${params.actor.officerCode}) co-signed Dual-Control revocation ${approvalId}. Certificate ${cert.verificationId} status is now REVOKED and removed from leaderboards.`,
    });

    return {
      status: 'REVOCATION_EXECUTED',
      certificate: updatedCert,
      dualControlRecord: {
        approvalId,
        operationType: 'CERTIFICATE_REVOKE',
        targetEntityId: cert.verificationId,
        initiatorUserId: String(existingPending.initiator_user_id),
        initiatorOfficerCode: String(existingPending.initiator_officer_code),
        initiatorRole: String(existingPending.initiator_role) as UserRole,
        reason: String(existingPending.reason),
        status: 'EXECUTED',
        cosignerUserId: params.actor.userId,
        cosignerOfficerCode: params.actor.officerCode,
        cosignerRole: params.actor.role,
        createdAtUtc: String(existingPending.created_at_utc),
        expiresAtUtc: String(existingPending.expires_at_utc),
        resolvedAtUtc: nowUtc,
      },
    };
  });
}

/**
 * SEC-PRIV-001 & SEC-PRIV-002:
 * Allows a credential holder (or authorized privacy officer) to update public
 * privacy consent settings on an issued certificate at any time after issuance.
 */
export function updateCertificatePrivacyConsentServer(params: {
  actor: AuthenticatedSessionUser;
  verificationId: string;
  publicIdentityMode: PublicCertificateRecord['holderPrivacyMode'];
  publicDatePrecision: 'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY';
  optInPublicLeaderboards: boolean;
}): PublicCertificateRecord {
  const db = getDb();
  return runInTransaction(db, () => {
    const cert = getCertificateByVerificationId(params.verificationId);
    if (!cert) {
      throw new Error(`CERTIFICATE_NOT_FOUND: ${params.verificationId}`);
    }
    const isOwner = params.actor.userId === cert.holderUserId;
    const isPrivacyOfficer = [
      'SECURITY_COMPLIANCE_OFFICER',
      'GOVERNANCE_COMMITTEE',
      'FOUNDER',
    ].includes(params.actor.role);
    if (!isOwner && !isPrivacyOfficer) {
      throw new Error(
        'PRIVACY_UPDATE_FORBIDDEN: Only the certificate holder or an authorized privacy governance officer may update certificate privacy consent.'
      );
    }
    if (cert.status !== 'VALID') {
      throw new Error(
        `PRIVACY_UPDATE_INVALID_STATUS: Cannot update privacy preferences on a ${cert.status} certificate.`
      );
    }

    const sub = getSubmissionById(cert.submissionId);
    const fullName = sub ? sub.applicantDisplayName : cert.holderPublicDisplay;
    const initials = sub ? sub.applicantInitials : 'A. H.';
    const rawDate = sub
      ? sub.completionDateUtc
      : cert.publicCompletionDateDisplay;

    const updatedDisplay = formatConsentedPublicIdentity({
      fullName,
      initials,
      identityMode: params.publicIdentityMode,
    });
    const updatedDate = formatConsentedPublicDate(
      rawDate,
      params.publicDatePrecision
    );

    const updatedCert: PublicCertificateRecord = {
      ...cert,
      holderPrivacyMode: params.publicIdentityMode,
      holderDatePrecision: params.publicDatePrecision,
      holderPublicDisplay: updatedDisplay,
      publicCompletionDateDisplay: updatedDate,
      optInPublicLeaderboards: params.optInPublicLeaderboards,
    };

    db.prepare(`
      UPDATE certificates
      SET opt_in_public_leaderboards = ?, record_json = ?
      WHERE verification_id = ?
    `).run(
      params.optInPublicLeaderboards ? 1 : 0,
      JSON.stringify(updatedCert),
      cert.verificationId
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: 'HOLDER_PRIVACY_CONSENT_UPDATED',
      targetEntityType: 'PUBLIC_CERTIFICATE',
      targetEntityId: cert.verificationId,
      summary: `Updated public privacy consent on ${cert.verificationId}: mode=${params.publicIdentityMode}, datePrecision=${params.publicDatePrecision}, leaderboardOptIn=${params.optInPublicLeaderboards}.`,
    });

    return updatedCert;
  });
}

/**
 * SEC-PRIV-001:
 * Executes cryptographic Key-Shredding (destroys user_dek in user_encryption_keys,
 * wipes encrypted PII in user_pii_vault, redacts PII in submissions & certificates,
 * revokes active sessions, and preserves the opaque UUID audit chain intact).
 */
export function executeCryptographicErasureServer(params: {
  actor: AuthenticatedSessionUser;
  targetUserId: string;
}): {
  shreddedUserId: string;
  deactivatedCertificatesCount: number;
  redactedSubmissionsCount: number;
  decryptedPiiAfterShred: string | null;
} {
  const db = getDb();
  return runInTransaction(db, () => {
    const userRow = db
      .prepare('SELECT * FROM users WHERE user_id = ?')
      .get(params.targetUserId) as Record<string, unknown> | undefined;

    if (!userRow) {
      throw new Error(`USER_NOT_FOUND: ${params.targetUserId}`);
    }

    const nowUtc = new Date().toISOString();

    // 1. Destroy user_dek in user_encryption_keys
    db.prepare(`
      UPDATE user_encryption_keys
      SET user_dek_hex = NULL, shredded_at_utc = ?
      WHERE user_id = ?
    `).run(nowUtc, params.targetUserId);

    // 2. Wipe ciphertexts in user_pii_vault
    db.prepare(`
      UPDATE user_pii_vault
      SET encrypted_full_name_json = NULL,
          encrypted_email_json = NULL,
          encrypted_nationality_json = NULL,
          updated_at_utc = ?
      WHERE user_id = ?
    `).run(nowUtc, params.targetUserId);

    // 3. Mark user record erased & revoke all sessions
    db.prepare(`
      UPDATE users
      SET display_label = 'Erased Account (Key-Shredded)',
          is_erased = 1
      WHERE user_id = ?
    `).run(params.targetUserId);

    db.prepare(`
      UPDATE user_sessions SET revoked_at_utc = ? WHERE user_id = ?
    `).run(nowUtc, params.targetUserId);

    // 4. Redact cleartext PII inside submissions
    const subRows = db
      .prepare('SELECT id, record_json FROM submissions WHERE applicant_user_id = ?')
      .all(params.targetUserId) as { id: string; record_json: string }[];

    for (const sRow of subRows) {
      const subObj = JSON.parse(sRow.record_json) as AchievementSubmission;
      const redactedSub: AchievementSubmission = {
        ...subObj,
        applicantDisplayName: '[ERASED_BY_KEY_SHREDDING]',
        applicantInitials: '[ERASED]',
        applicantNationality: '[ERASED]',
        applicantStory: '[Personal narrative erased upon holder key-shredding request]',
      };
      db.prepare('UPDATE submissions SET record_json = ? WHERE id = ?').run(
        JSON.stringify(redactedSub),
        sRow.id
      );
    }

    // 5. Transition all certificates of this holder to DEACTIVATED_BY_USER_ERASURE
    const certRows = db
      .prepare(
        'SELECT verification_id, record_json FROM certificates WHERE holder_user_id = ?'
      )
      .all(params.targetUserId) as {
      verification_id: string;
      record_json: string;
    }[];

    for (const cRow of certRows) {
      const certObj = JSON.parse(cRow.record_json) as PublicCertificateRecord;
      const deactivatedCert: PublicCertificateRecord = {
        ...certObj,
        status: 'DEACTIVATED_BY_USER_ERASURE',
        holderPublicDisplay: 'Erased under Cryptographic Key-Shredding (user_dek Destroyed)',
        holderPrivacyMode: 'PRIVATE_CREDENTIAL_HOLDER',
        holderNationality: 'Erased',
        optInPublicLeaderboards: false,
        revocationOrCorrectionNote:
          'Record deactivated at the request of the credential holder. Personal identity key-shredded in user_pii_vault; anonymized cryptographic audit chain preserved.',
      };
      db.prepare(`
        UPDATE certificates
        SET status = 'DEACTIVATED_BY_USER_ERASURE',
            opt_in_public_leaderboards = 0,
            record_json = ?
        WHERE verification_id = ?
      `).run(JSON.stringify(deactivatedCert), cRow.verification_id);
    }

    // Verify that attempting to decrypt PII with the shredded key returns null
    const keyAfter = db
      .prepare('SELECT user_dek_hex FROM user_encryption_keys WHERE user_id = ?')
      .get(params.targetUserId) as { user_dek_hex: string | null } | undefined;

    const decryptedAfter = decryptPiiWithUserDek(
      { ivHex: '00', authTagHex: '00', ciphertextHex: '00' },
      keyAfter?.user_dek_hex
    );

    appendAuditEventInternal(db, {
      actorInternalUuid: params.actor.internalActorUuid,
      actorRole: params.actor.role,
      actionType: 'USER_PII_KEY_SHREDDING_EXECUTED',
      targetEntityType: 'USER_PII_VAULT',
      targetEntityId: String(userRow.internal_actor_uuid),
      summary: `Destroyed user_dek and redacted PII across ${subRows.length} submission(s) and ${certRows.length} certificate(s) while preserving immutable audit chain.`,
    });

    return {
      shreddedUserId: params.targetUserId,
      deactivatedCertificatesCount: certRows.length,
      redactedSubmissionsCount: subRows.length,
      decryptedPiiAfterShred: decryptedAfter,
    };
  });
}
