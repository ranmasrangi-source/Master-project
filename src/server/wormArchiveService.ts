import crypto from 'node:crypto';
import { AppendOnlyAuditEvent } from '../types/platform';
import {
  computeHmacSha256Hex,
  computeSha256Hex,
  getActiveKeyVersion,
  verifyAuditChainIntegrity,
} from './cryptoEngine';

/**
 * BUG-09 Remediation:
 * Modular External Immutable Audit Archive & WORM (Write-Once-Read-Many) Replication Architecture.
 *
 * Honest Protection Level Reporting:
 * - Local SQLite triggers (`trg_audit_events_no_update`, `trg_audit_events_no_delete`) block SQL-level
 *   UPDATE and DELETE operations within the application database (`LOCAL_SQLITE_TRIGGER_IMMUTABLE`),
 *   but DO NOT constitute external hardware/cloud WORM Object Lock storage.
 * - `wormReplicated` is strictly `false` unless an external WORM provider adapter (e.g., AWS S3 Object Lock
 *   in COMPLIANCE mode or GCP Bucket Lock) is explicitly configured and confirms write verification.
 */

export type WormProviderType = 'NONE_LOCAL_SQLITE_ONLY' | 'AWS_S3_OBJECT_LOCK' | 'GCP_BUCKET_LOCK' | 'CUSTOM_WORM_ADAPTER';

export type WormReplicationStatusCode =
  | 'LOCAL_ONLY_WORM_UNCONFIGURED'
  | 'REPLICATED_AND_VERIFIED'
  | 'REPLICATION_FAILED'
  | 'DEGRADED_PENDING_RETRY';

export interface WormRetentionPolicyConfig {
  provider: WormProviderType;
  bucketOrVaultName?: string;
  region?: string;
  objectLockMode: 'COMPLIANCE' | 'GOVERNANCE';
  minRetentionDays: number;
  kmsKeyId?: string;
  independentAccountId?: string;
}

export interface EncryptedWormAuditBundle {
  bundleId: string;
  createdAtUtc: string;
  fromSequenceNumber: number;
  toSequenceNumber: number;
  eventCount: number;
  chainTipHmac: string;
  plaintextSha256: string;
  keyVersion: string;
  ivHex: string;
  authTagHex: string;
  ciphertextBase64: string;
  bundleHmacSignature: string;
  retentionMode: 'COMPLIANCE' | 'GOVERNANCE';
  retainUntilUtc: string;
}

export interface WormProviderTransportAdapter {
  providerName: WormProviderType;
  putImmutableObject(bundle: EncryptedWormAuditBundle): Promise<{
    verified: boolean;
    externalObjectId: string;
    versionId: string;
    retainedUntilUtc: string;
  }>;
  getImmutableObject(bundleId: string): Promise<EncryptedWormAuditBundle | null>;
}

export interface WormReplicationAttemptResult {
  status: WormReplicationStatusCode;
  wormReplicated: boolean;
  provider: WormProviderType;
  bundleId?: string;
  externalObjectId?: string;
  errorReason?: string;
  timestampUtc: string;
  alertTriggered: boolean;
}

let activeWormAdapter: WormProviderTransportAdapter | null = null;
let lastReplicationResult: WormReplicationAttemptResult = {
  status: 'LOCAL_ONLY_WORM_UNCONFIGURED',
  wormReplicated: false,
  provider: 'NONE_LOCAL_SQLITE_ONLY',
  timestampUtc: new Date().toISOString(),
  alertTriggered: false,
};
const replicationFailureAlerts: Array<{
  timestampUtc: string;
  reason: string;
  sequenceNumber?: number;
}> = [];

export function getWormRetentionPolicyConfig(
  envOverride?: Record<string, string | undefined>
): WormRetentionPolicyConfig {
  const env = envOverride ?? process.env;
  const providerRaw = (env.WORM_STORAGE_PROVIDER || 'NONE_LOCAL_SQLITE_ONLY').trim();
  const provider: WormProviderType =
    providerRaw === 'AWS_S3_OBJECT_LOCK' ||
    providerRaw === 'GCP_BUCKET_LOCK' ||
    providerRaw === 'CUSTOM_WORM_ADAPTER'
      ? providerRaw
      : 'NONE_LOCAL_SQLITE_ONLY';

  return {
    provider,
    bucketOrVaultName: env.WORM_BUCKET_NAME?.trim() || undefined,
    region: env.WORM_BUCKET_REGION?.trim() || undefined,
    objectLockMode: env.WORM_OBJECT_LOCK_MODE === 'GOVERNANCE' ? 'GOVERNANCE' : 'COMPLIANCE',
    minRetentionDays: Math.max(365, Number(env.WORM_RETENTION_DAYS) || 2555), // 7-year default constitutional retention
    kmsKeyId: env.WORM_KMS_KEY_ID?.trim() || undefined,
    independentAccountId: env.WORM_SECURITY_AWS_ACCOUNT_ID?.trim() || undefined,
  };
}

export function registerWormTransportAdapter(
  adapter: WormProviderTransportAdapter | null
): void {
  activeWormAdapter = adapter;
  if (!adapter) {
    lastReplicationResult = {
      status: 'LOCAL_ONLY_WORM_UNCONFIGURED',
      wormReplicated: false,
      provider: 'NONE_LOCAL_SQLITE_ONLY',
      timestampUtc: new Date().toISOString(),
      alertTriggered: false,
    };
  }
}

export function getWormReplicationStatus(): {
  protectionLevel: 'LOCAL_SQLITE_TRIGGER_IMMUTABLE' | 'EXTERNAL_WORM_OBJECT_LOCK_VERIFIED';
  wormReplicated: boolean;
  status: WormReplicationStatusCode;
  policy: WormRetentionPolicyConfig;
  lastAttempt: WormReplicationAttemptResult;
  recentAlertsCount: number;
  recentAlerts: Array<{ timestampUtc: string; reason: string; sequenceNumber?: number }>;
  honestDisclosure: string;
} {
  const policy = getWormRetentionPolicyConfig();
  const isVerifiedExternal =
    activeWormAdapter !== null &&
    lastReplicationResult.status === 'REPLICATED_AND_VERIFIED' &&
    lastReplicationResult.wormReplicated === true;

  return {
    protectionLevel: isVerifiedExternal
      ? 'EXTERNAL_WORM_OBJECT_LOCK_VERIFIED'
      : 'LOCAL_SQLITE_TRIGGER_IMMUTABLE',
    wormReplicated: isVerifiedExternal,
    status: activeWormAdapter ? lastReplicationResult.status : 'LOCAL_ONLY_WORM_UNCONFIGURED',
    policy,
    lastAttempt: lastReplicationResult,
    recentAlertsCount: replicationFailureAlerts.length,
    recentAlerts: replicationFailureAlerts.slice(-20),
    honestDisclosure: isVerifiedExternal
      ? `Audit events are replicated to external WORM storage (${activeWormAdapter?.providerName}) under ${policy.objectLockMode} retention.`
      : 'Local SQLite triggers block application UPDATE/DELETE queries and HMAC-SHA256 chains detect tampering, but external cloud WORM Object Lock is not currently connected.',
  };
}

export function clearWormReplicationAlerts(): void {
  replicationFailureAlerts.length = 0;
}

/**
 * Encrypts a batch of audit events into an authenticated AES-256-GCM WORM archive bundle
 * with an independent SHA-256 digest and HMAC signature.
 */
export function createEncryptedWormArchiveBundle(
  events: AppendOnlyAuditEvent[],
  encryptionKey32Bytes: Buffer,
  retentionDays: number = 2555
): EncryptedWormAuditBundle {
  if (events.length === 0) {
    throw new Error('WORM_EMPTY_EVENT_BATCH: Cannot create archive bundle for 0 audit events.');
  }
  if (encryptionKey32Bytes.length !== 32) {
    throw new Error('WORM_INVALID_KEY_LENGTH: Archive encryption key must be 32 bytes (256 bits).');
  }

  const chainCheck = verifyAuditChainIntegrity(events);
  if (!chainCheck.valid) {
    throw new Error(
      `WORM_CHAIN_INTEGRITY_FAILURE: Cannot archive corrupted audit chain (${chainCheck.failureReason}).`
    );
  }

  const sorted = [...events].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  const firstEvt = sorted[0];
  const lastEvt = sorted[sorted.length - 1];
  const canonicalJson = JSON.stringify(sorted);
  const plaintextSha256 = computeSha256Hex(canonicalJson);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey32Bytes, iv);
  const encrypted = Buffer.concat([
    cipher.update(canonicalJson, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const createdAtUtc = new Date().toISOString();
  const retainUntilUtc = new Date(
    Date.now() + retentionDays * 24 * 3600 * 1000
  ).toISOString();
  const bundleId = `worm-bundle-${firstEvt.sequenceNumber}-${lastEvt.sequenceNumber}-${plaintextSha256.slice(0, 12)}`;
  const keyVersion = getActiveKeyVersion();
  const ciphertextBase64 = encrypted.toString('base64');

  const signaturePayload = [
    bundleId,
    createdAtUtc,
    firstEvt.sequenceNumber,
    lastEvt.sequenceNumber,
    lastEvt.currentEventHmac,
    plaintextSha256,
    keyVersion,
    iv.toString('hex'),
    authTag.toString('hex'),
    retainUntilUtc,
  ].join('|');

  const bundleHmacSignature = computeHmacSha256Hex(signaturePayload);

  return {
    bundleId,
    createdAtUtc,
    fromSequenceNumber: firstEvt.sequenceNumber,
    toSequenceNumber: lastEvt.sequenceNumber,
    eventCount: sorted.length,
    chainTipHmac: lastEvt.currentEventHmac,
    plaintextSha256,
    keyVersion,
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextBase64,
    bundleHmacSignature,
    retentionMode: 'COMPLIANCE',
    retainUntilUtc,
  };
}

/**
 * Verifies and recovers audit events from an encrypted WORM archive bundle,
 * validating the bundle HMAC, AES-256-GCM authentication tag, plaintext SHA-256,
 * and end-to-end sequential HMAC chain integrity.
 */
export function verifyAndRecoverWormArchiveBundle(
  bundle: EncryptedWormAuditBundle,
  decryptionKey32Bytes: Buffer
): {
  valid: boolean;
  reason?: string;
  recoveredEvents: AppendOnlyAuditEvent[];
} {
  try {
    const signaturePayload = [
      bundle.bundleId,
      bundle.createdAtUtc,
      bundle.fromSequenceNumber,
      bundle.toSequenceNumber,
      bundle.chainTipHmac,
      bundle.plaintextSha256,
      bundle.keyVersion,
      bundle.ivHex,
      bundle.authTagHex,
      bundle.retainUntilUtc,
    ].join('|');

    const expectedSig = computeHmacSha256Hex(signaturePayload, undefined, bundle.keyVersion);
    const sigBufA = Buffer.from(expectedSig, 'utf8');
    const sigBufB = Buffer.from(bundle.bundleHmacSignature, 'utf8');
    if (sigBufA.length !== sigBufB.length || !crypto.timingSafeEqual(sigBufA, sigBufB)) {
      return {
        valid: false,
        reason: 'WORM_BUNDLE_HMAC_MISMATCH',
        recoveredEvents: [],
      };
    }

    const iv = Buffer.from(bundle.ivHex, 'hex');
    const authTag = Buffer.from(bundle.authTagHex, 'hex');
    const ciphertext = Buffer.from(bundle.ciphertextBase64, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptionKey32Bytes, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');

    const actualSha256 = computeSha256Hex(decrypted);
    if (actualSha256 !== bundle.plaintextSha256) {
      return {
        valid: false,
        reason: 'WORM_PLAINTEXT_SHA256_MISMATCH',
        recoveredEvents: [],
      };
    }

    const events = JSON.parse(decrypted) as AppendOnlyAuditEvent[];
    const chainCheck = verifyAuditChainIntegrity(events);
    if (!chainCheck.valid) {
      return {
        valid: false,
        reason: `WORM_RECOVERED_CHAIN_INVALID: ${chainCheck.failureReason}`,
        recoveredEvents: [],
      };
    }

    return {
      valid: true,
      recoveredEvents: events,
    };
  } catch (err) {
    return {
      valid: false,
      reason: `WORM_DECRYPTION_OR_RECOVERY_FAILED: ${err instanceof Error ? err.message : 'unknown'}`,
      recoveredEvents: [],
    };
  }
}

/**
 * Attempts to replicate an audit event batch to the configured External WORM Adapter.
 * Never claims replication succeeded if no adapter is configured or if the adapter fails.
 */
export async function replicateAuditBatchToExternalWorm(
  events: AppendOnlyAuditEvent[],
  encryptionKey32Bytes: Buffer
): Promise<WormReplicationAttemptResult> {
  const nowUtc = new Date().toISOString();
  if (!activeWormAdapter) {
    lastReplicationResult = {
      status: 'LOCAL_ONLY_WORM_UNCONFIGURED',
      wormReplicated: false,
      provider: 'NONE_LOCAL_SQLITE_ONLY',
      timestampUtc: nowUtc,
      alertTriggered: false,
    };
    return lastReplicationResult;
  }

  try {
    const policy = getWormRetentionPolicyConfig();
    const bundle = createEncryptedWormArchiveBundle(
      events,
      encryptionKey32Bytes,
      policy.minRetentionDays
    );
    const res = await activeWormAdapter.putImmutableObject(bundle);
    if (!res.verified || !res.externalObjectId) {
      throw new Error('WORM provider did not confirm immutable Object Lock verification.');
    }

    lastReplicationResult = {
      status: 'REPLICATED_AND_VERIFIED',
      wormReplicated: true,
      provider: activeWormAdapter.providerName,
      bundleId: bundle.bundleId,
      externalObjectId: res.externalObjectId,
      timestampUtc: nowUtc,
      alertTriggered: false,
    };
    return lastReplicationResult;
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'Unknown WORM replication error';
    const lastSeq = events.length > 0 ? events[events.length - 1].sequenceNumber : undefined;
    replicationFailureAlerts.push({
      timestampUtc: nowUtc,
      reason,
      sequenceNumber: lastSeq,
    });
    lastReplicationResult = {
      status: 'REPLICATION_FAILED',
      wormReplicated: false,
      provider: activeWormAdapter.providerName,
      errorReason: reason,
      timestampUtc: nowUtc,
      alertTriggered: true,
    };
    return lastReplicationResult;
  }
}
