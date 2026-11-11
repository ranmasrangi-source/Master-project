import crypto from 'node:crypto';
import { AppendOnlyAuditEvent } from '../types/platform';

const CROCKFORD_BASE32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * SEC-CRYPTO-001 Remediation:
 * Keyed configuration with key versioning & rotation support.
 */
interface CryptoKeyRing {
  activeVersion: string;
  keys: Record<string, Buffer>;
}

const DEFAULT_DEV_HMAC_KEY_HEX =
  '8848f00d9a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef01234567';

let keyRing: CryptoKeyRing = {
  activeVersion: process.env.AUDIT_KEY_VERSION || 'v1',
  keys: {
    v1: Buffer.from(
      process.env.AUDIT_HMAC_SECRET_HEX || DEFAULT_DEV_HMAC_KEY_HEX,
      'hex'
    ),
  },
};

export function configureKeyRing(newVersion: string, newKeyBytes: Buffer): void {
  if (newKeyBytes.length < 32) {
    throw new Error('Cryptographic HMAC key must be at least 256 bits (32 bytes).');
  }
  keyRing.keys[newVersion] = Buffer.from(newKeyBytes);
  keyRing.activeVersion = newVersion;
}

export function getActiveKeyVersion(): string {
  return keyRing.activeVersion;
}

/**
 * SEC-CRYPTO-001:
 * Encodes a byte buffer into Crockford Base32 (5 bits per character).
 * 16 bytes (128 bits) -> 26 Base32 characters.
 */
export function encodeCrockfordBase32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += CROCKFORD_BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += CROCKFORD_BASE32[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * SEC-CRYPTO-001:
 * Generates a non-enumerable public Verification ID with >= 128 bits of
 * genuine CSPRNG entropy using Node.js crypto.randomBytes(16).
 * Supports collision checking callback against the persistent database.
 */
export function generateNonEnumerableVerificationId(
  existsCheck?: (candidateId: string) => boolean
): string {
  const maxAttempts = 10;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const entropyBytes = crypto.randomBytes(16); // 128 bits of CSPRNG entropy
    const base32 = encodeCrockfordBase32(entropyBytes); // 26 chars
    const formatted = `8848-V1-${base32.slice(0, 4)}-${base32.slice(4, 8)}-${base32.slice(
      8,
      12
    )}-${base32.slice(12, 16)}-${base32.slice(16, 20)}-${base32.slice(20, 26)}`;

    if (!existsCheck || !existsCheck(formatted)) {
      return formatted;
    }
  }
  throw new Error('CSPRNG Verification ID collision retry limit exceeded.');
}

/**
 * SEC-CRYPTO-002:
 * Computes a genuine NIST FIPS 180-4 SHA-256 hex digest from raw bytes or UTF-8 string.
 */
export function computeSha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * SEC-CRYPTO-002:
 * Computes a genuine RFC 2104 / RFC 4231 HMAC-SHA256 hex digest.
 */
export function computeHmacSha256Hex(
  data: Buffer | string,
  secretKey?: Buffer | string,
  keyVersion?: string
): string {
  const resolvedKey =
    secretKey !== undefined
      ? secretKey
      : keyRing.keys[keyVersion || keyRing.activeVersion] || keyRing.keys.v1;
  return crypto.createHmac('sha256', resolvedKey).update(data).digest('hex');
}

/**
 * SEC-CRYPTO-002:
 * Constant-time signature verification using crypto.timingSafeEqual.
 */
export function verifyHmacTimingSafe(
  data: Buffer | string,
  expectedHex: string,
  secretKey?: Buffer | string,
  keyVersion?: string
): boolean {
  const computedHex = computeHmacSha256Hex(data, secretKey, keyVersion);
  const a = Buffer.from(computedHex, 'utf8');
  const b = Buffer.from(expectedHex, 'utf8');
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * Canonical audit event payload formatter & HMAC-SHA256 chain computer.
 */
export function formatAuditEventCanonicalPayload(params: {
  sequenceNumber: number;
  eventId: string;
  timestampUtc: string;
  actorInternalUuid: string;
  actorRole: string;
  actionType: string;
  targetEntityType: string;
  targetEntityId: string;
  summary: string;
  previousEventHmac: string;
}): string {
  return [
    params.sequenceNumber,
    params.eventId,
    params.timestampUtc,
    params.actorInternalUuid,
    params.actorRole,
    params.actionType,
    params.targetEntityType,
    params.targetEntityId,
    params.summary,
    params.previousEventHmac,
  ].join('|');
}

export function computeAuditEventHmac(
  params: {
    sequenceNumber: number;
    eventId: string;
    timestampUtc: string;
    actorInternalUuid: string;
    actorRole: string;
    actionType: string;
    targetEntityType: string;
    targetEntityId: string;
    summary: string;
    previousEventHmac: string;
  },
  keyVersion?: string
): { hmac: string; keyVersion: string } {
  const version = keyVersion || keyRing.activeVersion;
  const payload = formatAuditEventCanonicalPayload(params);
  const hmac = computeHmacSha256Hex(payload, undefined, version);
  return { hmac, keyVersion: version };
}

export interface AuditChainVerificationResult {
  valid: boolean;
  checkedCount: number;
  brokenAtSequenceNumber?: number;
  failureReason?: string;
}

/**
 * SEC-CRYPTO-002 & SEC-DB-001:
 * Verifies the entire sequential HMAC-SHA256 audit chain from Genesis (seq 1)
 * using constant-time HMAC comparisons.
 */
export function verifyAuditChainIntegrity(
  events: AppendOnlyAuditEvent[]
): AuditChainVerificationResult {
  if (events.length === 0) {
    return { valid: true, checkedCount: 0 };
  }

  const sorted = [...events].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  let expectedPrevHmac =
    '0000000000000000000000000000000000000000000000000000000000000000';

  for (let i = 0; i < sorted.length; i++) {
    const evt = sorted[i];
    const expectedSeq = i + 1;
    if (evt.sequenceNumber !== expectedSeq) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: evt.sequenceNumber,
        failureReason: `Sequence gap detected: expected sequenceNumber ${expectedSeq}, found ${evt.sequenceNumber}.`,
      };
    }

    if (evt.previousEventHmac !== expectedPrevHmac) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: evt.sequenceNumber,
        failureReason: `Chain link mismatch at sequence #${evt.sequenceNumber}: previousEventHmac does not match prior event's currentEventHmac.`,
      };
    }

    const payload = formatAuditEventCanonicalPayload({
      sequenceNumber: evt.sequenceNumber,
      eventId: evt.eventId,
      timestampUtc: evt.timestampUtc,
      actorInternalUuid: evt.actorInternalUuid,
      actorRole: evt.actorRole,
      actionType: evt.actionType,
      targetEntityType: evt.targetEntityType,
      targetEntityId: evt.targetEntityId,
      summary: evt.summary,
      previousEventHmac: evt.previousEventHmac,
    });

    const isValidSig = verifyHmacTimingSafe(
      payload,
      evt.currentEventHmac,
      undefined,
      evt.keyVersion || 'v1'
    );
    if (!isValidSig) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequenceNumber: evt.sequenceNumber,
        failureReason: `HMAC-SHA256 signature verification failed at sequence #${evt.sequenceNumber} (${evt.eventId}). Payload or signature was tampered with.`,
      };
    }

    expectedPrevHmac = evt.currentEventHmac;
  }

  return {
    valid: true,
    checkedCount: sorted.length,
  };
}

/**
 * Generates short-lived HMAC-signed access tokens for Private Evidence Vault objects (TTL <= 15 minutes).
 */
export function createSignedEvidenceAccessToken(params: {
  artifactId: string;
  viewerUserId: string;
  submissionId: string;
  ttlSeconds?: number;
}): { token: string; expiresAtEpochMs: number } {
  const ttl = Math.min(params.ttlSeconds ?? 900, 900); // Max 15 minutes (900s)
  const expiresAtEpochMs = Date.now() + ttl * 1000;
  const payload = `${params.artifactId}:${params.submissionId}:${params.viewerUserId}:${expiresAtEpochMs}`;
  const sig = computeHmacSha256Hex(payload);
  const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
  return {
    token: `${encodedPayload}.${sig}`,
    expiresAtEpochMs,
  };
}

export function verifySignedEvidenceAccessToken(
  token: string,
  expectedArtifactId: string,
  expectedViewerUserId: string
): { valid: boolean; reason?: string; submissionId?: string } {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'Malformed signed vault token.' };
  }
  const [encodedPayload, sig] = parts;
  let decoded = '';
  try {
    decoded = Buffer.from(encodedPayload, 'base64url').toString('utf8');
  } catch {
    return { valid: false, reason: 'Invalid base64url token encoding.' };
  }

  if (!verifyHmacTimingSafe(decoded, sig)) {
    return { valid: false, reason: 'Invalid HMAC signature on vault token.' };
  }

  const [artifactId, submissionId, viewerUserId, expiresStr] = decoded.split(':');
  const expiresAt = Number(expiresStr);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
    return { valid: false, reason: 'Signed vault access token has expired.' };
  }
  if (artifactId !== expectedArtifactId) {
    return { valid: false, reason: 'Token artifactId mismatch.' };
  }
  if (viewerUserId !== expectedViewerUserId) {
    return { valid: false, reason: 'Token viewerUserId mismatch.' };
  }

  return { valid: true, submissionId };
}
