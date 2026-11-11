import crypto from 'node:crypto';

export interface EncryptedPiiPayload {
  ivHex: string;
  authTagHex: string;
  ciphertextHex: string;
}

/**
 * SEC-PRIV-001:
 * Generates a 256-bit (32-byte) Data Encryption Key (user_dek) using Node.js CSPRNG.
 */
export function generateUserDekHex(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * SEC-PRIV-001:
 * Encrypts sensitive user PII using AES-256-GCM with the user's isolated user_dek.
 */
export function encryptPiiWithUserDek(
  plaintext: string,
  userDekHex: string
): EncryptedPiiPayload {
  const key = Buffer.from(userDekHex, 'hex');
  if (key.length !== 32) {
    throw new Error('Invalid user_dek length; requires 256-bit (32-byte) key.');
  }
  const iv = crypto.randomBytes(12); // 96-bit GCM IV
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextHex: encrypted.toString('hex'),
  };
}

/**
 * SEC-PRIV-001:
 * Decrypts sensitive user PII using AES-256-GCM. If the user_dek has been shredded
 * (destroyed during account erasure), decryption is cryptographically impossible.
 */
export function decryptPiiWithUserDek(
  payload: EncryptedPiiPayload,
  userDekHex: string | null | undefined
): string | null {
  if (!userDekHex) {
    return null; // Key shredded -> irreversibly erased
  }
  try {
    const key = Buffer.from(userDekHex, 'hex');
    const iv = Buffer.from(payload.ivHex, 'hex');
    const authTag = Buffer.from(payload.authTagHex, 'hex');
    const ciphertext = Buffer.from(payload.ciphertextHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

export interface GpxTrackpoint {
  lat: number;
  lon: number;
  ele: number;
  timeUtc?: string;
}

/**
 * Computes Haversine great-circle distance in meters between two WGS84 coordinates.
 */
export function haversineDistanceMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const R = 6371000; // Earth mean radius in meters
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * SEC-PRIV-001:
 * Masks/trims residential or trailhead-origin coordinates within a configurable
 * geofence radius (default 2,000 meters from start and end points) while always
 * preserving the summit/apex segment.
 */
export function maskResidentialTrackpoints(
  points: GpxTrackpoint[],
  maskRadiusMeters: number = 2000
): {
  maskedPoints: GpxTrackpoint[];
  removedCount: number;
  residentialStartEndMasked: boolean;
} {
  if (points.length <= 4) {
    return {
      maskedPoints: points,
      removedCount: 0,
      residentialStartEndMasked: true,
    };
  }

  const startPt = points[0];
  const endPt = points[points.length - 1];

  // Find index of highest elevation point so we never mask the summit apex
  let apexIndex = 0;
  for (let i = 1; i < points.length; i++) {
    if (points[i].ele > points[apexIndex].ele) {
      apexIndex = i;
    }
  }

  const kept: GpxTrackpoint[] = [];
  let removedCount = 0;

  for (let i = 0; i < points.length; i++) {
    if (i === apexIndex) {
      kept.push(points[i]);
      continue;
    }
    const distFromStart = haversineDistanceMeters(
      startPt.lat,
      startPt.lon,
      points[i].lat,
      points[i].lon
    );
    const distFromEnd = haversineDistanceMeters(
      endPt.lat,
      endPt.lon,
      points[i].lat,
      points[i].lon
    );

    const isStartTail = i < apexIndex && distFromStart < maskRadiusMeters;
    const isEndTail = i > apexIndex && distFromEnd < maskRadiusMeters;

    if (isStartTail || isEndTail) {
      removedCount++;
    } else {
      kept.push(points[i]);
    }
  }

  return {
    maskedPoints: kept,
    removedCount,
    residentialStartEndMasked: true,
  };
}

/**
 * Formats holder public identity and date precision according to explicit holder consent.
 */
export function formatConsentedPublicIdentity(params: {
  fullName: string;
  initials: string;
  identityMode:
    | 'FULL_VERIFIED_NAME'
    | 'DISPLAY_HANDLE_OR_INITIALS'
    | 'PRIVATE_CREDENTIAL_HOLDER';
}): string {
  if (params.identityMode === 'FULL_VERIFIED_NAME') {
    return params.fullName;
  }
  if (params.identityMode === 'DISPLAY_HANDLE_OR_INITIALS') {
    return `${params.initials} (Initials Consent Mode)`;
  }
  return 'Private Credential Holder (Identity Redacted by Holder Consent)';
}

export function formatConsentedPublicDate(
  isoDateOrTimestamp: string,
  datePrecision: 'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY'
): string {
  const cleanDate = isoDateOrTimestamp.slice(0, 10);
  if (datePrecision === 'EXACT_DATE') {
    return cleanDate;
  }
  if (datePrecision === 'MONTH_AND_YEAR_ONLY') {
    return cleanDate.slice(0, 7);
  }
  return cleanDate.slice(0, 4);
}
