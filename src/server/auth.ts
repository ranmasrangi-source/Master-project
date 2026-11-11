import crypto from 'node:crypto';
import { UserRole } from '../types/platform';

const PRIVILEGED_MFA_ROLES: UserRole[] = [
  'VERIFICATION_OFFICER',
  'SENIOR_VERIFICATION_LEAD',
  'APPEAL_OFFICER',
  'SECURITY_COMPLIANCE_OFFICER',
  'PLATFORM_SYSADMIN',
  'GOVERNANCE_COMMITTEE',
  'FOUNDER',
];

export function roleRequiresMfa(role: UserRole): boolean {
  return PRIVILEGED_MFA_ROLES.includes(role);
}

/**
 * SEC-AUTH-001:
 * Hashes a user password using Node.js crypto.scryptSync with a 128-bit random salt.
 */
export function hashPasswordScrypt(password: string, saltHex?: string): string {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${derived.toString('hex')}`;
}

/**
 * SEC-AUTH-001:
 * Verifies a user password in constant time using crypto.timingSafeEqual.
 */
export function verifyPasswordScrypt(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [saltHex, keyHex] = parts;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(keyHex, 'hex');
  const derived = crypto.scryptSync(password, salt, expected.length);
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

/**
 * SEC-AUTH-001:
 * RFC 6238 TOTP (Time-Based One-Time Password) 6-digit generator & verifier
 * for privileged staff MFA enforcement.
 */
export function generateTotpCode(
  secretHex: string,
  timestampMs: number = Date.now(),
  stepSeconds: number = 30
): string {
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);

  const key = Buffer.from(secretHex, 'hex');
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % 1000000;
  return String(otp).padStart(6, '0');
}

export function verifyTotpCode(
  secretHex: string,
  candidateCode: string,
  timestampMs: number = Date.now()
): boolean {
  const clean = (candidateCode || '').trim();
  if (!/^\d{6}$/.test(clean)) return false;

  // Check current 30s window and ±1 window for clock skew tolerance
  for (const offsetSteps of [-1, 0, 1]) {
    const expected = generateTotpCode(
      secretHex,
      timestampMs + offsetSteps * 30 * 1000
    );
    const a = Buffer.from(clean, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return true;
    }
  }
  return false;
}

/**
 * SEC-AUTH-001:
 * Generates a 256-bit CSPRNG session token and its SHA-256 database lookup hash.
 */
export function generateSessionTokenPair(ttlHours: number = 8): {
  rawSessionToken: string;
  tokenSha256Hash: string;
  expiresAtUtc: string;
} {
  const rawSessionToken = `sess_8848_${crypto.randomBytes(32).toString('hex')}`;
  const tokenSha256Hash = crypto
    .createHash('sha256')
    .update(rawSessionToken)
    .digest('hex');
  const expiresAtUtc = new Date(
    Date.now() + ttlHours * 3600 * 1000
  ).toISOString();
  return { rawSessionToken, tokenSha256Hash, expiresAtUtc };
}

export function hashSessionToken(rawSessionToken: string): string {
  return crypto.createHash('sha256').update(rawSessionToken).digest('hex');
}

/**
 * Login brute-force rate limiter (in-memory per-username/IP window).
 */
interface LoginRateRecord {
  failedCount: number;
  lockedUntilMs: number;
}

const loginRateMap = new Map<string, LoginRateRecord>();

export function checkLoginRateLimit(identifier: string): {
  allowed: boolean;
  retryAfterSeconds?: number;
} {
  const rec = loginRateMap.get(identifier);
  if (!rec) return { allowed: true };
  if (rec.lockedUntilMs > Date.now()) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((rec.lockedUntilMs - Date.now()) / 1000),
    };
  }
  return { allowed: true };
}

export function recordFailedLoginAttempt(identifier: string): void {
  const rec = loginRateMap.get(identifier) || {
    failedCount: 0,
    lockedUntilMs: 0,
  };
  rec.failedCount += 1;
  if (rec.failedCount >= 5) {
    rec.lockedUntilMs = Date.now() + 60 * 1000; // 60-second lockout after 5 failed attempts
  }
  loginRateMap.set(identifier, rec);
}

export function resetLoginAttempts(identifier: string): void {
  loginRateMap.delete(identifier);
}
