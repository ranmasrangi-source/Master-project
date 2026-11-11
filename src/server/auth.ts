import crypto from 'node:crypto';
import type { Request } from 'express';
import { UserRole } from '../types/platform';

const PRIVILEGED_MFA_ROLES: UserRole[] = [
  'DESTINATION_RESEARCHER',
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
 * BUG-03 Remediation:
 * Explicit Approved Scrypt Parameter Policy.
 * Validates N, r, p, salt length, derived key length, and memory bounds BEFORE invoking crypto.scryptSync.
 */
export const APPROVED_SCRYPT_POLICY = {
  targetN: 16384,
  targetR: 8,
  targetP: 1,
  targetKeyLenBytes: 64,
  minN: 16384,
  maxN: 65536,
  minR: 8,
  maxR: 16,
  minP: 1,
  maxP: 4,
  minSaltBytes: 16,
  maxSaltBytes: 64,
  minLegacyKeyBytes: 32,
  maxKeyBytes: 64,
  maxMemoryBytes: 32 * 1024 * 1024, // 32 MiB ceiling
} as const;

export interface ScryptParameterValidationResult {
  valid: boolean;
  reason?: string;
  needsRehash: boolean;
  params?: {
    n: number;
    r: number;
    p: number;
    salt: Buffer;
    expectedKey: Buffer;
    isLegacyFormat: boolean;
  };
}

function isStrictHex(str: string): boolean {
  return str.length > 0 && str.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(str);
}

function isPowerOfTwo(n: number): boolean {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

/**
 * BUG-03 Remediation:
 * Validates stored scrypt parameters against APPROVED_SCRYPT_POLICY before any CPU/memory allocation.
 */
export function validateScryptHashParameters(
  storedHash: string
): ScryptParameterValidationResult {
  if (!storedHash || typeof storedHash !== 'string') {
    return { valid: false, reason: 'EMPTY_OR_NON_STRING_HASH', needsRehash: false };
  }

  if (storedHash.startsWith('scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 6) {
      return { valid: false, reason: 'MALFORMED_SCRYPT_FIELD_COUNT', needsRehash: false };
    }
    const [, nStr, rStr, pStr, saltHex, keyHex] = parts;
    if (!/^\d+$/.test(nStr) || !/^\d+$/.test(rStr) || !/^\d+$/.test(pStr)) {
      return { valid: false, reason: 'NON_INTEGER_COST_PARAMETERS', needsRehash: false };
    }

    const n = Number(nStr);
    const r = Number(rStr);
    const p = Number(pStr);

    if (!Number.isSafeInteger(n) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) {
      return { valid: false, reason: 'UNSAFE_INTEGER_PARAMETERS', needsRehash: false };
    }
    if (!isPowerOfTwo(n)) {
      return { valid: false, reason: 'SCRYPT_N_NOT_POWER_OF_TWO', needsRehash: false };
    }
    if (n < APPROVED_SCRYPT_POLICY.minN || n > APPROVED_SCRYPT_POLICY.maxN) {
      return { valid: false, reason: 'SCRYPT_N_OUT_OF_APPROVED_BOUNDS', needsRehash: false };
    }
    if (r < APPROVED_SCRYPT_POLICY.minR || r > APPROVED_SCRYPT_POLICY.maxR) {
      return { valid: false, reason: 'SCRYPT_R_OUT_OF_APPROVED_BOUNDS', needsRehash: false };
    }
    if (p < APPROVED_SCRYPT_POLICY.minP || p > APPROVED_SCRYPT_POLICY.maxP) {
      return { valid: false, reason: 'SCRYPT_P_OUT_OF_APPROVED_BOUNDS', needsRehash: false };
    }

    // Memory required by scrypt is approximately 128 * N * r bytes (plus p overhead)
    const requiredMemBytes = 128 * n * r * p;
    if (requiredMemBytes > APPROVED_SCRYPT_POLICY.maxMemoryBytes) {
      return {
        valid: false,
        reason: 'SCRYPT_MEMORY_LIMIT_EXCEEDED',
        needsRehash: false,
      };
    }

    if (!isStrictHex(saltHex) || !isStrictHex(keyHex)) {
      return { valid: false, reason: 'INVALID_HEX_ENCODING', needsRehash: false };
    }

    const salt = Buffer.from(saltHex, 'hex');
    const expectedKey = Buffer.from(keyHex, 'hex');

    if (
      salt.length < APPROVED_SCRYPT_POLICY.minSaltBytes ||
      salt.length > APPROVED_SCRYPT_POLICY.maxSaltBytes
    ) {
      return { valid: false, reason: 'SALT_LENGTH_OUT_OF_BOUNDS', needsRehash: false };
    }
    if (expectedKey.length !== APPROVED_SCRYPT_POLICY.targetKeyLenBytes) {
      return { valid: false, reason: 'KEY_LENGTH_MISMATCH', needsRehash: false };
    }

    const needsRehash =
      n !== APPROVED_SCRYPT_POLICY.targetN ||
      r !== APPROVED_SCRYPT_POLICY.targetR ||
      p !== APPROVED_SCRYPT_POLICY.targetP;

    return {
      valid: true,
      needsRehash,
      params: { n, r, p, salt, expectedKey, isLegacyFormat: false },
    };
  }

  // Controlled Legacy Format Support: "<saltHex>:<derivedKeyHex>"
  const legacyParts = storedHash.split(':');
  if (legacyParts.length !== 2) {
    return { valid: false, reason: 'UNRECOGNIZED_HASH_FORMAT', needsRehash: false };
  }
  const [saltHex, keyHex] = legacyParts;
  if (!isStrictHex(saltHex) || !isStrictHex(keyHex)) {
    return { valid: false, reason: 'LEGACY_INVALID_HEX_ENCODING', needsRehash: false };
  }
  const salt = Buffer.from(saltHex, 'hex');
  const expectedKey = Buffer.from(keyHex, 'hex');
  if (
    salt.length < APPROVED_SCRYPT_POLICY.minSaltBytes ||
    salt.length > APPROVED_SCRYPT_POLICY.maxSaltBytes
  ) {
    return { valid: false, reason: 'LEGACY_SALT_LENGTH_OUT_OF_BOUNDS', needsRehash: false };
  }
  if (
    expectedKey.length < APPROVED_SCRYPT_POLICY.minLegacyKeyBytes ||
    expectedKey.length > APPROVED_SCRYPT_POLICY.maxKeyBytes
  ) {
    return { valid: false, reason: 'LEGACY_KEY_LENGTH_OUT_OF_BOUNDS', needsRehash: false };
  }

  return {
    valid: true,
    needsRehash: true, // Legacy format always upgrades to explicit scrypt$N$r$p$salt$key on login
    params: {
      n: APPROVED_SCRYPT_POLICY.targetN,
      r: APPROVED_SCRYPT_POLICY.targetR,
      p: APPROVED_SCRYPT_POLICY.targetP,
      salt,
      expectedKey,
      isLegacyFormat: true,
    },
  };
}

export function needsPasswordRehash(storedHash: string): boolean {
  const check = validateScryptHashParameters(storedHash);
  return check.valid && check.needsRehash;
}

/**
 * SEC-AUTH-001, BUG-P0-002 & BUG-03 Remediation:
 * Hashes a user password using Node.js crypto.scryptSync with a freshly generated
 * cryptographically secure 128-bit (16-byte) unique random salt per invocation.
 */
export function hashPasswordScrypt(password: string): string {
  if (!password || typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }
  if (password.length > 256) {
    throw new Error('Password exceeds maximum length of 256 characters.');
  }
  const salt = crypto.randomBytes(16); // Always unique 128-bit CSPRNG salt
  const { targetN, targetR, targetP, targetKeyLenBytes, maxMemoryBytes } =
    APPROVED_SCRYPT_POLICY;
  const derived = crypto.scryptSync(password, salt, targetKeyLenBytes, {
    N: targetN,
    r: targetR,
    p: targetP,
    maxmem: maxMemoryBytes,
  });
  return `scrypt$${targetN}$${targetR}$${targetP}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

/**
 * Extracts the hex salt from a stored password hash string for auditing salt uniqueness.
 */
export function extractSaltHexFromStoredHash(storedHash: string): string | null {
  const check = validateScryptHashParameters(storedHash);
  if (!check.valid || !check.params) return null;
  return check.params.salt.toString('hex');
}

/**
 * SEC-AUTH-001, BUG-P0-002 & BUG-03:
 * Validates stored scrypt parameters against strict policy bounds, then verifies
 * the password in constant time using crypto.timingSafeEqual.
 */
export function verifyPasswordScrypt(password: string, storedHash: string): boolean {
  if (!password || typeof password !== 'string' || password.length > 256 || !storedHash) {
    return false;
  }

  const validation = validateScryptHashParameters(storedHash);
  if (!validation.valid || !validation.params) {
    return false;
  }

  const { n, r, p, salt, expectedKey } = validation.params;
  try {
    const derived = crypto.scryptSync(password, salt, expectedKey.length, {
      N: n,
      r: r,
      p: p,
      maxmem: APPROVED_SCRYPT_POLICY.maxMemoryBytes,
    });
    if (derived.length !== expectedKey.length) return false;
    return crypto.timingSafeEqual(derived, expectedKey);
  } catch {
    return false;
  }
}

/**
 * Generates an independent 160-bit (20-byte) CSPRNG secret in hex for RFC 6238 TOTP MFA.
 */
export function generateRandomMfaSecretHex(): string {
  return crypto.randomBytes(20).toString('hex');
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
 * BUG-02 Remediation:
 * Builds secure Set-Cookie header strings for session establishment and logout revocation.
 * Enforces Secure flag in production or over HTTPS, HttpOnly, SameSite=Strict, and Path=/.
 */
export function buildSessionCookieHeader(
  sessionToken: string,
  options?: {
    isProduction?: boolean;
    isHttps?: boolean;
    maxAgeSeconds?: number;
    domain?: string;
  }
): string {
  const isProd =
    options?.isProduction !== undefined
      ? options.isProduction
      : process.env.NODE_ENV === 'production';
  const requireSecure = isProd || Boolean(options?.isHttps);
  const maxAge = options?.maxAgeSeconds ?? 28800; // 8 hours default
  const parts = [
    `0to8848_session=${encodeURIComponent(sessionToken)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAge}`,
  ];
  if (options?.domain && /^[a-zA-Z0-9.-]+$/.test(options.domain)) {
    parts.push(`Domain=${options.domain}`);
  }
  if (requireSecure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

export function buildClearSessionCookieHeader(options?: {
  isProduction?: boolean;
  isHttps?: boolean;
  domain?: string;
}): string {
  const isProd =
    options?.isProduction !== undefined
      ? options.isProduction
      : process.env.NODE_ENV === 'production';
  const requireSecure = isProd || Boolean(options?.isHttps);
  const parts = [
    '0to8848_session=',
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];
  if (options?.domain && /^[a-zA-Z0-9.-]+$/.test(options.domain)) {
    parts.push(`Domain=${options.domain}`);
  }
  if (requireSecure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * BUG-01 Remediation:
 * Trusted Proxy Client IP Resolver.
 * Never trusts X-Forwarded-For or X-Real-IP headers unless TRUST_PROXY === 'true' is explicitly configured.
 */
export function resolveTrustedClientIp(
  req: Pick<Request, 'headers' | 'socket' | 'ip'>,
  envOverride?: Record<string, string | undefined>
): string {
  const env = envOverride ?? process.env;
  const trustProxy = env.TRUST_PROXY === 'true';

  if (trustProxy) {
    const xff = req.headers?.['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim().length > 0) {
      const ips = xff
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (ips.length > 0) {
        return ips[0].slice(0, 64);
      }
    }
  }

  const socketIp = req.socket?.remoteAddress || req.ip || '127.0.0.1';
  return socketIp.replace(/^::ffff:/, '').slice(0, 64);
}

/**
 * BUG-01 Remediation:
 * Bounded, TTL-evicting & pluggable shared rate-limit store with 3-layer protection:
 * 1. Combined (Account + IP) bucket: prevents single-IP username-only DoS against other IPs.
 * 2. Per-IP global bucket: prevents distributed credential stuffing from a single IP across accounts.
 * 3. Account-wide distributed anomaly tracker: throttles coordinated multi-IP attacks against one account.
 */
export interface RateLimitEntry {
  failedCount: number;
  firstFailedAtMs: number;
  lastFailedAtMs: number;
  lockedUntilMs: number;
  expiresAtMs: number;
  distinctSources?: string[];
}

export interface RateLimitStore {
  get(key: string, nowMs?: number): RateLimitEntry | undefined;
  set(key: string, entry: RateLimitEntry, nowMs?: number): void;
  delete(key: string): void;
  clear(): void;
  size(): number;
  pruneExpired(nowMs?: number): number;
}

export class BoundedInMemoryRateLimitStore implements RateLimitStore {
  private readonly map = new Map<string, RateLimitEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries: number = 5000) {
    this.maxEntries = Math.max(50, maxEntries);
  }

  get(key: string, nowMs: number = Date.now()): RateLimitEntry | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (nowMs >= entry.expiresAtMs && nowMs >= entry.lockedUntilMs) {
      this.map.delete(key);
      return undefined;
    }
    return entry;
  }

  set(key: string, entry: RateLimitEntry, nowMs: number = Date.now()): void {
    if (!this.map.has(key) && this.map.size >= this.maxEntries) {
      this.pruneExpired(nowMs);
      if (this.map.size >= this.maxEntries) {
        // Evict oldest inserted key (Map preserves insertion order)
        const oldestKey = this.map.keys().next().value;
        if (oldestKey !== undefined) {
          this.map.delete(oldestKey);
        }
      }
    }
    this.map.delete(key);
    this.map.set(key, entry);
  }

  delete(key: string): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  size(): number {
    return this.map.size;
  }

  pruneExpired(nowMs: number = Date.now()): number {
    let pruned = 0;
    for (const [k, v] of this.map.entries()) {
      if (nowMs >= v.expiresAtMs && nowMs >= v.lockedUntilMs) {
        this.map.delete(k);
        pruned += 1;
      }
    }
    return pruned;
  }
}

export const LOGIN_RATE_LIMIT_POLICY = {
  windowMs: 15 * 60 * 1000, // 15-minute observation window
  accountIpLockoutThreshold: 5, // 5 failed attempts for (username + IP)
  ipGlobalLockoutThreshold: 15, // 15 failed attempts from same IP across any accounts
  accountDistributedThreshold: 15, // 15 failed attempts across >= 3 distinct IPs
  accountDistributedMinDistinctIps: 3,
  tier1LockoutMs: 60 * 1000, // 60 seconds (5-7 failures)
  tier2LockoutMs: 5 * 60 * 1000, // 5 minutes (8-9 failures)
  tier3LockoutMs: 15 * 60 * 1000, // 15 minutes (10+ failures or IP/distributed threshold)
  maxEntries: 5000,
} as const;

let activeRateLimitStore: RateLimitStore = new BoundedInMemoryRateLimitStore(
  LOGIN_RATE_LIMIT_POLICY.maxEntries
);

export function setLoginRateLimitStore(customStore: RateLimitStore): void {
  activeRateLimitStore = customStore;
}

export function getLoginRateLimitStore(): RateLimitStore {
  return activeRateLimitStore;
}

function normalizeIdentifier(identifier: string): string {
  return (identifier || '').trim().toLowerCase().slice(0, 128);
}

function computeProgressiveLockoutMs(failedCount: number): number {
  if (failedCount < LOGIN_RATE_LIMIT_POLICY.accountIpLockoutThreshold) {
    return 0;
  }
  if (failedCount <= 7) {
    return LOGIN_RATE_LIMIT_POLICY.tier1LockoutMs;
  }
  if (failedCount <= 9) {
    return LOGIN_RATE_LIMIT_POLICY.tier2LockoutMs;
  }
  return LOGIN_RATE_LIMIT_POLICY.tier3LockoutMs;
}

export interface LayeredRateLimitCheckResult {
  allowed: boolean;
  retryAfterSeconds?: number;
  progressiveDelayMs: number;
  blockedByLayer?: 'ACCOUNT_AND_IP' | 'CLIENT_IP_GLOBAL' | 'DISTRIBUTED_ACCOUNT_PROTECTION';
}

export function checkLoginRateLimit(
  identifier: string,
  clientIp: string = '127.0.0.1',
  nowMs: number = Date.now()
): LayeredRateLimitCheckResult {
  const normAccount = normalizeIdentifier(identifier);
  const normIp = (clientIp || '127.0.0.1').trim().toLowerCase().slice(0, 64);

  const pairKey = `acct_ip:${normAccount}:${normIp}`;
  const ipKey = `ip_global:${normIp}`;
  const acctDistKey = `acct_dist:${normAccount}`;

  // 1. Check Combined Account + IP bucket
  const pairRec = activeRateLimitStore.get(pairKey, nowMs);
  if (pairRec && pairRec.lockedUntilMs > nowMs) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((pairRec.lockedUntilMs - nowMs) / 1000)),
      progressiveDelayMs: 0,
      blockedByLayer: 'ACCOUNT_AND_IP',
    };
  }

  // 2. Check Per-IP Global bucket
  const ipRec = activeRateLimitStore.get(ipKey, nowMs);
  if (ipRec && ipRec.lockedUntilMs > nowMs) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((ipRec.lockedUntilMs - nowMs) / 1000)),
      progressiveDelayMs: 0,
      blockedByLayer: 'CLIENT_IP_GLOBAL',
    };
  }

  // 3. Check Distributed Multi-IP Account Attack bucket
  const distRec = activeRateLimitStore.get(acctDistKey, nowMs);
  if (distRec && distRec.lockedUntilMs > nowMs) {
    // Allow a clean IP with zero failures on this account to attempt login unless global distributed threshold is extreme (>= 25)
    const hasPriorFailureFromThisIp = Boolean(pairRec && pairRec.failedCount > 0);
    if (hasPriorFailureFromThisIp || distRec.failedCount >= 25) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((distRec.lockedUntilMs - nowMs) / 1000)),
        progressiveDelayMs: 0,
        blockedByLayer: 'DISTRIBUTED_ACCOUNT_PROTECTION',
      };
    }
  }

  const priorFailures = pairRec?.failedCount ?? 0;
  const progressiveDelayMs =
    priorFailures >= 2 ? Math.min(2000, (priorFailures - 1) * 250) : 0;

  return {
    allowed: true,
    progressiveDelayMs,
  };
}

export function recordFailedLoginAttempt(
  identifier: string,
  clientIp: string = '127.0.0.1',
  nowMs: number = Date.now()
): void {
  const normAccount = normalizeIdentifier(identifier);
  const normIp = (clientIp || '127.0.0.1').trim().toLowerCase().slice(0, 64);

  const pairKey = `acct_ip:${normAccount}:${normIp}`;
  const ipKey = `ip_global:${normIp}`;
  const acctDistKey = `acct_dist:${normAccount}`;
  const windowExpiresAt = nowMs + LOGIN_RATE_LIMIT_POLICY.windowMs;

  // 1. Update Combined Account + IP bucket
  const pairRec = activeRateLimitStore.get(pairKey, nowMs) || {
    failedCount: 0,
    firstFailedAtMs: nowMs,
    lastFailedAtMs: nowMs,
    lockedUntilMs: 0,
    expiresAtMs: windowExpiresAt,
  };
  pairRec.failedCount += 1;
  pairRec.lastFailedAtMs = nowMs;
  pairRec.expiresAtMs = windowExpiresAt;
  const pairLockoutMs = computeProgressiveLockoutMs(pairRec.failedCount);
  if (pairLockoutMs > 0) {
    pairRec.lockedUntilMs = nowMs + pairLockoutMs;
  }
  activeRateLimitStore.set(pairKey, pairRec, nowMs);

  // 2. Update Per-IP Global bucket
  const ipRec = activeRateLimitStore.get(ipKey, nowMs) || {
    failedCount: 0,
    firstFailedAtMs: nowMs,
    lastFailedAtMs: nowMs,
    lockedUntilMs: 0,
    expiresAtMs: windowExpiresAt,
  };
  ipRec.failedCount += 1;
  ipRec.lastFailedAtMs = nowMs;
  ipRec.expiresAtMs = windowExpiresAt;
  if (ipRec.failedCount >= LOGIN_RATE_LIMIT_POLICY.ipGlobalLockoutThreshold) {
    ipRec.lockedUntilMs = nowMs + LOGIN_RATE_LIMIT_POLICY.tier3LockoutMs;
  }
  activeRateLimitStore.set(ipKey, ipRec, nowMs);

  // 3. Update Distributed Account Attack bucket
  const distRec = activeRateLimitStore.get(acctDistKey, nowMs) || {
    failedCount: 0,
    firstFailedAtMs: nowMs,
    lastFailedAtMs: nowMs,
    lockedUntilMs: 0,
    expiresAtMs: windowExpiresAt,
    distinctSources: [],
  };
  distRec.failedCount += 1;
  distRec.lastFailedAtMs = nowMs;
  distRec.expiresAtMs = windowExpiresAt;
  const sources = new Set(distRec.distinctSources || []);
  sources.add(normIp);
  distRec.distinctSources = Array.from(sources).slice(0, 50);

  if (
    distRec.failedCount >= LOGIN_RATE_LIMIT_POLICY.accountDistributedThreshold &&
    distRec.distinctSources.length >= LOGIN_RATE_LIMIT_POLICY.accountDistributedMinDistinctIps
  ) {
    distRec.lockedUntilMs = nowMs + LOGIN_RATE_LIMIT_POLICY.tier2LockoutMs;
  }
  activeRateLimitStore.set(acctDistKey, distRec, nowMs);
}

export function resetLoginAttempts(
  identifier?: string,
  clientIp?: string
): void {
  if (!identifier) {
    activeRateLimitStore.clear();
    return;
  }
  const normAccount = normalizeIdentifier(identifier);
  // Strip legacy "login:" prefix if caller passed "login:username"
  const cleanAccount = normAccount.startsWith('login:')
    ? normAccount.slice(6)
    : normAccount;

  if (clientIp) {
    const normIp = clientIp.trim().toLowerCase().slice(0, 64);
    activeRateLimitStore.delete(`acct_ip:${cleanAccount}:${normIp}`);
    activeRateLimitStore.delete(`acct_ip:${normAccount}:${normIp}`);
  } else {
    activeRateLimitStore.delete(`acct_ip:${cleanAccount}:127.0.0.1`);
    activeRateLimitStore.delete(`acct_ip:${normAccount}:127.0.0.1`);
    activeRateLimitStore.delete(`acct_dist:${cleanAccount}`);
    activeRateLimitStore.delete(`acct_dist:${normAccount}`);
  }
}
