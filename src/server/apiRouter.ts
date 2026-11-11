import express, { NextFunction, Request, Response } from 'express';
import { GoogleGenAI } from '@google/genai';
import {
  evaluateRbacPermission,
  ResourceDomain,
} from '../data/governanceAndPhases';
import { ActionVerb, AuthenticatedSessionUser, EvidenceArtifact } from '../types/platform';
import {
  buildClearSessionCookieHeader,
  buildSessionCookieHeader,
  checkLoginRateLimit,
  recordFailedLoginAttempt,
  resetLoginAttempts,
  resolveTrustedClientIp,
} from './auth';
import {
  computeSha256Hex,
  createSignedEvidenceAccessToken,
  verifyAuditChainIntegrity,
  verifySignedEvidenceAccessToken,
} from './cryptoEngine';
import {
  advanceDestinationStageServer,
  appendAuditEvent,
  attemptDemoSeedOperationServer,
  authenticateUserSession,
  buildScopedBootstrapPayload,
  createSubmissionServer,
  executeCryptographicErasureServer,
  executeDualControlCertificateRevocationServer,
  executeHumanReviewDecisionServer,
  fileAppealOnSubmissionServer,
  getCertificateByVerificationId,
  getDestinationByIdOrCode,
  getEvidenceArtifactById,
  getSubmissionById,
  isDemoProvisioningAllowed,
  listAuditEvents,
  listCertificates,
  listDestinations,
  listSubmissions,
  revokeSessionToken,
  sanitizeCertificateForViewer,
  sanitizeSubmissionForViewer,
  saveUploadedEvidenceArtifact,
  updateCertificatePrivacyConsentServer,
  validateSessionToken,
  validateStartupEnvironmentSecurity,
} from './db';
import {
  decodeAndValidateBase64Payload,
  ingestEvidenceFile,
  MAX_EVIDENCE_FILE_BYTES,
  readBoundedUploadStream,
  UPLOAD_STREAM_TIMEOUT_MS,
} from './evidenceProcessor';
import { getWormReplicationStatus } from './wormArchiveService';
import { runAutomatedFiveSignalCoiCheck } from '../domain/verificationEngine';
import { MASTER_21_PHASES } from '../data/governanceAndPhases';

export const apiRouter = express.Router();

// SEC-API-001: Security Headers Middleware
apiRouter.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'"
  );
  next();
});

// BUG-04 Remediation: 15mb JSON limit accounts for 10 MiB binary evidence + 33.3% Base64 overhead + JSON envelope
apiRouter.use(express.json({ limit: '15mb' }));
apiRouter.use((err: any, _req: Request, res: Response, next: NextFunction) => {
  if (err && (err.type === 'entity.too.large' || err.status === 413)) {
    return res.status(413).json({
      error: 'FILE_SIZE_LIMIT_EXCEEDED',
      message: `Request payload exceeds the maximum allowed evidence upload size (${MAX_EVIDENCE_FILE_BYTES} decoded bytes / 15MB JSON envelope).`,
    });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({
      error: 'MALFORMED_JSON_PAYLOAD',
      message: 'Request body is not valid JSON.',
    });
  }
  return next(err);
});

// Simple per-IP/endpoint rate limiter for public verification & AI endpoints
const endpointRateBuckets = new Map<string, { count: number; resetAtMs: number }>();
function checkEndpointRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): boolean {
  const now = Date.now();
  if (endpointRateBuckets.size > 5000) {
    for (const [k, v] of endpointRateBuckets.entries()) {
      if (now > v.resetAtMs) endpointRateBuckets.delete(k);
    }
  }
  const bucket = endpointRateBuckets.get(key);
  if (!bucket || now > bucket.resetAtMs) {
    endpointRateBuckets.set(key, { count: 1, resetAtMs: now + windowMs });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= maxRequests;
}

/**
 * BUG-02 Remediation:
 * Extracts the raw session token and identifies its source (BEARER, HEADER, or COOKIE)
 * so both session validation and logout revocation handle cookie-only sessions identically.
 */
export function extractRawSessionToken(req: Request): {
  token?: string;
  source?: 'BEARER' | 'HEADER' | 'COOKIE';
} {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const t = authHeader.slice(7).trim();
    if (t) return { token: t, source: 'BEARER' };
  }
  if (typeof req.headers['x-session-token'] === 'string') {
    const t = req.headers['x-session-token'].trim();
    if (t) return { token: t, source: 'HEADER' };
  }
  if (typeof req.headers.cookie === 'string') {
    const match = req.headers.cookie.match(/(?:^|;\s*)0to8848_session=([^;]+)/);
    if (match && match[1]) {
      try {
        const decoded = decodeURIComponent(match[1].trim());
        if (decoded) return { token: decoded, source: 'COOKIE' };
      } catch {
        return {};
      }
    }
  }
  return {};
}

/**
 * BUG-02 Remediation:
 * CSRF Protection Middleware for state-changing requests authenticated via Cookie.
 * Blocks cross-origin Origin/Referer headers and simple form-encoded CSRF attacks.
 */
apiRouter.use((req: Request, res: Response, next: NextFunction) => {
  const method = req.method.toUpperCase();
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return next();
  }

  const extracted = extractRawSessionToken(req);
  if (extracted.source === 'COOKIE') {
    const originHeader = req.headers.origin || req.headers.referer;
    if (typeof originHeader === 'string' && originHeader.trim().length > 0) {
      try {
        const originUrl = new URL(originHeader);
        const reqHost = (req.headers.host || '').split(':')[0].toLowerCase();
        const originHost = originUrl.hostname.toLowerCase();
        const allowedHosts = new Set([
          reqHost,
          '0to8848official.com',
          'www.0to8848official.com',
          'localhost',
          '127.0.0.1',
        ]);
        if (!allowedHosts.has(originHost)) {
          return res.status(403).json({
            error: 'CSRF_ORIGIN_MISMATCH',
            message: `Cross-origin state-changing cookie request from "${originHost}" was blocked by CSRF protection.`,
          });
        }
      } catch {
        return res.status(403).json({
          error: 'CSRF_INVALID_ORIGIN_HEADER',
          message: 'Malformed Origin or Referer header on cookie-authenticated mutation.',
        });
      }
    }

    const contentType = (req.headers['content-type'] || '').toLowerCase();
    if (
      contentType.startsWith('application/x-www-form-urlencoded') ||
      contentType.startsWith('text/plain')
    ) {
      return res.status(403).json({
        error: 'CSRF_FORM_ENCODING_BLOCKED',
        message: 'Simple form-encoded state-changing requests are blocked by CSRF protection.',
      });
    }
  }

  return next();
});

function resolveSessionUser(req: Request): AuthenticatedSessionUser | null {
  const { token } = extractRawSessionToken(req);
  return validateSessionToken(token);
}

function requireAuth(
  req: Request,
  res: Response
): AuthenticatedSessionUser | null {
  const user = resolveSessionUser(req);
  if (!user) {
    res.status(401).json({
      error: 'AUTHENTICATION_REQUIRED',
      message:
        'A valid, non-expired server session (with MFA verified for privileged roles) is required.',
    });
    return null;
  }
  return user;
}

function requireRbac(
  req: Request,
  res: Response,
  resource: ResourceDomain,
  action: ActionVerb
): AuthenticatedSessionUser | null {
  const user = requireAuth(req, res);
  if (!user) return null;

  const perm = evaluateRbacPermission(user.role, resource, action);
  if (!perm.allowed) {
    res.status(403).json({
      error: 'RBAC_PERMISSION_DENIED',
      ruleCode: perm.ruleCode,
      qualifier: perm.qualifier,
      message: perm.explanation,
      actorRole: user.role,
      resource,
      action,
    });
    return null;
  }
  return user;
}

// 1. Health, WORM Status & Runtime-Verified Constitutional Gate Status (Part 3 & BUG-09)
apiRouter.get('/health', (_req: Request, res: Response) => {
  const dests = listDestinations();
  const audits = listAuditEvents();
  const chainCheck = verifyAuditChainIntegrity(audits);
  const wormStatus = getWormReplicationStatus();
  const startupCheck = validateStartupEnvironmentSecurity();

  const phase17Spec = MASTER_21_PHASES.find((p) => p.phaseNumber === 17);
  const phase18Spec = MASTER_21_PHASES.find((p) => p.phaseNumber === 18);
  const paymentsLocked = phase17Spec?.status === 'HARD_LOCKED_GATE';
  const blockchainLocked = phase18Spec?.status === 'HARD_LOCKED_GATE';
  const sponsorCannotApproveVerification = !evaluateRbacPermission(
    'SPONSOR_ACCOUNT',
    'VERIFICATION_DECISIONS',
    'APPROVE'
  ).allowed;

  const isHealthy =
    chainCheck.valid &&
    dests.length === 100 &&
    MASTER_21_PHASES.length === 21 &&
    paymentsLocked &&
    blockchainLocked &&
    sponsorCannotApproveVerification;

  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'OK' : 'DEGRADED',
    platform: '0 TO 8848 — Global Adventure Achievement Platform',
    domain: 'https://0to8848official.com',
    catalogCount: dests.length,
    phasesCount: MASTER_21_PHASES.length,
    publishedDestinationsCount: dests.filter(
      (d) => d.researchStage === '5_PUBLISHED'
    ).length,
    proposedDestinationsCount: dests.filter(
      (d) => d.researchStage === '1_PROPOSED'
    ).length,
    auditEventsCount: audits.length,
    auditChainValid: chainCheck.valid,
    auditProtectionLevel: wormStatus.protectionLevel,
    wormReplicated: wormStatus.wormReplicated,
    wormStatus: wormStatus.status,
    demoProvisioningAllowed: isDemoProvisioningAllowed(),
    startupSecuritySafe: startupCheck.safe,
    constitutionalInvariants: {
      achievementsEarnedNeverBought: sponsorCannotApproveVerification && paymentsLocked,
      standardDigitalBadgesFree: paymentsLocked,
      humanVerificationFinalAuthority: true,
      aiStrictlyAdvisoryOnly: true,
      paymentsEnabled: !paymentsLocked,
      blockchainMintingEnabled: !blockchainLocked,
    },
  });
});

apiRouter.get('/audit/worm-status', (_req: Request, res: Response) => {
  res.json(getWormReplicationStatus());
});

apiRouter.post('/admin/demo-seed', (req: Request, res: Response) => {
  try {
    const sessionUser = resolveSessionUser(req);
    const result = attemptDemoSeedOperationServer(
      sessionUser?.internalActorUuid || 'unauthenticated-caller',
      sessionUser?.role || 'PUBLIC_VISITOR'
    );
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Demo seed operation rejected.';
    return res.status(403).json({
      error: 'DEMO_SEED_FORBIDDEN_IN_PRODUCTION',
      message: msg,
    });
  }
});

// 2. Authentication & Session Endpoints (SEC-AUTH-001, BUG-P0-001, BUG-01 & BUG-02 Remediation)
apiRouter.all('/auth/accounts', (_req: Request, res: Response) => {
  return res.status(403).json({
    error: 'PUBLIC_ACCOUNT_DIRECTORY_DISABLED',
    message:
      'Public account directory, password hints, and MFA/TOTP code disclosure are strictly prohibited.',
  });
});

apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const body = (req.body || {}) as {
    username?: string;
    usernameOrEmail?: string;
    password?: string;
    totpCode?: string;
  };
  const rawUsername = (body.username || body.usernameOrEmail || '').trim();
  const password = body.password;
  const totpCode = body.totpCode;

  if (!rawUsername || !password) {
    return res.status(400).json({
      error: 'MISSING_CREDENTIALS',
      message: 'Both username and password are required.',
    });
  }

  const clientIp = resolveTrustedClientIp(req);
  const normalizedUser = rawUsername.toLowerCase();
  const rateCheck = checkLoginRateLimit(normalizedUser, clientIp);
  if (!rateCheck.allowed) {
    res.setHeader('Retry-After', String(rateCheck.retryAfterSeconds ?? 60));
    return res.status(429).json({
      error: 'AUTH_RATE_LIMITED',
      blockedByLayer: rateCheck.blockedByLayer,
      retryAfterSeconds: rateCheck.retryAfterSeconds,
      message: `Too many failed login attempts. Please wait ${rateCheck.retryAfterSeconds}s before retrying.`,
    });
  }

  try {
    const result = authenticateUserSession({
      usernameOrUserId: rawUsername,
      password,
      totpCode,
    });
    resetLoginAttempts(normalizedUser, clientIp);
    const isHttps =
      req.secure ||
      req.headers['x-forwarded-proto'] === 'https' ||
      process.env.NODE_ENV === 'production';
    res.setHeader(
      'Set-Cookie',
      buildSessionCookieHeader(result.sessionToken, {
        isHttps,
        maxAgeSeconds: 28800,
      })
    );
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Authentication failed.';
    if (msg.startsWith('DEMO_ACCOUNT_FORBIDDEN_IN_PRODUCTION')) {
      recordFailedLoginAttempt(normalizedUser, clientIp);
      return res.status(403).json({
        error: 'DEMO_ACCOUNT_FORBIDDEN_IN_PRODUCTION',
        message: 'Demo credentials are disabled in production.',
      });
    }
    if (msg.startsWith('AUTH_INVALID_CREDENTIALS')) {
      recordFailedLoginAttempt(normalizedUser, clientIp);
      return res.status(401).json({
        error: 'AUTH_INVALID_CREDENTIALS',
        message: 'AUTH_INVALID_CREDENTIALS: Invalid username or password.',
      });
    }
    if (msg.startsWith('MFA_REQUIRED') || msg.startsWith('MFA_INVALID_CODE')) {
      recordFailedLoginAttempt(normalizedUser, clientIp);
      return res.status(401).json({
        error: 'MFA_VERIFICATION_FAILED',
        message: msg,
      });
    }
    return res.status(400).json({
      error: 'AUTH_ERROR',
      message: 'Authentication request could not be processed.',
    });
  }
});

apiRouter.post('/auth/logout', (req: Request, res: Response) => {
  const { token } = extractRawSessionToken(req);
  const revoked = token ? revokeSessionToken(token) : false;

  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', buildClearSessionCookieHeader({ isHttps }));
  res.json({ status: 'LOGGED_OUT', sessionRevoked: revoked, revoked });
});

apiRouter.get(['/auth/session', '/auth/me'], (req: Request, res: Response) => {
  const user = requireAuth(req, res);
  if (!user) return;
  res.json({ authenticated: true, user });
});

// 3. Authoritative Role-Scoped Bootstrap State Endpoint (SEC-DB-001 & BUG-P0-003 Remediation)
apiRouter.get('/bootstrap', (req: Request, res: Response) => {
  const sessionUser = resolveSessionUser(req);
  const scopedPayload = buildScopedBootstrapPayload(sessionUser);
  res.json(scopedPayload);
});

// 4. Destinations Catalog & Server-Enforced 5-Stage Progression (SEC-GOV-001, SEC-GOV-003)
apiRouter.get('/destinations', (req: Request, res: Response) => {
  const { region, stage, q } = req.query;
  let results = listDestinations();

  if (typeof region === 'string' && region !== 'ALL') {
    if (region === 'NEPAL_ANCHOR') {
      results = results.filter((d) => d.isNepalOriginAnchor);
    } else {
      results = results.filter((d) => d.region === region);
    }
  }
  if (typeof stage === 'string' && stage !== 'ALL') {
    results = results.filter((d) => d.researchStage === stage);
  }
  if (typeof q === 'string' && q.trim().length > 0) {
    const query = q.toLowerCase();
    results = results.filter(
      (d) =>
        d.officialNameEn.toLowerCase().includes(query) ||
        d.code.toLowerCase().includes(query) ||
        d.countryNames.toLowerCase().includes(query)
    );
  }

  res.json({
    totalCatalogCount: 100,
    matchedCount: results.length,
    destinations: results,
  });
});

apiRouter.post(
  '/destinations/:idOrCode/advance-stage',
  (req: Request, res: Response) => {
    const user = requireAuth(req, res);
    if (!user) return;

    const dest = getDestinationByIdOrCode(req.params.idOrCode);
    if (!dest) {
      return res.status(404).json({
        error: 'NOT_FOUND',
        message: `DESTINATION_NOT_FOUND: ${req.params.idOrCode}`,
      });
    }

    const targetResource: ResourceDomain =
      dest.researchStage === '4_REVIEWED_AND_APPROVED'
        ? 'PUBLIC_DESTINATIONS_STAGE_5'
        : 'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4';

    const requiredAction: ActionVerb =
      dest.researchStage === '1_PROPOSED' || dest.researchStage === '2_UNDER_RESEARCH'
        ? 'UPDATE'
        : dest.researchStage === '3_RESEARCH_COMPLETED'
          ? 'APPROVE'
          : 'PUBLISH';

    const perm = evaluateRbacPermission(
      user.role,
      targetResource,
      requiredAction
    );
    if (!perm.allowed) {
      return res.status(403).json({
        error: 'GOVERNANCE_FORBIDDEN',
        ruleCode: perm.ruleCode,
        message: perm.explanation,
      });
    }

    try {
      const result = advanceDestinationStageServer({
        actor: user,
        destinationIdOrCode: req.params.idOrCode,
        reason: req.body?.reason,
      });
      return res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to advance stage.';
      if (
        msg.startsWith('RBAC_') ||
        msg.startsWith('DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN')
      ) {
        return res.status(403).json({ error: 'GOVERNANCE_FORBIDDEN', message: msg });
      }
      if (msg.startsWith('DESTINATION_NOT_FOUND')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: msg });
      }
      return res.status(400).json({ error: 'STAGE_TRANSITION_ERROR', message: msg });
    }
  }
);

// 5. Real Evidence Upload, Streaming & Base64 Bounds, XXE Blocking & Private Vault Signed Access (SEC-EVID-001 & BUG-04)
apiRouter.post('/evidence/upload', async (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'PRIVATE_EVIDENCE_VAULT', 'CREATE');
  if (!user) return;

  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const isBinaryStream = contentType.startsWith('application/octet-stream');

  let fileName: string | undefined;
  let artifactType: EvidenceArtifact['type'] | undefined;
  let destinationId: string | undefined;
  let permitReferenceCode: string | undefined;
  let fileBuffer: Buffer;

  try {
    if (isBinaryStream) {
      fileName =
        typeof req.headers['x-file-name'] === 'string'
          ? req.headers['x-file-name'].trim()
          : undefined;
      artifactType =
        typeof req.headers['x-artifact-type'] === 'string'
          ? (req.headers['x-artifact-type'].trim() as EvidenceArtifact['type'])
          : undefined;
      destinationId =
        typeof req.headers['x-destination-id'] === 'string'
          ? req.headers['x-destination-id'].trim()
          : undefined;
      permitReferenceCode =
        typeof req.headers['x-permit-reference'] === 'string'
          ? req.headers['x-permit-reference'].trim()
          : undefined;

      if (!fileName || !artifactType || !destinationId) {
        return res.status(400).json({
          error: 'MISSING_EVIDENCE_PARAMETERS',
          message:
            'x-file-name, x-artifact-type, and x-destination-id headers are required for binary stream uploads.',
        });
      }

      fileBuffer = await readBoundedUploadStream(
        req,
        MAX_EVIDENCE_FILE_BYTES,
        UPLOAD_STREAM_TIMEOUT_MS
      );
    } else {
      const body = (req.body || {}) as {
        fileName?: string;
        artifactType?: EvidenceArtifact['type'];
        destinationId?: string;
        contentBase64?: string;
        rawText?: string;
        permitReferenceCode?: string;
      };

      fileName = body.fileName;
      artifactType = body.artifactType;
      destinationId = body.destinationId;
      permitReferenceCode = body.permitReferenceCode;

      if (!fileName || !artifactType || !destinationId) {
        return res.status(400).json({
          error: 'MISSING_EVIDENCE_PARAMETERS',
          message: 'fileName, artifactType, and destinationId are required.',
        });
      }

      if (typeof body.contentBase64 === 'string' && body.contentBase64.length > 0) {
        fileBuffer = decodeAndValidateBase64Payload(
          body.contentBase64,
          MAX_EVIDENCE_FILE_BYTES
        );
      } else if (typeof body.rawText === 'string') {
        const rawBytes = Buffer.byteLength(body.rawText, 'utf8');
        if (rawBytes > MAX_EVIDENCE_FILE_BYTES) {
          return res.status(413).json({
            error: 'FILE_SIZE_LIMIT_EXCEEDED',
            message: `Raw text payload (${rawBytes} bytes) exceeds maximum limit of ${MAX_EVIDENCE_FILE_BYTES} bytes.`,
          });
        }
        fileBuffer = Buffer.from(body.rawText, 'utf8');
      } else {
        return res.status(400).json({
          error: 'MISSING_FILE_CONTENT',
          message: 'Either contentBase64, rawText, or binary stream payload must be provided.',
        });
      }
    }

    const dest = getDestinationByIdOrCode(destinationId);
    if (!dest) {
      return res.status(404).json({
        error: 'DESTINATION_NOT_FOUND',
        message: `Destination ${destinationId} not found.`,
      });
    }

    const parsedArtifact = ingestEvidenceFile({
      rawBuffer: fileBuffer,
      fileName,
      artifactType,
      destination: dest,
      permitReferenceCode,
    });
    const saved = saveUploadedEvidenceArtifact(user, parsedArtifact);
    const { vaultStorageKey: _omitKey, ...sanitizedSaved } = saved;
    return res.status(201).json({ artifact: sanitizedSaved });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Evidence ingestion failed.';
    if (msg.startsWith('FILE_SIZE_LIMIT_EXCEEDED')) {
      return res.status(413).json({ error: 'FILE_SIZE_LIMIT_EXCEEDED', message: msg });
    }
    if (msg.startsWith('UPLOAD_STREAM_TIMEOUT')) {
      return res.status(408).json({ error: 'UPLOAD_STREAM_TIMEOUT', message: msg });
    }
    if (msg.startsWith('DUPLICATE_EVIDENCE_SHA256_DETECTED')) {
      return res.status(409).json({ error: 'DUPLICATE_EVIDENCE', message: msg });
    }
    return res.status(400).json({ error: 'EVIDENCE_VALIDATION_FAILED', message: msg });
  }
});

apiRouter.post(
  '/evidence/:artifactId/signed-url',
  (req: Request, res: Response) => {
    const user = requireRbac(req, res, 'PRIVATE_EVIDENCE_VAULT', 'READ');
    if (!user) return;

    const record = getEvidenceArtifactById(req.params.artifactId);
    if (!record) {
      return res.status(404).json({
        error: 'ARTIFACT_NOT_FOUND',
        message: 'Evidence artifact not found in Private Vault.',
      });
    }

    // Adventurers/Guides can ONLY access their own uploaded artifacts
    if (
      user.role === 'REGISTERED_ADVENTURER' ||
      user.role === 'PREMIUM_MEMBER_FUTURE' ||
      user.role === 'VERIFIED_GUIDE'
    ) {
      if (record.uploaderUserId !== user.userId) {
        return res.status(403).json({
          error: 'VAULT_NOT_OWNER',
          message:
            'Adventurers may only access evidence artifacts they uploaded themselves.',
        });
      }
    }

    // Verification & Appeal Officers must pass 5-Signal COI check on the parent submission before accessing private evidence
    if (
      record.submissionId &&
      (user.role === 'VERIFICATION_OFFICER' ||
        user.role === 'SENIOR_VERIFICATION_LEAD' ||
        user.role === 'APPEAL_OFFICER')
    ) {
      const sub = getSubmissionById(record.submissionId);
      if (sub) {
        const coi = runAutomatedFiveSignalCoiCheck(
          {
            userId: user.userId,
            officerCode: user.officerCode,
            displayName: user.displayName,
            role: user.role,
            organizationId: user.organizationId,
            expeditionRosterGroupCode: user.expeditionRosterGroupCode,
            isGuideForUserIds: user.isGuideForUserIds,
          },
          sub,
          sub.status === 'APPEALED'
        );
        if (!coi.overallPassed) {
          return res.status(403).json({
            error: 'VAULT_COI_BLOCKED',
            message: `Private Evidence Vault access blocked by 5-Signal COI: ${coi.blockingReason}`,
          });
        }
      }
    }

    const signed = createSignedEvidenceAccessToken({
      artifactId: record.artifact.id,
      submissionId: record.submissionId || 'unassigned',
      viewerUserId: user.userId,
      ttlSeconds: 900, // 15 minutes max TTL
    });

    return res.json({
      artifactId: record.artifact.id,
      signedToken: signed.token,
      expiresAtEpochMs: signed.expiresAtEpochMs,
      downloadPath: `/api/v1/evidence/${record.artifact.id}/download?token=${encodeURIComponent(
        signed.token
      )}`,
    });
  }
);

apiRouter.get(
  '/evidence/:artifactId/download',
  (req: Request, res: Response) => {
    const user = requireRbac(req, res, 'PRIVATE_EVIDENCE_VAULT', 'READ');
    if (!user) return;

    const token = String(req.query.token || '');
    const verification = verifySignedEvidenceAccessToken(
      token,
      req.params.artifactId,
      user.userId
    );
    if (!verification.valid) {
      return res.status(403).json({
        error: 'INVALID_OR_EXPIRED_VAULT_TOKEN',
        message: verification.reason,
      });
    }

    const record = getEvidenceArtifactById(req.params.artifactId);
    if (!record) {
      return res.status(404).json({ error: 'ARTIFACT_NOT_FOUND' });
    }

    const { vaultStorageKey: _omitKey, ...sanitizedArtifact } = record.artifact;
    return res.json({
      artifact: sanitizedArtifact,
      vaultAccessVerified: true,
      viewerUserId: user.userId,
    });
  }
);

// 6. Submissions, Human Verification & Appeal Tribunal Endpoints (SEC-GOV-002)
apiRouter.get('/submissions', (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'ACHIEVEMENT_SUBMISSIONS', 'READ');
  if (!user) return;

  let submissions = listSubmissions(user.role);
  if (
    user.role === 'REGISTERED_ADVENTURER' ||
    user.role === 'PREMIUM_MEMBER_FUTURE' ||
    user.role === 'VERIFIED_GUIDE' ||
    user.role === 'ORGANIZATION_ADMIN' ||
    user.role === 'DESTINATION_PARTNER'
  ) {
    submissions = submissions.filter((s) => s.applicantUserId === user.userId);
  } else if (
    user.role === 'VERIFICATION_OFFICER' ||
    user.role === 'SENIOR_VERIFICATION_LEAD'
  ) {
    submissions = submissions.filter((s) => s.status !== 'APPEALED');
  } else if (user.role === 'APPEAL_OFFICER') {
    submissions = submissions.filter(
      (s) =>
        s.status === 'APPEALED' &&
        !s.appealRecord?.originalReviewerUserIdsBlocked.includes(user.userId)
    );
  }

  const sanitized = submissions.map((s) => sanitizeSubmissionForViewer(s, user));
  res.json({ submissions: sanitized });
});

apiRouter.post('/submissions', (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'ACHIEVEMENT_SUBMISSIONS', 'CREATE');
  if (!user) return;

  try {
    const created = createSubmissionServer({
      applicant: user,
      destinationId: req.body.destinationId,
      verificationTrack: req.body.verificationTrack || 'STANDARD_DIGITAL',
      applicantDisplayName: req.body.applicantDisplayName || user.displayName,
      applicantNationality: req.body.applicantNationality || 'Nepal (NP)',
      completionDateUtc: req.body.completionDateUtc || new Date().toISOString(),
      applicantStory: req.body.applicantStory || '',
      truthfulnessDeclarationSigned: Boolean(
        req.body.truthfulnessDeclarationSigned
      ),
      guidedByUserId: req.body.guidedByUserId,
      organizationId: req.body.organizationId,
      expeditionRosterGroupCode: req.body.expeditionRosterGroupCode,
      privacyConsent: req.body.privacyConsent || {
        publicIdentityMode: 'FULL_VERIFIED_NAME',
        publicDatePrecision: 'EXACT_DATE',
        optInPublicLeaderboards: true,
      },
      evidenceArtifactIds: req.body.evidenceArtifactIds,
      inlineArtifacts: req.body.inlineArtifacts,
    });
    return res.status(201).json({
      submission: sanitizeSubmissionForViewer(created, user),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Submission creation failed.';
    if (msg.startsWith('DUPLICATE_EVIDENCE')) {
      return res.status(409).json({ error: 'DUPLICATE_EVIDENCE', message: msg });
    }
    return res.status(400).json({ error: 'SUBMISSION_INVALID', message: msg });
  }
});

apiRouter.post('/submissions/:id/review', (req: Request, res: Response) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const sub = getSubmissionById(req.params.id);
  if (!sub) {
    return res.status(404).json({
      error: 'SUBMISSION_NOT_FOUND',
      message: `Submission ${req.params.id} not found.`,
    });
  }

  const targetResource: ResourceDomain =
    sub.status === 'APPEALED'
      ? 'APPEAL_TRIBUNAL_DECISIONS'
      : 'VERIFICATION_DECISIONS';
  const perm = evaluateRbacPermission(user.role, targetResource, 'APPROVE');
  if (!perm.allowed) {
    return res.status(403).json({
      error: 'RBAC_PERMISSION_DENIED',
      ruleCode: perm.ruleCode,
      message: perm.explanation,
    });
  }

  try {
    const result = executeHumanReviewDecisionServer({
      actor: user,
      submissionId: sub.id,
      decision: req.body.decision,
      humanRationale: req.body.humanRationale,
      coiHumanAttestationSigned: Boolean(req.body.coiHumanAttestationSigned),
      reasonCode: req.body.reasonCode,
    });
    return res.json({
      submission: sanitizeSubmissionForViewer(result.submission, user),
      issuedCertificate: result.issuedCertificate
        ? sanitizeCertificateForViewer(result.issuedCertificate, user)
        : undefined,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Review execution failed.';
    if (
      msg.startsWith('COI_BLOCKED') ||
      msg.startsWith('FIREWALL_') ||
      msg.startsWith('ESCALATED_SPLIT_REQUIRES_SENIOR_LEAD')
    ) {
      return res.status(403).json({ error: 'VERIFICATION_BLOCKED', message: msg });
    }
    return res.status(400).json({ error: 'REVIEW_VALIDATION_ERROR', message: msg });
  }
});

apiRouter.post('/submissions/:id/appeal', (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'APPEAL_TRIBUNAL_DECISIONS', 'CREATE');
  if (!user) return;

  try {
    const updated = fileAppealOnSubmissionServer({
      actor: user,
      submissionId: req.params.id,
      appellantGrounds: req.body.appellantGrounds,
      supplementaryEvidenceSummary:
        req.body.supplementaryEvidenceSummary ||
        'Supplementary forensic telemetry attached.',
    });
    return res.json({ submission: sanitizeSubmissionForViewer(updated, user) });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed to file appeal.';
    if (msg.startsWith('APPEAL_OWNERSHIP_FORBIDDEN')) {
      return res.status(403).json({ error: 'APPEAL_OWNERSHIP_FORBIDDEN', message: msg });
    }
    return res.status(400).json({ error: 'APPEAL_FILING_ERROR', message: msg });
  }
});

// 7. Public Certificate Verification, Dual-Control Revocation & Privacy Controls
apiRouter.get('/verify/:verificationId', (req: Request, res: Response) => {
  const ipKey = `verify:${req.ip || 'local'}`;
  if (!checkEndpointRateLimit(ipKey, 120, 60_000)) {
    return res.status(429).json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many verification lookups. Please wait before retrying.',
    });
  }

  const cert = getCertificateByVerificationId(req.params.verificationId);
  if (!cert) {
    return res.status(404).json({
      error: 'CERTIFICATE_NOT_FOUND',
      message: `No certificate found matching Verification ID ${req.params.verificationId}.`,
    });
  }

  // Return privacy-filtered public projection (never exposes raw GPX files, holderUserId, or internal UUIDs)
  return res.json({
    certificate: sanitizeCertificateForViewer(cert, null),
  });
});

apiRouter.post(
  '/certificates/:verificationId/revoke',
  (req: Request, res: Response) => {
    const user = requireRbac(req, res, 'BADGES_AND_CERTIFICATES', 'REVOKE');
    if (!user) return;

    try {
      const result = executeDualControlCertificateRevocationServer({
        actor: user,
        verificationId: req.params.verificationId,
        reason: req.body?.reason,
      });
      return res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Revocation failed.';
      if (
        msg.startsWith('CERT_REVOKE_DENIED') ||
        msg.startsWith('DUAL_CONTROL_SAME_PRINCIPAL_FORBIDDEN')
      ) {
        return res.status(403).json({ error: 'DUAL_CONTROL_FORBIDDEN', message: msg });
      }
      if (msg.startsWith('CERTIFICATE_NOT_FOUND')) {
        return res.status(404).json({ error: 'NOT_FOUND', message: msg });
      }
      return res.status(400).json({ error: 'REVOCATION_ERROR', message: msg });
    }
  }
);

const handleCertificatePrivacyUpdate = (req: Request, res: Response) => {
  const user = requireAuth(req, res);
  if (!user) return;

  try {
    const updated = updateCertificatePrivacyConsentServer({
      actor: user,
      verificationId: req.params.verificationId,
      publicIdentityMode:
        req.body.publicIdentityMode ||
        req.body.holderPrivacyMode ||
        'FULL_NAME',
      publicDatePrecision:
        req.body.publicDatePrecision ||
        req.body.holderDatePrecision ||
        'EXACT_DATE',
      optInPublicLeaderboards: Boolean(req.body.optInPublicLeaderboards),
    });
    return res.json({
      certificate: sanitizeCertificateForViewer(updated, user),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Privacy update failed.';
    if (msg.startsWith('PRIVACY_UPDATE_FORBIDDEN')) {
      return res.status(403).json({ error: 'PRIVACY_UPDATE_FORBIDDEN', message: msg });
    }
    if (msg.startsWith('CERTIFICATE_NOT_FOUND')) {
      return res.status(404).json({ error: 'NOT_FOUND', message: msg });
    }
    return res.status(400).json({ error: 'PRIVACY_UPDATE_ERROR', message: msg });
  }
};

apiRouter.patch('/certificates/:verificationId/privacy', handleCertificatePrivacyUpdate);
apiRouter.post('/certificates/:verificationId/privacy', handleCertificatePrivacyUpdate);

apiRouter.post('/privacy/erasure', (req: Request, res: Response) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const targetUserId = req.body?.targetUserId || user.userId;

  // Users may erase their own account; Governance/Security may execute verified holder erasure requests
  if (
    targetUserId !== user.userId &&
    !['SECURITY_COMPLIANCE_OFFICER', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
      user.role
    )
  ) {
    return res.status(403).json({
      error: 'ERASURE_FORBIDDEN',
      message: 'You may only request cryptographic erasure for your own account.',
    });
  }

  try {
    const result = executeCryptographicErasureServer({
      actor: user,
      targetUserId,
    });
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Erasure failed.';
    return res.status(400).json({ error: 'ERASURE_ERROR', message: msg });
  }
});

// 8. Server-Computed Verified Leaderboards (Phase 14 — Privacy-Preserving Public Projection)
apiRouter.get('/leaderboards', (_req: Request, res: Response) => {
  const validOptInCerts = listCertificates().filter(
    (c) => c.status === 'VALID' && c.optInPublicLeaderboards
  );

  const grouped: Record<
    string,
    {
      standingEntryKey: string;
      displayName: string;
      nationality: string;
      verifiedCount: number;
      cumulativeElevationM: number;
      highestApexM: number;
      badges: string[];
    }
  > = {};

  for (const cert of validOptInCerts) {
    const entryKey = `ldr_${computeSha256Hex(`standing:${cert.holderUserId}`).slice(0, 12)}`;
    if (!grouped[entryKey]) {
      grouped[entryKey] = {
        standingEntryKey: entryKey,
        displayName: cert.holderPublicDisplay,
        nationality: cert.holderNationality,
        verifiedCount: 0,
        cumulativeElevationM: 0,
        highestApexM: 0,
        badges: [],
      };
    }
    const g = grouped[entryKey];
    g.verifiedCount += 1;
    g.cumulativeElevationM += cert.verifiedElevationM;
    if (cert.verifiedElevationM > g.highestApexM) {
      g.highestApexM = cert.verifiedElevationM;
    }
    g.badges.push(`${cert.destinationNameEn} (${cert.verifiedElevationM}m)`);
  }

  res.json({
    standings: Object.values(grouped),
  });
});

// 9. Server-Side 1,680-Permutation RBAC Evaluator & Audit Logs (SEC-RBAC-001)
apiRouter.post('/rbac/evaluate', (req: Request, res: Response) => {
  const { role, resource, action } = req.body as {
    role: AuthenticatedSessionUser['role'];
    resource: ResourceDomain;
    action: ActionVerb;
  };
  if (!role || !resource || !action) {
    return res
      .status(400)
      .json({ error: 'Missing role, resource, or action verb.' });
  }
  const decision = evaluateRbacPermission(role, resource, action);
  return res.json(decision);
});

apiRouter.get('/audit-logs', (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'APPEND_ONLY_AUDIT_LOGS', 'READ');
  if (!user) return;

  const events = listAuditEvents();
  const chainIntegrity = verifyAuditChainIntegrity(events);
  res.json({
    events,
    chainIntegrity,
  });
});

// 10. Phase 17 Payment Hard-Lock Enforcement (Stage D — HTTP 503)
apiRouter.post('/payments/checkout', (_req: Request, res: Response) => {
  return res.status(503).json({
    error: 'PAYMENTS_HARD_DISABLED',
    code: 'PHASE_17_HARD_LOCK',
    message:
      'Constitutional Gate Lock: Payment collection is hard-disabled (PAYMENTS_ENABLED = FALSE) until company registration, legal review, financial compliance, payment-provider approval, and PCI security readiness are formally signed off by the Founder.',
  });
});

// 11. Phase 18 Blockchain Minting Hard-Lock Enforcement (Stage D — HTTP 503)
apiRouter.post('/blockchain/mint', (_req: Request, res: Response) => {
  return res.status(503).json({
    error: 'BLOCKCHAIN_MINTING_HARD_DISABLED',
    code: 'PHASE_18_HARD_LOCK',
    message:
      'Constitutional Gate Lock: Optional Soulbound/NFT credential minting is hard-disabled (BLOCKCHAIN_MINTING_ENABLED = FALSE). The primary relational database is permanently authoritative.',
  });
});

// 12. Sanitized & Audited Server-Side Advisory AI Assistant (SEC-API-002 & BUG-P1-004)
apiRouter.post('/ai/advisory-brief', async (req: Request, res: Response) => {
  const sessionUser = requireAuth(req, res);
  if (!sessionUser) return;

  const allowedAdvisoryRoles = [
    'VERIFICATION_OFFICER',
    'SENIOR_VERIFICATION_LEAD',
    'APPEAL_OFFICER',
    'DESTINATION_RESEARCHER',
    'GOVERNANCE_COMMITTEE',
    'FOUNDER',
  ];
  if (!allowedAdvisoryRoles.includes(sessionUser.role)) {
    return res.status(403).json({
      error: 'ADVISORY_AI_FORBIDDEN',
      message: `Role (${sessionUser.role}) is not authorized to request internal verification forensic briefings.`,
    });
  }

  const { destinationId, destinationCode } = req.body as {
    destinationId?: string;
    destinationCode?: string;
  };

  const lookupKey = destinationId || destinationCode || 'DEST-001';
  const canonicalDest = getDestinationByIdOrCode(lookupKey);
  if (!canonicalDest) {
    return res.status(404).json({
      error: 'DESTINATION_NOT_FOUND',
      message: `Cannot generate advisory brief for unknown destination: ${lookupKey}`,
    });
  }

  appendAuditEvent({
    actorInternalUuid: sessionUser.internalActorUuid,
    actorRole: sessionUser.role,
    actionType: 'ADVISORY_AI_BRIEF_REQUESTED',
    targetEntityType: 'DESTINATION_RECORD',
    targetEntityId: canonicalDest.code,
    summary: `Generated non-decisional advisory forensic brief for ${canonicalDest.code} (${canonicalDest.officialNameEn}).`,
  });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return res.json({
      advisoryOnly: true,
      canApproveAchievements: false,
      source: 'DETERMINISTIC_FORENSIC_RULEBOOK (GEMINI_API_KEY not set)',
      briefing: `Advisory Forensic Brief for ${canonicalDest.officialNameEn} (${canonicalDest.code}, ${canonicalDest.elevationM}m via ${canonicalDest.canonicalRouteName}): 1) Verify continuous GPX/FIT telemetry intersects summit geofence (<= ${canonicalDest.telemetryEnvelope.summitGeofenceRadiusM}m) and elevation band (±${canonicalDest.telemetryEnvelope.elevationBandToleranceM}m); 2) Inspect barometric channel & camera EXIF headers; 3) Confirm permit authority (${canonicalDest.permitAuthority}). Final approval decision rests 100% with human Verification Officers.`,
    });
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `You are an advisory cartographic and mountaineering forensics assistant for the 0 TO 8848 Verification Department. Provide a concise 3-bullet forensic verification & safety briefing for human reviewers evaluating an ascent of ${canonicalDest.officialNameEn} (${canonicalDest.code}, ${canonicalDest.elevationM}m) via ${canonicalDest.canonicalRouteName}. State clearly that final verification approval is strictly reserved for human Verification Officers.`,
    });

    return res.json({
      advisoryOnly: true,
      canApproveAchievements: false,
      source: 'GEMINI_3_FLASH_SERVER_ADVISORY',
      briefing: response.text || 'Advisory briefing generated.',
    });
  } catch {
    return res.json({
      advisoryOnly: true,
      canApproveAchievements: false,
      source: 'FALLBACK_FORENSIC_RULEBOOK',
      briefing: `Advisory Forensic Brief for ${canonicalDest.officialNameEn} (${canonicalDest.code}): Verify summit geofence intersection, barometric pressure altitude consistency, and permit documentation. Human Verification Officer decision required.`,
    });
  }
});
