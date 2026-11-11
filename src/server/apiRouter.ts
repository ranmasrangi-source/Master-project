import express, { NextFunction, Request, Response } from 'express';
import { GoogleGenAI } from '@google/genai';
import {
  evaluateRbacPermission,
  ResourceDomain,
} from '../data/governanceAndPhases';
import { ActionVerb, AuthenticatedSessionUser, EvidenceArtifact } from '../types/platform';
import {
  checkLoginRateLimit,
  recordFailedLoginAttempt,
  resetLoginAttempts,
} from './auth';
import {
  createSignedEvidenceAccessToken,
  verifyAuditChainIntegrity,
  verifySignedEvidenceAccessToken,
} from './cryptoEngine';
import {
  advanceDestinationStageServer,
  appendAuditEvent,
  authenticateUserSession,
  createSubmissionServer,
  executeCryptographicErasureServer,
  executeDualControlCertificateRevocationServer,
  executeHumanReviewDecisionServer,
  fileAppealOnSubmissionServer,
  getCertificateByVerificationId,
  getDestinationByIdOrCode,
  getEvidenceArtifactById,
  getSubmissionById,
  getTotpCodeForUser,
  listAuditEvents,
  listCertificates,
  listDestinations,
  listDualControlApprovals,
  listSubmissions,
  revokeSessionToken,
  saveUploadedEvidenceArtifact,
  TEST_ACCOUNTS_CREDENTIAL_INFO,
  updateCertificatePrivacyConsentServer,
  validateSessionToken,
} from './db';
import { ingestEvidenceFile } from './evidenceProcessor';
import { runAutomatedFiveSignalCoiCheck } from '../domain/verificationEngine';

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

apiRouter.use(express.json({ limit: '5mb' }));

// Simple per-IP/endpoint rate limiter for public verification & AI endpoints
const endpointRateBuckets = new Map<string, { count: number; resetAtMs: number }>();
function checkEndpointRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): boolean {
  const now = Date.now();
  const bucket = endpointRateBuckets.get(key);
  if (!bucket || now > bucket.resetAtMs) {
    endpointRateBuckets.set(key, { count: 1, resetAtMs: now + windowMs });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= maxRequests;
}

/**
 * Extracts and validates the server-side session token from Authorization Bearer header,
 * X-Session-Token header, or Cookie header. Never trusts client-provided role strings.
 */
function resolveSessionUser(req: Request): AuthenticatedSessionUser | null {
  let token: string | undefined;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (typeof req.headers['x-session-token'] === 'string') {
    token = req.headers['x-session-token'].trim();
  } else if (typeof req.headers.cookie === 'string') {
    const match = req.headers.cookie.match(/(?:^|;\s*)0to8848_session=([^;]+)/);
    if (match) {
      token = decodeURIComponent(match[1]);
    }
  }
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

// 1. Health & Constitutional Gate Status
apiRouter.get('/health', (_req: Request, res: Response) => {
  const dests = listDestinations();
  const audits = listAuditEvents();
  const chainCheck = verifyAuditChainIntegrity(audits);

  res.json({
    status: 'OK',
    platform: '0 TO 8848 — Global Adventure Achievement Platform',
    domain: 'https://0to8848official.com',
    catalogCount: dests.length,
    publishedDestinationsCount: dests.filter(
      (d) => d.researchStage === '5_PUBLISHED'
    ).length,
    proposedDestinationsCount: dests.filter(
      (d) => d.researchStage === '1_PROPOSED'
    ).length,
    auditEventsCount: audits.length,
    auditChainValid: chainCheck.valid,
    constitutionalInvariants: {
      achievementsEarnedNeverBought: true,
      standardDigitalBadgesFree: true,
      humanVerificationFinalAuthority: true,
      aiStrictlyAdvisoryOnly: true,
      paymentsEnabled: false,
      blockchainMintingEnabled: false,
    },
  });
});

// 2. Authentication & Session Endpoints (SEC-AUTH-001)
apiRouter.get('/auth/accounts', (_req: Request, res: Response) => {
  const accounts = Object.values(TEST_ACCOUNTS_CREDENTIAL_INFO).map((acc) => ({
    userId: acc.userId,
    username: acc.username,
    role: acc.role,
    officerCode: acc.officerCode,
    displayName: acc.displayName,
    defaultPasswordHint: acc.defaultPassword,
    currentTotpCode: getTotpCodeForUser(acc.userId),
  }));
  res.json({ accounts });
});

apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const { username, password, totpCode } = req.body as {
    username?: string;
    password?: string;
    totpCode?: string;
  };

  if (!username || !password) {
    return res.status(400).json({
      error: 'MISSING_CREDENTIALS',
      message: 'Both username and password are required.',
    });
  }

  const rateKey = `login:${username.toLowerCase()}`;
  const rateCheck = checkLoginRateLimit(rateKey);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: 'AUTH_RATE_LIMITED',
      retryAfterSeconds: rateCheck.retryAfterSeconds,
      message: `Too many failed login attempts. Account locked for ${rateCheck.retryAfterSeconds}s.`,
    });
  }

  try {
    const result = authenticateUserSession({
      usernameOrUserId: username,
      password,
      totpCode,
    });
    resetLoginAttempts(rateKey);
    res.setHeader(
      'Set-Cookie',
      `0to8848_session=${encodeURIComponent(
        result.sessionToken
      )}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800`
    );
    return res.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Authentication failed.';
    if (msg.startsWith('AUTH_INVALID_CREDENTIALS')) {
      recordFailedLoginAttempt(rateKey);
      return res.status(401).json({ error: 'AUTH_INVALID_CREDENTIALS', message: msg });
    }
    if (msg.startsWith('MFA_REQUIRED') || msg.startsWith('MFA_INVALID_CODE')) {
      recordFailedLoginAttempt(rateKey);
      return res.status(401).json({ error: 'MFA_VERIFICATION_FAILED', message: msg });
    }
    return res.status(400).json({ error: 'AUTH_ERROR', message: msg });
  }
});

apiRouter.post('/auth/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : (req.headers['x-session-token'] as string | undefined);

  if (token) {
    revokeSessionToken(token);
  }
  res.setHeader(
    'Set-Cookie',
    '0to8848_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
  );
  res.json({ status: 'LOGGED_OUT' });
});

apiRouter.get('/auth/session', (req: Request, res: Response) => {
  const user = requireAuth(req, res);
  if (!user) return;
  res.json({ authenticated: true, user });
});

// 3. Authoritative Bootstrap State Endpoint (SEC-DB-001)
apiRouter.get('/bootstrap', (req: Request, res: Response) => {
  const sessionUser = resolveSessionUser(req);
  const destinations = listDestinations();
  const certificates = listCertificates();
  const dualControlApprovals = listDualControlApprovals();
  const auditEvents = listAuditEvents();
  const auditChainStatus = verifyAuditChainIntegrity(auditEvents);

  let submissions = listSubmissions(sessionUser?.role);
  if (sessionUser) {
    const subPerm = evaluateRbacPermission(
      sessionUser.role,
      'ACHIEVEMENT_SUBMISSIONS',
      'READ'
    );
    if (!subPerm.allowed) {
      submissions = [];
    }
  }

  res.json({
    sessionUser,
    destinations,
    submissions,
    certificates,
    dualControlApprovals,
    auditEvents,
    auditChainStatus,
  });
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

// 5. Real Evidence Upload, Parsing, XXE Blocking & Private Vault Signed Access (SEC-EVID-001)
apiRouter.post('/evidence/upload', (req: Request, res: Response) => {
  const user = requireRbac(req, res, 'PRIVATE_EVIDENCE_VAULT', 'CREATE');
  if (!user) return;

  const {
    fileName,
    artifactType,
    destinationId,
    contentBase64,
    rawText,
    permitReferenceCode,
  } = req.body as {
    fileName?: string;
    artifactType?: EvidenceArtifact['type'];
    destinationId?: string;
    contentBase64?: string;
    rawText?: string;
    permitReferenceCode?: string;
  };

  if (!fileName || !artifactType || !destinationId) {
    return res.status(400).json({
      error: 'MISSING_EVIDENCE_PARAMETERS',
      message: 'fileName, artifactType, and destinationId are required.',
    });
  }

  const dest = getDestinationByIdOrCode(destinationId);
  if (!dest) {
    return res.status(404).json({
      error: 'DESTINATION_NOT_FOUND',
      message: `Destination ${destinationId} not found.`,
    });
  }

  let fileBuffer: Buffer;
  if (typeof contentBase64 === 'string' && contentBase64.length > 0) {
    const stripped = contentBase64.replace(/^data:[^;]+;base64,/, '');
    fileBuffer = Buffer.from(stripped, 'base64');
  } else if (typeof rawText === 'string') {
    fileBuffer = Buffer.from(rawText, 'utf8');
  } else {
    return res.status(400).json({
      error: 'MISSING_FILE_CONTENT',
      message: 'Either contentBase64 or rawText file payload must be provided.',
    });
  }

  try {
    const parsedArtifact = ingestEvidenceFile({
      rawBuffer: fileBuffer,
      fileName,
      artifactType,
      destination: dest,
      permitReferenceCode,
    });
    const saved = saveUploadedEvidenceArtifact(user, parsedArtifact);
    return res.status(201).json({ artifact: saved });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Evidence ingestion failed.';
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

    return res.json({
      artifact: record.artifact,
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
    user.role === 'VERIFIED_GUIDE'
  ) {
    submissions = submissions.filter((s) => s.applicantUserId === user.userId);
  }

  res.json({ submissions });
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
    return res.status(201).json({ submission: created });
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
    return res.json(result);
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
    return res.json({ submission: updated });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed to file appeal.';
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

  // Return privacy-filtered public projection (never exposes raw GPX files or internal UUIDs)
  return res.json({
    certificate: {
      verificationId: cert.verificationId,
      holderPublicDisplay: cert.holderPublicDisplay,
      holderPrivacyMode: cert.holderPrivacyMode,
      holderNationality: cert.holderNationality,
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
    },
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

apiRouter.patch(
  '/certificates/:verificationId/privacy',
  (req: Request, res: Response) => {
    const user = requireAuth(req, res);
    if (!user) return;

    try {
      const updated = updateCertificatePrivacyConsentServer({
        actor: user,
        verificationId: req.params.verificationId,
        publicIdentityMode: req.body.publicIdentityMode,
        publicDatePrecision: req.body.publicDatePrecision,
        optInPublicLeaderboards: Boolean(req.body.optInPublicLeaderboards),
      });
      return res.json({ certificate: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Privacy update failed.';
      return res.status(400).json({ error: 'PRIVACY_UPDATE_ERROR', message: msg });
    }
  }
);

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

// 8. Server-Computed Verified Leaderboards (Phase 14)
apiRouter.get('/leaderboards', (_req: Request, res: Response) => {
  const validOptInCerts = listCertificates().filter(
    (c) => c.status === 'VALID' && c.optInPublicLeaderboards
  );

  const grouped: Record<
    string,
    {
      holderUserId: string;
      displayName: string;
      nationality: string;
      verifiedCount: number;
      cumulativeElevationM: number;
      highestApexM: number;
      badges: string[];
    }
  > = {};

  for (const cert of validOptInCerts) {
    if (!grouped[cert.holderUserId]) {
      grouped[cert.holderUserId] = {
        holderUserId: cert.holderUserId,
        displayName: cert.holderPublicDisplay,
        nationality: cert.holderNationality,
        verifiedCount: 0,
        cumulativeElevationM: 0,
        highestApexM: 0,
        badges: [],
      };
    }
    const g = grouped[cert.holderUserId];
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

// 12. Sanitized & Audited Server-Side Advisory AI Assistant (SEC-API-002)
apiRouter.post('/ai/advisory-brief', async (req: Request, res: Response) => {
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

  const sessionUser = resolveSessionUser(req);
  appendAuditEvent({
    actorInternalUuid: sessionUser?.internalActorUuid || 'act-uuid-advisory-ai',
    actorRole: sessionUser?.role || 'VERIFICATION_OFFICER',
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
