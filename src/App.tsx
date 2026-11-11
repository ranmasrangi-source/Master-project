import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  KeyRound,
  LogOut,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  XCircle,
} from 'lucide-react';
import { Badge3DViewer } from './components/Badge3DViewer';
import { DESTINATIONS_100_CATALOG } from './data/destinations100';
import {
  ALL_ACTION_VERBS,
  ALL_RESOURCE_DOMAINS,
  ALL_USER_ROLES,
  evaluateRbacPermission,
  MASTER_21_PHASES,
  ResourceDomain,
} from './data/governanceAndPhases';
import {
  BootstrapLifecycleStatus,
  resolveBootstrapFailureState,
  resolveBootstrapSuccessState,
} from './domain/bootstrapClientState';
import {
  ActiveActorProfile,
  DEMO_ACTOR_PROFILES,
  evaluateContextualTelemetry,
  runAutomatedFiveSignalCoiCheck,
} from './domain/verificationEngine';
import {
  AchievementSubmission,
  ActionVerb,
  AppendOnlyAuditEvent,
  AuthenticatedSessionUser,
  DestinationRecord,
  DualControlApprovalRecord,
  EvidenceArtifact,
  PublicCertificateRecord,
  ResearchStage,
  UserRole,
  VerificationTrack,
  WorldRegion,
} from './types/platform';

const HERO_EVEREST_IMG = '/src/assets/images/everest_himalaya_hero_1794391532629.jpg';
const CARD_AMADABLAM_IMG = '/src/assets/images/ama_dablam_expedition_1794391533361.jpg';
const CARD_ANNAPURNA_IMG = '/src/assets/images/annapurna_thorong_pass_1794391535524.jpg';
const CARD_KILIMANJARO_IMG = '/src/assets/images/kilimanjaro_uhuru_glacier_1794391535358.jpg';

type ActiveSection =
  | 'DESTINATIONS'
  | 'SUBMIT_PROVE'
  | 'VERIFICATION_APPEALS'
  | 'CERTIFICATES_STANDINGS'
  | 'GOVERNANCE_PHASES';

export default function App() {
  // Navigation & Global Workspace Preferences
  const [activeSection, setActiveSection] = useState<ActiveSection>('DESTINATIONS');
  const [lang, setLang] = useState<'EN' | 'NE'>('EN');
  const [unitSystem, setUnitSystem] = useState<'METRIC' | 'IMPERIAL'>('METRIC');

  // Authenticated Server Session State (SEC-AUTH-001 & BUG-P0-001: Zero client-side credential/MFA disclosure)
  const [sessionToken, setSessionToken] = useState<string>('');
  const [sessionUser, setSessionUser] = useState<AuthenticatedSessionUser | null>(null);
  const [loginUsername, setLoginUsername] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [loginTotp, setLoginTotp] = useState<string>('');
  const [authLoading, setAuthLoading] = useState<boolean>(false);

  // Server-Synchronized Catalog, Submissions, Certificates, Dual-Control & Audit Ledger (BUG-08: Zero demo records in initial state)
  const [bootstrapStatus, setBootstrapStatus] = useState<BootstrapLifecycleStatus>('LOADING');
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);
  const [devDemoBannerLabel, setDevDemoBannerLabel] = useState<string | null>(null);
  const [destinations, setDestinations] = useState<DestinationRecord[]>(DESTINATIONS_100_CATALOG);
  const [submissions, setSubmissions] = useState<AchievementSubmission[]>([]);
  const [certificates, setCertificates] = useState<PublicCertificateRecord[]>([]);
  const [auditEvents, setAuditEvents] = useState<AppendOnlyAuditEvent[]>([]);
  const [auditIntegrityValid, setAuditIntegrityValid] = useState<boolean>(true);
  const [dualControlApprovals, setDualControlApprovals] = useState<DualControlApprovalRecord[]>([]);

  // Destination Explorer Filters
  const [selectedRegion, setSelectedRegion] = useState<WorldRegion | 'ALL' | 'NEPAL_ANCHOR'>('ALL');
  const [selectedStage, setSelectedStage] = useState<ResearchStage | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedDestinationId, setSelectedDestinationId] = useState<string>('dest-001');

  // Submission Lab State
  const [subDestId, setSubDestId] = useState<string>('dest-009');
  const [subTrack, setSubTrack] = useState<VerificationTrack>('STANDARD_DIGITAL');
  const [subHolderName, setSubHolderName] = useState<string>('Tashi Lhamu Sherpa');
  const [subNationality, setSubNationality] = useState<string>('Nepal (NP)');
  const [subCompletionDate, setSubCompletionDate] = useState<string>('2026-11-04');
  const [subMaxElevM, setSubMaxElevM] = useState<number>(6810.5);
  const [subApexDistM, setSubApexDistM] = useState<number>(8.2);
  const [subAscentRate, setSubAscentRate] = useState<number>(280);
  const [subHasBaro, setSubHasBaro] = useState<boolean>(true);
  const [subPermitRef, setSubPermitRef] = useState<string>('DOT-NP-AMD-2026-8841');
  const [subIdentityConsent, setSubIdentityConsent] = useState<
    'FULL_VERIFIED_NAME' | 'DISPLAY_HANDLE_OR_INITIALS' | 'PRIVATE_CREDENTIAL_HOLDER'
  >('FULL_VERIFIED_NAME');
  const [subDatePrecision, setSubDatePrecision] = useState<
    'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY'
  >('EXACT_DATE');
  const [subLeaderboardOptIn, setSubLeaderboardOptIn] = useState<boolean>(true);
  const [subTruthDeclaration, setSubTruthDeclaration] = useState<boolean>(true);
  const [subNarrative, setSubNarrative] = useState<string>(
    'Completed Southwest Ridge ascent from Camp II across Mushroom Ridge to main summit snow dome. Continuous multi-band GNSS + barometric altimeter telemetry and original EXIF summit photographs attached.'
  );
  const [uploadedArtifacts, setUploadedArtifacts] = useState<EvidenceArtifact[]>([]);
  const [uploadStatusMsg, setUploadStatusMsg] = useState<string | null>(null);
  const [submissionFeedback, setSubmissionFeedback] = useState<string | null>(null);

  // Verification Workstation & Appeal Tribunal State
  const [selectedSubmissionId, setSelectedSubmissionId] = useState<string>('sub-queue-101');
  const [coiAttestedByOfficer, setCoiAttestedByOfficer] = useState<boolean>(false);
  const [reviewRationaleInput, setReviewRationaleInput] = useState<string>(
    'Corroborated multi-band GNSS + barometric altitude profile against official route geofence, verified raw EXIF solar geometry, and confirmed official climbing permit.'
  );
  const [appealGroundsInput, setAppealGroundsInput] = useState<string>(
    'Submitting secondary dual-frequency GNSS logger and high-camp barometric log demonstrating continuous summit ridge progression.'
  );
  const [workstationBanner, setWorkstationBanner] = useState<{
    type: 'SUCCESS' | 'ERROR' | 'INFO';
    text: string;
  } | null>(null);
  const [aiBriefText, setAiBriefText] = useState<string | null>(null);
  const [aiBriefLoading, setAiBriefLoading] = useState<boolean>(false);
  const [signedArtifactUrlInfo, setSignedArtifactUrlInfo] = useState<string | null>(null);

  // Public Certificate Verifier & Leaderboard State (BUG-08: Do not pre-fill sample verification ID before server bootstrap)
  const [verifyLookupId, setVerifyLookupId] = useState<string>('');
  const [leaderboardMetric, setLeaderboardMetric] = useState<
    'ELEVATION_SUM' | 'VERIFIED_COUNT' | 'HIGHEST_APEX'
  >('ELEVATION_SUM');

  // Governance & RBAC Tester State
  const [testRole, setTestRole] = useState<UserRole>('VERIFICATION_OFFICER');
  const [testResource, setTestResource] = useState<ResourceDomain>('VERIFICATION_DECISIONS');
  const [testVerb, setTestVerb] = useState<ActionVerb>('APPROVE');
  const [gateTestMessage, setGateTestMessage] = useState<string | null>(null);

  const authHeaders = useCallback((): Record<string, string> => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (sessionToken) {
      headers.Authorization = `Bearer ${sessionToken}`;
    }
    return headers;
  }, [sessionToken]);

  const fetchBootstrapData = useCallback(
    async (tokenOverride?: string, explicitDevDemoMode: boolean = false) => {
      setBootstrapStatus('LOADING');
      setBootstrapError(null);
      try {
        const headers: Record<string, string> = {};
        const tok = tokenOverride !== undefined ? tokenOverride : sessionToken;
        if (tok) headers.Authorization = `Bearer ${tok}`;

        const bootRes = await fetch('/api/v1/bootstrap', { headers });
        if (!bootRes.ok) {
          throw new Error(`Bootstrap request returned HTTP ${bootRes.status}.`);
        }

        const data = await bootRes.json();
        const nextState = resolveBootstrapSuccessState(data);
        setBootstrapStatus(nextState.status);
        setBootstrapError(null);
        setDevDemoBannerLabel(null);
        setDestinations(nextState.destinations);
        setSubmissions(nextState.submissions);
        setCertificates(nextState.certificates);
        setAuditEvents(nextState.auditEvents);
        setAuditIntegrityValid(nextState.auditIntegrityValid);
        setDualControlApprovals(nextState.dualControlApprovals);
        setSessionUser(nextState.sessionUser);
        if (nextState.certificates.length > 0) {
          setVerifyLookupId((prev) => prev || nextState.certificates[0].verificationId);
        }
      } catch (err) {
        const isOffline = typeof navigator !== 'undefined' && navigator.onLine === false;
        const failState = resolveBootstrapFailureState({
          errorMessage:
            err instanceof Error
              ? err.message
              : 'Failed to load server state from /api/v1/bootstrap.',
          isOffline,
          isProduction: !import.meta.env.DEV,
          explicitDevDemoModeRequested: explicitDevDemoMode,
        });
        setBootstrapStatus(failState.status);
        setBootstrapError(failState.errorMessage);
        setDevDemoBannerLabel(failState.demoBannerLabel);
        setDestinations(failState.destinations);
        setSubmissions(failState.submissions);
        setCertificates(failState.certificates);
        setAuditEvents(failState.auditEvents);
        setAuditIntegrityValid(failState.auditIntegrityValid);
        setDualControlApprovals(failState.dualControlApprovals);
        setSessionUser(failState.sessionUser);
      }
    },
    [sessionToken]
  );

  useEffect(() => {
    fetchBootstrapData();
  }, [fetchBootstrapData]);

  // Map current authenticated user (or public visitor) to an ActorProfile for COI preview
  const activeActor: ActiveActorProfile = useMemo(() => {
    if (!sessionUser) {
      return {
        userId: 'anonymous-visitor',
        displayName: 'Unauthenticated Public Visitor',
        role: 'PUBLIC_VISITOR',
        officerCode: 'PUBLIC-VISITOR',
        isGuideForUserIds: [],
      };
    }
    const matchingDemo = Object.values(DEMO_ACTOR_PROFILES).find(
      (p) => p.userId === sessionUser.userId
    );
    if (matchingDemo) return matchingDemo;
    return {
      userId: sessionUser.userId,
      displayName: sessionUser.displayName,
      role: sessionUser.role,
      officerCode: sessionUser.officerCode,
      organizationId: sessionUser.organizationId,
      expeditionRosterGroupCode: sessionUser.expeditionRosterGroupCode,
      isGuideForUserIds: sessionUser.isGuideForUserIds || [],
    };
  }, [sessionUser]);

  // Authenticate with Backend Server (scrypt password + RFC 6238 TOTP MFA)
  const handleServerLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setWorkstationBanner(null);
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword,
          totpCode: loginTotp.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setWorkstationBanner({
          type: 'ERROR',
          text: `HTTP ${res.status} (${data.error}): ${data.message}`,
        });
        return;
      }
      setSessionToken(data.sessionToken);
      setSessionUser(data.user);
      setCoiAttestedByOfficer(false);
      await fetchBootstrapData(data.sessionToken);
      setWorkstationBanner({
        type: 'SUCCESS',
        text: `Authenticated server session established for ${data.user.displayName} [${data.user.role}] (MFA Verified: ${data.user.mfaVerified}).`,
      });
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Network error communicating with authentication server.',
      });
    } finally {
      setAuthLoading(false);
    }
  };

  const handleServerLogout = async () => {
    try {
      if (sessionToken) {
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: authHeaders(),
        });
      }
    } finally {
      setSessionToken('');
      setSessionUser(null);
      setCoiAttestedByOfficer(false);
      await fetchBootstrapData('');
      setWorkstationBanner({
        type: 'INFO',
        text: 'Session revoked on server. Now browsing as PUBLIC_VISITOR.',
      });
    }
  };

  // Format elevation helper
  const formatElev = (m: number) => {
    if (unitSystem === 'METRIC') {
      return `${m.toLocaleString()} m`;
    }
    return `${Math.round(m * 3.28084).toLocaleString()} ft`;
  };

  // Filtered 100 Destinations
  const filteredDestinations = useMemo(() => {
    return destinations.filter((d) => {
      if (selectedRegion === 'NEPAL_ANCHOR' && !d.isNepalOriginAnchor) return false;
      if (selectedRegion !== 'ALL' && selectedRegion !== 'NEPAL_ANCHOR' && d.region !== selectedRegion)
        return false;
      if (selectedStage !== 'ALL' && d.researchStage !== selectedStage) return false;
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const matchName = d.officialNameEn.toLowerCase().includes(q);
        const matchCode = d.code.toLowerCase().includes(q);
        const matchCountry = d.countryNames.toLowerCase().includes(q);
        const matchRoute = d.canonicalRouteName.toLowerCase().includes(q);
        if (!matchName && !matchCode && !matchCountry && !matchRoute) return false;
      }
      return true;
    });
  }, [destinations, selectedRegion, selectedStage, searchQuery]);

  const selectedDestination = useMemo(
    () => destinations.find((d) => d.id === selectedDestinationId) || destinations[0],
    [destinations, selectedDestinationId]
  );

  const publishedDestinations = useMemo(
    () => destinations.filter((d) => d.researchStage === '5_PUBLISHED'),
    [destinations]
  );

  const submissionTargetDestination = useMemo(
    () =>
      publishedDestinations.find((d) => d.id === subDestId) ||
      publishedDestinations[0] ||
      destinations[0],
    [publishedDestinations, destinations, subDestId]
  );

  const liveTelemetryPreview = useMemo(
    () =>
      evaluateContextualTelemetry(
        submissionTargetDestination,
        subMaxElevM,
        subApexDistM,
        subAscentRate,
        subHasBaro
      ),
    [submissionTargetDestination, subMaxElevM, subApexDistM, subAscentRate, subHasBaro]
  );

  const selectedSubmission: AchievementSubmission | null = useMemo(
    () =>
      submissions.find((s) => s.id === selectedSubmissionId) ||
      submissions[0] ||
      null,
    [submissions, selectedSubmissionId]
  );

  const activeCoiResult = useMemo(() => {
    if (!selectedSubmission) {
      return {
        overallPassed: true,
        signals: [],
        blockingReason: undefined,
      };
    }
    return runAutomatedFiveSignalCoiCheck(
      activeActor,
      selectedSubmission,
      selectedSubmission.status === 'APPEALED'
    );
  }, [activeActor, selectedSubmission]);

  const lookedUpCertificate = useMemo(() => {
    if (bootstrapStatus !== 'READY' && bootstrapStatus !== 'DEV_DEMO_FIXTURE_MODE') {
      return undefined;
    }
    const clean = verifyLookupId.trim().toLowerCase();
    if (!clean) return undefined;
    return certificates.find(
      (c) => c.verificationId.toLowerCase() === clean
    );
  }, [certificates, verifyLookupId, bootstrapStatus]);

  // Server-Enforced Advance Destination Research Stage handler (SEC-GOV-001 & SEC-GOV-003 Dual-Control 2P)
  const handleAdvanceDestinationStage = async (dest: DestinationRecord) => {
    setWorkstationBanner(null);
    try {
      const res = await fetch(`/api/v1/destinations/${encodeURIComponent(dest.id)}/advance-stage`, {
        method: 'POST',
        headers: authHeaders(),
      });
      const data = await res.json();
      await fetchBootstrapData();
      if (!res.ok) {
        setWorkstationBanner({
          type: 'ERROR',
          text: `HTTP ${res.status} (${data.error}): ${data.message}`,
        });
        return;
      }
      setWorkstationBanner({
        type: data.status === 'PENDING_SECOND_PRINCIPAL' ? 'INFO' : 'SUCCESS',
        text: data.message,
      });
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Failed to contact server for destination stage transition.',
      });
    }
  };

  // Real Evidence File Upload Handler (SEC-EVID-001: SHA-256, Magic Bytes, XXE Block, GPX/EXIF Parsing)
  const handleEvidenceFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadStatusMsg('Uploading and running server-side SHA-256 & forensic parser...');
    try {
      const arrayBuf = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuf);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const contentBase64 = btoa(binary);

      const lower = file.name.toLowerCase();
      const artifactType: EvidenceArtifact['type'] = lower.endsWith('.gpx')
        ? 'GPX_TELEMETRY'
        : lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.png')
        ? 'RAW_EXIF_PHOTO'
        : subTrack === 'HISTORICAL_DOCUMENTARY'
        ? 'MINISTRY_LEGACY_CERTIFICATE'
        : 'OFFICIAL_PERMIT_DOC';

      const res = await fetch('/api/v1/evidence/upload', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          fileName: file.name,
          artifactType,
          destinationId: submissionTargetDestination.id,
          permitReferenceCode: subPermitRef,
          contentBase64,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setUploadStatusMsg(`Upload Blocked (${data.error}): ${data.message}`);
        return;
      }
      const art: EvidenceArtifact = data.artifact;
      setUploadedArtifacts((prev) => [...prev, art]);
      if (art.extractedMetadata.recordedMaxElevationM) {
        setSubMaxElevM(art.extractedMetadata.recordedMaxElevationM);
      }
      if (art.extractedMetadata.distanceSummitedFromApexM !== undefined) {
        setSubApexDistM(art.extractedMetadata.distanceSummitedFromApexM);
      }
      if (art.extractedMetadata.rolling15mMaxAscentMPerHr !== undefined) {
        setSubAscentRate(art.extractedMetadata.rolling15mMaxAscentMPerHr);
      }
      setUploadStatusMsg(
        `Verified & Stored in Private Vault: ${art.fileName} (SHA-256: ${art.sha256PostUploadDigest.slice(0, 20)}...)`
      );
      await fetchBootstrapData();
    } catch {
      setUploadStatusMsg('Failed to upload evidence file to Private Vault.');
    }
  };

  // Submit New Achievement Application via Server API
  const handleCreateSubmission = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmissionFeedback(null);
    try {
      const res = await fetch('/api/v1/submissions', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          destinationId: submissionTargetDestination.id,
          verificationTrack: subTrack,
          applicantDisplayName: subHolderName,
          applicantNationality: subNationality,
          completionDateUtc: `${subCompletionDate}T06:30:00Z`,
          applicantStory: subNarrative,
          truthfulnessDeclarationSigned: subTruthDeclaration,
          privacyConsent: {
            publicIdentityMode: subIdentityConsent,
            publicDatePrecision: subDatePrecision,
            optInPublicLeaderboards: subLeaderboardOptIn,
          },
          evidenceArtifactIds: uploadedArtifacts.map((a) => a.id),
        }),
      });
      const data = await res.json();
      await fetchBootstrapData();
      if (!res.ok) {
        setSubmissionFeedback(`HTTP ${res.status} (${data.error}): ${data.message}`);
        return;
      }
      setSelectedSubmissionId(data.submission.id);
      setUploadedArtifacts([]);
      setSubmissionFeedback(
        `Dossier ${data.submission.submissionCode} persisted in SQLite & Private Evidence Vault. Routed to Independent Verification Department.`
      );
    } catch {
      setSubmissionFeedback('Network error submitting achievement dossier.');
    }
  };

  // Execute Human Verification Decision or Appeal Tribunal Decision on Server (SEC-GOV-002)
  const handleExecuteHumanDecision = async (
    decisionType:
      | 'APPROVE'
      | 'REJECT'
      | 'REQUEST_ADDITIONAL_EVIDENCE'
      | 'OVERTURN_AND_APPROVE'
      | 'UPHOLD_REJECTION'
  ) => {
    if (!selectedSubmission) return;
    setWorkstationBanner(null);
    try {
      const res = await fetch(
        `/api/v1/submissions/${encodeURIComponent(selectedSubmission.id)}/review`,
        {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            decision: decisionType,
            humanRationale: reviewRationaleInput,
            coiHumanAttestationSigned: coiAttestedByOfficer,
          }),
        }
      );
      const data = await res.json();
      await fetchBootstrapData();
      if (!res.ok) {
        setWorkstationBanner({
          type: 'ERROR',
          text: `HTTP ${res.status} (${data.error}): ${data.message}`,
        });
        return;
      }
      if (data.issuedCertificate) {
        setVerifyLookupId(data.issuedCertificate.verificationId);
      }
      setWorkstationBanner({
        type: 'SUCCESS',
        text: data.issuedCertificate
          ? `Human Verification Complete (${data.submission.status}): Free 3D Badge & 128-bit CSPRNG Certificate (${data.issuedCertificate.verificationId}) issued.`
          : `Server recorded ${decisionType}. Submission status is now ${data.submission.status}.`,
      });
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Failed to execute human verification decision on server.',
      });
    }
  };

  // File Formal Appeal against a Rejected Submission
  const handleFileAppeal = async () => {
    if (!selectedSubmission) return;
    setWorkstationBanner(null);
    try {
      const res = await fetch(
        `/api/v1/submissions/${encodeURIComponent(selectedSubmission.id)}/appeal`,
        {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            appellantGrounds: appealGroundsInput,
            supplementaryEvidenceSummary:
              'Attached backup barometric log & witness attestation for Independent Appeal Review Team.',
          }),
        }
      );
      const data = await res.json();
      await fetchBootstrapData();
      if (!res.ok) {
        setWorkstationBanner({
          type: 'ERROR',
          text: `HTTP ${res.status} (${data.error}): ${data.message}`,
        });
        return;
      }
      setWorkstationBanner({
        type: 'SUCCESS',
        text: `Appeal filed (${data.submission.appealRecord?.appealId}). Original reviewer(s) hard-blocked from Appeal Tribunal.`,
      });
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Failed to file appeal on server.',
      });
    }
  };

  // Request Short-TTL Signed URL for Private Vault Artifact (SEC-EVID-001)
  const handleRequestSignedEvidenceUrl = async (artifactId: string) => {
    setSignedArtifactUrlInfo(null);
    try {
      const res = await fetch(
        `/api/v1/evidence/${encodeURIComponent(artifactId)}/signed-url`,
        {
          method: 'POST',
          headers: authHeaders(),
        }
      );
      const data = await res.json();
      if (!res.ok) {
        setSignedArtifactUrlInfo(`Access Denied (${data.error}): ${data.message}`);
        return;
      }
      setSignedArtifactUrlInfo(
        `Short-TTL Signed URL Issued (Expires: ${new Date(data.expiresAtEpochMs).toISOString()}): ${data.downloadPath}`
      );
    } catch {
      setSignedArtifactUrlInfo('Error requesting signed evidence URL.');
    }
  };

  // Trigger Server-Side Advisory AI Brief (Non-Decisional)
  const handleRequestServerAiBrief = async () => {
    if (!selectedSubmission) return;
    setAiBriefLoading(true);
    setAiBriefText(null);
    try {
      const response = await fetch('/api/v1/ai/advisory-brief', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          destinationId: selectedSubmission.destinationId,
          destinationCode: selectedSubmission.destinationId.toUpperCase(),
        }),
      });
      const data = await response.json();
      setAiBriefText(`[${data.source}] ${data.briefing}`);
    } catch {
      setAiBriefText(
        '[DETERMINISTIC_FORENSIC_FALLBACK] Advisory check: Corroborate GPX apex geofence intersection, barometric altitude channel, raw EXIF solar azimuth, and official permit.'
      );
    } finally {
      setAiBriefLoading(false);
    }
  };

  // Dual-Control Certificate Revocation or GDPR User Erasure via Server API (SEC-GOV-003 & SEC-PRIV-001)
  const handleCertificateLifecycleAction = async (
    cert: PublicCertificateRecord,
    mode: 'DUAL_CONTROL_REVOKE' | 'GDPR_USER_ERASURE_SHRED'
  ) => {
    setWorkstationBanner(null);
    try {
      if (mode === 'DUAL_CONTROL_REVOKE') {
        const res = await fetch(
          `/api/v1/certificates/${encodeURIComponent(cert.verificationId)}/revoke`,
          {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
              reason:
                'REVOKED under Dual-Control Governance Resolution: Post-issuance audit invalidated achievement. Removed from public standings.',
            }),
          }
        );
        const data = await res.json();
        await fetchBootstrapData();
        if (!res.ok) {
          setWorkstationBanner({
            type: 'ERROR',
            text: `HTTP ${res.status} (${data.error}): ${data.message}`,
          });
          return;
        }
        setWorkstationBanner({
          type: data.status === 'PENDING_SECOND_PRINCIPAL' ? 'INFO' : 'SUCCESS',
          text: data.message,
        });
      } else {
        const res = await fetch('/api/v1/privacy/erasure', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ targetUserId: cert.holderUserId }),
        });
        const data = await res.json();
        await fetchBootstrapData();
        if (!res.ok) {
          setWorkstationBanner({
            type: 'ERROR',
            text: `HTTP ${res.status} (${data.error}): ${data.message}`,
          });
          return;
        }
        setWorkstationBanner({
          type: 'SUCCESS',
          text: `Executed AES-256-GCM key-shredding erasure for ${data.shreddedUserId}. Deactivated ${data.deactivatedCertificatesCount} certificate(s) while preserving WORM audit chain.`,
        });
      }
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Failed to execute certificate lifecycle action on server.',
      });
    }
  };

  // Toggle Post-Issuance Leaderboard Opt-In (SEC-PRIV-001)
  const handleToggleCertificateLeaderboard = async (cert: PublicCertificateRecord) => {
    setWorkstationBanner(null);
    try {
      const res = await fetch(
        `/api/v1/certificates/${encodeURIComponent(cert.verificationId)}/privacy`,
        {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({
            publicIdentityMode: cert.holderPrivacyMode,
            publicDatePrecision: cert.holderDatePrecision,
            optInPublicLeaderboards: !cert.optInPublicLeaderboards,
          }),
        }
      );
      const data = await res.json();
      await fetchBootstrapData();
      if (!res.ok) {
        setWorkstationBanner({
          type: 'ERROR',
          text: `HTTP ${res.status} (${data.error}): ${data.message}`,
        });
        return;
      }
      setWorkstationBanner({
        type: 'SUCCESS',
        text: `Updated leaderboard opt-in preference for certificate ${cert.verificationId}.`,
      });
    } catch {
      setWorkstationBanner({
        type: 'ERROR',
        text: 'Failed to update certificate privacy preference.',
      });
    }
  };

  // Test Hard-Locked Payment & Blockchain Endpoints
  const handleTestHardLockedEndpoint = async (endpoint: 'payments' | 'blockchain') => {
    const url =
      endpoint === 'payments' ? '/api/v1/payments/checkout' : '/api/v1/blockchain/mint';
    try {
      const res = await fetch(url, { method: 'POST' });
      const data = await res.json();
      setGateTestMessage(`HTTP ${res.status} — ${data.code}: ${data.message}`);
    } catch {
      setGateTestMessage(
        endpoint === 'payments'
          ? 'HTTP 503 — PHASE_17_HARD_LOCK: Real payment collection is disabled until company registration, legal review, financial compliance, and security readiness are confirmed.'
          : 'HTTP 503 — PHASE_18_HARD_LOCK: Blockchain minting is disabled until legal approval, smart contract security audit, and Founder authorization.'
      );
    }
  };

  // Computed Verified Leaderboards (Strictly from VALID certificates where optInPublicLeaderboards === true)
  const verifiedLeaderboardRows = useMemo(() => {
    const validCerts = certificates.filter(
      (c) => c.status === 'VALID' && c.optInPublicLeaderboards
    );
    const byHolder = new Map<
      string,
      {
        holderUserId: string;
        displayName: string;
        nationality: string;
        verifiedCount: number;
        cumulativeElevationM: number;
        highestApexM: number;
        latestVerificationId: string;
        badges: string[];
      }
    >();

    for (const cert of validCerts) {
      const existing = byHolder.get(cert.holderUserId);
      if (!existing) {
        byHolder.set(cert.holderUserId, {
          holderUserId: cert.holderUserId,
          displayName: cert.holderPublicDisplay,
          nationality: cert.holderNationality,
          verifiedCount: 1,
          cumulativeElevationM: cert.verifiedElevationM,
          highestApexM: cert.verifiedElevationM,
          latestVerificationId: cert.verificationId,
          badges: [cert.destinationNameEn.split(' (')[0]],
        });
      } else {
        existing.verifiedCount += 1;
        existing.cumulativeElevationM += cert.verifiedElevationM;
        existing.highestApexM = Math.max(existing.highestApexM, cert.verifiedElevationM);
        existing.badges.push(cert.destinationNameEn.split(' (')[0]);
      }
    }

    const rows = Array.from(byHolder.values());
    rows.sort((a, b) => {
      if (leaderboardMetric === 'VERIFIED_COUNT') {
        return b.verifiedCount - a.verifiedCount || b.highestApexM - a.highestApexM;
      }
      if (leaderboardMetric === 'HIGHEST_APEX') {
        return b.highestApexM - a.highestApexM || b.cumulativeElevationM - a.cumulativeElevationM;
      }
      return b.cumulativeElevationM - a.cumulativeElevationM;
    });
    return rows;
  }, [certificates, leaderboardMetric]);

  const currentRbacEvaluation = useMemo(
    () => evaluateRbacPermission(testRole, testResource, testVerb),
    [testRole, testResource, testVerb]
  );

  // Stage counts across the 100 destinations
  const stageCounts = useMemo(() => {
    return {
      total: destinations.length,
      published: destinations.filter((d) => d.researchStage === '5_PUBLISHED').length,
      approved: destinations.filter((d) => d.researchStage === '4_REVIEWED_AND_APPROVED').length,
      researchDone: destinations.filter((d) => d.researchStage === '3_RESEARCH_COMPLETED').length,
      underResearch: destinations.filter((d) => d.researchStage === '2_UNDER_RESEARCH').length,
      proposed: destinations.filter((d) => d.researchStage === '1_PROPOSED').length,
    };
  }, [destinations]);

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-white flex flex-col">
      {/* =====================================================================
          MANDATORY 3-ZONE TOP BAR CONTRACT
          Zone 1: Single wordmark | Zone 2: 5 single-line nav links | Zone 3: 1 primary CTA
      ===================================================================== */}
      <header className="sticky top-0 z-40 bg-[#0A0A0A]/95 backdrop-blur-md border-b border-[#C9A86A]/25 px-6 py-4 flex items-center justify-between gap-8">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('DESTINATIONS');
          }}
          className="font-display text-xl font-bold tracking-wider text-[#FFD700] whitespace-nowrap shrink-0"
        >
          0 TO 8848
        </a>

        <nav className="hidden lg:flex items-center gap-7 text-sm font-medium text-[#A1A1AA]">
          <button
            type="button"
            onClick={() => setActiveSection('DESTINATIONS')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
              activeSection === 'DESTINATIONS'
                ? 'text-[#FFD700] border-b border-[#FFD700]'
                : ''
            }`}
          >
            {lang === 'EN' ? '100 Destinations' : '१०० गन्तव्यहरू'}
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('SUBMIT_PROVE')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
              activeSection === 'SUBMIT_PROVE'
                ? 'text-[#FFD700] border-b border-[#FFD700]'
                : ''
            }`}
          >
            {lang === 'EN' ? 'Submit Evidence' : 'प्रमाण पेश गर्नुहोस्'}
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('VERIFICATION_APPEALS')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
              activeSection === 'VERIFICATION_APPEALS'
                ? 'text-[#FFD700] border-b border-[#FFD700]'
                : ''
            }`}
          >
            {lang === 'EN' ? 'Verification & Appeals' : 'प्रमाणीकरण र पुनरावेदन'}
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('CERTIFICATES_STANDINGS')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
              activeSection === 'CERTIFICATES_STANDINGS'
                ? 'text-[#FFD700] border-b border-[#FFD700]'
                : ''
            }`}
          >
            {lang === 'EN' ? 'Registry & Standings' : 'प्रमाणपत्र र वरीयता'}
          </button>
          <button
            type="button"
            onClick={() => setActiveSection('GOVERNANCE_PHASES')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
              activeSection === 'GOVERNANCE_PHASES'
                ? 'text-[#FFD700] border-b border-[#FFD700]'
                : ''
            }`}
          >
            {lang === 'EN' ? 'Governance & 21 Phases' : 'सुशासन र २१ चरण'}
          </button>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => setActiveSection('CERTIFICATES_STANDINGS')}
            className="px-4 py-2 text-xs font-semibold text-[#0A0A0A] bg-[#C9A86A] hover:bg-[#FFD700] rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            {lang === 'EN' ? 'Verify Credential' : 'प्रमाणपत्र जाँच'}
          </button>
        </div>
      </header>

      {/* BUG-08: Bootstrap Loading, Error/Retry, or Explicit Dev Demo Banner */}
      {bootstrapStatus === 'LOADING' && (
        <div
          role="status"
          className="bg-[#18181B] border-b border-[#C9A86A]/30 px-6 py-2 text-xs text-[#C9A86A] flex items-center justify-between"
        >
          <span>Synchronizing verified platform state with /api/v1/bootstrap...</span>
          <span className="font-mono-tabular">LOADING</span>
        </div>
      )}

      {(bootstrapStatus === 'ERROR' || bootstrapStatus === 'OFFLINE_ERROR') && (
        <div
          role="alert"
          className="bg-red-950/80 border-b border-red-500/40 px-6 py-3 text-xs text-red-200 flex flex-wrap items-center justify-between gap-4"
        >
          <div>
            <strong className="text-red-300 font-semibold">
              {bootstrapStatus === 'OFFLINE_ERROR'
                ? 'Offline — Server Synchronization Unavailable: '
                : 'Bootstrap Synchronization Failed: '}
            </strong>
            <span>{bootstrapError}</span>
            <span className="ml-2 text-red-300/80">
              (Demo fallback is disabled to protect verification integrity.)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fetchBootstrapData()}
              className="px-3 py-1 rounded bg-red-500 text-black font-semibold hover:bg-red-400 transition-colors"
            >
              Retry Synchronization
            </button>
            {import.meta.env.DEV && (
              <button
                type="button"
                onClick={() => fetchBootstrapData(undefined, true)}
                className="px-3 py-1 rounded border border-amber-400/50 text-amber-300 hover:bg-amber-950/50 transition-colors"
              >
                Load Labeled Dev Demo Fixtures
              </button>
            )}
          </div>
        </div>
      )}

      {devDemoBannerLabel && (
        <div
          role="status"
          className="bg-amber-950/80 border-b border-amber-500/40 px-6 py-2 text-xs text-amber-200 flex items-center justify-between"
        >
          <span className="font-mono-tabular font-semibold">{devDemoBannerLabel}</span>
          <button
            type="button"
            onClick={() => fetchBootstrapData()}
            className="underline hover:text-white"
          >
            Reconnect to Live Server
          </button>
        </div>
      )}

      {/* =====================================================================
          SERVER-SIDE AUTHENTICATION & MFA SESSION BAR (SEC-AUTH-001)
      ===================================================================== */}
      <div className="bg-[#121214] border-b border-white/10 px-6 py-2.5">
        <div className="max-w-[1400px] mx-auto flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-3 text-[#A1A1AA]">
            <span className="text-[#C9A86A] font-medium">
              {lang === 'EN'
                ? 'BUILT IN NEPAL. MADE FOR THE WORLD.'
                : 'नेपालमा निर्मित। विश्वका लागि समर्पित।'}
            </span>
            <span aria-hidden="true">·</span>
            <span>
              {lang === 'EN'
                ? 'ACHIEVEMENTS MUST BE EARNED, NEVER BOUGHT'
                : 'उपलब्धि कमाउनुपर्छ, किन्न सकिँदैन'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Mobile Section Switcher */}
            <div className="flex lg:hidden items-center gap-1 bg-[#18181B] p-1 rounded-lg border border-white/10">
              {(
                [
                  ['DESTINATIONS', 'Catalog'],
                  ['SUBMIT_PROVE', 'Submit'],
                  ['VERIFICATION_APPEALS', 'Verify'],
                  ['CERTIFICATES_STANDINGS', 'Registry'],
                  ['GOVERNANCE_PHASES', 'Governance'],
                ] as [ActiveSection, string][]
              ).map(([sec, label]) => (
                <button
                  key={sec}
                  type="button"
                  onClick={() => setActiveSection(sec)}
                  className={`px-2 py-1 rounded text-xs font-medium whitespace-nowrap shrink-0 ${
                    activeSection === sec
                      ? 'bg-[#C9A86A] text-[#0A0A0A]'
                      : 'text-[#A1A1AA] hover:text-white'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {sessionUser ? (
              <div className="flex flex-wrap items-center gap-2 bg-[#18181B] border border-emerald-500/40 rounded-lg px-3 py-1">
                <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-white font-medium">
                  {sessionUser.displayName} [{sessionUser.role}]
                </span>
                <span className="font-mono-tabular text-[11px] text-emerald-400">
                  {sessionUser.mfaVerified ? 'MFA:VERIFIED' : 'SESSION:ACTIVE'}
                </span>
                <button
                  type="button"
                  onClick={handleServerLogout}
                  className="ml-1 px-2 py-0.5 rounded bg-red-950/80 border border-red-500/40 text-red-200 hover:bg-red-900 flex items-center gap-1"
                >
                  <LogOut className="w-3 h-3" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <form onSubmit={handleServerLogin} className="flex flex-wrap items-center gap-2">
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  placeholder="Username"
                  autoComplete="username"
                  aria-label="Username"
                  className="w-36 bg-[#18181B] text-white border border-[#C9A86A]/40 rounded px-2 py-1 text-xs"
                />
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Password"
                  autoComplete="current-password"
                  className="w-28 bg-[#18181B] text-white border border-white/15 rounded px-2 py-1 text-xs"
                />
                <input
                  type="text"
                  value={loginTotp}
                  onChange={(e) => setLoginTotp(e.target.value)}
                  placeholder="TOTP MFA"
                  className="w-24 bg-[#18181B] text-[#FFD700] border border-white/15 rounded px-2 py-1 text-xs font-mono-tabular"
                />
                <button
                  type="submit"
                  disabled={authLoading}
                  className="px-2.5 py-1 rounded bg-[#C9A86A] text-[#0A0A0A] font-semibold hover:bg-[#FFD700] transition-colors"
                >
                  {authLoading ? 'Signing in...' : 'Server Login'}
                </button>
              </form>
            )}

            <div className="flex items-center gap-1 bg-[#18181B] p-0.5 rounded border border-white/10">
              <button
                type="button"
                onClick={() => setLang('EN')}
                className={`px-2 py-1 rounded text-xs font-medium whitespace-nowrap shrink-0 ${
                  lang === 'EN' ? 'bg-[#C9A86A] text-[#0A0A0A]' : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                EN
              </button>
              <button
                type="button"
                onClick={() => setLang('NE')}
                className={`px-2 py-1 rounded text-xs font-nepali font-medium whitespace-nowrap shrink-0 ${
                  lang === 'NE' ? 'bg-[#C9A86A] text-[#0A0A0A]' : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                नेपाली
              </button>
            </div>

            <div className="flex items-center gap-1 bg-[#18181B] p-0.5 rounded border border-white/10">
              <button
                type="button"
                onClick={() => setUnitSystem('METRIC')}
                className={`px-2 py-1 rounded text-xs font-mono-tabular whitespace-nowrap shrink-0 ${
                  unitSystem === 'METRIC'
                    ? 'bg-[#C9A86A] text-[#0A0A0A]'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Meters (m)
              </button>
              <button
                type="button"
                onClick={() => setUnitSystem('IMPERIAL')}
                className={`px-2 py-1 rounded text-xs font-mono-tabular whitespace-nowrap shrink-0 ${
                  unitSystem === 'IMPERIAL'
                    ? 'bg-[#C9A86A] text-[#0A0A0A]'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                Feet (ft)
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Global Notification Banner for Server Governance / RBAC Feedback */}
      {workstationBanner && (
        <div
          className={`px-6 py-3 border-b text-xs flex items-center justify-between gap-4 ${
            workstationBanner.type === 'ERROR'
              ? 'bg-red-950/80 border-red-500/40 text-red-200'
              : workstationBanner.type === 'SUCCESS'
              ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-200'
              : 'bg-[#18181B] border-[#C9A86A]/40 text-[#FFD700]'
          }`}
        >
          <div className="max-w-[1400px] mx-auto w-full flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              {workstationBanner.type === 'ERROR' ? (
                <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span>{workstationBanner.text}</span>
            </div>
            <button
              type="button"
              onClick={() => setWorkstationBanner(null)}
              className="text-xs underline whitespace-nowrap shrink-0"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* =====================================================================
          MAIN VIEWPORT CONTAINER
      ===================================================================== */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-8 space-y-12">
        {/* ===================================================================
            SECTION 1: 100 GLOBAL DESTINATIONS & 5-STAGE RESEARCH PIPELINE
        =================================================================== */}
        {activeSection === 'DESTINATIONS' && (
          <>
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
              <div className="lg:col-span-7 flex flex-col justify-between bg-[#121214] border border-white/10 rounded-2xl p-8">
                <div className="space-y-5">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-[#C9A86A] font-mono-tabular">
                    <span>0m SEA LEVEL TO 8,848.86m SAGARMATHA</span>
                    <span aria-hidden="true">·</span>
                    <span>ORIGIN: NEPAL</span>
                    <span aria-hidden="true">·</span>
                    <span>TARGET: WORLDWIDE</span>
                  </div>

                  <h1
                    className="font-display text-3xl sm:text-5xl font-bold text-white tracking-tight leading-tight"
                    style={{ textWrap: 'balance' }}
                  >
                    {lang === 'EN'
                      ? 'Explore. Achieve. Prove.'
                      : 'अन्वेषण गर्नुहोस्। हासिल गर्नुहोस्। प्रमाणित गर्नुहोस्।'}
                  </h1>

                  <p className="text-base text-[#A1A1AA] leading-relaxed max-w-2xl">
                    {lang === 'EN'
                      ? 'The institutional registry of human outdoor achievement across 100 iconic destinations on six continents. Every public recognition is backed by corroborated multi-modal telemetry, raw EXIF forensics, and an independent human verification department—never bought.'
                      : 'छ महाद्वीपका १०० प्रमुख साहसिक गन्तव्यहरूमा मानव उपलब्धिको विश्वव्यापी प्रमाणीकरण प्लेटफर्म। प्रत्येक उपलब्धि स्वतन्त्र मानवीय परीक्षण र बहु-आयामिक प्रमाणद्वारा प्रमाणित हुन्छ।'}
                  </p>

                  <div className="pt-4 border-t border-white/10 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-[#A1A1AA]">
                    <div>01. Every Adventurer Deserves Respect.</div>
                    <div>02. Every Achievement Deserves Recognition.</div>
                    <div>03. Every Journey Has a Story.</div>
                    <div>04. Every Badge Must Be Earned.</div>
                    <div className="sm:col-span-2 text-[#C9A86A] font-medium">
                      05. Adventure Unites The World — Non-Negotiable Rule: Achievements Must Be Earned, Never Bought.
                    </div>
                  </div>
                </div>

                <div className="pt-6 mt-6 border-t border-white/10 flex flex-wrap items-center gap-4">
                  <button
                    type="button"
                    onClick={() => setActiveSection('SUBMIT_PROVE')}
                    className="px-5 py-2.5 text-sm font-semibold text-[#0A0A0A] bg-[#C9A86A] hover:bg-[#FFD700] rounded-lg transition-colors whitespace-nowrap shrink-0"
                  >
                    Submit Achievement Evidence
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveSection('VERIFICATION_APPEALS')}
                    className="px-5 py-2.5 text-sm font-medium text-white bg-[#18181B] border border-[#C9A86A]/40 hover:border-[#FFD700] rounded-lg transition-colors whitespace-nowrap shrink-0"
                  >
                    Inspect Verification Workstation
                  </button>
                </div>
              </div>

              <div className="lg:col-span-5 relative rounded-2xl overflow-hidden border border-[#C9A86A]/30 min-h-[340px] bg-[#121214] flex flex-col justify-end">
                <img
                  src={HERO_EVEREST_IMG}
                  alt="Mount Everest (Sagarmatha) and Lhotse summit pyramid at twilight from high camp"
                  referrerPolicy="no-referrer"
                  className="absolute inset-0 w-full h-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/45 to-transparent" />
                <div className="relative p-6 space-y-2">
                  <div className="flex items-center gap-2 text-xs text-[#FFD700] font-mono-tabular">
                    <span>DEST-001</span>
                    <span aria-hidden="true">·</span>
                    <span>27.9881° N, 86.9250° E</span>
                    <span aria-hidden="true">·</span>
                    <span>{formatElev(8848.86)}</span>
                  </div>
                  <h2 className="font-display text-2xl font-bold text-white">
                    Mount Everest · सगरमाथा
                  </h2>
                  <p className="text-xs text-neutral-300">
                    Survey Department of Nepal (2020 Official Joint Trigonometric & GNSS Survey) · Dual-Control Published
                  </p>
                </div>
              </div>
            </section>

            {/* Full-Width 4-Column Institutional Trust & Catalog Telemetry Strip */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#121214] border border-white/10 rounded-xl p-5">
                <p className="text-xs text-[#A1A1AA]">Global Launch Catalog</p>
                <p className="text-2xl font-bold text-white font-mono-tabular mt-1">
                  100 Distinct Objectives
                </p>
                <p className="text-xs text-[#C9A86A] mt-1">
                  32 Asia (18 Nepal Origin) · 18 Europe · 16 N. America · 14 S. America · 10 Africa · 10 Oceania
                </p>
              </div>
              <div className="bg-[#121214] border border-white/10 rounded-xl p-5">
                <p className="text-xs text-[#A1A1AA]">5-Stage Research Pipeline</p>
                <p className="text-2xl font-bold text-[#FFD700] font-mono-tabular mt-1">
                  {stageCounts.published} Published · {100 - stageCounts.published} In Research
                </p>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  Stage 4 & 5 require Two-Person (2P) Dual-Control governance approval
                </p>
              </div>
              <div className="bg-[#121214] border border-white/10 rounded-xl p-5">
                <p className="text-xs text-[#A1A1AA]">Verification Authority</p>
                <p className="text-2xl font-bold text-white font-mono-tabular mt-1">
                  100% Human Decided
                </p>
                <p className="text-xs text-emerald-400 mt-1">
                  5-Signal COI Blocker · Dual-Review on Tier-A · Independent Appeals
                </p>
              </div>
              <div className="bg-[#121214] border border-white/10 rounded-xl p-5">
                <p className="text-xs text-[#A1A1AA]">Commercial & Crypto Locks</p>
                <p className="text-2xl font-bold text-white font-mono-tabular mt-1">
                  Badges & Certs: Free
                </p>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  Payments & Blockchain hard-locked (HTTP 503) until legal & security gates
                </p>
              </div>
            </section>

            {/* Featured Visual Spotlights Across Continents */}
            <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[
                {
                  img: CARD_AMADABLAM_IMG,
                  code: 'DEST-009',
                  id: 'dest-009',
                  title: 'Ama Dablam · आमा दब्लम',
                  meta: `Nepal · ${formatElev(6812)} · Southwest Ridge`,
                  note: 'Tier-A Technical Alpine · Dual Independent Human Review Required',
                },
                {
                  img: CARD_ANNAPURNA_IMG,
                  code: 'DEST-014',
                  id: 'dest-014',
                  title: 'Annapurna Circuit · थोराङ ला',
                  meta: `Nepal · ${formatElev(5416)} · Thorong La Pass`,
                  note: 'Tier-B High-Altitude Circuit · ACAP & Survey Dept Verified',
                },
                {
                  img: CARD_KILIMANJARO_IMG,
                  code: 'DEST-081',
                  id: 'dest-081',
                  title: 'Mount Kilimanjaro (Uhuru Peak)',
                  meta: `Tanzania · ${formatElev(5895)} · Machame / Lemosho`,
                  note: 'Africa Anchor · TANAPA Official Survey Citation Verified',
                },
              ].map((card) => (
                <div
                  key={card.code}
                  onClick={() => setSelectedDestinationId(card.id)}
                  className="group cursor-pointer bg-[#121214] border border-white/10 hover:border-[#C9A86A]/60 rounded-xl overflow-hidden transition-colors flex flex-col justify-between"
                >
                  <div className="relative h-48 overflow-hidden bg-[#18181B]">
                    <img
                      src={card.img}
                      alt={card.title}
                      referrerPolicy="no-referrer"
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent" />
                    <div className="absolute bottom-3 left-4 right-4 flex items-center justify-between text-xs font-mono-tabular text-[#FFD700]">
                      <span>{card.code}</span>
                      <span>5_PUBLISHED</span>
                    </div>
                  </div>
                  <div className="p-5 space-y-1.5">
                    <h3 className="font-display text-lg font-bold text-white">{card.title}</h3>
                    <p className="text-xs text-[#C9A86A] font-mono-tabular">{card.meta}</p>
                    <p className="text-xs text-[#A1A1AA] pt-1">{card.note}</p>
                  </div>
                </div>
              ))}
            </section>

            {/* Interactive 100-Destination Catalog & 5-Stage Research Inspector */}
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              <div className="lg:col-span-7 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4">
                  <div>
                    <h2 className="font-display text-xl font-bold text-white">
                      01. Global 100-Destination Catalog & Research Registry
                    </h2>
                    <p className="text-xs text-[#A1A1AA] mt-1">
                      Showing {filteredDestinations.length} of 100 distinct global destinations · Select any record to inspect its 16 mandatory attributes & 3D badge
                    </p>
                  </div>

                  <div className="relative w-full sm:w-64">
                    <Search className="w-4 h-4 text-[#A1A1AA] absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search peak, code, country, route..."
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder:text-[#A1A1AA] focus:outline-none focus:border-[#C9A86A]"
                    />
                  </div>
                </div>

                {/* Region Filter Buttons */}
                <div className="flex flex-wrap items-center gap-1.5 bg-[#18181B] p-1.5 rounded-lg border border-white/10">
                  {(
                    [
                      ['ALL', 'All Regions (100)'],
                      ['NEPAL_ANCHOR', 'Nepal Origin (18)'],
                      ['ASIA', 'Asia (32)'],
                      ['EUROPE', 'Europe (18)'],
                      ['NORTH_AMERICA', 'N. America (16)'],
                      ['SOUTH_AMERICA', 'S. America (14)'],
                      ['AFRICA', 'Africa (10)'],
                      ['OCEANIA', 'Oceania (10)'],
                    ] as [WorldRegion | 'ALL' | 'NEPAL_ANCHOR', string][]
                  ).map(([regKey, label]) => (
                    <button
                      key={regKey}
                      type="button"
                      onClick={() => setSelectedRegion(regKey)}
                      className={`px-2.5 py-1.5 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                        selectedRegion === regKey
                          ? 'bg-[#C9A86A] text-[#0A0A0A] font-semibold'
                          : 'text-[#A1A1AA] hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                {/* 5-Stage Research Pipeline Filter Buttons */}
                <div className="flex flex-wrap items-center gap-1.5 bg-[#18181B] p-1.5 rounded-lg border border-white/10">
                  {(
                    [
                      ['ALL', `All Stages (${stageCounts.total})`],
                      ['5_PUBLISHED', `5. Published (${stageCounts.published})`],
                      ['4_REVIEWED_AND_APPROVED', `4. Approved (${stageCounts.approved})`],
                      ['3_RESEARCH_COMPLETED', `3. Research Done (${stageCounts.researchDone})`],
                      ['2_UNDER_RESEARCH', `2. Under Research (${stageCounts.underResearch})`],
                      ['1_PROPOSED', `1. Proposed (${stageCounts.proposed})`],
                    ] as [ResearchStage | 'ALL', string][]
                  ).map(([stKey, label]) => (
                    <button
                      key={stKey}
                      type="button"
                      onClick={() => setSelectedStage(stKey)}
                      className={`px-2.5 py-1 rounded text-xs font-mono-tabular transition-colors whitespace-nowrap shrink-0 ${
                        selectedStage === stKey
                          ? 'bg-white text-[#0A0A0A] font-semibold'
                          : 'text-[#A1A1AA] hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                {/* Scrollable High-Density Table */}
                <div className="max-h-[540px] overflow-y-auto border border-white/10 rounded-xl divide-y divide-white/10">
                  <table className="w-full text-left border-collapse">
                    <thead className="bg-[#18181B] sticky top-0 z-10 text-[11px] uppercase tracking-wider text-[#A1A1AA]">
                      <tr>
                        <th className="py-2.5 px-3">Code</th>
                        <th className="py-2.5 px-3">Official Destination</th>
                        <th className="py-2.5 px-3">Region / ISO</th>
                        <th className="py-2.5 px-3 text-right">Elevation</th>
                        <th className="py-2.5 px-3">Research Stage</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 text-xs">
                      {filteredDestinations.map((dest) => {
                        const isSelected = dest.id === selectedDestination.id;
                        return (
                          <tr
                            key={dest.id}
                            onClick={() => setSelectedDestinationId(dest.id)}
                            className={`cursor-pointer transition-colors ${
                              isSelected
                                ? 'bg-[#C9A86A]/15 text-white'
                                : 'hover:bg-white/5 text-neutral-200'
                            }`}
                          >
                            <td className="py-2.5 px-3 font-mono-tabular text-[#C9A86A] whitespace-nowrap">
                              {dest.code}
                            </td>
                            <td className="py-2.5 px-3">
                              <div className="font-medium text-white">
                                {dest.officialNameEn}
                              </div>
                              {dest.officialNameNe && (
                                <div className="font-nepali text-[11px] text-[#C9A86A]">
                                  {dest.officialNameNe}
                                </div>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-[#A1A1AA] whitespace-nowrap">
                              {dest.region} · {dest.countryIsoCodes.join('/')}
                            </td>
                            <td className="py-2.5 px-3 text-right font-mono-tabular text-[#FFD700] whitespace-nowrap">
                              {formatElev(dest.elevationM)}
                            </td>
                            <td className="py-2.5 px-3 font-mono-tabular whitespace-nowrap">
                              {dest.researchStage === '5_PUBLISHED' ? (
                                <span className="text-emerald-400">5_PUBLISHED</span>
                              ) : dest.researchStage === '4_REVIEWED_AND_APPROVED' ? (
                                <span className="text-[#FFD700]">4_APPROVED</span>
                              ) : (
                                <span className="text-[#A1A1AA]">{dest.researchStage}</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right 5 Columns: Selected Destination 16-Attribute Dossier & 3D Badge */}
              <div className="lg:col-span-5 space-y-6">
                <Badge3DViewer destination={selectedDestination} />

                <div className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-4">
                  <div className="border-b border-white/10 pb-3">
                    <div className="flex items-center gap-2 text-xs font-mono-tabular text-[#C9A86A]">
                      <span>{selectedDestination.code}</span>
                      <span aria-hidden="true">·</span>
                      <span>{selectedDestination.region}</span>
                      <span aria-hidden="true">·</span>
                      <span>
                        {selectedDestination.coordinates.lat.toFixed(4)}°,{' '}
                        {selectedDestination.coordinates.lng.toFixed(4)}°
                      </span>
                    </div>
                    <h3 className="font-display text-2xl font-bold text-white mt-1">
                      {selectedDestination.officialNameEn}
                    </h3>
                    {selectedDestination.officialNameNe && (
                      <p className="font-nepali text-sm text-[#FFD700] mt-0.5">
                        {selectedDestination.officialNameNe} ({selectedDestination.officialNameLocal})
                      </p>
                    )}
                  </div>

                  {/* Research Status Notice */}
                  <div className="p-3.5 rounded-lg bg-[#18181B] border border-white/10 text-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[#A1A1AA]">Research Workflow Stage:</span>
                      <span className="font-mono-tabular font-semibold text-[#FFD700]">
                        {selectedDestination.researchStage}
                      </span>
                    </div>
                    <p className="text-[#A1A1AA]">
                      {selectedDestination.researchStage === '5_PUBLISHED'
                        ? 'Confirmed & Published: Geodetic survey citation and safety criteria verified by Two-Person (2P) Dual-Control Governance. Open for achievement submissions.'
                        : 'UNPUBLISHED RESEARCH RECORD: In accordance with Phase 09 rules, unverified destination data is never presented as confirmed and cannot accept achievement submissions until Stage 5.'}
                    </p>
                    {selectedDestination.researchStage !== '5_PUBLISHED' && (
                      <button
                        type="button"
                        onClick={() => handleAdvanceDestinationStage(selectedDestination)}
                        className="w-full mt-2 px-3 py-2 text-xs font-semibold bg-[#C9A86A] text-[#0A0A0A] hover:bg-[#FFD700] rounded transition-colors"
                      >
                        Server Advance Research Stage (Session Role: {activeActor.role})
                      </button>
                    )}
                  </div>

                  <dl className="divide-y divide-white/10 text-xs">
                    <div className="py-2 flex justify-between gap-4">
                      <dt className="text-[#A1A1AA]">Target / Verified Elevation</dt>
                      <dd className="font-mono-tabular text-white font-semibold text-right">
                        {selectedDestination.elevationM.toLocaleString()} m /{' '}
                        {selectedDestination.elevationFt.toLocaleString()} ft
                      </dd>
                    </div>
                    <div className="py-2 flex flex-col gap-1">
                      <dt className="text-[#A1A1AA]">Authoritative Reference Source</dt>
                      <dd className="text-white">{selectedDestination.elevationReferenceSource}</dd>
                    </div>
                    <div className="py-2 flex flex-col gap-1">
                      <dt className="text-[#A1A1AA]">Canonical Route & Distance</dt>
                      <dd className="text-white">
                        {selectedDestination.canonicalRouteName} ({selectedDestination.routeDistanceKm} km · +
                        {selectedDestination.routeVerticalGainM.toLocaleString()}m gain)
                      </dd>
                    </div>
                    <div className="py-2 flex justify-between gap-4">
                      <dt className="text-[#A1A1AA]">Activity & Grade</dt>
                      <dd className="text-white text-right">
                        {selectedDestination.activityType} · {selectedDestination.difficultyGrade}
                      </dd>
                    </div>
                    <div className="py-2 flex flex-col gap-1">
                      <dt className="text-[#A1A1AA]">Permit & Access Authority</dt>
                      <dd className="text-white">{selectedDestination.permitAndAccessRequirements}</dd>
                    </div>
                    <div className="py-2 flex justify-between gap-4">
                      <dt className="text-[#A1A1AA]">Seasonal Window</dt>
                      <dd className="text-white text-right">{selectedDestination.seasonalWindows}</dd>
                    </div>
                    <div className="py-2 flex flex-col gap-1">
                      <dt className="text-[#A1A1AA]">Contextual Anti-Fraud Telemetry Envelope</dt>
                      <dd className="font-mono-tabular text-[#C9A86A]">
                        Apex Radius &le; {selectedDestination.telemetryEnvelope.summitGeofenceRadiusM}m · Elev Band &plusmn;
                        {selectedDestination.telemetryEnvelope.elevationBandToleranceM}m · Max 15m Ascent &le;{' '}
                        {selectedDestination.telemetryEnvelope.maxPlausibleAscentRateMPerHr} m/hr
                      </dd>
                    </div>
                    <div className="py-2 flex flex-col gap-1">
                      <dt className="text-[#A1A1AA]">Risk & Mountaineering Safety</dt>
                      <dd className="text-neutral-300">{selectedDestination.riskAndSafetySummary}</dd>
                    </div>
                  </dl>

                  {selectedDestination.researchStage === '5_PUBLISHED' && (
                    <button
                      type="button"
                      onClick={() => {
                        setSubDestId(selectedDestination.id);
                        setSubMaxElevM(selectedDestination.elevationM);
                        setActiveSection('SUBMIT_PROVE');
                      }}
                      className="w-full py-2.5 px-4 text-xs font-semibold text-[#0A0A0A] bg-[#C9A86A] hover:bg-[#FFD700] rounded-lg transition-colors"
                    >
                      Submit Achievement Application for {selectedDestination.officialNameEn.split(' (')[0]}
                    </button>
                  )}
                </div>
              </div>
            </section>
          </>
        )}

        {/* ===================================================================
            SECTION 2: ACHIEVEMENT SUBMISSION & EVIDENCE ENGINE (PHASE 11)
        =================================================================== */}
        {activeSection === 'SUBMIT_PROVE' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-7 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-6">
              <div className="border-b border-white/10 pb-4">
                <p className="text-xs text-[#C9A86A] font-mono-tabular">
                  PHASE 11 · MULTI-MODAL EVIDENCE DOSSIER & PRIVACY ENGINE (SEC-EVID-001)
                </p>
                <h2 className="font-display text-2xl font-bold text-white mt-1">
                  Submit Achievement Application
                </h2>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  All raw GPX tracks, EXIF photos, and permits are validated for magic bytes & XXE, hashed with NIST SHA-256 from raw bytes, and isolated in the Private Evidence Vault.
                </p>
              </div>

              <form onSubmit={handleCreateSubmission} className="space-y-5 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <label className="space-y-1.5 block">
                    <span className="text-[#A1A1AA] font-medium">
                      Select Published Destination (Stage 5 Only)
                    </span>
                    <select
                      value={subDestId}
                      onChange={(e) => {
                        const found = publishedDestinations.find((d) => d.id === e.target.value);
                        setSubDestId(e.target.value);
                        if (found) setSubMaxElevM(found.elevationM);
                      }}
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-[#C9A86A]"
                    >
                      {publishedDestinations.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.code} — {d.officialNameEn} ({d.elevationM}m)
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="space-y-1.5 block">
                    <span className="text-[#A1A1AA] font-medium">
                      Verification Evidentiary Track (Correction 2.8)
                    </span>
                    <select
                      value={subTrack}
                      onChange={(e) => setSubTrack(e.target.value as VerificationTrack)}
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-[#C9A86A]"
                    >
                      <option value="STANDARD_DIGITAL">
                        Contemporary Digital Track (GPX/FIT + Raw EXIF + Permit)
                      </option>
                      <option value="HISTORICAL_DOCUMENTARY">
                        Historical Documentary Track (Ministry Certificate + Archival Log)
                      </option>
                    </select>
                  </label>
                </div>

                {/* Real Evidence File Upload Widget */}
                <div className="p-4 rounded-xl bg-[#18181B] border border-[#C9A86A]/35 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-[#FFD700]">
                      Upload Evidence File to Private Vault (.gpx, .jpg, .png, .pdf)
                    </span>
                    <span className="font-mono-tabular text-[11px] text-[#A1A1AA]">
                      NIST SHA-256 + XXE & Magic-Byte Enforced
                    </span>
                  </div>
                  <input
                    type="file"
                    accept=".gpx,.xml,.jpg,.jpeg,.png,.pdf"
                    onChange={handleEvidenceFileUpload}
                    className="w-full text-xs text-neutral-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-[#C9A86A] file:text-[#0A0A0A] hover:file:bg-[#FFD700]"
                  />
                  {uploadStatusMsg && (
                    <p className="text-[11px] font-mono-tabular text-emerald-400">
                      {uploadStatusMsg}
                    </p>
                  )}
                  {uploadedArtifacts.length > 0 && (
                    <div className="space-y-1 pt-1">
                      {uploadedArtifacts.map((art) => (
                        <div
                          key={art.id}
                          className="text-[11px] font-mono-tabular text-neutral-300 flex items-center justify-between"
                        >
                          <span>
                            [{art.type}] {art.fileName}
                          </span>
                          <span className="text-[#C9A86A]">
                            SHA-256: {art.sha256PostUploadDigest.slice(0, 16)}...
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <label className="space-y-1.5 block">
                    <span className="text-[#A1A1AA]">Adventurer Full Name</span>
                    <input
                      type="text"
                      value={subHolderName}
                      onChange={(e) => setSubHolderName(e.target.value)}
                      required
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg px-3 py-2 text-white"
                    />
                  </label>
                  <label className="space-y-1.5 block">
                    <span className="text-[#A1A1AA]">Nationality / Country</span>
                    <input
                      type="text"
                      value={subNationality}
                      onChange={(e) => setSubNationality(e.target.value)}
                      required
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg px-3 py-2 text-white"
                    />
                  </label>
                  <label className="space-y-1.5 block">
                    <span className="text-[#A1A1AA]">Completion Date</span>
                    <input
                      type="date"
                      value={subCompletionDate}
                      onChange={(e) => setSubCompletionDate(e.target.value)}
                      required
                      className="w-full bg-[#18181B] border border-white/15 rounded-lg px-3 py-2 text-white font-mono-tabular"
                    />
                  </label>
                </div>

                {/* Telemetry Parameters */}
                <div className="p-4 rounded-xl bg-[#18181B] border border-white/10 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[#C9A86A]">
                      Extracted GPX / GNSS & Permit Forensic Parameters
                    </span>
                    <span className="font-mono-tabular text-[11px] text-[#A1A1AA]">
                      Official Apex: {submissionTargetDestination.elevationM} m
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">Recorded Max Elev (m)</span>
                      <input
                        type="number"
                        step="0.1"
                        value={subMaxElevM}
                        onChange={(e) => setSubMaxElevM(Number(e.target.value))}
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white font-mono-tabular"
                      />
                    </label>
                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">Distance to Apex (m)</span>
                      <input
                        type="number"
                        step="0.5"
                        value={subApexDistM}
                        onChange={(e) => setSubApexDistM(Number(e.target.value))}
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white font-mono-tabular"
                      />
                    </label>
                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">15m Ascent (m/hr)</span>
                      <input
                        type="number"
                        value={subAscentRate}
                        onChange={(e) => setSubAscentRate(Number(e.target.value))}
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white font-mono-tabular"
                      />
                    </label>
                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">Permit Reference ID</span>
                      <input
                        type="text"
                        value={subPermitRef}
                        onChange={(e) => setSubPermitRef(e.target.value)}
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white font-mono-tabular"
                      />
                    </label>
                  </div>

                  <label className="flex items-center gap-2 text-neutral-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={subHasBaro}
                      onChange={(e) => setSubHasBaro(e.target.checked)}
                      className="rounded border-white/20"
                    />
                    <span>
                      GPX/FIT file includes calibrated barometric pressure altimeter channel (Required on Tier-A peaks)
                    </span>
                  </label>
                </div>

                {/* Granular Holder Privacy Consent */}
                <div className="p-4 rounded-xl bg-[#18181B] border border-white/10 space-y-3">
                  <p className="font-semibold text-white">
                    Granular Public Verification & Privacy Consent (Correction 2.9)
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">Public Certificate Holder Display</span>
                      <select
                        value={subIdentityConsent}
                        onChange={(e) =>
                          setSubIdentityConsent(
                            e.target.value as
                              | 'FULL_VERIFIED_NAME'
                              | 'DISPLAY_HANDLE_OR_INITIALS'
                              | 'PRIVATE_CREDENTIAL_HOLDER'
                          )
                        }
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="FULL_VERIFIED_NAME">Full Verified Name</option>
                        <option value="DISPLAY_HANDLE_OR_INITIALS">Initials Only (e.g. T. L. S.)</option>
                        <option value="PRIVATE_CREDENTIAL_HOLDER">
                          Private Credential Holder (Redacted Public Name)
                        </option>
                      </select>
                    </label>

                    <label className="space-y-1 block">
                      <span className="text-[#A1A1AA]">Public Completion Date Precision</span>
                      <select
                        value={subDatePrecision}
                        onChange={(e) =>
                          setSubDatePrecision(
                            e.target.value as 'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY'
                          )
                        }
                        className="w-full bg-[#121214] border border-white/15 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="EXACT_DATE">Exact Date (YYYY-MM-DD)</option>
                        <option value="MONTH_AND_YEAR_ONLY">Month & Year Only (YYYY-MM)</option>
                        <option value="YEAR_ONLY">Year Only (YYYY)</option>
                      </select>
                    </label>
                  </div>
                  <label className="flex items-center gap-2 text-neutral-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={subLeaderboardOptIn}
                      onChange={(e) => setSubLeaderboardOptIn(e.target.checked)}
                    />
                    <span>
                      Opt-in to include this achievement on Public Verified Leaderboards (Can be toggled off anytime)
                    </span>
                  </label>
                </div>

                <label className="space-y-1.5 block">
                  <span className="text-[#A1A1AA]">Expedition Narrative & Route Conditions</span>
                  <textarea
                    rows={3}
                    value={subNarrative}
                    onChange={(e) => setSubNarrative(e.target.value)}
                    className="w-full bg-[#18181B] border border-white/15 rounded-lg p-3 text-white"
                  />
                </label>

                <label className="flex items-start gap-2.5 p-3 rounded-lg bg-[#18181B] border border-[#C9A86A]/30 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={subTruthDeclaration}
                    onChange={(e) => setSubTruthDeclaration(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span className="text-neutral-200 leading-relaxed">
                    <strong>Truthfulness & Anti-Fraud Declaration:</strong> I solemnly declare that I personally completed this ascent/trek in accordance with the route criteria and that all attached telemetry, photographs, and permits are authentic. I understand that forged evidence results in permanent revocation.
                  </span>
                </label>

                <button
                  type="submit"
                  className="w-full py-3 px-5 text-sm font-semibold text-[#0A0A0A] bg-[#C9A86A] hover:bg-[#FFD700] rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <Upload className="w-4 h-4" />
                  <span>Lock Evidence in Private Vault & Submit to Verification Dept</span>
                </button>

                {submissionFeedback && (
                  <div className="p-4 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-200 flex items-center justify-between gap-4">
                    <span>{submissionFeedback}</span>
                    <button
                      type="button"
                      onClick={() => setActiveSection('VERIFICATION_APPEALS')}
                      className="px-3 py-1.5 bg-emerald-400 text-[#0A0A0A] font-semibold rounded whitespace-nowrap shrink-0"
                    >
                      Open in Workstation
                    </button>
                  </div>
                )}
              </form>
            </div>

            <div className="lg:col-span-5 space-y-6">
              <div className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-4">
                <h3 className="font-display text-lg font-bold text-white">
                  Live Pre-Flight Contextual Telemetry Check (Correction 2.7)
                </h3>
                <p className="text-xs text-[#A1A1AA]">
                  Evaluated against <strong>{submissionTargetDestination.officialNameEn}</strong> route envelope. Note: Anomalies never trigger automatic rejection—they generate diagnostic overlays for human reviewers.
                </p>

                <div className="space-y-2.5 text-xs">
                  {liveTelemetryPreview.summaryNotes.map((note, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-[#18181B] border border-white/10 font-mono-tabular text-neutral-200"
                    >
                      {note}
                    </div>
                  ))}
                </div>

                <div className="p-4 rounded-xl bg-[#18181B] border border-[#C9A86A]/30 space-y-2 text-xs">
                  <p className="font-semibold text-[#FFD700]">
                    Correction 2.2 Enforcement: File Integrity vs. Real-World Authenticity
                  </p>
                  <p className="text-[#A1A1AA] leading-relaxed">
                    <strong>1. SHA-256 Post-Upload Digest:</strong> Proves only that the file stored in the Private Evidence Vault has not been modified since upload. It does <em>not</em> prove a photo or GPX track is genuine.
                  </p>
                  <p className="text-[#A1A1AA] leading-relaxed">
                    <strong>2. Multi-Layered Authenticity Corroboration:</strong> Evaluates C2PA/RAW camera headers, barometric pressure vs. GNSS altitude variance, solar shadow azimuth, perceptual hash duplicate scanning, official permits, and mandatory human reviewer judgment.
                  </p>
                </div>
              </div>

              <Badge3DViewer destination={submissionTargetDestination} compact />
            </div>
          </section>
        )}

        {/* ===================================================================
            SECTION 3: INDEPENDENT HUMAN VERIFICATION WORKSTATION & APPEALS (PHASE 12)
        =================================================================== */}
        {activeSection === 'VERIFICATION_APPEALS' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-4 bg-[#121214] border border-white/10 rounded-2xl p-5 space-y-4">
              <div className="border-b border-white/10 pb-3">
                <p className="text-xs text-[#C9A86A] font-mono-tabular">
                  INDEPENDENT VERIFICATION & APPEALS
                </p>
                <h2 className="font-display text-lg font-bold text-white mt-0.5">
                  Active Dossier Queue ({submissions.length})
                </h2>
                <p className="text-xs text-[#A1A1AA] mt-1">
                  Blind Reviewer Projection: Commercial & membership fields are stripped from all dossiers.
                </p>
              </div>

              <div className="space-y-3">
                {submissions.length === 0 && (
                  <div className="p-4 rounded-xl bg-[#18181B]/60 border border-white/10 text-xs text-[#A1A1AA]">
                    {bootstrapStatus === 'LOADING'
                      ? 'Loading verified submission queue from server...'
                      : 'No achievement dossiers currently in queue.'}
                  </div>
                )}
                {submissions.map((sub) => {
                  const isSelected = selectedSubmission?.id === sub.id;
                  return (
                    <div
                      key={sub.id}
                      onClick={() => {
                        setSelectedSubmissionId(sub.id);
                        setCoiAttestedByOfficer(false);
                        setAiBriefText(null);
                        setSignedArtifactUrlInfo(null);
                      }}
                      className={`cursor-pointer p-4 rounded-xl border transition-colors space-y-2 ${
                        isSelected
                          ? 'bg-[#18181B] border-[#FFD700]'
                          : 'bg-[#18181B]/50 border-white/10 hover:border-white/30'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-mono-tabular">
                        <span className="text-[#C9A86A]">{sub.submissionCode}</span>
                        <span
                          className={
                            sub.status === 'APPROVED'
                              ? 'text-emerald-400'
                              : sub.status === 'APPEALED'
                              ? 'text-amber-400'
                              : sub.status === 'REJECTED'
                              ? 'text-red-400'
                              : 'text-[#FFD700]'
                          }
                        >
                          {sub.status}
                        </span>
                      </div>
                      <h3 className="font-semibold text-sm text-white">{sub.destinationName}</h3>
                      <div className="text-xs text-[#A1A1AA]">
                        <span>{sub.applicantDisplayName}</span>
                        <span aria-hidden="true"> · </span>
                        <span>{formatElev(sub.destinationElevationM)}</span>
                        <span aria-hidden="true"> · </span>
                        <span>{sub.requiresDualHumanReview ? 'Dual-Review (2P)' : 'Single Review'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="lg:col-span-8 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-6">
              {!selectedSubmission ? (
                <div className="p-8 rounded-xl bg-[#18181B] border border-white/10 text-center space-y-2">
                  <p className="font-semibold text-sm text-white">
                    {bootstrapStatus === 'LOADING'
                      ? 'Synchronizing Verification Workstation...'
                      : 'No Active Dossier Selected'}
                  </p>
                  <p className="text-xs text-[#A1A1AA]">
                    {bootstrapError
                      ? 'Unable to load server verification queue. Retry connection above.'
                      : 'Select a dossier from the queue or submit a new achievement record.'}
                  </p>
                </div>
              ) : (
                <>
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/10 pb-4">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono-tabular text-[#C9A86A]">
                    <span>{selectedSubmission.submissionCode}</span>
                    <span aria-hidden="true">·</span>
                    <span>{selectedSubmission.verificationTrack}</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      {selectedSubmission.requiresDualHumanReview
                        ? 'TIER-A DUAL HUMAN REVIEW REQUIRED'
                        : 'STANDARD HUMAN REVIEW'}
                    </span>
                  </div>
                  <h2 className="font-display text-2xl font-bold text-white mt-1">
                    {selectedSubmission.destinationName} ({formatElev(selectedSubmission.destinationElevationM)})
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-0.5">
                    Applicant: <strong className="text-white">{selectedSubmission.applicantDisplayName}</strong> ({selectedSubmission.applicantNationality}) · Route: {selectedSubmission.routeName}
                  </p>
                </div>

                <div className="text-right font-mono-tabular text-xs">
                  <div className="text-[#A1A1AA]">Current Status</div>
                  <div className="text-sm font-bold text-[#FFD700] mt-0.5">
                    {selectedSubmission.status}
                  </div>
                </div>
              </div>

              {/* 5-Signal Automated Conflict-of-Interest (COI) Gate */}
              <div
                className={`p-4 rounded-xl border space-y-3 ${
                  activeCoiResult.overallPassed
                    ? 'bg-[#18181B] border-emerald-500/35'
                    : 'bg-red-950/40 border-red-500/50'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {activeCoiResult.overallPassed ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-red-400" />
                    )}
                    <span className="text-xs font-semibold text-white">
                      Automated 5-Signal Conflict-of-Interest Check for: {activeActor.displayName} [{activeActor.role}]
                    </span>
                  </div>
                  <span
                    className={`text-xs font-mono-tabular font-semibold ${
                      activeCoiResult.overallPassed ? 'text-emerald-400' : 'text-red-400'
                    }`}
                  >
                    {activeCoiResult.overallPassed ? 'ALL 5 COI SIGNALS PASSED' : 'CONFLICT DETECTED — BLOCKED'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {activeCoiResult.signals.map((sig, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded bg-[#121214] border border-white/10 flex items-start gap-2"
                    >
                      {sig.passed ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <div className="font-medium text-white">{sig.signalName}</div>
                        <div className="text-[11px] text-[#A1A1AA] mt-0.5">{sig.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Evidence Artifacts in Private Vault */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[#C9A86A]">
                  Private Evidence Vault Artifacts (Short-TTL Signed Access · Residential Coordinates Masked)
                </h3>
                <div className="grid grid-cols-1 gap-3">
                  {selectedSubmission.evidenceArtifacts.map((art) => (
                    <div
                      key={art.id}
                      className="p-3.5 rounded-xl bg-[#18181B] border border-white/10 text-xs space-y-1.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-semibold text-white">
                          [{art.type}] {art.fileName}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono-tabular text-[11px] text-[#C9A86A]">
                            SHA-256: {art.sha256PostUploadDigest.slice(0, 20)}...
                          </span>
                          <button
                            type="button"
                            onClick={() => handleRequestSignedEvidenceUrl(art.id)}
                            className="px-2 py-0.5 rounded bg-[#121214] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] text-[11px]"
                          >
                            Request Signed Vault Token
                          </button>
                        </div>
                      </div>
                      <div className="text-[#A1A1AA] flex flex-wrap items-center gap-2">
                        {art.extractedMetadata.deviceModel && (
                          <span>Sensor: {art.extractedMetadata.deviceModel}</span>
                        )}
                        {art.extractedMetadata.recordedMaxElevationM && (
                          <span>
                            · Max Elev: {art.extractedMetadata.recordedMaxElevationM}m (Apex dist:{' '}
                            {art.extractedMetadata.distanceSummitedFromApexM}m)
                          </span>
                        )}
                        {art.extractedMetadata.rolling15mMaxAscentMPerHr && (
                          <span>
                            · 15m Ascent: {art.extractedMetadata.rolling15mMaxAscentMPerHr} m/hr
                          </span>
                        )}
                        {art.extractedMetadata.permitReferenceCode && (
                          <span>· Permit Ref: {art.extractedMetadata.permitReferenceCode}</span>
                        )}
                        {art.perceptualHash && <span>· {art.perceptualHash}</span>}
                      </div>
                    </div>
                  ))}
                </div>
                {signedArtifactUrlInfo && (
                  <div className="p-2.5 rounded-lg bg-[#18181B] border border-[#C9A86A]/40 font-mono-tabular text-[11px] text-[#FFD700]">
                    {signedArtifactUrlInfo}
                  </div>
                )}
              </div>

              {/* Advisory AI Forensic Panel */}
              <div className="p-4 rounded-xl bg-[#18181B] border border-[#C9A86A]/30 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-[#FFD700]" />
                    <span className="font-semibold text-white">
                      Advisory AI Forensic Pre-Screening (Risk Flag: {selectedSubmission.advisoryAiAssessment.advisoryRiskLevel})
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleRequestServerAiBrief}
                    disabled={aiBriefLoading}
                    className="px-3 py-1 rounded bg-[#121214] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] transition-colors whitespace-nowrap shrink-0"
                  >
                    {aiBriefLoading ? 'Querying Server...' : 'Run Server Advisory Forensic Brief'}
                  </button>
                </div>
                <p className="text-neutral-300">
                  <strong>Kinematic Analysis:</strong>{' '}
                  {selectedSubmission.advisoryAiAssessment.kinematicConsistencyNote}
                </p>
                <p className="text-neutral-300">
                  <strong>EXIF & Provenance:</strong>{' '}
                  {selectedSubmission.advisoryAiAssessment.exifForensicNote}
                </p>
                {aiBriefText && (
                  <div className="p-3 rounded bg-[#121214] border border-[#FFD700]/30 text-[#FFD700]">
                    {aiBriefText}
                  </div>
                )}
                <p className="text-[11px] font-mono-tabular text-[#C9A86A]">
                  {selectedSubmission.advisoryAiAssessment.disclaimer}
                </p>
              </div>

              {/* Appeal Tribunal Box */}
              {selectedSubmission.appealRecord && (
                <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/40 space-y-2 text-xs">
                  <div className="font-semibold text-amber-300">
                    Independent Appeal Tribunal Record ({selectedSubmission.appealRecord.appealId})
                  </div>
                  <p className="text-neutral-200">
                    <strong>Appellant Grounds:</strong> {selectedSubmission.appealRecord.appellantGrounds}
                  </p>
                  <p className="text-neutral-300">
                    <strong>Supplementary Evidence:</strong>{' '}
                    {selectedSubmission.appealRecord.supplementaryEvidenceSummary}
                  </p>
                  <p className="font-mono-tabular text-amber-400">
                    Original Reviewer Hard-Blocked from Appeal Tribunal:{' '}
                    {selectedSubmission.appealRecord.originalReviewerUserIdsBlocked.join(', ')}
                  </p>
                </div>
              )}

              {/* Prior Human Reviews Log */}
              {selectedSubmission.humanReviews.length > 0 && (
                <div className="space-y-2 text-xs">
                  <h4 className="font-semibold text-[#A1A1AA]">
                    Recorded Human Officer Decisions ({selectedSubmission.humanReviews.length})
                  </h4>
                  {selectedSubmission.humanReviews.map((rev) => (
                    <div
                      key={rev.reviewId}
                      className="p-3 rounded-lg bg-[#18181B] border border-white/10 space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono-tabular">
                        <span className="text-[#FFD700]">
                          {rev.reviewerOfficerCode} ({rev.reviewerRole})
                        </span>
                        <span>{rev.decision}</span>
                      </div>
                      <p className="text-neutral-300">{rev.humanRationale}</p>
                      <p className="text-[10px] font-mono-tabular text-[#A1A1AA]">
                        Signed: {rev.decidedAtUtc} · {rev.decisionHmacSignature}
                      </p>
                    </div>
                  ))}
                </div>
              )}

              {/* Human Decision Execution Form */}
              <div className="pt-4 border-t border-white/10 space-y-4 text-xs">
                <label className="flex items-start gap-2.5 p-3 rounded-lg bg-[#18181B] border border-white/15 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={coiAttestedByOfficer}
                    onChange={(e) => setCoiAttestedByOfficer(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span className="text-neutral-200">
                    <strong>Mandatory Officer Attestation ({activeActor.officerCode}):</strong> I confirm I have no personal, financial, guiding, or organizational conflict of interest with this applicant, and I have personally inspected the corroborating evidence.
                  </span>
                </label>

                <label className="space-y-1 block">
                  <span className="text-[#A1A1AA]">
                    Human Verification / Appeal Rationale (Logged to Append-Only SQLite Audit Trail)
                  </span>
                  <textarea
                    rows={2}
                    value={reviewRationaleInput}
                    onChange={(e) => setReviewRationaleInput(e.target.value)}
                    className="w-full bg-[#18181B] border border-white/15 rounded-lg p-2.5 text-white"
                  />
                </label>

                {selectedSubmission.status === 'APPEALED' ? (
                  <div className="flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={() => handleExecuteHumanDecision('OVERTURN_AND_APPROVE')}
                      className="px-4 py-2.5 rounded-lg font-semibold bg-emerald-500 text-[#0A0A0A] hover:bg-emerald-400 transition-colors"
                    >
                      Appeal Tribunal: Overturn Rejection & Approve Achievement
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExecuteHumanDecision('UPHOLD_REJECTION')}
                      className="px-4 py-2.5 rounded-lg font-semibold bg-red-600 text-white hover:bg-red-500 transition-colors"
                    >
                      Appeal Tribunal: Uphold Original Rejection
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={() => handleExecuteHumanDecision('APPROVE')}
                      className="px-4 py-2.5 rounded-lg font-semibold bg-[#C9A86A] text-[#0A0A0A] hover:bg-[#FFD700] transition-colors"
                    >
                      Record Human Verification Approval ({activeActor.officerCode})
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExecuteHumanDecision('REQUEST_ADDITIONAL_EVIDENCE')}
                      className="px-4 py-2.5 rounded-lg font-semibold bg-[#18181B] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] transition-colors"
                    >
                      Request Additional Evidence
                    </button>
                    <button
                      type="button"
                      onClick={() => handleExecuteHumanDecision('REJECT')}
                      className="px-4 py-2.5 rounded-lg font-semibold bg-red-900/80 border border-red-500/50 text-red-100 hover:bg-red-800 transition-colors"
                    >
                      Reject Submission with Structured Reason
                    </button>
                  </div>
                )}

                {selectedSubmission.status === 'REJECTED' && (
                  <div className="pt-3 border-t border-white/10 space-y-2">
                    <p className="font-semibold text-amber-300">
                      Adventurer Right of Appeal (Routes to Independent Appeal Review Team)
                    </p>
                    <input
                      type="text"
                      value={appealGroundsInput}
                      onChange={(e) => setAppealGroundsInput(e.target.value)}
                      className="w-full bg-[#18181B] border border-white/15 rounded px-3 py-1.5 text-white"
                    />
                    <button
                      type="button"
                      onClick={handleFileAppeal}
                      className="px-3.5 py-2 rounded bg-amber-500 text-[#0A0A0A] font-semibold hover:bg-amber-400 transition-colors"
                    >
                      File Formal Appeal on Server
                    </button>
                  </div>
                )}
              </div>
                </>
              )}
            </div>
          </section>
        )}

        {/* ===================================================================
            SECTION 4: PUBLIC QR/ID VERIFICATION REGISTRY & VERIFIED LEADERBOARDS (PHASES 13 & 14)
        =================================================================== */}
        {activeSection === 'CERTIFICATES_STANDINGS' && (
          <div className="space-y-12">
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              <div className="lg:col-span-5 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
                <div>
                  <p className="text-xs text-[#C9A86A] font-mono-tabular">
                    PHASE 13 · NON-ENUMERABLE 128-BIT PUBLIC VERIFICATION REGISTRY
                  </p>
                  <h2 className="font-display text-2xl font-bold text-white mt-1">
                    Verify Public Achievement Credential
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-1">
                    Enter or select a cryptographic Verification ID. Public pages respect holder privacy consent and never expose raw GPX files or personal documents.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-xs text-[#A1A1AA] block">
                    Enter Cryptographic Verification ID
                  </label>
                  <input
                    type="text"
                    value={verifyLookupId}
                    onChange={(e) => setVerifyLookupId(e.target.value)}
                    className="w-full bg-[#18181B] border border-[#C9A86A]/40 rounded-lg px-3.5 py-2.5 text-sm font-mono-tabular text-[#FFD700] focus:outline-none focus:border-[#FFD700]"
                  />
                </div>

                <div className="space-y-2">
                  <p className="text-xs text-[#A1A1AA]">
                    Quick-Select Registry Records ({certificates.length}):
                  </p>
                  <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                    {certificates.map((cert) => (
                      <button
                        key={cert.verificationId}
                        type="button"
                        onClick={() => setVerifyLookupId(cert.verificationId)}
                        className={`w-full text-left p-2.5 rounded-lg border text-xs flex items-center justify-between gap-2 transition-colors ${
                          verifyLookupId === cert.verificationId
                            ? 'bg-[#C9A86A]/15 border-[#FFD700] text-white'
                            : 'bg-[#18181B] border-white/10 text-[#A1A1AA] hover:text-white'
                        }`}
                      >
                        <span className="font-mono-tabular truncate">{cert.verificationId}</span>
                        <span
                          className={`font-mono-tabular shrink-0 ${
                            cert.status === 'VALID' ? 'text-emerald-400' : 'text-red-400'
                          }`}
                        >
                          {cert.status}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-7">
                {lookedUpCertificate ? (
                  <div className="bg-[#121214] border-2 border-[#C9A86A] rounded-2xl p-8 space-y-6 relative">
                    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#C9A86A]/30 pb-5">
                      <div>
                        <p className="text-xs tracking-widest uppercase text-[#C9A86A] font-mono-tabular">
                          0 TO 8848 · OFFICIAL VERIFIED ACHIEVEMENT CERTIFICATE
                        </p>
                        <h3 className="font-display text-2xl sm:text-3xl font-bold text-white mt-1">
                          {lookedUpCertificate.destinationNameEn}
                        </h3>
                        {lookedUpCertificate.destinationNameNe && (
                          <p className="font-nepali text-base text-[#FFD700] mt-0.5">
                            {lookedUpCertificate.destinationNameNe}
                          </p>
                        )}
                      </div>

                      <div className="text-right font-mono-tabular">
                        <span
                          className={`text-sm font-bold ${
                            lookedUpCertificate.status === 'VALID'
                              ? 'text-emerald-400'
                              : 'text-red-400'
                          }`}
                        >
                          STATUS: {lookedUpCertificate.status}
                        </span>
                        <p className="text-xs text-[#A1A1AA] mt-0.5">
                          {lookedUpCertificate.verificationId}
                        </p>
                      </div>
                    </div>

                    {lookedUpCertificate.revocationOrCorrectionNote && (
                      <div className="p-4 rounded-xl bg-red-950/60 border border-red-500/50 text-xs text-red-200">
                        {lookedUpCertificate.revocationOrCorrectionNote}
                      </div>
                    )}

                    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                      <div className="p-3.5 rounded-lg bg-[#18181B] border border-white/10">
                        <dt className="text-[#A1A1AA]">
                          Credential Holder (Consent Mode: {lookedUpCertificate.holderPrivacyMode})
                        </dt>
                        <dd className="text-base font-semibold text-white mt-1">
                          {lookedUpCertificate.holderPublicDisplay}
                        </dd>
                        <dd className="text-[#A1A1AA] mt-0.5">
                          Nationality: {lookedUpCertificate.holderNationality}
                        </dd>
                      </div>

                      <div className="p-3.5 rounded-lg bg-[#18181B] border border-white/10">
                        <dt className="text-[#A1A1AA]">Verified Elevation & Survey Source</dt>
                        <dd className="text-base font-bold text-[#FFD700] font-mono-tabular mt-1">
                          {lookedUpCertificate.verifiedElevationM.toLocaleString()} m /{' '}
                          {lookedUpCertificate.verifiedElevationFt.toLocaleString()} ft
                        </dd>
                        <dd className="text-[#A1A1AA] mt-0.5 line-clamp-1">
                          {lookedUpCertificate.elevationSourceCitation}
                        </dd>
                      </div>

                      <div className="p-3.5 rounded-lg bg-[#18181B] border border-white/10">
                        <dt className="text-[#A1A1AA]">Canonical Route & Evidentiary Basis</dt>
                        <dd className="text-white font-medium mt-1">
                          {lookedUpCertificate.routeName}
                        </dd>
                        <dd className="text-[#C9A86A] font-mono-tabular mt-0.5">
                          Track: {lookedUpCertificate.verificationTrack}
                        </dd>
                      </div>

                      <div className="p-3.5 rounded-lg bg-[#18181B] border border-white/10">
                        <dt className="text-[#A1A1AA]">Completion Date & Human Review Seal</dt>
                        <dd className="text-white font-mono-tabular font-medium mt-1">
                          Completed: {lookedUpCertificate.publicCompletionDateDisplay}
                        </dd>
                        <dd className="text-emerald-400 font-mono-tabular mt-0.5">
                          Signed: {lookedUpCertificate.reviewingOfficersCodes.join(' + ')}
                        </dd>
                      </div>
                    </dl>

                    <div className="pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-4 text-xs text-[#A1A1AA]">
                      <div className="font-mono-tabular">
                        Integrity Digest: {lookedUpCertificate.certificateIntegrityDigest.slice(0, 32)}...
                      </div>
                      {lookedUpCertificate.status === 'VALID' && (
                        <div className="flex flex-wrap items-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleToggleCertificateLeaderboard(lookedUpCertificate)}
                            className="px-3 py-1.5 rounded bg-[#18181B] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] transition-colors"
                          >
                            {lookedUpCertificate.optInPublicLeaderboards
                              ? 'Opt-Out of Public Leaderboard'
                              : 'Opt-In to Public Leaderboard'}
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleCertificateLifecycleAction(
                                lookedUpCertificate,
                                'GDPR_USER_ERASURE_SHRED'
                              )
                            }
                            className="px-3 py-1.5 rounded bg-[#18181B] border border-white/15 text-neutral-300 hover:text-white transition-colors"
                          >
                            Execute AES-256-GCM Key-Shredding Erasure
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleCertificateLifecycleAction(
                                lookedUpCertificate,
                                'DUAL_CONTROL_REVOKE'
                              )
                            }
                            className="px-3 py-1.5 rounded bg-red-950/70 border border-red-500/40 text-red-200 hover:bg-red-900 transition-colors"
                          >
                            Execute Dual-Control (2P) Revocation
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="bg-[#121214] border border-white/10 rounded-2xl p-8 text-center space-y-2">
                    <p className="text-base font-semibold text-white">
                      No matching certificate found for ID: {verifyLookupId}
                    </p>
                    <p className="text-xs text-[#A1A1AA]">
                      Verification IDs use non-enumerable 128-bit Base32 tokens. Select a valid ID from the registry list on the left.
                    </p>
                  </div>
                )}
              </div>
            </section>

            {/* Verified Achievement Leaderboards */}
            <section className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4">
                <div>
                  <p className="text-xs text-[#C9A86A] font-mono-tabular">
                    PHASE 14 · DETERMINISTIC VERIFIED LEADERBOARDS (ZERO PAID RANKINGS)
                  </p>
                  <h2 className="font-display text-xl font-bold text-white mt-1">
                    Global Verified Adventurer Standings
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-0.5">
                    Computed 100% from VALID human-verified certificates where the holder opted in. Revoked or erased records are automatically excluded.
                  </p>
                </div>

                <div className="flex items-center gap-1.5 bg-[#18181B] p-1 rounded-lg border border-white/10">
                  {(
                    [
                      ['ELEVATION_SUM', 'Cumulative Elevation'],
                      ['VERIFIED_COUNT', 'Verified Ascent Count'],
                      ['HIGHEST_APEX', 'Highest Verified Apex'],
                    ] as ['ELEVATION_SUM' | 'VERIFIED_COUNT' | 'HIGHEST_APEX', string][]
                  ).map(([mKey, label]) => (
                    <button
                      key={mKey}
                      type="button"
                      onClick={() => setLeaderboardMetric(mKey)}
                      className={`px-3 py-1.5 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                        leaderboardMetric === mKey
                          ? 'bg-[#C9A86A] text-[#0A0A0A] font-semibold'
                          : 'text-[#A1A1AA] hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-[#18181B] text-[#A1A1AA] uppercase text-[11px]">
                    <tr>
                      <th className="py-3 px-4">Rank</th>
                      <th className="py-3 px-4">Verified Adventurer</th>
                      <th className="py-3 px-4">Nationality</th>
                      <th className="py-3 px-4">Earned Destination Badges</th>
                      <th className="py-3 px-4 text-right">Verified Count</th>
                      <th className="py-3 px-4 text-right">Highest Apex</th>
                      <th className="py-3 px-4 text-right">Cumulative Elevation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/10">
                    {verifiedLeaderboardRows.map((row, index) => (
                      <tr key={row.holderUserId} className="hover:bg-white/5">
                        <td className="py-3 px-4 font-mono-tabular font-bold text-[#FFD700]">
                          #{index + 1}
                        </td>
                        <td className="py-3 px-4 font-semibold text-white">{row.displayName}</td>
                        <td className="py-3 px-4 text-[#A1A1AA]">{row.nationality}</td>
                        <td className="py-3 px-4 text-[#C9A86A]">{row.badges.join(' · ')}</td>
                        <td className="py-3 px-4 text-right font-mono-tabular text-white">
                          {row.verifiedCount}
                        </td>
                        <td className="py-3 px-4 text-right font-mono-tabular text-white">
                          {formatElev(row.highestApexM)}
                        </td>
                        <td className="py-3 px-4 text-right font-mono-tabular font-semibold text-[#FFD700]">
                          {formatElev(row.cumulativeElevationM)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}

        {/* ===================================================================
            SECTION 5: GOVERNANCE COMMAND, RBAC TESTER, HARD LOCKS & 21 PHASES
        =================================================================== */}
        {activeSection === 'GOVERNANCE_PHASES' && (
          <div className="space-y-12">
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
              {/* 1,680-Permutation RBAC Matrix Tester */}
              <div className="lg:col-span-6 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
                <div>
                  <p className="text-xs text-[#C9A86A] font-mono-tabular">
                    SEC-RBAC-001 · 15-ROLE × 14-RESOURCE × 8-VERB RBAC ENGINE (1,680 PERMUTATIONS)
                  </p>
                  <h2 className="font-display text-xl font-bold text-white mt-1">
                    Strict Deny-By-Default Permission Matrix Tester
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-1">
                    Inspect all 15 roles, 14 resource domains, and 8 action verbs. Zero permissive catch-all fallbacks exist.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <label className="space-y-1 block">
                    <span className="text-[#A1A1AA]">1. Select User Role (15)</span>
                    <select
                      value={testRole}
                      onChange={(e) => setTestRole(e.target.value as UserRole)}
                      className="w-full bg-[#18181B] border border-white/15 rounded px-2.5 py-2 text-white"
                    >
                      {ALL_USER_ROLES.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="space-y-1 block">
                    <span className="text-[#A1A1AA]">2. Select Resource (14)</span>
                    <select
                      value={testResource}
                      onChange={(e) => setTestResource(e.target.value as ResourceDomain)}
                      className="w-full bg-[#18181B] border border-white/15 rounded px-2.5 py-2 text-white"
                    >
                      {ALL_RESOURCE_DOMAINS.map((res) => (
                        <option key={res} value={res}>
                          {res}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="space-y-1 block">
                    <span className="text-[#A1A1AA]">3. Select Action Verb (8)</span>
                    <select
                      value={testVerb}
                      onChange={(e) => setTestVerb(e.target.value as ActionVerb)}
                      className="w-full bg-[#18181B] border border-white/15 rounded px-2.5 py-2 text-white"
                    >
                      {ALL_ACTION_VERBS.map((v) => (
                        <option key={v} value={v}>
                          {v}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>

                <div
                  className={`p-4 rounded-xl border text-xs space-y-1.5 ${
                    currentRbacEvaluation.allowed
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                      : 'bg-red-950/40 border-red-500/40 text-red-200'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono-tabular font-bold">
                    <span>
                      Decision: {currentRbacEvaluation.allowed ? 'HTTP 200 ALLOW' : 'HTTP 403 DENY'}
                    </span>
                    <span>{currentRbacEvaluation.ruleCode}</span>
                  </div>
                  <div className="font-semibold text-white">
                    Qualifier: {currentRbacEvaluation.qualifier}
                  </div>
                  <p className="text-neutral-300 leading-relaxed">
                    {currentRbacEvaluation.explanation}
                  </p>
                </div>
              </div>

              {/* Phase 17 Payment & Phase 18 Blockchain Hard-Lock Gate Verifier */}
              <div className="lg:col-span-6 bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
                <div>
                  <p className="text-xs text-[#C9A86A] font-mono-tabular">
                    PHASES 17 & 18 · CONSTITUTIONAL HARD-LOCK GATE VERIFICATION
                  </p>
                  <h2 className="font-display text-xl font-bold text-white mt-1">
                    Payment & Blockchain Hard-Disable Controls
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-1">
                    Verify server-side enforcement that all payment collection and optional blockchain minting remain disabled until formal legal, financial, and security approvals are recorded.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 rounded-xl bg-[#18181B] border border-white/10 space-y-2">
                    <div className="flex items-center justify-between font-mono-tabular">
                      <span className="text-white font-semibold">PAYMENTS_ENABLED</span>
                      <span className="text-red-400 font-bold">FALSE (LOCKED)</span>
                    </div>
                    <p className="text-[#A1A1AA]">
                      Requires company registration, legal review, financial compliance, payment-provider approval, and PCI security readiness.
                    </p>
                    <button
                      type="button"
                      onClick={() => handleTestHardLockedEndpoint('payments')}
                      className="w-full py-2 px-3 rounded bg-[#121214] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] font-medium transition-colors"
                    >
                      Test POST /api/v1/payments/checkout
                    </button>
                  </div>

                  <div className="p-4 rounded-xl bg-[#18181B] border border-white/10 space-y-2">
                    <div className="flex items-center justify-between font-mono-tabular">
                      <span className="text-white font-semibold">BLOCKCHAIN_MINTING</span>
                      <span className="text-red-400 font-bold">FALSE (LOCKED)</span>
                    </div>
                    <p className="text-[#A1A1AA]">
                      Primary database is authoritative. Requires legal approval, smart contract audit, and formal Founder authorization.
                    </p>
                    <button
                      type="button"
                      onClick={() => handleTestHardLockedEndpoint('blockchain')}
                      className="w-full py-2 px-3 rounded bg-[#121214] border border-[#C9A86A]/40 text-[#FFD700] hover:border-[#FFD700] font-medium transition-colors"
                    >
                      Test POST /api/v1/blockchain/mint
                    </button>
                  </div>
                </div>

                {gateTestMessage && (
                  <div className="p-3.5 rounded-xl bg-[#18181B] border border-[#FFD700]/40 font-mono-tabular text-xs text-[#FFD700]">
                    {gateTestMessage}
                  </div>
                )}
              </div>
            </section>

            {/* Dual-Control (2P) Approvals Ledger (SEC-GOV-003) */}
            <section className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-4">
              <div className="border-b border-white/10 pb-3">
                <p className="text-xs text-[#C9A86A] font-mono-tabular">
                  SEC-GOV-003 · TWO-PERSON (2P) DUAL-CONTROL APPROVAL STATE MACHINE
                </p>
                <h2 className="font-display text-xl font-bold text-white mt-1">
                  Dual-Control Governance & Revocation Ledger ({dualControlApprovals.length})
                </h2>
                <p className="text-xs text-[#A1A1AA] mt-0.5">
                  Stage 4/5 destination publication and certificate revocations require two distinct authenticated principals (Initiator &ne; Co-Signer).
                </p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs max-h-60 overflow-y-auto pr-1">
                {dualControlApprovals.map((app) => (
                  <div
                    key={app.approvalId}
                    className="p-3.5 rounded-xl bg-[#18181B] border border-white/10 space-y-1"
                  >
                    <div className="flex items-center justify-between font-mono-tabular">
                      <span className="text-[#FFD700] font-semibold">
                        {app.operationType} · {app.targetEntityId}
                      </span>
                      <span
                        className={
                          app.status === 'EXECUTED'
                            ? 'text-emerald-400'
                            : 'text-amber-400'
                        }
                      >
                        {app.status}
                      </span>
                    </div>
                    <p className="text-neutral-300">{app.reason}</p>
                    <p className="text-[11px] font-mono-tabular text-[#A1A1AA]">
                      Principal 1: {app.initiatorUserId} ({app.initiatorRole}) · Principal 2:{' '}
                      {app.cosignerUserId
                        ? `${app.cosignerUserId} (${app.cosignerRole})`
                        : 'AWAITING_SECOND_PRINCIPAL'}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            {/* Append-Only SQLite Trigger-Protected Audit Trail Explorer (SEC-DB-001 & SEC-CRYPTO-002) */}
            <section className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4">
                <div>
                  <p className="text-xs text-[#C9A86A] font-mono-tabular">
                    SEC-DB-001 & SEC-CRYPTO-002 · APPEND-ONLY SQLITE TRIGGER-IMMUTABLE AUDIT LEDGER
                  </p>
                  <h2 className="font-display text-xl font-bold text-white mt-1">
                    Tamper-Evident Governance & Verification Audit Log
                  </h2>
                  <p className="text-xs text-[#A1A1AA] mt-0.5">
                    Protected by SQLite BEFORE UPDATE / BEFORE DELETE triggers + RFC 4231 HMAC-SHA256 sequential hash chaining. Honest WORM reporting: local trigger-immutable until external cloud WORM sink is configured.
                  </p>
                </div>
                <span
                  className={`text-xs font-mono-tabular ${
                    auditIntegrityValid ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  HMAC-SHA256 Chain Integrity: {auditEvents.length} Events (
                  {auditIntegrityValid ? 'VERIFIED' : 'TAMPER_DETECTED'})
                </span>
              </div>

              <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
                {auditEvents.map((evt) => (
                  <div
                    key={evt.eventId}
                    className="p-3.5 rounded-xl bg-[#18181B] border border-white/10 text-xs space-y-1"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono-tabular">
                      <span className="text-[#FFD700] font-semibold">
                        #{evt.sequenceNumber} · {evt.eventId} · {evt.actionType}
                      </span>
                      <span className="text-[#A1A1AA]">
                        {evt.timestampUtc} · Role: {evt.actorRole} · Mode:{' '}
                        {evt.storageMode || 'LOCAL_SQLITE_TRIGGER_IMMUTABLE'} (External WORM:{' '}
                        {evt.wormReplicated ? 'TRUE' : 'FALSE'})
                      </span>
                    </div>
                    <p className="text-white">{evt.summary}</p>
                    <div className="text-[11px] font-mono-tabular text-[#A1A1AA] truncate">
                      Prev HMAC: {evt.previousEventHmac.slice(0, 28)}... → Curr HMAC: {evt.currentEventHmac}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Exact 21-Phase Master Roadmap Browser */}
            <section className="bg-[#121214] border border-white/10 rounded-2xl p-6 space-y-5">
              <div className="border-b border-white/10 pb-4">
                <p className="text-xs text-[#C9A86A] font-mono-tabular">
                  MASTER ROADMAP · EXACTLY 21 MAIN PHASES WITH EVIDENCE-BASED STATUSES
                </p>
                <h2 className="font-display text-xl font-bold text-white mt-1">
                  0 TO 8848 — 21-Phase Master Implementation & Governance Roadmap
                </h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {MASTER_21_PHASES.map((ph) => (
                  <div
                    key={ph.phaseNumber}
                    className="p-4 rounded-xl bg-[#18181B] border border-white/10 flex flex-col justify-between space-y-3 text-xs"
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between font-mono-tabular">
                        <span className="text-[#FFD700] font-bold">{ph.code}</span>
                        <span
                          className={
                            ph.status === 'TESTED' || ph.status === 'DOCUMENTED'
                              ? 'text-emerald-400'
                              : ph.status === 'HARD_LOCKED_GATE'
                              ? 'text-red-400'
                              : ph.status === 'NOT_STARTED'
                              ? 'text-[#A1A1AA]'
                              : 'text-[#C9A86A]'
                          }
                        >
                          {ph.status}
                        </span>
                      </div>
                      <h3 className="font-display text-sm font-bold text-white">{ph.title}</h3>
                      <p className="text-[#A1A1AA] leading-relaxed">{ph.purpose}</p>
                    </div>

                    <div className="pt-2 border-t border-white/10 space-y-1 text-[11px]">
                      <div className="text-neutral-300">
                        <strong>Modules:</strong> {ph.modules.join(' · ')}
                      </div>
                      <div className="text-[#C9A86A]">
                        <strong>Security:</strong> {ph.securityControls}
                      </div>
                      <div className="text-[#A1A1AA]">
                        <strong>Gate:</strong> {ph.acceptanceCriteria}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}
      </main>

      {/* =====================================================================
          INSTITUTIONAL FOOTER
      ===================================================================== */}
      <footer className="bg-[#0A0A0A] border-t border-white/10 px-6 py-8 mt-12 text-xs text-[#A1A1AA]">
        <div className="max-w-[1400px] mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <p className="font-display font-bold text-white tracking-wider">
              0 TO 8848 — GLOBAL ADVENTURE ACHIEVEMENT PLATFORM
            </p>
            <p>
              Official Domain: https://0to8848official.com · Built in Nepal. Made for the World.
            </p>
          </div>
          <div className="font-mono-tabular text-right space-y-1">
            <p className="text-[#C9A86A]">EXPLORE. ACHIEVE. PROVE.</p>
            <p>100 Global Destinations · 21 Master Phases · Earned, Never Bought</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
