import { DESTINATIONS_100_CATALOG } from '../data/destinations100';
import {
  INITIAL_AUDIT_EVENTS,
  INITIAL_SUBMISSIONS_QUEUE,
  INITIAL_VERIFIED_CERTIFICATES,
} from '../data/governanceAndPhases';
import {
  AchievementSubmission,
  AppendOnlyAuditEvent,
  AuthenticatedSessionUser,
  DestinationRecord,
  DualControlApprovalRecord,
  PublicCertificateRecord,
} from '../types/platform';

/**
 * BUG-08 Remediation:
 * Strict separation between production server-synchronized UI state and development-only
 * demo fixtures. Prevents failed or loading /api/v1/bootstrap requests from silently
 * displaying hardcoded demo submissions, actors, or verification IDs as real records.
 */

export type BootstrapLifecycleStatus =
  | 'LOADING'
  | 'READY'
  | 'ERROR'
  | 'OFFLINE_ERROR'
  | 'DEV_DEMO_FIXTURE_MODE';

export interface BootstrapClientState {
  status: BootstrapLifecycleStatus;
  isLoading: boolean;
  errorMessage: string | null;
  isDevDemoFixture: boolean;
  demoBannerLabel: string | null;
  sessionUser: AuthenticatedSessionUser | null;
  destinations: DestinationRecord[];
  submissions: AchievementSubmission[];
  certificates: PublicCertificateRecord[];
  auditEvents: AppendOnlyAuditEvent[];
  dualControlApprovals: DualControlApprovalRecord[];
  auditIntegrityValid: boolean;
}

export function createInitialLoadingBootstrapState(): BootstrapClientState {
  return {
    status: 'LOADING',
    isLoading: true,
    errorMessage: null,
    isDevDemoFixture: false,
    demoBannerLabel: null,
    sessionUser: null,
    destinations: DESTINATIONS_100_CATALOG,
    submissions: [],
    certificates: [],
    auditEvents: [],
    dualControlApprovals: [],
    auditIntegrityValid: true,
  };
}

export function resolveBootstrapSuccessState(
  serverPayload: Record<string, any>
): BootstrapClientState {
  return {
    status: 'READY',
    isLoading: false,
    errorMessage: null,
    isDevDemoFixture: false,
    demoBannerLabel: null,
    sessionUser: serverPayload.sessionUser || null,
    destinations: Array.isArray(serverPayload.destinations)
      ? serverPayload.destinations
      : DESTINATIONS_100_CATALOG,
    submissions: Array.isArray(serverPayload.submissions)
      ? serverPayload.submissions
      : [],
    certificates: Array.isArray(serverPayload.certificates)
      ? serverPayload.certificates
      : [],
    auditEvents: Array.isArray(serverPayload.auditEvents)
      ? serverPayload.auditEvents
      : [],
    dualControlApprovals: Array.isArray(serverPayload.dualControlApprovals)
      ? serverPayload.dualControlApprovals
      : [],
    auditIntegrityValid: serverPayload.auditChainStatus
      ? Boolean(serverPayload.auditChainStatus.valid)
      : true,
  };
}

export function resolveBootstrapFailureState(params: {
  errorMessage: string;
  isOffline?: boolean;
  isProduction?: boolean;
  explicitDevDemoModeRequested?: boolean;
}): BootstrapClientState {
  const isProd =
    params.isProduction !== undefined
      ? params.isProduction
      : process.env.NODE_ENV === 'production';

  // Production NEVER falls back to demo data, even if explicitDevDemoModeRequested is true
  if (!isProd && params.explicitDevDemoModeRequested === true) {
    return {
      status: 'DEV_DEMO_FIXTURE_MODE',
      isLoading: false,
      errorMessage: params.errorMessage,
      isDevDemoFixture: true,
      demoBannerLabel:
        '[DEVELOPMENT DEMO FIXTURE MODE — NOT SERVER-VERIFIED PRODUCTION DATA]',
      sessionUser: null,
      destinations: DESTINATIONS_100_CATALOG,
      submissions: INITIAL_SUBMISSIONS_QUEUE.map((s) => ({
        ...s,
        applicantDisplayName: `[DEV DEMO] ${s.applicantDisplayName}`,
      })),
      certificates: INITIAL_VERIFIED_CERTIFICATES.map((c) => ({
        ...c,
        holderPublicDisplay: `[DEV DEMO] ${c.holderPublicDisplay}`,
      })),
      auditEvents: INITIAL_AUDIT_EVENTS,
      dualControlApprovals: [],
      auditIntegrityValid: true,
    };
  }

  // Standard fail-safe state: clear all sensitive/verifiable collections and show error/retry banner
  return {
    status: params.isOffline ? 'OFFLINE_ERROR' : 'ERROR',
    isLoading: false,
    errorMessage:
      params.errorMessage ||
      'Unable to synchronize with the 0 TO 8848 verification server. Please check your connection and retry.',
    isDevDemoFixture: false,
    demoBannerLabel: null,
    sessionUser: null,
    destinations: DESTINATIONS_100_CATALOG,
    submissions: [],
    certificates: [],
    auditEvents: [],
    dualControlApprovals: [],
    auditIntegrityValid: false,
  };
}

/**
 * BUG-08 Remediation:
 * Resolves a certificate by Verification ID strictly from server-backed state when status === 'READY'.
 * Rejects sample/demo IDs when bootstrap failed or is still loading.
 */
export function lookupVerifiedCertificateFromState(
  state: BootstrapClientState,
  candidateVerificationId: string
): PublicCertificateRecord | null {
  if (state.status !== 'READY') {
    return null;
  }
  const clean = (candidateVerificationId || '').trim().toLowerCase();
  if (!clean) return null;
  const match = state.certificates.find(
    (c) => c.verificationId.toLowerCase() === clean
  );
  return match || null;
}
