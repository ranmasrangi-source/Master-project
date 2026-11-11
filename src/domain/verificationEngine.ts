import {
  AchievementSubmission,
  DestinationRecord,
  UserRole,
} from '../types/platform';

export interface ReviewerProfileContext {
  userId: string;
  internalActorUuid?: string;
  officerCode: string;
  displayName: string;
  role: UserRole;
  organizationId?: string;
  expeditionRosterGroupCode?: string;
  isGuideForUserIds?: string[];
}

export type ActiveActorProfile = ReviewerProfileContext;

export const DEMO_ACTOR_PROFILES: Record<string, ReviewerProfileContext> = {
  'actor-adventurer-tenzing': {
    userId: 'usr-tenzing-nepal',
    internalActorUuid: 'act-uuid-tenzing-001',
    officerCode: 'ADV-NP-001',
    displayName: 'Mingma Dorjee Sherpa (Adventurer)',
    role: 'REGISTERED_ADVENTURER',
    organizationId: 'org-himalayan-alpinists',
    expeditionRosterGroupCode: 'EXP-KHUMBU-SPRING-26A',
  },
  'actor-reviewer-independent-219': {
    userId: 'usr-reviewer-219',
    internalActorUuid: 'act-uuid-rev-219',
    officerCode: 'REV-OFFICER-219',
    displayName: 'Dr. Pemba Sherpa (Independent Verification Officer)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-independent-verif-dept',
  },
  'actor-reviewer-104': {
    userId: 'usr-reviewer-104',
    internalActorUuid: 'act-uuid-rev-104',
    officerCode: 'REV-OFFICER-104',
    displayName: 'Kilian Vance (Verification Officer — Reviewed Sub 101 & 103)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-independent-verif-dept',
  },
  'actor-senior-lead-301': {
    userId: 'usr-senior-lead-301',
    internalActorUuid: 'act-uuid-lead-301',
    officerCode: 'REV-LEAD-301',
    displayName: 'Ang Phurba Sherpa (Senior Verification Lead)',
    role: 'SENIOR_VERIFICATION_LEAD',
    organizationId: 'org-independent-verif-dept',
  },
  'actor-reviewer-conflicted-guide': {
    userId: 'usr-guide-conflict-demo',
    internalActorUuid: 'act-uuid-guide-399',
    officerCode: 'REV-OFFICER-399',
    displayName: 'Dawa Geljen (Reviewer with Guide/Roster COI on Sub 101)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-himalayan-alpinists',
    expeditionRosterGroupCode: 'EXP-KHUMBU-SPRING-26A',
    isGuideForUserIds: ['usr-tenzing-nepal'],
  },
  'actor-appeal-officer-401': {
    userId: 'usr-appeal-401',
    internalActorUuid: 'act-uuid-appeal-401',
    officerCode: 'APL-TRIBUNAL-401',
    displayName: 'Justice Ananya Adhikari (Independent Appeal Officer)',
    role: 'APPEAL_OFFICER',
    organizationId: 'org-independent-appeal-tribunal',
  },
  'actor-governance-founder': {
    userId: 'usr-gov-founder-001',
    internalActorUuid: 'act-uuid-founder-001',
    officerCode: 'GOV-FOUNDER-001',
    displayName: 'Platform Founder (Dual-Control Principal 1)',
    role: 'FOUNDER',
  },
  'actor-governance-committee-002': {
    userId: 'usr-gov-committee-002',
    internalActorUuid: 'act-uuid-gov-002',
    officerCode: 'GOV-COMMITTEE-002',
    displayName: 'Governance Committee Chair (Dual-Control Principal 2)',
    role: 'GOVERNANCE_COMMITTEE',
  },
  'actor-researcher-501': {
    userId: 'usr-researcher-501',
    internalActorUuid: 'act-uuid-res-501',
    officerCode: 'RES-CARTO-501',
    displayName: 'Suman Thapa (Destination Geodetic Researcher)',
    role: 'DESTINATION_RESEARCHER',
  },
};

export interface CoiCheckResult {
  overallPassed: boolean;
  signals: {
    signalName: string;
    passed: boolean;
    detail: string;
  }[];
  blockingReason?: string;
}

export function runAutomatedFiveSignalCoiCheck(
  actor: ReviewerProfileContext,
  submission: AchievementSubmission,
  isAppealAdjudication: boolean
): CoiCheckResult {
  const s1Passed = actor.userId !== submission.applicantUserId;
  const s2Passed =
    actor.userId !== submission.guidedByUserId &&
    !(actor.isGuideForUserIds || []).includes(submission.applicantUserId);
  const s3Passed =
    !actor.organizationId ||
    !submission.organizationId ||
    actor.organizationId !== submission.organizationId;
  const s4Passed =
    !actor.expeditionRosterGroupCode ||
    !submission.expeditionRosterGroupCode ||
    actor.expeditionRosterGroupCode !== submission.expeditionRosterGroupCode;

  const participatedInPriorReview = submission.humanReviews.some(
    (r) => r.reviewerUserId === actor.userId
  );
  const blockedInAppeal =
    isAppealAdjudication &&
    (participatedInPriorReview ||
      (submission.appealRecord?.originalReviewerUserIdsBlocked || []).includes(actor.userId));

  const s5Passed = isAppealAdjudication ? !blockedInAppeal : !participatedInPriorReview;

  const signals = [
    {
      signalName: 'Signal 1: Self-Review Prohibition',
      passed: s1Passed,
      detail: s1Passed
        ? 'Actor UID is distinct from Applicant UID.'
        : 'BLOCKED: Reviewers can never verify or approve their own achievement submissions.',
    },
    {
      signalName: 'Signal 2: Guide / Marketplace Client Firewall',
      passed: s2Passed,
      detail: s2Passed
        ? 'Zero commercial guiding relationship detected with applicant.'
        : 'BLOCKED: Actor served as commercial guide for this applicant/expedition.',
    },
    {
      signalName: 'Signal 3: Organization & Club Independence',
      passed: s3Passed,
      detail: s3Passed
        ? 'No shared club or expedition agency affiliation.'
        : `BLOCKED: Actor shares organization (${submission.organizationId}) with applicant.`,
    },
    {
      signalName: 'Signal 4: Shared Expedition Roster Check',
      passed: s4Passed,
      detail: s4Passed
        ? 'Actor was not a member of the applicant’s climbing roster.'
        : `BLOCKED: Actor participated in shared roster (${submission.expeditionRosterGroupCode}).`,
    },
    {
      signalName: isAppealAdjudication
        ? 'Signal 5: Appeal Tribunal Independence (No Original Reviewer)'
        : 'Signal 5: Dual-Review Officer Distinctness',
      passed: s5Passed,
      detail: s5Passed
        ? isAppealAdjudication
          ? 'Appeal Officer had zero involvement in the disputed initial decision.'
          : 'Officer has not yet cast a review vote on this dossier.'
        : isAppealAdjudication
        ? 'BLOCKED: Original decision-maker is strictly prohibited from reviewing their own disputed rejection.'
        : 'BLOCKED: Officer already submitted the first review on this Tier-A dossier; second review requires a distinct human officer.',
    },
  ];

  const failedSignal = signals.find((s) => !s.passed);

  return {
    overallPassed: !failedSignal,
    signals,
    blockingReason: failedSignal ? failedSignal.detail : undefined,
  };
}

export interface TelemetryForensicEvaluation {
  withinGeofence: boolean;
  withinElevationBand: boolean;
  withinKinematicAscentEnvelope: boolean;
  barometricCorroborated: boolean;
  summaryNotes: string[];
}

export function evaluateContextualTelemetry(
  destination: DestinationRecord,
  recordedMaxElevationM: number,
  distanceFromApexM: number,
  rolling15mAscentRateMPerHr: number,
  hasBarometricChannel: boolean
): TelemetryForensicEvaluation {
  const env = destination.telemetryEnvelope;
  const elevDelta = Math.abs(recordedMaxElevationM - destination.elevationM);
  const withinElevationBand = elevDelta <= env.elevationBandToleranceM;
  const withinGeofence = distanceFromApexM <= env.summitGeofenceRadiusM;
  const withinKinematicAscentEnvelope =
    rolling15mAscentRateMPerHr <= env.maxPlausibleAscentRateMPerHr &&
    rolling15mAscentRateMPerHr > 0;
  const barometricCorroborated = env.requiresBarometricChannel ? hasBarometricChannel : true;

  const summaryNotes: string[] = [
    `Apex Geofence Check: ${distanceFromApexM.toFixed(1)}m from official coordinates (Threshold <= ${env.summitGeofenceRadiusM}m) — ${withinGeofence ? 'PASS' : 'FLAGGED FOR HUMAN REVIEW'}`,
    `Elevation Band Check: Recorded ${recordedMaxElevationM.toFixed(1)}m vs Official ${destination.elevationM}m (Delta ${elevDelta.toFixed(1)}m, Tolerance ±${env.elevationBandToleranceM}m) — ${withinElevationBand ? 'PASS' : 'FLAGGED FOR HUMAN REVIEW'}`,
    `15-Min Rolling Ascent Rate: ${rolling15mAscentRateMPerHr} m/hr (Destination Max Envelope <= ${env.maxPlausibleAscentRateMPerHr} m/hr) — ${withinKinematicAscentEnvelope ? 'PASS' : 'ANOMALY FLAGGED (Requires Human Inspection)'}`,
    `Barometric Altimeter Corroboration: ${barometricCorroborated ? 'VERIFIED' : 'MISSING BAROMETRIC CHANNEL ON TIER-A PEAK'}`,
  ];

  return {
    withinGeofence,
    withinElevationBand,
    withinKinematicAscentEnvelope,
    barometricCorroborated,
    summaryNotes,
  };
}
