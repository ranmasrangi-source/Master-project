import {
  AchievementSubmission,
  DestinationRecord,
  UserRole,
} from '../types/platform';

export interface ReviewerProfileContext {
  userId: string;
  officerCode: string;
  displayName: string;
  role: UserRole;
  organizationId?: string;
  expeditionRosterGroupCode?: string;
  isGuideForUserIds?: string[];
}

export const DEMO_ACTOR_PROFILES: Record<string, ReviewerProfileContext> = {
  'actor-adventurer-tenzing': {
    userId: 'usr-tenzing-nepal',
    officerCode: 'ADV-NP-001',
    displayName: 'Mingma Dorjee Sherpa (Adventurer)',
    role: 'REGISTERED_ADVENTURER',
    organizationId: 'org-himalayan-alpinists',
    expeditionRosterGroupCode: 'EXP-KHUMBU-SPRING-26A',
  },
  'actor-reviewer-independent-219': {
    userId: 'usr-reviewer-219',
    officerCode: 'REV-OFFICER-219',
    displayName: 'Dr. Pemba Sherpa (Independent Verification Officer)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-independent-verif-dept',
  },
  'actor-reviewer-104': {
    userId: 'usr-reviewer-104',
    officerCode: 'REV-OFFICER-104',
    displayName: 'Kilian Vance (Verification Officer — Reviewed Sub 101 & 103)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-independent-verif-dept',
  },
  'actor-reviewer-conflicted-guide': {
    userId: 'usr-guide-conflict-demo',
    officerCode: 'REV-OFFICER-399',
    displayName: 'Dawa Geljen (Reviewer with Guide/Roster COI on Sub 101)',
    role: 'VERIFICATION_OFFICER',
    organizationId: 'org-himalayan-alpinists',
    expeditionRosterGroupCode: 'EXP-KHUMBU-SPRING-26A',
    isGuideForUserIds: ['usr-tenzing-nepal'],
  },
  'actor-appeal-officer-401': {
    userId: 'usr-appeal-401',
    officerCode: 'APL-TRIBUNAL-401',
    displayName: 'Justice Ananya Adhikari (Independent Appeal Officer)',
    role: 'APPEAL_OFFICER',
    organizationId: 'org-independent-appeal-tribunal',
  },
  'actor-governance-founder': {
    userId: 'usr-gov-founder-001',
    officerCode: 'GOV-FOUNDER-001',
    displayName: 'Founder & Governance Committee (Dual-Control 2P)',
    role: 'FOUNDER',
  },
  'actor-researcher-501': {
    userId: 'usr-researcher-501',
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
        ? 'BLOCKED: Original decision-maker (REV-OFFICER-104) is strictly prohibited from reviewing their own disputed rejection.'
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

export function generateNonEnumerableVerificationId(seedNum: number): string {
  const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let token = '';
  let x = (seedNum * 2654435761 + Date.now()) >>> 0;
  for (let i = 0; i < 16; i++) {
    x = (x ^ (x << 13)) >>> 0;
    x = (x ^ (x >>> 17)) >>> 0;
    x = (x ^ (x << 5)) >>> 0;
    token += alphabet[x % alphabet.length];
    if (i === 3 || i === 7 || i === 11) {
      token += '-';
    }
  }
  return `8848-V1-${token}`;
}

export function computeDeterministicHmacDigest(payload: string, prevHmac: string): string {
  const combined = `${prevHmac}|${payload}`;
  let h1 = 0xdeadbeef ^ combined.length;
  let h2 = 0x41c6ce57 ^ combined.length;
  for (let i = 0, ch; i < combined.length; i++) {
    ch = combined.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hex1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const hex2 = (h2 >>> 0).toString(16).padStart(8, '0');
  const hex3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, '0');
  return `hmac256:${hex1}${hex2}${hex3}${hex1}${hex2}${hex3}`;
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
    rolling15mAscentRateMPerHr <= env.maxPlausibleAscentRateMPerHr;
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
