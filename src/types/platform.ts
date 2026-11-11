export type WorldRegion =
  | 'ASIA'
  | 'EUROPE'
  | 'NORTH_AMERICA'
  | 'SOUTH_AMERICA'
  | 'AFRICA'
  | 'OCEANIA';

export type ResearchStage =
  | '1_PROPOSED'
  | '2_UNDER_RESEARCH'
  | '3_RESEARCH_COMPLETED'
  | '4_REVIEWED_AND_APPROVED'
  | '5_PUBLISHED';

export type DestinationTier = 'TIER_A_EXPEDITION' | 'TIER_B_ALPINE_TREK' | 'TIER_C_TRAIL_SUMMIT';

export type VerificationTrack = 'STANDARD_DIGITAL' | 'HISTORICAL_DOCUMENTARY';

export type UserRole =
  | 'PUBLIC_VISITOR'
  | 'REGISTERED_ADVENTURER'
  | 'PREMIUM_MEMBER_FUTURE'
  | 'VERIFIED_GUIDE'
  | 'ORGANIZATION_ADMIN'
  | 'DESTINATION_PARTNER'
  | 'SPONSOR_ACCOUNT'
  | 'DESTINATION_RESEARCHER'
  | 'VERIFICATION_OFFICER'
  | 'SENIOR_VERIFICATION_LEAD'
  | 'APPEAL_OFFICER'
  | 'SECURITY_COMPLIANCE_OFFICER'
  | 'PLATFORM_SYSADMIN'
  | 'GOVERNANCE_COMMITTEE'
  | 'FOUNDER';

export type ActionVerb =
  | 'READ'
  | 'CREATE'
  | 'UPDATE'
  | 'DELETE'
  | 'APPROVE'
  | 'REJECT'
  | 'PUBLISH'
  | 'REVOKE';

export type EvidenceBasedPhaseStatus =
  | 'NOT_STARTED'
  | 'DOCUMENTED'
  | 'DESIGNED'
  | 'PARTIALLY_IMPLEMENTED'
  | 'IMPLEMENTED'
  | 'TESTED'
  | 'ACCEPTED'
  | 'HARD_LOCKED_GATE';

export interface TelemetryEnvelope {
  summitGeofenceRadiusM: number;
  elevationBandToleranceM: number;
  maxPlausibleAscentRateMPerHr: number;
  maxPlausibleDescentRateMPerHr: number;
  knownMultipathZones: string;
  requiresBarometricChannel: boolean;
}

export interface DestinationRecord {
  id: string;
  code: string;
  officialNameEn: string;
  officialNameNe?: string;
  officialNameLocal: string;
  countryNames: string;
  countryIsoCodes: string[];
  region: WorldRegion;
  isNepalOriginAnchor: boolean;
  coordinates: {
    lat: number;
    lng: number;
  };
  elevationM: number;
  elevationFt: number;
  elevationReferenceSource: string;
  elevationCitationVerified: boolean;
  canonicalRouteName: string;
  routeDistanceKm: number;
  routeVerticalGainM: number;
  activityType: string;
  difficultyGrade: string;
  tier: DestinationTier;
  riskAndSafetySummary: string;
  permitAndAccessRequirements: string;
  permitAuthority: string;
  seasonalWindows: string;
  evidenceRequirements: string[];
  verificationCriteria: string;
  telemetryEnvelope: TelemetryEnvelope;
  researchStage: ResearchStage;
  publicationStatus: 'PUBLISHED' | 'UNPUBLISHED_DRAFT';
  badgeIdentity: {
    badgeCode: string;
    badgeTitle: string;
    metallicFinish: 'GOLD_8000M' | 'BRUSHED_GOLD_ALPINE' | 'OBSIDIAN_GOLD_TREK';
    reliefContourSeed: number;
  };
  authorizedPartnerName?: string;
  partnerWrittenAuthRef?: string;
  heroImageKey?: 'everest' | 'amadablam' | 'annapurna' | 'kilimanjaro';
}

export type SubmissionStatus =
  | 'SUBMITTED'
  | 'UNDER_REVIEW'
  | 'AWAITING_SECOND_REVIEW'
  | 'ESCALATED_SPLIT_DECISION'
  | 'ADDITIONAL_EVIDENCE_REQUESTED'
  | 'APPROVED'
  | 'REJECTED'
  | 'APPEALED'
  | 'REVOKED';

export interface EvidenceArtifact {
  id: string;
  type: 'GPX_TELEMETRY' | 'RAW_EXIF_PHOTO' | 'OFFICIAL_PERMIT_DOC' | 'SUMMIT_REGISTER_LOG' | 'MINISTRY_LEGACY_CERTIFICATE';
  fileName: string;
  fileSizeBytes?: number;
  mimeType?: string;
  sha256PostUploadDigest: string;
  perceptualHash?: string;
  uploadedAtUtc: string;
  vaultStorageKey?: string;
  extractedMetadata: {
    deviceModel?: string;
    captureTimestampUtc?: string;
    recordedMaxElevationM?: number;
    distanceSummitedFromApexM?: number;
    rolling15mMaxAscentMPerHr?: number;
    trackpointCount?: number;
    maskedResidentialTrackpointsCount?: number;
    exifSoftwareTag?: string;
    residentialStartEndMasked: boolean;
    permitReferenceCode?: string;
    barometricChannelDetected?: boolean;
    gpsTimestampConsistent?: boolean;
    spoofingIndicators?: string[];
    exifTamperingIndicator?: boolean;
  };
}

export interface AdvisoryAiAssessment {
  modelId: string;
  generatedAtUtc: string;
  advisoryRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  kinematicConsistencyNote: string;
  exifForensicNote: string;
  duplicateCheckNote: string;
  disclaimer: string;
}

export interface HumanReviewDecisionRecord {
  reviewId: string;
  reviewerUserId: string;
  reviewerOfficerCode: string;
  reviewerRole: 'VERIFICATION_OFFICER' | 'SENIOR_VERIFICATION_LEAD' | 'APPEAL_OFFICER';
  coiAutomatedCheckPassed: boolean;
  coiHumanAttestationSigned: boolean;
  decision: 'APPROVE' | 'REJECT' | 'REQUEST_ADDITIONAL_EVIDENCE' | 'OVERTURN_AND_APPROVE' | 'UPHOLD_REJECTION';
  reasonCode?: string;
  humanRationale: string;
  contextualAnomalyOverrideJustification?: string;
  decidedAtUtc: string;
  decisionHmacSignature: string;
}

export interface AchievementSubmission {
  id: string;
  submissionCode: string;
  applicantUserId: string;
  applicantInternalActorUuid?: string;
  applicantDisplayName: string;
  applicantInitials: string;
  applicantNationality: string;
  destinationId: string;
  destinationName: string;
  destinationElevationM: number;
  destinationTier: DestinationTier;
  routeName: string;
  verificationTrack: VerificationTrack;
  completionDateUtc: string;
  expeditionRosterGroupCode?: string;
  guidedByUserId?: string;
  organizationId?: string;
  applicantStory: string;
  truthfulnessDeclarationSigned: boolean;
  privacyConsent: {
    publicIdentityMode: 'FULL_VERIFIED_NAME' | 'DISPLAY_HANDLE_OR_INITIALS' | 'PRIVATE_CREDENTIAL_HOLDER';
    publicDatePrecision: 'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY';
    optInPublicLeaderboards: boolean;
  };
  evidenceArtifacts: EvidenceArtifact[];
  advisoryAiAssessment: AdvisoryAiAssessment;
  status: SubmissionStatus;
  requiresDualHumanReview: boolean;
  humanReviews: HumanReviewDecisionRecord[];
  appealRecord?: {
    appealId: string;
    filedAtUtc: string;
    appellantGrounds: string;
    supplementaryEvidenceSummary: string;
    originalReviewerUserIdsBlocked: string[];
    appealResolution?: HumanReviewDecisionRecord;
  };
  issuedCertificateId?: string;
  submittedAtUtc: string;
}

export interface PublicCertificateRecord {
  verificationId: string; // Non-enumerable 128-bit Base32 token e.g. 8848-V1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXXXX
  submissionId: string;
  holderUserId: string;
  holderInternalActorUuid?: string;
  holderPublicDisplay: string;
  holderPrivacyMode: 'FULL_VERIFIED_NAME' | 'DISPLAY_HANDLE_OR_INITIALS' | 'PRIVATE_CREDENTIAL_HOLDER';
  holderDatePrecision?: 'EXACT_DATE' | 'MONTH_AND_YEAR_ONLY' | 'YEAR_ONLY';
  holderNationality: string;
  destinationId: string;
  destinationCode: string;
  destinationNameEn: string;
  destinationNameNe?: string;
  verifiedElevationM: number;
  verifiedElevationFt: number;
  elevationSourceCitation: string;
  routeName: string;
  verificationTrack: VerificationTrack;
  publicCompletionDateDisplay: string;
  issuedAtUtc: string;
  status: 'VALID' | 'REVOKED' | 'CORRECTED' | 'DEACTIVATED_BY_USER_ERASURE';
  revocationOrCorrectionNote?: string;
  reviewingOfficersCodes: string[];
  badgeCode: string;
  certificateIntegrityDigest: string;
  optInPublicLeaderboards: boolean;
}

export interface AppendOnlyAuditEvent {
  sequenceNumber: number;
  eventId: string;
  timestampUtc: string;
  actorInternalUuid: string;
  actorRole: UserRole;
  actionType: string;
  targetEntityType: string;
  targetEntityId: string;
  summary: string;
  previousEventHmac: string;
  currentEventHmac: string;
  keyVersion?: string;
  wormReplicated: boolean;
  storageMode?: 'LOCAL_SQLITE_TRIGGER_IMMUTABLE' | 'CLOUD_WORM_OBJECT_LOCK';
}

export interface DualControlApprovalRecord {
  approvalId: string;
  operationType:
    | 'DESTINATION_STAGE_4_APPROVE'
    | 'DESTINATION_STAGE_5_PUBLISH'
    | 'CERTIFICATE_REVOKE'
    | 'ROLE_ASSIGNMENT';
  targetEntityId: string;
  initiatorUserId: string;
  initiatorOfficerCode: string;
  initiatorRole: UserRole;
  reason: string;
  status: 'PENDING_SECOND_APPROVAL' | 'EXECUTED' | 'CANCELLED' | 'EXPIRED';
  cosignerUserId?: string;
  cosignerOfficerCode?: string;
  cosignerRole?: UserRole;
  createdAtUtc: string;
  expiresAtUtc: string;
  resolvedAtUtc?: string;
}

export interface AuthenticatedSessionUser {
  userId: string;
  internalActorUuid: string;
  username: string;
  officerCode: string;
  displayName: string;
  role: UserRole;
  organizationId?: string;
  expeditionRosterGroupCode?: string;
  isGuideForUserIds?: string[];
  mfaRequired: boolean;
  mfaVerified: boolean;
  sessionExpiresAtUtc: string;
}
