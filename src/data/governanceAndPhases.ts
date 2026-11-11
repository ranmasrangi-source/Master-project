import {
  AchievementSubmission,
  ActionVerb,
  AppendOnlyAuditEvent,
  PublicCertificateRecord,
  UserRole,
} from '../types/platform';

export interface MasterPhaseSpec {
  phaseNumber: number;
  code: string;
  title: string;
  status: 'APPROVED_BASELINE' | 'ACTIVE_ARCHITECTURE' | 'ARCHITECTED_READY' | 'HARD_LOCKED_GATE';
  purpose: string;
  modules: string[];
  securityControls: string;
  governanceControls: string;
  deliverables: string[];
  acceptanceCriteria: string;
}

export const MASTER_21_PHASES: MasterPhaseSpec[] = [
  {
    phaseNumber: 1,
    code: 'PHASE 01',
    title: 'Master Requirements & Blueprint',
    status: 'APPROVED_BASELINE',
    purpose: 'Establish the complete product vision, objectives, feature inventory, user journeys, governance requirements, trust rules, and acceptance criteria.',
    modules: ['Project Constitution', 'Master Requirements', '17 Blueprint Specifications', 'Traceability Matrix'],
    securityControls: 'Zero client trust; separation of post-upload SHA-256 integrity from multi-modal authenticity.',
    governanceControls: 'Founder approval recorded; 5 Permanent Principles & Non-Negotiable Rule locked.',
    deliverables: ['Master Requirements Doc', 'Feature Inventory', 'Functional & NFR Specs', 'User Journey Maps', 'Risk & Open Decisions Registers'],
    acceptanceCriteria: '100% requirement traceability and Founder sign-off.',
  },
  {
    phaseNumber: 2,
    code: 'PHASE 02',
    title: 'Technical Architecture & System Design',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Design the complete frontend, backend, API, database, authentication, private vault storage, security boundaries, scalability, and disaster recovery architecture.',
    modules: ['Three-Zone Storage Isolation', 'IdP Credential Boundary', 'Repository Pattern Layer', 'RPO/RTO Continuity Design'],
    securityControls: 'Isolated IdP credentials; short-TTL signed URLs for Private Evidence Vault; RPO <= 15m, RTO <= 4h.',
    governanceControls: 'Blind Reviewer API projections stripping commercial metadata.',
    deliverables: ['System Architecture Blueprint', 'API Contract Spec', 'Three-Zone Data Isolation Spec', 'DR & Vendor Exit Plan'],
    acceptanceCriteria: 'Verified server-side authority and zero direct client mutations to trust tables.',
  },
  {
    phaseNumber: 3,
    code: 'PHASE 03',
    title: 'Development Infrastructure & GitHub',
    status: 'ARCHITECTED_READY',
    purpose: 'Establish clean-slate repository structure, branch protection, CI/CD, secrets policy, dependency management, automated testing, and backup runbooks.',
    modules: ['Branch Protection', 'Environment & Secrets Policy', 'Automated Typecheck/Lint/Test CI', 'Release & Recovery Runbooks'],
    securityControls: 'Zero secrets in source control; automated dependency CVE scanning.',
    governanceControls: 'Mandatory code review and phase-gate verification.',
    deliverables: ['Clean Repo Structure', '.env.example Template', 'Automated Verification Harness'],
    acceptanceCriteria: 'Passing build and lint checks with zero exposed credentials.',
  },
  {
    phaseNumber: 4,
    code: 'PHASE 04',
    title: 'Brand, UI/UX & Design System',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Establish the Obsidian (#0A0A0A), Metallic Gold (#C9A86A), Highlight Gold (#FFD700), and White (#FFFFFF) visual system with Cinzel, Plus Jakarta Sans, and Noto Sans Devanagari.',
    modules: ['Obsidian & Gold Tokens', 'Bilingual EN/NE Typography', '3D Badge Inspector', 'WCAG 2.1 AA Accessible Layouts'],
    securityControls: 'Zerohue-only state signaling; measured media contrast scrims.',
    governanceControls: 'Strict visual distinction between verified records, unverified drafts, and SPONSORED placements.',
    deliverables: ['Design Tokens', 'Homepage', 'Destination Explorer', 'Verification Workstation', 'Public QR Verifier'],
    acceptanceCriteria: 'WCAG 2.1 AA contrast compliance and responsive desktop/mobile parity.',
  },
  {
    phaseNumber: 5,
    code: 'PHASE 05',
    title: 'Database Architecture & Data Governance',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Design the 18-domain data model separating public catalog data, private evidence artifacts, user PII vaults, and append-only governance audit records.',
    modules: ['18 Normalized Domains', 'Segregated User PII Vault', 'Per-User DEK Key-Shredding', 'WORM Audit Ledger'],
    securityControls: 'Write-only INSERT privileges on audit logs; cryptographic pseudonymization on account erasure.',
    governanceControls: 'Hard schema foreign keys requiring human review records for every certificate.',
    deliverables: ['18-Domain Schema Spec', 'Data Classification Matrix', 'Retention & Erasure Protocol'],
    acceptanceCriteria: 'Zero PII leakage in public projections or immutable audit trails.',
  },
  {
    phaseNumber: 6,
    code: 'PHASE 06',
    title: 'Backend Infrastructure & API Architecture',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Enforce server-side validation, RBAC authorization, forensic file processing, rate limiting, and structured monitoring across all API endpoints.',
    modules: ['REST/RPC Gateway', 'GPX/EXIF Forensic Processor', 'Rate Limiter Shield', 'Structured Audit Middleware'],
    securityControls: 'XXE-disabled XML parsing; magic-byte validation; server-side RBAC enforcement.',
    governanceControls: 'All sensitive decisions enforced exclusively server-side.',
    deliverables: ['/api/v1/* Enforcement Routes', 'Telemetry Parser Service', 'Rate Limiting Middleware'],
    acceptanceCriteria: '100% server-side validation of verification, appeal, and catalog state transitions.',
  },
  {
    phaseNumber: 7,
    code: 'PHASE 07',
    title: 'Security Foundation & Governance Enforcement',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Enforce RBAC, least privilege, separation of duties, Dual-Control (2P) governance, COI blocking, and WORM audit logging before sensitive operations.',
    modules: ['1,680-Permutation RBAC Engine', '5-Signal COI Blocker', 'Dual-Control Two-Person Gate', 'Incident Response Playbook'],
    securityControls: 'Prevents privilege escalation, self-approval, and evidence tampering; never claims 100% unhackable.',
    governanceControls: 'Two-person rule required for role grants, destination publishing, and revocations.',
    deliverables: ['RBAC Guard Engine', 'COI Prevention Matrix', 'WORM Audit Chain Verifier'],
    acceptanceCriteria: 'Zero unauthorized writes or self-review paths permitted.',
  },
  {
    phaseNumber: 8,
    code: 'PHASE 08',
    title: 'Authentication, User & Account Management',
    status: 'ARCHITECTED_READY',
    purpose: 'Build identity lifecycle: registration, login, email verification, MFA readiness, privacy consent controls, account deletion requests, and role assignment guards.',
    modules: ['Identity Lifecycle', 'MFA Step-Up Readiness', 'Granular Privacy Consent', 'Account Deletion & Key-Shredding'],
    securityControls: 'Zero public admin registration; isolated credential boundary.',
    governanceControls: 'User controls public name/date granularity and leaderboard opt-in.',
    deliverables: ['Account & Privacy Settings', 'Erasure Request Workflow', 'Role Assignment Controls'],
    acceptanceCriteria: 'Verified session security and GDPR erasure compatibility.',
  },
  {
    phaseNumber: 9,
    code: 'PHASE 09',
    title: 'Global Destinations & Route Management',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Manage the global catalog of exactly 100 Featured Destinations across 6 world regions with the mandatory 5-stage research and approval workflow.',
    modules: ['100 Distinct Global Destinations', '5-Stage Research State Machine', 'Contextual Telemetry Envelopes', 'Elevation Citation Registry'],
    securityControls: 'Unverified destinations blocked from public confirmation or achievement submission.',
    governanceControls: 'Dual-control Governance sign-off required to advance from Stage 3 to Stages 4 and 5.',
    deliverables: ['100 Destination Records', 'Nepal Origin Anchor (18)', 'Route & Safety Profiles', 'Research Pipeline Console'],
    acceptanceCriteria: 'Zero duplicate/combined records; strict stage gating enforced.',
  },
  {
    phaseNumber: 10,
    code: 'PHASE 10',
    title: 'Adventure Guide & Marketplace',
    status: 'ARCHITECTED_READY',
    purpose: 'Design guide identity/license vetting, expedition listings, availability, booking workflow, safety requirements, and dispute handling.',
    modules: ['Guide License Vetting', 'Expedition Service Listings', 'Safety & Cancellation Disclosures', 'Dispute Intake'],
    securityControls: 'Automated COI link blocks guides from reviewing their own clients.',
    governanceControls: 'Marketplace commercial activity has zero influence on achievement verification.',
    deliverables: ['Verified Guide Directory', 'Vetting Workflow', 'Commercial Firewall Attestation'],
    acceptanceCriteria: '100% isolation between guide bookings and verification approvals.',
  },
  {
    phaseNumber: 11,
    code: 'PHASE 11',
    title: 'Achievement Submission & Evidence Engine',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Build the multi-modal achievement submission wizard supporting GPX/FIT telemetry, raw EXIF photos, official permits, SHA-256 post-upload digests, and privacy masking.',
    modules: ['Multi-Modal Dossier Builder', 'SHA-256 Post-Upload Integrity', 'Start/End Privacy Geofence Masker', 'Truthfulness Declaration'],
    securityControls: 'Private Evidence Vault storage; residential coordinate masking.',
    governanceControls: 'Supports both Contemporary Digital Track and Historical Documentary Track.',
    deliverables: ['Submission & Forensics Lab', 'Evidence Vault Metadata Handler', 'Resubmission Flow'],
    acceptanceCriteria: 'Accurate telemetry extraction and strict private evidence isolation.',
  },
  {
    phaseNumber: 12,
    code: 'PHASE 12',
    title: 'Human Verification & Anti-Fraud Engine',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Build the Independent Verification Department workstation with 5-signal COI blocking, contextual GPX/EXIF forensics, advisory AI flags, and Dual Human Review.',
    modules: ['Verification Officer Workstation', 'Contextual Telemetry Analyzer', 'Advisory AI Risk Panel', 'Dual-Review & QA Audit Engine'],
    securityControls: 'AI service accounts have zero permission to approve or reject submissions.',
    governanceControls: 'Human-only final decisions; Tier-A peaks require two independent human reviewers.',
    deliverables: ['Blind Reviewer Workstation', 'COI Attestation Gate', 'Reviewer Misconduct Containment Flow'],
    acceptanceCriteria: 'Verified block on self-review, guide-client conflict, and AI auto-approval.',
  },
  {
    phaseNumber: 13,
    code: 'PHASE 13',
    title: 'Badges, Certificates & Public Verification',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Deliver 100 destination-specific 3D badges, free official certificates, non-enumerable 128-bit verification IDs, QR verification pages, and revocation workflows.',
    modules: ['100 3D Badge Identities', 'Free Official Certificate Generator', '128-Bit Non-Enumerable QR Verifier', 'Dual-Control Revocation Ledger'],
    securityControls: 'High-entropy verification tokens prevent scraping; respects holder privacy consent.',
    governanceControls: 'Standard badges and certificates are permanently free; zero issuance for unapproved claims.',
    deliverables: ['Interactive 3D/2D Badge Viewer', 'Public Verification Portal', 'Revocation & Correction Registry'],
    acceptanceCriteria: 'Cryptographically traceable verification record for every public achievement.',
  },
  {
    phaseNumber: 14,
    code: 'PHASE 14',
    title: 'Leaderboards, Community & Social',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Build verified achievement leaderboards (Global, Regional, Destination), expedition stories, public profiles, and moderation controls.',
    modules: ['Multi-View Verified Leaderboards', 'Expedition Story Journals', 'Moderation & Abuse Reporting', 'Opt-In Ranking Privacy'],
    securityControls: 'Instant leaderboard recalculation upon certificate revocation or user erasure.',
    governanceControls: 'Rankings derived 100% from verified achievements; ranking positions can never be bought.',
    deliverables: ['Verified Standings Table', 'Community Stories Feed', 'Transparent Scoring Formula'],
    acceptanceCriteria: 'Zero commercial influence on leaderboard sorting.',
  },
  {
    phaseNumber: 15,
    code: 'PHASE 15',
    title: 'Organizations & Destination Partners',
    status: 'ARCHITECTED_READY',
    purpose: 'Build portals for mountaineering clubs, agencies, tourism boards, and national parks with strict written authorization verification.',
    modules: ['Organization Vetting', 'Destination Partner Registry', 'Written MOU Verification Lock', 'Official Safety Advisories'],
    securityControls: 'Database constraint blocks partner display unless written_authorization_verified is true.',
    governanceControls: 'Partners cannot control or influence independent achievement verification.',
    deliverables: ['Authorized Partner Portal', 'MOU Verification Registry', 'Partner Audit Logs'],
    acceptanceCriteria: 'Zero unauthorized partner logos or fabricated partnerships.',
  },
  {
    phaseNumber: 16,
    code: 'PHASE 16',
    title: 'Sponsorship & Advertising System',
    status: 'ARCHITECTED_READY',
    purpose: 'Build transparent commercial placement framework with mandatory SPONSORED labels and conflict-of-interest controls.',
    modules: ['Sponsor Compliance Console', 'Mandatory Disclosure Labels', 'Campaign Audit Trail'],
    securityControls: 'Sponsors have zero access to user PII, evidence vaults, or verification queues.',
    governanceControls: 'Zero fake sponsors or fabricated campaign metrics.',
    deliverables: ['Sponsor Disclosure Framework', 'Commercial Firewall Policy'],
    acceptanceCriteria: '100% labeled commercial placements and zero verification interference.',
  },
  {
    phaseNumber: 17,
    code: 'PHASE 17',
    title: 'Revenue, Membership & Payment Infrastructure',
    status: 'HARD_LOCKED_GATE',
    purpose: 'Architect ethical revenue streams (Memberships, Org SaaS, Guide Commissions, Partnerships) with real payment collection hard-disabled until compliance sign-off.',
    modules: ['Ethical Revenue Catalog', 'PAYMENTS_ENABLED = FALSE Hard Lock', 'Legal & Tax Readiness Checklist'],
    securityControls: 'Server-side 503 lock on all payment endpoints until PCI/legal/security sign-off.',
    governanceControls: 'Standard digital badges and certificates remain permanently free.',
    deliverables: ['Dormant Revenue Architecture', 'Payment Gate Lock Enforcer'],
    acceptanceCriteria: 'Confirmed zero premature payment collection.',
  },
  {
    phaseNumber: 18,
    code: 'PHASE 18',
    title: 'AI, Blockchain & NFT Future Architecture',
    status: 'HARD_LOCKED_GATE',
    purpose: 'Design advisory AI assistance and dormant post-verification Soulbound credential architecture while keeping the primary database authoritative.',
    modules: ['Advisory AI Forensic Assistant', 'BLOCKCHAIN_MINTING_ENABLED = FALSE Lock', 'Non-Transferable SBT Specification'],
    securityControls: 'No wallet connection or smart contract minting prior to legal and security audits.',
    governanceControls: 'Primary database is permanently authoritative; blockchain never establishes achievement truth.',
    deliverables: ['Advisory AI Service', 'Dormant Soulbound Schema & Gate Lock'],
    acceptanceCriteria: 'Confirmed zero premature blockchain minting.',
  },
  {
    phaseNumber: 19,
    code: 'PHASE 19',
    title: 'Admin, Governance & Globalization',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Deliver unified Governance & Admin console, Dual-Control approval queue, WORM audit explorer, and bilingual English + Nepali (Devanagari) globalization.',
    modules: ['Governance Command Center', 'WORM Audit Log Explorer', 'Bilingual EN/NE Switcher', 'Metric/Imperial Unit Engine'],
    securityControls: 'Every privileged action requires authorized role and writes to append-only audit ledger.',
    governanceControls: 'Dual-Control (2P) enforcement for constitutional actions.',
    deliverables: ['Governance Console', 'Bilingual EN/NE Interface', 'Audit Chain Inspector'],
    acceptanceCriteria: 'Complete auditability and native Devanagari rendering.',
  },
  {
    phaseNumber: 20,
    code: 'PHASE 20',
    title: 'Complete QA, Security Audit & Performance Testing',
    status: 'ACTIVE_ARCHITECTURE',
    purpose: 'Verify RBAC permissions, COI blocking, evidence integrity, appeal firewalls, accessibility, and disaster recovery readiness.',
    modules: ['Interactive RBAC Matrix Tester', 'COI & Appeal Firewall Simulator', 'Audit Chain Integrity Verifier', 'RPO/RTO Restore Readiness'],
    securityControls: 'Zero unresolved critical or high-severity vulnerabilities permitted before release.',
    governanceControls: 'Independent security review and Founder gate approval required.',
    deliverables: ['Interactive Governance & Security Test Suite', 'Traceability Verification Matrix'],
    acceptanceCriteria: '100% pass rate on constitutional and security invariant tests.',
  },
  {
    phaseNumber: 21,
    code: 'PHASE 21',
    title: 'Production Launch & Global Expansion',
    status: 'ARCHITECTED_READY',
    purpose: 'Execute formal launch readiness checklist for 0to8848official.com, legal disclosures, incident response, and post-launch expansion beyond 100 destinations.',
    modules: ['Production Readiness Checklist', 'Domain & SSL Governance', 'Global Expansion Roadmap (100 -> 1,000+ Peaks)'],
    securityControls: 'Continuous monitoring, WORM backup verification, and incident response readiness.',
    governanceControls: 'No premature public launch without Founder final authorization.',
    deliverables: ['Launch Readiness Gate', 'Long-Term Global Sustainability Charter'],
    acceptanceCriteria: 'All 21 phase gates verified and approved by Founder.',
  },
];

export const INITIAL_VERIFIED_CERTIFICATES: PublicCertificateRecord[] = [
  {
    verificationId: '8848-V1-9K4M-7P2X-Q8R5-3N6W',
    submissionId: 'sub-everest-001',
    holderUserId: 'usr-pasangnya-01',
    holderPublicDisplay: 'Pasang Dawa Sherpa',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderNationality: 'Nepal (NP)',
    destinationId: 'dest-001',
    destinationCode: 'DEST-001',
    destinationNameEn: 'Mount Everest (Sagarmatha)',
    destinationNameNe: 'सगरमाथा (चोमोलुङमा)',
    verifiedElevationM: 8848.86,
    verifiedElevationFt: 29032,
    elevationSourceCitation: 'Survey Department of Nepal (2020 Official Joint Trigonometric & GNSS Survey)',
    routeName: 'South Col — Southeast Ridge (Nepal)',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-05-19',
    issuedAtUtc: '2026-05-28T09:15:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104 (Lead)', 'REV-OFFICER-219 (Dual Concurrence)'],
    badgeCode: 'BDG-8848-001',
    certificateIntegrityDigest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-4T8H-2W9C-L5V1-8M3J',
    submissionId: 'sub-amadablam-002',
    holderUserId: 'usr-elena-02',
    holderPublicDisplay: 'Elena Rostova',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderNationality: 'Switzerland (CH)',
    destinationId: 'dest-009',
    destinationCode: 'DEST-009',
    destinationNameEn: 'Ama Dablam',
    destinationNameNe: 'आमा दब्लम',
    verifiedElevationM: 6812,
    verifiedElevationFt: 22349,
    elevationSourceCitation: 'Survey Department of Nepal & Nepal Mountaineering Association',
    routeName: 'Southwest Ridge via Camp I, Yellow Tower & Mushroom Ridge',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-10-24',
    issuedAtUtc: '2026-10-29T14:40:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104', 'REV-OFFICER-308 (Dual Concurrence)'],
    badgeCode: 'BDG-8848-009',
    certificateIntegrityDigest: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-6B3N-9F4D-X2Z7-1Q5P',
    submissionId: 'sub-thorong-003',
    holderUserId: 'usr-aarav-03',
    holderPublicDisplay: 'A. K. Gurung (Initials Consent Mode)',
    holderPrivacyMode: 'DISPLAY_HANDLE_OR_INITIALS',
    holderNationality: 'Nepal (NP)',
    destinationId: 'dest-014',
    destinationCode: 'DEST-014',
    destinationNameEn: 'Annapurna Circuit via Thorong La Pass',
    destinationNameNe: 'अन्नपूर्ण चक्रीय पदमार्ग (थोराङ ला भन्ज्याङ)',
    verifiedElevationM: 5416,
    verifiedElevationFt: 17769,
    elevationSourceCitation: 'Survey Department of Nepal & ACAP',
    routeName: 'Dharapani – Manang – Yak Kharka – Thorong La Pass (5,416m) – Muktinath',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: 'October 2026 (Month Precision Consent)',
    issuedAtUtc: '2026-11-01T11:20:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-219'],
    badgeCode: 'BDG-8848-014',
    certificateIntegrityDigest: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-7Y2K-5R8M-W3N9-4C1Z',
    submissionId: 'sub-kili-004',
    holderUserId: 'usr-mateo-04',
    holderPublicDisplay: 'Mateo Valdés',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderNationality: 'Argentina (AR)',
    destinationId: 'dest-081',
    destinationCode: 'DEST-081',
    destinationNameEn: 'Mount Kilimanjaro (Uhuru Peak)',
    verifiedElevationM: 5895,
    verifiedElevationFt: 19341,
    elevationSourceCitation: 'Tanzania National Parks Authority (TANAPA) & Survey of Tanzania',
    routeName: 'Machame / Lemosho Route via Stella Point to Uhuru Peak',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-08-14',
    issuedAtUtc: '2026-08-19T16:05:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104'],
    badgeCode: 'BDG-8848-081',
    certificateIntegrityDigest: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-0REV-8812-FRAUD-990X',
    submissionId: 'sub-revoked-005',
    holderUserId: 'usr-redacted-99',
    holderPublicDisplay: 'Credential Revoked by Governance Tribunal',
    holderPrivacyMode: 'PRIVATE_CREDENTIAL_HOLDER',
    holderNationality: 'Redacted',
    destinationId: 'dest-035',
    destinationCode: 'DEST-035',
    destinationNameEn: 'Mont Blanc',
    verifiedElevationM: 4805.59,
    verifiedElevationFt: 15766,
    elevationSourceCitation: 'IGN France 2023 Biennial Survey',
    routeName: 'Voie Royale (Goûter Route)',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-07',
    issuedAtUtc: '2026-07-18T10:00:00Z',
    status: 'REVOKED',
    revocationOrCorrectionNote:
      'REVOKED under Dual-Control Resolution GOV-REV-2026-04: Post-issuance forensic audit detected synthetic GPX track manipulation and recycled summit photograph perceptual hash match.',
    reviewingOfficersCodes: ['REV-LEAD-001', 'GOV-COMMITTEE-002'],
    badgeCode: 'BDG-8848-035',
    certificateIntegrityDigest: 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
    optInPublicLeaderboards: false,
  },
];

export const INITIAL_SUBMISSIONS_QUEUE: AchievementSubmission[] = [
  {
    id: 'sub-queue-101',
    submissionCode: 'SUB-2026-8848-101',
    applicantUserId: 'usr-tenzing-nepal',
    applicantDisplayName: 'Mingma Dorjee Sherpa',
    applicantInitials: 'M. D. S.',
    applicantNationality: 'Nepal (NP)',
    destinationId: 'dest-001',
    destinationName: 'Mount Everest (Sagarmatha)',
    destinationElevationM: 8848.86,
    destinationTier: 'TIER_A_EXPEDITION',
    routeName: 'South Col — Southeast Ridge (Nepal)',
    verificationTrack: 'STANDARD_DIGITAL',
    completionDateUtc: '2026-05-22T05:42:00Z',
    expeditionRosterGroupCode: 'EXP-KHUMBU-SPRING-26A',
    guidedByUserId: 'usr-guide-conflict-demo',
    organizationId: 'org-himalayan-alpinists',
    applicantStory:
      'Departed Camp IV (South Col, 7,906m) at 21:30 NPT on May 21. Reached Balcony at 01:45 NPT and South Summit at 04:30 NPT. Continuous Garmin inReach + Fenix 7X Pro multi-band GNSS + barometric altimeter track recorded across the Hillary Step cornices to the true summit pyramid at 05:42 NPT.',
    truthfulnessDeclarationSigned: true,
    privacyConsent: {
      publicIdentityMode: 'FULL_VERIFIED_NAME',
      publicDatePrecision: 'EXACT_DATE',
      optInPublicLeaderboards: true,
    },
    evidenceArtifacts: [
      {
        id: 'art-101-gpx',
        type: 'GPX_TELEMETRY',
        fileName: 'everest_south_col_summit_20260522.fit.gpx',
        sha256PostUploadDigest: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        uploadedAtUtc: '2026-05-26T12:10:00Z',
        extractedMetadata: {
          deviceModel: 'Garmin Fenix 7X Pro Sapphire Solar (Multi-Band GNSS + Baro)',
          captureTimestampUtc: '2026-05-22T05:42:14Z',
          recordedMaxElevationM: 8851.2,
          distanceSummitedFromApexM: 6.4,
          rolling15mMaxAscentMPerHr: 195,
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-101-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'DSC04819_Everest_Summit_Panorama.ARW.jpg',
        sha256PostUploadDigest: '7c4a8d09ca3762af61e59520943dc26494f8941b532a9981234567890abcdef1',
        perceptualHash: 'pHash:f8c39a1204e77b19 (0% match against existing archive — Unique)',
        uploadedAtUtc: '2026-05-26T12:11:30Z',
        extractedMetadata: {
          deviceModel: 'Sony ILCE-7RM5 (C2PA Content Credentials Valid)',
          captureTimestampUtc: '2026-05-22T05:44:02Z',
          recordedMaxElevationM: 8849.0,
          exifSoftwareTag: 'Camera Firmware v2.01 (No Post-Processing Detected)',
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-101-permit',
        type: 'OFFICIAL_PERMIT_DOC',
        fileName: 'DoT_Nepal_Mountaineering_Royalty_Permit_Spring2026.pdf',
        sha256PostUploadDigest: '3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',
        uploadedAtUtc: '2026-05-26T12:12:45Z',
        extractedMetadata: {
          permitReferenceCode: 'DOT-NP-SGR-2026-0418',
          residentialStartEndMasked: true,
        },
      },
    ],
    advisoryAiAssessment: {
      modelId: 'gemini-3-flash-preview (Server-Side Advisory Only)',
      generatedAtUtc: '2026-05-26T12:13:05Z',
      advisoryRiskLevel: 'LOW',
      kinematicConsistencyNote:
        'Rolling 15-min vertical ascent rate (195 m/hr from South Col to Summit) is well within the DEST-001 Tier-A envelope (<= 650 m/hr). Barometric pressure channel (337 hPa) corroborates GNSS altitude (8,851.2m).',
      exifForensicNote:
        'EXIF timestamp (05:44 UTC+5:45) and solar shadow azimuth (78° ENE over Makalu/Lhotse ridge) match May 22 dawn geometry. Zero editing software signatures.',
      duplicateCheckNote: 'Perceptual hash (pHash) shows zero collision across 14,200 indexed summit photographs.',
      disclaimer:
        'ADVISORY AI ANALYSIS ONLY — AI has zero permission to approve or reject achievements. Two independent human Verification Officers must evaluate and sign off on this Tier-A dossier.',
    },
    status: 'AWAITING_SECOND_REVIEW',
    requiresDualHumanReview: true,
    humanReviews: [
      {
        reviewId: 'rev-everest-101-a',
        reviewerUserId: 'usr-reviewer-104',
        reviewerOfficerCode: 'REV-OFFICER-104',
        reviewerRole: 'VERIFICATION_OFFICER',
        coiAutomatedCheckPassed: true,
        coiHumanAttestationSigned: true,
        decision: 'APPROVE',
        humanRationale:
          'First Human Review Complete: Verified DoT permit #DOT-NP-SGR-2026-0418, continuous multi-band GNSS + barometric track to within 6.4m of official 8,848.86m apex, and authentic C2PA-signed summit photo showing Lhotse and Makalu horizon. Ready for second independent officer concurrence.',
        decidedAtUtc: '2026-05-27T08:30:00Z',
        decisionHmacSignature: 'hmac-sha256:4a91e8c77b2019f3d827164e9a0b5c11',
      },
    ],
    submittedAtUtc: '2026-05-26T12:13:00Z',
  },
  {
    id: 'sub-queue-102',
    submissionCode: 'SUB-2026-8848-102',
    applicantUserId: 'usr-claire-fr',
    applicantDisplayName: 'Claire Moreau',
    applicantInitials: 'C. M.',
    applicantNationality: 'France (FR)',
    destinationId: 'dest-011',
    destinationName: 'Imja Tse (Island Peak)',
    destinationElevationM: 6189,
    destinationTier: 'TIER_B_ALPINE_TREK',
    routeName: 'Southeast Flank & Summit Headwall',
    verificationTrack: 'STANDARD_DIGITAL',
    completionDateUtc: '2026-10-18T07:15:00Z',
    applicantStory:
      'Climbed from Island Peak Base Camp (5,087m) via Crampon Point and the 50° headwall fixed rope line to the narrow summit ridge at 6,189m. Note: In the steep gully below Crampon Point (5,650m), single-point GPS bounced briefly due to narrow rock walls, but barometric altimeter remained continuous.',
    truthfulnessDeclarationSigned: true,
    privacyConsent: {
      publicIdentityMode: 'FULL_VERIFIED_NAME',
      publicDatePrecision: 'EXACT_DATE',
      optInPublicLeaderboards: true,
    },
    evidenceArtifacts: [
      {
        id: 'art-102-gpx',
        type: 'GPX_TELEMETRY',
        fileName: 'imja_tse_summit_track_20261018.gpx',
        sha256PostUploadDigest: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        uploadedAtUtc: '2026-10-21T09:00:00Z',
        extractedMetadata: {
          deviceModel: 'COROS VERTIX 2S',
          captureTimestampUtc: '2026-10-18T07:15:40Z',
          recordedMaxElevationM: 6186.5,
          distanceSummitedFromApexM: 11.2,
          rolling15mMaxAscentMPerHr: 420,
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-102-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'IMG_8821_ImjaTse_Summit_LhotseSouthWall.JPG',
        sha256PostUploadDigest: '1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014',
        perceptualHash: 'pHash:a119d4087bc2301e (Unique)',
        uploadedAtUtc: '2026-10-21T09:02:00Z',
        extractedMetadata: {
          deviceModel: 'Apple iPhone 16 Pro (RAW)',
          captureTimestampUtc: '2026-10-18T07:18:10Z',
          recordedMaxElevationM: 6188.0,
          exifSoftwareTag: 'iOS 19.1 Native Camera (Unmodified)',
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-102-permit',
        type: 'OFFICIAL_PERMIT_DOC',
        fileName: 'NMA_Imja_Tse_Climbing_Permit_Autumn2026.pdf',
        sha256PostUploadDigest: '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752',
        uploadedAtUtc: '2026-10-21T09:03:10Z',
        extractedMetadata: {
          permitReferenceCode: 'NMA-PK-IMJ-2026-1192',
          residentialStartEndMasked: true,
        },
      },
    ],
    advisoryAiAssessment: {
      modelId: 'gemini-3-flash-preview (Server-Side Advisory Only)',
      generatedAtUtc: '2026-10-21T09:04:00Z',
      advisoryRiskLevel: 'MEDIUM',
      kinematicConsistencyNote:
        'Single-point GNSS multipath bounce detected at 5,650m rock gully (3-second horizontal spike), while 15-minute rolling ascent rate (420 m/hr) and barometric altitude progression remain physically consistent within DEST-011 envelope (<= 950 m/hr).',
      exifForensicNote:
        'Summit photo EXIF coordinates and Lhotse Shar / Imja Glacier backdrop match canonical Imja Tse summit crest.',
      duplicateCheckNote: 'Zero duplicate hash matches found.',
      disclaimer:
        'ADVISORY AI ANALYSIS ONLY — Multipath flag requires human reviewer contextual inspection under Correction 2.7.',
    },
    status: 'UNDER_REVIEW',
    requiresDualHumanReview: false,
    humanReviews: [],
    submittedAtUtc: '2026-10-21T09:03:30Z',
  },
  {
    id: 'sub-queue-103',
    submissionCode: 'SUB-2026-8848-103',
    applicantUserId: 'usr-lukas-at',
    applicantDisplayName: 'Lukas Hofer',
    applicantInitials: 'L. H.',
    applicantNationality: 'Austria (AT)',
    destinationId: 'dest-037',
    destinationName: 'Matterhorn (Cervino)',
    destinationElevationM: 4478,
    destinationTier: 'TIER_A_EXPEDITION',
    routeName: 'Hörnli Ridge (Northeast Ridge via Hörnlihütte & Solvay Bivouac)',
    verificationTrack: 'STANDARD_DIGITAL',
    completionDateUtc: '2026-08-09T08:50:00Z',
    applicantStory:
      'Ascended Hörnli Ridge from Hörnlihütte (3,260m) at 04:00 CEST. Initial submission was rejected because my watch battery died at the Shoulder (4,200m) in -12°C wind; filing Independent Appeal with my climbing partner’s linked Suunto Vertical GPX track, Hörnlihütte warden log confirmation, and timestamped Swiss Summit Cross RAW photo.',
    truthfulnessDeclarationSigned: true,
    privacyConsent: {
      publicIdentityMode: 'FULL_VERIFIED_NAME',
      publicDatePrecision: 'EXACT_DATE',
      optInPublicLeaderboards: true,
    },
    evidenceArtifacts: [
      {
        id: 'art-103-gpx',
        type: 'GPX_TELEMETRY',
        fileName: 'matterhorn_hoernli_rope_team_full_track.gpx',
        sha256PostUploadDigest: 'f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b',
        uploadedAtUtc: '2026-08-14T15:20:00Z',
        extractedMetadata: {
          deviceModel: 'Suunto Vertical Titanium Solar (Rope-Team Linked Track)',
          captureTimestampUtc: '2026-08-09T08:51:00Z',
          recordedMaxElevationM: 4476.8,
          distanceSummitedFromApexM: 4.1,
          rolling15mMaxAscentMPerHr: 310,
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-103-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'DSC_0912_Matterhorn_Summit_Cross_Exif.NEF.jpg',
        sha256PostUploadDigest: 'cab8589f22134901238471092834710928374109283740192837409182734091',
        perceptualHash: 'pHash:77d21904ef812c44 (Unique)',
        uploadedAtUtc: '2026-08-14T15:21:00Z',
        extractedMetadata: {
          deviceModel: 'Nikon Z7 II',
          captureTimestampUtc: '2026-08-09T08:52:19Z',
          recordedMaxElevationM: 4478.0,
          exifSoftwareTag: 'Ver.1.60 (Original RAW Header Verified)',
          residentialStartEndMasked: true,
        },
      },
    ],
    advisoryAiAssessment: {
      modelId: 'gemini-3-flash-preview (Server-Side Advisory Only)',
      generatedAtUtc: '2026-08-14T15:22:00Z',
      advisoryRiskLevel: 'LOW',
      kinematicConsistencyNote:
        'Supplementary rope-team GPX track covers full Hörnlihütte -> Solvay -> Shoulder -> Swiss Summit Cross (4,476.8m) and complete descent.',
      exifForensicNote:
        'RAW photo EXIF timestamp (08:52 CEST) aligns within 79 seconds of rope-team GPX apex point.',
      duplicateCheckNote: 'Unique image hash.',
      disclaimer:
        'ADVISORY AI ANALYSIS ONLY — Case is in Independent Appeal Tribunal; original reviewer (usr-reviewer-104) is hard-blocked from adjudicating.',
    },
    status: 'APPEALED',
    requiresDualHumanReview: true,
    humanReviews: [
      {
        reviewId: 'rev-matterhorn-initial-reject',
        reviewerUserId: 'usr-reviewer-104',
        reviewerOfficerCode: 'REV-OFFICER-104',
        reviewerRole: 'VERIFICATION_OFFICER',
        coiAutomatedCheckPassed: true,
        coiHumanAttestationSigned: true,
        decision: 'REJECT',
        reasonCode: 'INCOMPLETE_GPX_APEX_INTERSECTION',
        humanRationale:
          'Initial uploaded watch track terminated at 4,195m (below the Shoulder) prior to the 4,478m summit ridge. Applicant advised to submit supplementary rope-team telemetry or appeal.',
        decidedAtUtc: '2026-08-12T11:00:00Z',
        decisionHmacSignature: 'hmac-sha256:9918b2c4e1029384756a',
      },
    ],
    appealRecord: {
      appealId: 'APL-2026-8848-019',
      filedAtUtc: '2026-08-14T15:25:00Z',
      appellantGrounds:
        'My primary watch battery froze at 4,195m on the Shoulder. I have now attached the continuous Suunto Vertical GPX log from my roped partner (linked expedition ID), Hörnlihütte booking confirmation, and unedited Nikon RAW summit cross photo with intact GPS/timestamp EXIF.',
      supplementaryEvidenceSummary:
        'Added full rope-team GPX track (4,476.8m apex) + Nikon Z7 II RAW header verification + Hörnlihütte registry.',
      originalReviewerUserIdsBlocked: ['usr-reviewer-104'],
    },
    submittedAtUtc: '2026-08-10T18:00:00Z',
  },
];

export const INITIAL_AUDIT_EVENTS: AppendOnlyAuditEvent[] = [
  {
    sequenceNumber: 1,
    eventId: 'AUD-8848-0001',
    timestampUtc: '2026-11-11T00:01:00Z',
    actorInternalUuid: 'uuid-gov-founder-001',
    actorRole: 'FOUNDER',
    actionType: 'CONSTITUTIONAL_INVARIANTS_LOCKED',
    targetEntityType: 'SYSTEM_CONSTITUTION',
    targetEntityId: 'DOC-P01-01',
    summary:
      'Locked 5 Permanent Principles and Non-Negotiable Rule: Achievements Must Be Earned, Never Bought. PAYMENTS_ENABLED=false, BLOCKCHAIN_MINTING_ENABLED=false.',
    previousEventHmac: 'GENESIS_000000000000000000000000000000000000000000000000',
    currentEventHmac: 'hmac256:a8f5f167f44f4964e6c998dee827110c9281726354182736',
    wormReplicated: true,
  },
  {
    sequenceNumber: 2,
    eventId: 'AUD-8848-0002',
    timestampUtc: '2026-11-11T00:15:00Z',
    actorInternalUuid: 'uuid-rev-officer-104',
    actorRole: 'VERIFICATION_OFFICER',
    actionType: 'TIER_A_FIRST_HUMAN_APPROVAL',
    targetEntityType: 'ACHIEVEMENT_SUBMISSION',
    targetEntityId: 'SUB-2026-8848-101',
    summary:
      'Completed COI attestation and recorded first human approval on Mount Everest submission SUB-2026-8848-101. Routed for mandatory second independent officer concurrence.',
    previousEventHmac: 'hmac256:a8f5f167f44f4964e6c998dee827110c9281726354182736',
    currentEventHmac: 'hmac256:b7e23c918273645519283746591827364519283746519283',
    wormReplicated: true,
  },
  {
    sequenceNumber: 3,
    eventId: 'AUD-8848-0003',
    timestampUtc: '2026-11-11T01:05:00Z',
    actorInternalUuid: 'uuid-gov-dual-control',
    actorRole: 'GOVERNANCE_COMMITTEE',
    actionType: 'CERTIFICATE_REVOCATION_DUAL_CONTROL',
    targetEntityType: 'PUBLIC_CERTIFICATE',
    targetEntityId: '8848-V1-0REV-8812-FRAUD-990X',
    summary:
      'Executed Dual-Control Revocation (REV-LEAD-001 + GOV-COMMITTEE-002) on certificate 8848-V1-0REV-8812-FRAUD-990X after post-issuance perceptual hash & telemetry audit.',
    previousEventHmac: 'hmac256:b7e23c918273645519283746591827364519283746519283',
    currentEventHmac: 'hmac256:c9d41e00192837465918273645192837465192837465a1b2',
    wormReplicated: true,
  },
];

export type ResourceDomain =
  | 'PUBLIC_DESTINATIONS_STAGE_5'
  | 'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4'
  | 'ACHIEVEMENT_SUBMISSIONS'
  | 'PRIVATE_EVIDENCE_VAULT'
  | 'VERIFICATION_DECISIONS'
  | 'APPEAL_TRIBUNAL_DECISIONS'
  | 'BADGES_AND_CERTIFICATES'
  | 'VERIFIED_LEADERBOARDS'
  | 'COMMUNITY_STORIES_AND_COMMENTS'
  | 'GUIDE_MARKETPLACE_LISTINGS'
  | 'ORGANIZATIONS_AND_PARTNERS'
  | 'SPONSORS_AND_CAMPAIGNS'
  | 'USER_ROLES_AND_PERMISSIONS'
  | 'APPEND_ONLY_AUDIT_LOGS';

export interface PermissionEvaluationResult {
  allowed: boolean;
  ruleCode: string;
  qualifier: string;
  explanation: string;
}

export function evaluateRbacPermission(
  role: UserRole,
  resource: ResourceDomain,
  action: ActionVerb
): PermissionEvaluationResult {
  // Constitutional Invariant 1: Append-Only Audit Logs can NEVER be Updated, Deleted, or Revoked by ANY role
  if (resource === 'APPEND_ONLY_AUDIT_LOGS') {
    if (action === 'UPDATE' || action === 'DELETE' || action === 'REVOKE' || action === 'CREATE' || action === 'APPROVE' || action === 'REJECT' || action === 'PUBLISH') {
      return {
        allowed: false,
        ruleCode: 'INVARIANT_WORM_AUDIT_IMMUTABLE',
        qualifier: 'HARD_DENY_ALL_ROLES',
        explanation:
          'Append-Only Audit Logs are write-once system records replicated to WORM storage. No human role (including Founder, Governance Committee, or SysAdmin) can modify, delete, or revoke audit events.',
      };
    }
    const canReadAudit = [
      'SENIOR_VERIFICATION_LEAD',
      'APPEAL_OFFICER',
      'SECURITY_COMPLIANCE_OFFICER',
      'PLATFORM_SYSADMIN',
      'GOVERNANCE_COMMITTEE',
      'FOUNDER',
    ].includes(role);
    return {
      allowed: canReadAudit,
      ruleCode: canReadAudit ? 'RBAC_AUDIT_READ_AUTHORIZED' : 'RBAC_AUDIT_READ_DENIED',
      qualifier: canReadAudit ? 'ALLOW (Scoped/Oversight)' : 'PROHIBITED',
      explanation: canReadAudit
        ? 'Role is authorized for read-only audit inspection.'
        : 'Standard, commercial, and public roles cannot read internal security audit logs.',
    };
  }

  // Constitutional Invariant 2: Commercial Firewall — Premium Member has identical trust permissions to Registered Adventurer
  const effectiveRole: UserRole =
    role === 'PREMIUM_MEMBER_FUTURE' ? 'REGISTERED_ADVENTURER' : role;

  // Constitutional Invariant 3: Commercial roles (Guides, Orgs, Partners, Sponsors) and Executive roles cannot directly APPROVE/REJECT Achievement Verification
  if (resource === 'VERIFICATION_DECISIONS') {
    if (action === 'APPROVE' || action === 'REJECT' || action === 'CREATE') {
      if (effectiveRole === 'VERIFICATION_OFFICER' || effectiveRole === 'SENIOR_VERIFICATION_LEAD') {
        return {
          allowed: true,
          ruleCode: 'RBAC_INDEPENDENT_VERIFICATION_DEPT_ONLY',
          qualifier: 'ALLOW (Never Own / Must Pass 5-Signal COI Check)',
          explanation:
            'Only vetted officers of the Independent Verification Department who pass all 5 automated Conflict-of-Interest checks and sign the COI attestation may approve or reject submissions.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'FIREWALL_VERIFICATION_INDEPENDENCE',
        qualifier: 'HARD_BLOCKED',
        explanation: `Role ${role} is strictly blocked from approving or rejecting achievement verifications. Even Founder/Governance and Commercial roles cannot bypass the Independent Verification Department.`,
      };
    }
  }

  // Constitutional Invariant 4: Appeal Decisions can ONLY be adjudicated by Appeal Officers (never original reviewer)
  if (resource === 'APPEAL_TRIBUNAL_DECISIONS') {
    if (action === 'APPROVE' || action === 'REJECT' || action === 'UPDATE') {
      if (effectiveRole === 'APPEAL_OFFICER') {
        return {
          allowed: true,
          ruleCode: 'RBAC_INDEPENDENT_APPEAL_TEAM_ONLY',
          qualifier: 'ALLOW (Never Original Reviewer / Never Applicant)',
          explanation:
            'Only members of the Independent Appeal Review Team who had zero participation in the original verification decision may adjudicate appeals.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'FIREWALL_APPEAL_INDEPENDENCE',
        qualifier: 'HARD_BLOCKED',
        explanation: `Role ${role} cannot adjudicate appeals. Original Verification Officers, Commercial roles, and Executive roles are blocked from voting on appeal outcomes.`,
      };
    }
  }

  // Private Evidence Vault
  if (resource === 'PRIVATE_EVIDENCE_VAULT') {
    if (action === 'READ') {
      if (
        ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)
      ) {
        return {
          allowed: true,
          ruleCode: 'VAULT_OWNER_READ',
          qualifier: 'ALLOW (Own Uploaded Evidence Only)',
          explanation: 'Users may view only their own uploaded evidence files.',
        };
      }
      if (
        ['VERIFICATION_OFFICER', 'SENIOR_VERIFICATION_LEAD', 'APPEAL_OFFICER', 'SECURITY_COMPLIANCE_OFFICER'].includes(
          effectiveRole
        )
      ) {
        return {
          allowed: true,
          ruleCode: 'VAULT_ASSIGNED_SHORT_TTL_SIGNED_URL',
          qualifier: 'ALLOW (Assigned Dossier Only via 15m Signed Token after COI Gate)',
          explanation:
            'Assigned, non-conflicted reviewers access private evidence via short-TTL signed URLs.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'VAULT_ZERO_PUBLIC_OR_COMMERCIAL_ACCESS',
        qualifier: 'PROHIBITED',
        explanation: 'Private Evidence Vault files are strictly isolated from public visitors, sponsors, partners, and unassigned staff.',
      };
    }
  }

  // Draft/Research Destinations (Stages 1-4)
  if (resource === 'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4') {
    if (action === 'PUBLISH' || action === 'APPROVE') {
      if (effectiveRole === 'GOVERNANCE_COMMITTEE' || effectiveRole === 'FOUNDER') {
        return {
          allowed: true,
          ruleCode: 'DEST_PUBLISH_DUAL_CONTROL_2P',
          qualifier: 'ALLOW (Requires Dual-Control 2P + Verified Elevation Citation)',
          explanation:
            'Transitioning a destination to Stage 4 (Reviewed & Approved) or Stage 5 (Published) requires verified survey citations and Dual-Control Governance approval.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'DEST_RESEARCHER_CANNOT_SELF_PUBLISH',
        qualifier: 'PROHIBITED',
        explanation: 'Destination Researchers can research Stages 1–3, but cannot unilaterally approve or publish destinations to the public catalog.',
      };
    }
    if (action === 'UPDATE' && effectiveRole === 'DESTINATION_RESEARCHER') {
      return {
        allowed: true,
        ruleCode: 'DEST_RESEARCH_STAGES_1_TO_3',
        qualifier: 'ALLOW (Stages 1–3 Research Only)',
        explanation: 'Destination Researchers compile citations, coordinates, route hazards, and telemetry envelopes in Stages 1–3.',
      };
    }
  }

  // Badges & Certificates Revocation
  if (resource === 'BADGES_AND_CERTIFICATES') {
    if (action === 'REVOKE') {
      if (['SENIOR_VERIFICATION_LEAD', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole)) {
        return {
          allowed: true,
          ruleCode: 'CERT_REVOKE_DUAL_CONTROL_2P',
          qualifier: 'ALLOW (Requires Dual-Control 2P Sign-Off + Audit Reason)',
          explanation: 'Post-issuance certificate revocation requires two distinct authorized principals and records a permanent public revocation audit entry.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'CERT_REVOKE_DENIED',
        qualifier: 'PROHIBITED',
        explanation: 'Only Dual-Control Governance + Senior Verification Lead can execute a formal certificate revocation.',
      };
    }
  }

  // Public Destinations & Leaderboards Read
  if (
    (resource === 'PUBLIC_DESTINATIONS_STAGE_5' || resource === 'VERIFIED_LEADERBOARDS') &&
    action === 'READ'
  ) {
    return {
      allowed: true,
      ruleCode: 'PUBLIC_READ_ALLOWED',
      qualifier: 'ALLOW (Public Projection)',
      explanation: 'Published Stage 5 destinations and verified leaderboards are readable by all roles.',
    };
  }

  // Default fallback for remaining permutations
  if (action === 'READ' && effectiveRole !== 'PUBLIC_VISITOR') {
    return {
      allowed: true,
      ruleCode: 'SCOPED_ROLE_READ',
      qualifier: 'ALLOW (Role-Scoped Projection)',
      explanation: 'Authenticated role permitted to read scoped projection of resource.',
    };
  }

  return {
    allowed: false,
    ruleCode: 'DENY_BY_DEFAULT_LEAST_PRIVILEGE',
    qualifier: 'PROHIBITED',
    explanation: `Deny-by-default least-privilege policy blocks (${role}) from executing (${action}) on (${resource}).`,
  };
}
