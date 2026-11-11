import {
  AchievementSubmission,
  ActionVerb,
  AppendOnlyAuditEvent,
  EvidenceBasedPhaseStatus,
  PublicCertificateRecord,
  UserRole,
} from '../types/platform';

export interface MasterPhaseSpec {
  phaseNumber: number;
  code: string;
  title: string;
  status: EvidenceBasedPhaseStatus;
  purpose: string;
  modules: string[];
  securityControls: string;
  governanceControls: string;
  deliverables: string[];
  acceptanceCriteria: string;
}

export const ALL_USER_ROLES: UserRole[] = [
  'PUBLIC_VISITOR',
  'REGISTERED_ADVENTURER',
  'PREMIUM_MEMBER_FUTURE',
  'VERIFIED_GUIDE',
  'ORGANIZATION_ADMIN',
  'DESTINATION_PARTNER',
  'SPONSOR_ACCOUNT',
  'DESTINATION_RESEARCHER',
  'VERIFICATION_OFFICER',
  'SENIOR_VERIFICATION_LEAD',
  'APPEAL_OFFICER',
  'SECURITY_COMPLIANCE_OFFICER',
  'PLATFORM_SYSADMIN',
  'GOVERNANCE_COMMITTEE',
  'FOUNDER',
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

export const ALL_RESOURCE_DOMAINS: ResourceDomain[] = [
  'PUBLIC_DESTINATIONS_STAGE_5',
  'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4',
  'ACHIEVEMENT_SUBMISSIONS',
  'PRIVATE_EVIDENCE_VAULT',
  'VERIFICATION_DECISIONS',
  'APPEAL_TRIBUNAL_DECISIONS',
  'BADGES_AND_CERTIFICATES',
  'VERIFIED_LEADERBOARDS',
  'COMMUNITY_STORIES_AND_COMMENTS',
  'GUIDE_MARKETPLACE_LISTINGS',
  'ORGANIZATIONS_AND_PARTNERS',
  'SPONSORS_AND_CAMPAIGNS',
  'USER_ROLES_AND_PERMISSIONS',
  'APPEND_ONLY_AUDIT_LOGS',
];

export const ALL_ACTION_VERBS: ActionVerb[] = [
  'READ',
  'CREATE',
  'UPDATE',
  'DELETE',
  'APPROVE',
  'REJECT',
  'PUBLISH',
  'REVOKE',
];

export const MASTER_21_PHASES: MasterPhaseSpec[] = [
  {
    phaseNumber: 1,
    code: 'PHASE 01',
    title: 'Master Requirements & Blueprint',
    status: 'DOCUMENTED',
    purpose:
      'Establish the complete product vision, objectives, feature inventory, user journeys, governance requirements, trust rules, and acceptance criteria.',
    modules: [
      'Project Charter (DOC-P01-01)',
      'Scope & Principles (DOC-P01-02)',
      'Open Decision Register OD-01..OD-08',
      'Phase 01 Closure Report',
    ],
    securityControls:
      'Zero client trust; separation of post-upload SHA-256 byte integrity from multi-modal authenticity.',
    governanceControls:
      '12 Non-Negotiable Principles locked; unapproved OD sub-parameters honestly marked UNRESOLVED.',
    deliverables: [
      '/docs/phase-01/00_PHASE_01_INDEX.md .. 13_PHASE_01_CLOSURE_REPORT.md',
    ],
    acceptanceCriteria: 'Complete Phase 01 documentation suite on disk and truthful status baseline.',
  },
  {
    phaseNumber: 2,
    code: 'PHASE 02',
    title: 'Technical Architecture & System Design',
    status: 'DESIGNED',
    purpose:
      'Design the complete frontend, backend, API, database, authentication, private vault storage, security boundaries, scalability, and disaster recovery architecture.',
    modules: [
      'Three-Zone Storage Isolation',
      'IdP Session Boundary',
      'SQLite/SQL Repository Layer',
      'RPO/RTO Continuity Design',
    ],
    securityControls:
      'Isolated authentication sessions; short-TTL signed tokens for Private Evidence Vault.',
    governanceControls: 'Blind Reviewer API projections stripping applicant PII and commercial metadata.',
    deliverables: ['System Architecture Blueprint', 'API Contract Spec', 'Three-Zone Data Isolation Spec'],
    acceptanceCriteria: 'Verified server-side authority and zero direct client mutations to trust tables.',
  },
  {
    phaseNumber: 3,
    code: 'PHASE 03',
    title: 'Development Infrastructure & GitHub',
    status: 'TESTED',
    purpose:
      'Establish clean-slate repository structure, strict TypeScript checking, environment template, and automated test execution.',
    modules: [
      'Strict TypeScript Config',
      'Environment & Secrets Policy',
      'Automated Vitest + Supertest Harness',
    ],
    securityControls: 'Zero secrets in source control; strict compile-time and runtime verification.',
    governanceControls: 'Mandatory phase-gate verification before advancing.',
    deliverables: ['Clean Repo Structure', '.env.example Template', 'Automated Test Suite'],
    acceptanceCriteria: 'Passing build, strict lint, and automated security/unit test checks.',
  },
  {
    phaseNumber: 4,
    code: 'PHASE 04',
    title: 'Brand, UI/UX & Design System',
    status: 'PARTIALLY_IMPLEMENTED',
    purpose:
      'Establish the Obsidian (#0A0A0A), Metallic Gold (#C9A86A), Highlight Gold (#FFD700), and White (#FFFFFF) visual system with Cinzel, Plus Jakarta Sans, and Noto Sans Devanagari.',
    modules: [
      'Obsidian & Gold Tokens',
      'Bilingual EN/NE Typography',
      '3D Badge Inspector',
      'WCAG 2.1 AA Accessible Layouts',
    ],
    securityControls: 'Zero hue-only state signaling; measured media contrast scrims.',
    governanceControls:
      'Strict visual distinction between verified records, unverified drafts, and SPONSORED placements.',
    deliverables: ['Design Tokens', 'Destination Explorer', 'Verification Workstation', 'Public Verifier'],
    acceptanceCriteria: 'WCAG 2.1 AA contrast compliance and responsive desktop/mobile parity.',
  },
  {
    phaseNumber: 5,
    code: 'PHASE 05',
    title: 'Database Architecture & Data Governance',
    status: 'TESTED',
    purpose:
      'Implement persistent relational database storage separating public catalog data, private evidence artifacts, encrypted user PII vaults, and append-only audit records.',
    modules: [
      'Persistent SQLite WAL Engine',
      'AES-256-GCM User PII Vault',
      'Per-User DEK Key-Shredding',
      'Trigger-Enforced Immutable Audit Log',
    ],
    securityControls:
      'SQL BEFORE UPDATE/DELETE triggers abort audit mutations; AES-256-GCM key-shredding on erasure.',
    governanceControls: 'Foreign key constraints requiring human review records for every certificate.',
    deliverables: ['src/server/db.ts', 'src/server/privacyVault.ts', 'Database Migration & Concurrency Tests'],
    acceptanceCriteria: 'Verified ACID persistence, FK integrity, and zero PII leakage in audit logs.',
  },
  {
    phaseNumber: 6,
    code: 'PHASE 06',
    title: 'Backend Infrastructure & API Architecture',
    status: 'TESTED',
    purpose:
      'Enforce server-side validation, RBAC authorization, forensic file processing, rate limiting, and security headers across all API endpoints.',
    modules: [
      'Express REST Gateway (/api/v1)',
      'GPX/EXIF/PDF Forensic Processor',
      'Rate Limiter & Security Headers Shield',
    ],
    securityControls:
      'XXE-blocking XML/PDF inspection; magic-byte validation; server-side session & RBAC enforcement.',
    governanceControls: 'All sensitive state transitions enforced exclusively on the backend server.',
    deliverables: ['src/server/apiRouter.ts', 'src/server/evidenceProcessor.ts'],
    acceptanceCriteria: '100% server-side validation of verification, appeal, and catalog state transitions.',
  },
  {
    phaseNumber: 7,
    code: 'PHASE 07',
    title: 'Security Foundation & Governance Enforcement',
    status: 'TESTED',
    purpose:
      'Enforce 1,680-permutation RBAC, least privilege, separation of duties, Dual-Control (2P) governance, COI blocking, and HMAC-SHA256 audit chaining.',
    modules: [
      '1,680-Permutation RBAC Engine',
      '5-Signal COI Blocker',
      'Dual-Control Two-Person Gate',
      'RFC 4231 HMAC-SHA256 Audit Verifier',
    ],
    securityControls:
      'Prevents privilege escalation, self-approval, and audit tampering; uses genuine node:crypto.',
    governanceControls: 'Two-person rule enforced on server for Stage 4/5 publishing and revocations.',
    deliverables: ['src/server/cryptoEngine.ts', 'src/tests/rbac1680.test.ts'],
    acceptanceCriteria: '100% pass rate across all 1,680 RBAC combinations and tamper-detection tests.',
  },
  {
    phaseNumber: 8,
    code: 'PHASE 08',
    title: 'Authentication, User & Account Management',
    status: 'TESTED',
    purpose:
      'Implement real authentication: scrypt password verification, RFC 6238 TOTP MFA for privileged roles, CSPRNG server sessions, expiration/revocation, and privacy controls.',
    modules: [
      'scrypt Password Verifier',
      'RFC 6238 TOTP MFA Gate',
      'CSPRNG Session Store',
      'Account Erasure & Key-Shredding',
    ],
    securityControls:
      'No unauthenticated role switching; privileged roles require MFA; constant-time comparisons.',
    governanceControls: 'Holder controls public name mode, date precision, and leaderboard opt-in.',
    deliverables: ['src/server/auth.ts', 'Authentication & Session Security Tests'],
    acceptanceCriteria: 'Verified server session validation, MFA enforcement, and key-shredding erasure.',
  },
  {
    phaseNumber: 9,
    code: 'PHASE 09',
    title: 'Global Destinations & Route Management',
    status: 'TESTED',
    purpose:
      'Manage the global catalog of exactly 100 Featured Destinations across 6 world regions initialized at 1_PROPOSED and governed by the 5-stage workflow.',
    modules: [
      '100 Distinct Global Destinations',
      '1_PROPOSED Baseline Reset',
      '5-Stage Server State Machine',
      'Dual-Control (2P) Publication Gate',
    ],
    securityControls: 'Unpublished destinations (Stages 1–4) blocked from accepting achievement submissions.',
    governanceControls: 'Two distinct governance principals required to advance Stages 4 and 5.',
    deliverables: ['src/data/destinations100.ts', 'Destination Stage & Dual-Control Tests'],
    acceptanceCriteria: 'Zero duplicate records; baseline reset to 1_PROPOSED; strict 2P stage gating.',
  },
  {
    phaseNumber: 10,
    code: 'PHASE 10',
    title: 'Adventure Guide & Marketplace',
    status: 'NOT_STARTED',
    purpose:
      'Protected future phase: Guide license vetting, expedition listings, availability, booking workflow, safety disclosures, and dispute handling.',
    modules: ['Guide License Vetting (Planned)', 'Commercial Firewall Signal 2 (Active)'],
    securityControls: 'Automated COI Signal 2 blocks guides from reviewing their own clients.',
    governanceControls: 'Held at NOT_STARTED per Stage D directive until foundation sign-off.',
    deliverables: ['COI Signal 2 Enforcement Active'],
    acceptanceCriteria: '100% isolation between guide relationships and verification approvals.',
  },
  {
    phaseNumber: 11,
    code: 'PHASE 11',
    title: 'Achievement Submission & Evidence Engine',
    status: 'TESTED',
    purpose:
      'Implement real evidence upload and forensic parsing: GPX telemetry, JPEG EXIF headers, PDF XXE checks, SHA-256 byte digests, duplicate detection, and 2 km residential masking.',
    modules: [
      'Binary/Multipart Evidence Uploader',
      'SHA-256 File Digest Calculator',
      'XXE-Safe GPX/EXIF/PDF Parser',
      '2km Residential Geofence Masker',
    ],
    securityControls:
      'Private Vault storage (.data/vault); blocks XXE payloads and duplicate file hashes; signed short-TTL links.',
    governanceControls: 'Supports both Contemporary Digital Track and Historical Documentary Track.',
    deliverables: ['src/server/evidenceProcessor.ts', 'Evidence & XXE Security Tests'],
    acceptanceCriteria: 'Verified real SHA-256 calculation, GPX extraction, XXE rejection, and coordinate masking.',
  },
  {
    phaseNumber: 12,
    code: 'PHASE 12',
    title: 'Human Verification & Anti-Fraud Engine',
    status: 'TESTED',
    purpose:
      'Implement server-side Independent Verification Department workflows with 5-signal COI blocking, blind reviewer projections, Tier-A Dual Review, split-vote escalation, and appeals.',
    modules: [
      'Server Verification Endpoint',
      '5-Signal COI Gate',
      'Split-Decision Escalation Engine',
      'Independent Appeal Tribunal Endpoint',
    ],
    securityControls: 'AI service accounts have zero permission to approve or reject submissions.',
    governanceControls: 'Human-only final decisions; Tier-A peaks require two distinct human officers.',
    deliverables: ['src/domain/verificationEngine.ts', 'Verification & Appeal Tribunal Tests'],
    acceptanceCriteria: 'Verified server block on self-review, guide COI, original-reviewer appeal, and split votes.',
  },
  {
    phaseNumber: 13,
    code: 'PHASE 13',
    title: 'Badges, Certificates & Public Verification',
    status: 'TESTED',
    purpose:
      'Deliver 100 destination 3D badges, free official certificates, 128-bit CSPRNG verification IDs, rate-limited public verification endpoint, and Dual-Control revocation.',
    modules: [
      '128-Bit CSPRNG Token Generator',
      'Free Official Certificate Issuer',
      'Rate-Limited Public Verifier (/api/v1/verify/:id)',
      'Dual-Control (2P) Revocation Engine',
    ],
    securityControls: 'crypto.randomBytes(16) prevents enumeration; respects holder privacy consent.',
    governanceControls: 'Standard badges and certificates are permanently free; zero issuance for unapproved claims.',
    deliverables: ['src/components/Badge3DViewer.tsx', 'CSPRNG & Revocation Tests'],
    acceptanceCriteria: 'Verified 128-bit CSPRNG entropy, collision handling, and Dual-Control revocation.',
  },
  {
    phaseNumber: 14,
    code: 'PHASE 14',
    title: 'Leaderboards, Community & Social',
    status: 'PARTIALLY_IMPLEMENTED',
    purpose:
      'Deliver server-computed verified leaderboards (derived 100% from VALID opt-in certificates) while holding social/community feeds under Stage D.',
    modules: [
      'Server Verified Leaderboards (/api/v1/leaderboards)',
      'Instant Revocation/Erasure Recalculation',
      'Community Stories (Held under Stage D)',
    ],
    securityControls: 'Revoked or erased certificates are immediately excluded from standings.',
    governanceControls: 'Rankings derived 100% from verified achievements; positions can never be bought.',
    deliverables: ['Verified Leaderboard API & UI'],
    acceptanceCriteria: 'Zero commercial influence on leaderboard sorting.',
  },
  {
    phaseNumber: 15,
    code: 'PHASE 15',
    title: 'Organizations & Destination Partners',
    status: 'NOT_STARTED',
    purpose:
      'Protected future phase: Portals for mountaineering clubs, agencies, tourism boards, and national parks with written MOU verification.',
    modules: ['Partner MOU Registry (Planned)', 'COI Signal 3 Organization Firewall (Active)'],
    securityControls: 'Shared organization affiliation is blocked by COI Signal 3.',
    governanceControls: 'Held at NOT_STARTED per Stage D directive.',
    deliverables: ['COI Signal 3 Enforcement Active'],
    acceptanceCriteria: 'Zero partner interference in verification.',
  },
  {
    phaseNumber: 16,
    code: 'PHASE 16',
    title: 'Sponsorship & Advertising System',
    status: 'NOT_STARTED',
    purpose:
      'Protected future phase: Transparent commercial placement framework with mandatory SPONSORED labels and strict firewall isolation.',
    modules: ['Sponsor Compliance Console (Planned)', 'RBAC Sponsor Firewall (Active)'],
    securityControls: 'SPONSOR_ACCOUNT is hard-blocked from reading submissions, evidence, decisions, or audit logs.',
    governanceControls: 'Held at NOT_STARTED per Stage D directive.',
    deliverables: ['RBAC Commercial Firewall Verified'],
    acceptanceCriteria: 'Zero sponsor read/write access to verification or private data.',
  },
  {
    phaseNumber: 17,
    code: 'PHASE 17',
    title: 'Revenue, Membership & Payment Infrastructure',
    status: 'HARD_LOCKED_GATE',
    purpose:
      'Enforce constitutional hard lock (PAYMENTS_ENABLED = FALSE) returning HTTP 503 on all payment endpoints until legal, financial, and security sign-off.',
    modules: ['PAYMENTS_ENABLED = FALSE Hard Lock', 'HTTP 503 Payment Gate Enforcer'],
    securityControls: 'Server-side HTTP 503 lock on POST /api/v1/payments/checkout.',
    governanceControls: 'Standard digital badges and certificates remain permanently free.',
    deliverables: ['Payment Hard-Lock Endpoint & Regression Test'],
    acceptanceCriteria: 'Confirmed HTTP 503 response and zero payment collection.',
  },
  {
    phaseNumber: 18,
    code: 'PHASE 18',
    title: 'AI, Blockchain & NFT Future Architecture',
    status: 'HARD_LOCKED_GATE',
    purpose:
      'Enforce constitutional hard lock (BLOCKCHAIN_MINTING_ENABLED = FALSE) returning HTTP 503 on minting endpoints and maintain sanitized, non-decisional advisory AI.',
    modules: [
      'BLOCKCHAIN_MINTING_ENABLED = FALSE Hard Lock',
      'Sanitized Server-Side Advisory AI Assistant',
    ],
    securityControls: 'HTTP 503 on POST /api/v1/blockchain/mint; catalog-lookup sanitization on AI brief.',
    governanceControls: 'Primary database is authoritative; AI never approves or rejects achievements.',
    deliverables: ['Blockchain Hard-Lock Endpoint & Regression Test'],
    acceptanceCriteria: 'Confirmed HTTP 503 response and audited advisory-only AI.',
  },
  {
    phaseNumber: 19,
    code: 'PHASE 19',
    title: 'Admin, Governance & Globalization',
    status: 'PARTIALLY_IMPLEMENTED',
    purpose:
      'Deliver Dual-Control (2P) approval queue, HMAC-SHA256 audit chain verifier, and English + Nepali (Devanagari) / Metric + Imperial support.',
    modules: [
      'Dual-Control Approval Queue',
      'HMAC-SHA256 Audit Chain Inspector',
      'EN/NE & Metric/Imperial Switchers',
    ],
    securityControls: 'Every privileged action requires authenticated session and writes to immutable audit table.',
    governanceControls: 'Dual-Control (2P) enforced on server for Stage 4/5 publication and certificate revocation.',
    deliverables: ['Governance Console & Audit Verifier'],
    acceptanceCriteria: 'Verified server audit chain integrity and Dual-Control enforcement.',
  },
  {
    phaseNumber: 20,
    code: 'PHASE 20',
    title: 'Complete QA, Security Audit & Performance Testing',
    status: 'TESTED',
    purpose:
      'Verify all 1,680 RBAC permutations, 5-signal COI blocking, CSPRNG entropy, NIST SHA-256, RFC 4231 HMAC-SHA256, XXE rejection, Dual-Control, and database concurrency.',
    modules: [
      '1,680-Permutation RBAC Test Suite',
      'Cryptography & Audit Tamper Test Suite',
      'API & Evidence Security Test Suite',
    ],
    securityControls: 'Automated tests exercise real backend functions, SQLite database, and Express routes.',
    governanceControls: 'Zero mocked frontend state used as proof of backend security.',
    deliverables: ['src/tests/rbac1680.test.ts', 'src/tests/foundation.test.ts'],
    acceptanceCriteria: '100% pass rate on automated Vitest + Supertest verification suite.',
  },
  {
    phaseNumber: 21,
    code: 'PHASE 21',
    title: 'Production Launch & Global Expansion',
    status: 'NOT_STARTED',
    purpose:
      'Execute formal launch readiness checklist for 0to8848official.com after external cloud infrastructure provisioning, legal sign-off, and Founder final authorization.',
    modules: ['Production Cloud Provisioning (Pending OD-04)', 'Legal & Compliance Sign-Off (Pending)'],
    securityControls: 'Requires external cloud WORM storage and production TLS/KMS setup.',
    governanceControls: 'No premature public launch without Founder final authorization.',
    deliverables: ['Production Readiness Gate Report'],
    acceptanceCriteria: 'All 21 phase gates verified and approved by Founder.',
  },
];

export const INITIAL_VERIFIED_CERTIFICATES: PublicCertificateRecord[] = [
  {
    verificationId: '8848-V1-9K4M-7P2X-Q8R5-3N6W-5T8B-2M',
    submissionId: 'sub-everest-001',
    holderUserId: 'usr-pasangnya-01',
    holderInternalActorUuid: 'act-uuid-pasangnya-01',
    holderPublicDisplay: 'Pasang Dawa Sherpa',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderDatePrecision: 'EXACT_DATE',
    holderNationality: 'Nepal (NP)',
    destinationId: 'dest-001',
    destinationCode: 'DEST-001',
    destinationNameEn: 'Mount Everest (Sagarmatha)',
    destinationNameNe: 'सगरमाथा (चोमोलुङमा)',
    verifiedElevationM: 8848.86,
    verifiedElevationFt: 29032,
    elevationSourceCitation:
      'Survey Department of Nepal (2020 Official Joint Trigonometric & GNSS Survey)',
    routeName: 'South Col — Southeast Ridge (Nepal)',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-05-19',
    issuedAtUtc: '2026-05-28T09:15:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104 (Lead)', 'REV-OFFICER-219 (Dual Concurrence)'],
    badgeCode: 'BDG-8848-001',
    certificateIntegrityDigest:
      'a4f2c891e7023d4b8c9a1157e3f60912d84a6b73c90e1f23456789abcdef0123',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-4T8H-2W9C-L5V1-8M3J-7R4K-9P',
    submissionId: 'sub-amadablam-002',
    holderUserId: 'usr-elena-02',
    holderInternalActorUuid: 'act-uuid-elena-02',
    holderPublicDisplay: 'Elena Rostova',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderDatePrecision: 'EXACT_DATE',
    holderNationality: 'Switzerland (CH)',
    destinationId: 'dest-009',
    destinationCode: 'DEST-009',
    destinationNameEn: 'Ama Dablam',
    destinationNameNe: 'आमा दब्लम',
    verifiedElevationM: 6812,
    verifiedElevationFt: 22349,
    elevationSourceCitation:
      'Survey Department of Nepal & Nepal Mountaineering Association',
    routeName: 'Southwest Ridge via Camp I, Yellow Tower & Mushroom Ridge',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-10-24',
    issuedAtUtc: '2026-10-29T14:40:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104', 'REV-OFFICER-219 (Dual Concurrence)'],
    badgeCode: 'BDG-8848-009',
    certificateIntegrityDigest:
      '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-6B3N-9F4D-X2Z7-1Q5P-3C8V-4L',
    submissionId: 'sub-thorong-003',
    holderUserId: 'usr-aarav-03',
    holderInternalActorUuid: 'act-uuid-aarav-03',
    holderPublicDisplay: 'A. K. Gurung (Initials Consent Mode)',
    holderPrivacyMode: 'DISPLAY_HANDLE_OR_INITIALS',
    holderDatePrecision: 'MONTH_AND_YEAR_ONLY',
    holderNationality: 'Nepal (NP)',
    destinationId: 'dest-014',
    destinationCode: 'DEST-014',
    destinationNameEn: 'Annapurna Circuit via Thorong La Pass',
    destinationNameNe: 'अन्नपूर्ण चक्रीय पदमार्ग (थोराङ ला भन्ज्याङ)',
    verifiedElevationM: 5416,
    verifiedElevationFt: 17769,
    elevationSourceCitation: 'Survey Department of Nepal & ACAP',
    routeName:
      'Dharapani – Manang – Yak Kharka – Thorong La Pass (5,416m) – Muktinath',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-10',
    issuedAtUtc: '2026-11-01T11:20:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-219'],
    badgeCode: 'BDG-8848-014',
    certificateIntegrityDigest:
      '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-7Y2K-5R8M-W3N9-4C1Z-8H2Q-6X',
    submissionId: 'sub-kili-004',
    holderUserId: 'usr-mateo-04',
    holderInternalActorUuid: 'act-uuid-mateo-04',
    holderPublicDisplay: 'Mateo Valdés',
    holderPrivacyMode: 'FULL_VERIFIED_NAME',
    holderDatePrecision: 'EXACT_DATE',
    holderNationality: 'Argentina (AR)',
    destinationId: 'dest-081',
    destinationCode: 'DEST-081',
    destinationNameEn: 'Mount Kilimanjaro (Uhuru Peak)',
    verifiedElevationM: 5895,
    verifiedElevationFt: 19341,
    elevationSourceCitation:
      'Tanzania National Parks Authority (TANAPA) & Survey of Tanzania',
    routeName: 'Machame / Lemosho Route via Stella Point to Uhuru Peak',
    verificationTrack: 'STANDARD_DIGITAL',
    publicCompletionDateDisplay: '2026-08-14',
    issuedAtUtc: '2026-08-19T16:05:00Z',
    status: 'VALID',
    reviewingOfficersCodes: ['REV-OFFICER-104'],
    badgeCode: 'BDG-8848-081',
    certificateIntegrityDigest:
      '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    optInPublicLeaderboards: true,
  },
  {
    verificationId: '8848-V1-0REV-8812-FRAUD-990X-4M2P-7Z',
    submissionId: 'sub-revoked-005',
    holderUserId: 'usr-redacted-99',
    holderInternalActorUuid: 'act-uuid-redacted-99',
    holderPublicDisplay: 'Credential Revoked by Governance Tribunal',
    holderPrivacyMode: 'PRIVATE_CREDENTIAL_HOLDER',
    holderDatePrecision: 'MONTH_AND_YEAR_ONLY',
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
      'REVOKED under Dual-Control Resolution GOV-REV-2026-04: Post-issuance forensic audit detected synthetic GPX track manipulation and duplicate SHA-256 summit photograph match.',
    reviewingOfficersCodes: ['REV-LEAD-001', 'GOV-COMMITTEE-002'],
    badgeCode: 'BDG-8848-035',
    certificateIntegrityDigest:
      'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
    optInPublicLeaderboards: false,
  },
];

export const INITIAL_SUBMISSIONS_QUEUE: AchievementSubmission[] = [
  {
    id: 'sub-queue-101',
    submissionCode: 'SUB-2026-8848-101',
    applicantUserId: 'usr-tenzing-nepal',
    applicantInternalActorUuid: 'act-uuid-tenzing-001',
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
        fileName: 'everest_south_col_summit_20260522.gpx',
        sha256PostUploadDigest:
          '3a9f4b2c8e1d70654f92a1c3e8b7d6045219f8e7c6b5a4938271605f4e3d2c1b',
        uploadedAtUtc: '2026-05-26T12:10:00Z',
        extractedMetadata: {
          deviceModel: 'Garmin Fenix 7X Pro Sapphire Solar (Multi-Band GNSS + Baro)',
          captureTimestampUtc: '2026-05-22T05:42:14Z',
          recordedMaxElevationM: 8851.2,
          distanceSummitedFromApexM: 6.4,
          rolling15mMaxAscentMPerHr: 195,
          residentialStartEndMasked: true,
          barometricChannelDetected: true,
        },
      },
      {
        id: 'art-101-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'DSC04819_Everest_Summit_Panorama.jpg',
        sha256PostUploadDigest:
          '7c4a8d09ca3762af61e59520943dc26494f8941b532a99818b9c7d6e5f4a3b21',
        perceptualHash: 'pHash:f8c39a1204e77b19',
        uploadedAtUtc: '2026-05-26T12:11:30Z',
        extractedMetadata: {
          deviceModel: 'Sony ILCE-7RM5',
          captureTimestampUtc: '2026-05-22T05:44:02Z',
          recordedMaxElevationM: 8849.0,
          exifSoftwareTag: 'Camera Firmware v2.01',
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-101-permit',
        type: 'OFFICIAL_PERMIT_DOC',
        fileName: 'DoT_Nepal_Mountaineering_Royalty_Permit_Spring2026.pdf',
        sha256PostUploadDigest:
          '3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b',
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
        'Rolling 15-min vertical ascent rate (195 m/hr from South Col to Summit) is within the DEST-001 Tier-A envelope (<= 650 m/hr). Barometric pressure channel corroborates GNSS altitude (8,851.2m).',
      exifForensicNote:
        'EXIF timestamp (05:44 UTC+5:45) and horizon landmarks match May 22 dawn geometry.',
      duplicateCheckNote: 'SHA-256 and perceptual hash show zero collision against stored artifacts.',
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
          'First Human Review Complete: Verified DoT permit #DOT-NP-SGR-2026-0418, continuous multi-band GNSS + barometric track to within 6.4m of official 8,848.86m apex, and summit photo. Ready for second independent officer concurrence.',
        decidedAtUtc: '2026-05-27T08:30:00Z',
        decisionHmacSignature:
          '9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3',
      },
    ],
    submittedAtUtc: '2026-05-26T12:13:00Z',
  },
  {
    id: 'sub-queue-102',
    submissionCode: 'SUB-2026-8848-102',
    applicantUserId: 'usr-claire-fr',
    applicantInternalActorUuid: 'act-uuid-claire-002',
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
      'Climbed from Island Peak Base Camp (5,087m) via Crampon Point and the 50° headwall fixed rope line to the narrow summit ridge at 6,189m.',
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
        sha256PostUploadDigest:
          '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        uploadedAtUtc: '2026-10-21T09:00:00Z',
        extractedMetadata: {
          deviceModel: 'COROS VERTIX 2S',
          captureTimestampUtc: '2026-10-18T07:15:40Z',
          recordedMaxElevationM: 6186.5,
          distanceSummitedFromApexM: 11.2,
          rolling15mMaxAscentMPerHr: 420,
          residentialStartEndMasked: true,
          barometricChannelDetected: true,
        },
      },
      {
        id: 'art-102-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'IMG_8821_ImjaTse_Summit_LhotseSouthWall.jpg',
        sha256PostUploadDigest:
          '1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014',
        perceptualHash: 'pHash:a119d4087bc2301e',
        uploadedAtUtc: '2026-10-21T09:02:00Z',
        extractedMetadata: {
          deviceModel: 'Apple iPhone 16 Pro (RAW)',
          captureTimestampUtc: '2026-10-18T07:18:10Z',
          recordedMaxElevationM: 6188.0,
          exifSoftwareTag: 'iOS 19.1 Native Camera',
          residentialStartEndMasked: true,
        },
      },
      {
        id: 'art-102-permit',
        type: 'OFFICIAL_PERMIT_DOC',
        fileName: 'NMA_Imja_Tse_Climbing_Permit_Autumn2026.pdf',
        sha256PostUploadDigest:
          '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752',
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
        'Single-point GNSS multipath bounce detected at 5,650m rock gully, while 15-minute rolling ascent rate (420 m/hr) and barometric altitude progression remain physically consistent within DEST-011 envelope (<= 950 m/hr).',
      exifForensicNote:
        'Summit photo EXIF coordinates and Lhotse Shar backdrop match canonical Imja Tse summit crest.',
      duplicateCheckNote: 'Zero duplicate hash matches found.',
      disclaimer:
        'ADVISORY AI ANALYSIS ONLY — Multipath flag requires human reviewer contextual inspection.',
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
    applicantInternalActorUuid: 'act-uuid-lukas-003',
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
        sha256PostUploadDigest:
          'f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b',
        uploadedAtUtc: '2026-08-14T15:20:00Z',
        extractedMetadata: {
          deviceModel: 'Suunto Vertical Titanium Solar (Rope-Team Linked Track)',
          captureTimestampUtc: '2026-08-09T08:51:00Z',
          recordedMaxElevationM: 4476.8,
          distanceSummitedFromApexM: 4.1,
          rolling15mMaxAscentMPerHr: 310,
          residentialStartEndMasked: true,
          barometricChannelDetected: true,
        },
      },
      {
        id: 'art-103-photo',
        type: 'RAW_EXIF_PHOTO',
        fileName: 'DSC_0912_Matterhorn_Summit_Cross_Exif.jpg',
        sha256PostUploadDigest:
          '4e9c8b7a6d5f4e3c2b1a0987654321fedcba9876543210abcdef1234567890ab',
        perceptualHash: 'pHash:77d21904ef812c44',
        uploadedAtUtc: '2026-08-14T15:21:00Z',
        extractedMetadata: {
          deviceModel: 'Nikon Z7 II',
          captureTimestampUtc: '2026-08-09T08:52:19Z',
          recordedMaxElevationM: 4478.0,
          exifSoftwareTag: 'Ver.1.60',
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
        decisionHmacSignature:
          '7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e',
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

export const INITIAL_AUDIT_EVENTS: AppendOnlyAuditEvent[] = [];

export interface PermissionEvaluationResult {
  allowed: boolean;
  ruleCode: string;
  qualifier: string;
  explanation: string;
}

/**
 * Exhaustive, deterministic 1,680-permutation RBAC policy engine
 * (15 UserRoles × 14 ResourceDomains × 8 ActionVerbs = 1,680 combinations).
 * Enforces strict Deny-By-Default with zero permissive catch-all fallbacks.
 */
export function evaluateRbacPermission(
  role: UserRole,
  resource: ResourceDomain,
  action: ActionVerb
): PermissionEvaluationResult {
  // Constitutional Invariant 1: Commercial Firewall — PREMIUM_MEMBER_FUTURE has identical trust/data permissions to REGISTERED_ADVENTURER
  const effectiveRole: UserRole =
    role === 'PREMIUM_MEMBER_FUTURE' ? 'REGISTERED_ADVENTURER' : role;

  switch (resource) {
    // 1. APPEND_ONLY_AUDIT_LOGS
    case 'APPEND_ONLY_AUDIT_LOGS': {
      if (action === 'READ') {
        const canReadAudit = [
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
          'PLATFORM_SYSADMIN',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
        return {
          allowed: canReadAudit,
          ruleCode: canReadAudit ? 'RBAC_AUDIT_READ_AUTHORIZED' : 'RBAC_AUDIT_READ_DENIED',
          qualifier: canReadAudit ? 'ALLOW (Read-Only Oversight)' : 'PROHIBITED',
          explanation: canReadAudit
            ? 'Authorized oversight role may inspect immutable audit logs.'
            : 'Public, adventurer, and commercial roles cannot read internal security audit logs.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'INVARIANT_WORM_AUDIT_IMMUTABLE',
        qualifier: 'HARD_DENY_ALL_ROLES',
        explanation:
          'Append-Only Audit Logs are written exclusively by internal server transactions and protected by database immutability triggers. No human role can create, update, delete, approve, reject, publish, or revoke audit events.',
      };
    }

    // 2. PUBLIC_DESTINATIONS_STAGE_5
    case 'PUBLIC_DESTINATIONS_STAGE_5': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'PUBLIC_STAGE_5_READ_ALLOWED',
          qualifier: 'ALLOW (Public Catalog)',
          explanation: 'Published Stage 5 destinations are readable by all roles.',
        };
      }
      if (action === 'PUBLISH' || action === 'REVOKE') {
        if (effectiveRole === 'GOVERNANCE_COMMITTEE' || effectiveRole === 'FOUNDER') {
          return {
            allowed: true,
            ruleCode: 'STAGE_5_DUAL_CONTROL_2P',
            qualifier: 'ALLOW (Requires Dual-Control 2P Co-Signer)',
            explanation:
              'Publishing or unpublishing a Stage 5 destination requires two distinct governance principals.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'STAGE_5_MUTATION_DENIED',
          qualifier: 'PROHIBITED',
          explanation: 'Only Dual-Control Governance authority can publish or revoke Stage 5 destinations.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'STAGE_5_DIRECT_EDIT_DENIED',
        qualifier: 'PROHIBITED',
        explanation: 'Published Stage 5 records cannot be directly edited or deleted outside the research stage pipeline.',
      };
    }

    // 3. DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4
    case 'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4': {
      if (action === 'READ') {
        const canReadDrafts = [
          'DESTINATION_RESEARCHER',
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
        return {
          allowed: canReadDrafts,
          ruleCode: canReadDrafts ? 'DRAFT_DEST_READ_AUTHORIZED' : 'DRAFT_DEST_READ_DENIED',
          qualifier: canReadDrafts ? 'ALLOW (Internal Research Pipeline)' : 'PROHIBITED',
          explanation: canReadDrafts
            ? 'Authorized research, verification, and governance staff may inspect draft destinations in Stages 1–4.'
            : 'Public visitors, adventurers, and commercial roles cannot access unverified draft research dossiers.',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        const canEditDrafts = [
          'DESTINATION_RESEARCHER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
        return {
          allowed: canEditDrafts,
          ruleCode: canEditDrafts ? 'DEST_RESEARCH_STAGES_1_TO_3' : 'DEST_RESEARCH_EDIT_DENIED',
          qualifier: canEditDrafts ? 'ALLOW (Stages 1–3 Dossier Compilation)' : 'PROHIBITED',
          explanation: canEditDrafts
            ? 'Destination Researchers and Governance compile citations, coordinates, and telemetry envelopes in Stages 1–3.'
            : 'Role is not authorized to modify destination research dossiers.',
        };
      }
      if (action === 'APPROVE' || action === 'PUBLISH') {
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
          explanation:
            'Destination Researchers and non-governance roles cannot unilaterally approve Stage 4 or publish Stage 5 destinations.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'DRAFT_DEST_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Action (${action}) is not permitted on draft destination dossiers.`,
      };
    }

    // 4. ACHIEVEMENT_SUBMISSIONS
    case 'ACHIEVEMENT_SUBMISSIONS': {
      if (action === 'READ') {
        const canReadOwn = ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole);
        if (canReadOwn) {
          return {
            allowed: true,
            ruleCode: 'SUBMISSION_READ_OWN_ONLY',
            qualifier: 'ALLOW (Own Submissions Only)',
            explanation: 'Adventurers may read only their own submitted achievement dossiers.',
          };
        }
        const canReadAssigned = [
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
        ].includes(effectiveRole);
        if (canReadAssigned) {
          return {
            allowed: true,
            ruleCode: 'SUBMISSION_READ_BLIND_REVIEW_PROJECTION',
            qualifier: 'ALLOW (Blind Reviewer Projection)',
            explanation:
              'Verification, Appeal, and Security officers may read assigned dossiers via blind projection.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'SUBMISSION_READ_DENIED_COMMERCIAL_AND_PUBLIC',
          qualifier: 'HARD_BLOCKED',
          explanation:
            'Public visitors, sponsors, partners, organizations, and non-review roles are strictly blocked from reading private achievement submissions.',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'SUBMISSION_CREATE_UPDATE_OWN',
            qualifier: 'ALLOW (Own Submission & Additional Evidence)',
            explanation:
              'Authenticated adventurers may submit new achievement claims and attach requested supplementary evidence.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'SUBMISSION_CREATE_DENIED',
          qualifier: 'PROHIBITED',
          explanation: 'Only registered adventurers may create or update their own achievement submissions.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'SUBMISSION_DIRECT_DECISION_DENIED',
        qualifier: 'PROHIBITED',
        explanation:
          'Submissions cannot be deleted, approved, or rejected directly on the submission resource; decisions must go through VERIFICATION_DECISIONS or APPEAL_TRIBUNAL_DECISIONS.',
      };
    }

    // 5. PRIVATE_EVIDENCE_VAULT
    case 'PRIVATE_EVIDENCE_VAULT': {
      if (action === 'READ') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'VAULT_OWNER_READ',
            qualifier: 'ALLOW (Own Uploaded Evidence Only)',
            explanation: 'Users may view only their own uploaded evidence files.',
          };
        }
        if (
          [
            'VERIFICATION_OFFICER',
            'SENIOR_VERIFICATION_LEAD',
            'APPEAL_OFFICER',
            'SECURITY_COMPLIANCE_OFFICER',
          ].includes(effectiveRole)
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
          explanation:
            'Private Evidence Vault files are strictly isolated from public visitors, sponsors, partners, and unassigned staff.',
        };
      }
      if (action === 'CREATE') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'VAULT_OWNER_UPLOAD',
            qualifier: 'ALLOW (Multipart Upload with Magic-Byte & SHA-256 Lock)',
            explanation: 'Adventurers may upload GPX, EXIF photo, and PDF permit evidence for their own submissions.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'VAULT_MUTATION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: 'Locked evidence artifacts in the Private Vault cannot be modified or overwritten.',
      };
    }

    // 6. VERIFICATION_DECISIONS
    case 'VERIFICATION_DECISIONS': {
      if (action === 'READ') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'VERIF_DECISION_READ_OWN',
            qualifier: 'ALLOW (Own Submission Decision Outcome)',
            explanation: 'Applicants may read the verification decision and rationale on their own submission.',
          };
        }
        if (
          [
            'VERIFICATION_OFFICER',
            'SENIOR_VERIFICATION_LEAD',
            'APPEAL_OFFICER',
            'SECURITY_COMPLIANCE_OFFICER',
            'GOVERNANCE_COMMITTEE',
            'FOUNDER',
          ].includes(effectiveRole)
        ) {
          return {
            allowed: true,
            ruleCode: 'VERIF_DECISION_READ_OVERSIGHT',
            qualifier: 'ALLOW (Departmental & Governance Oversight)',
            explanation: 'Verification, Appeal, Security, and Governance roles may inspect verification decision records.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'VERIF_DECISION_READ_DENIED_COMMERCIAL',
          qualifier: 'HARD_BLOCKED',
          explanation:
            'Sponsors, partners, organizations, and public visitors cannot read internal verification decision records.',
        };
      }
      if (action === 'CREATE' || action === 'APPROVE' || action === 'REJECT') {
        if (
          effectiveRole === 'VERIFICATION_OFFICER' ||
          effectiveRole === 'SENIOR_VERIFICATION_LEAD'
        ) {
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
      return {
        allowed: false,
        ruleCode: 'VERIF_DECISION_IMMUTABLE',
        qualifier: 'PROHIBITED',
        explanation: 'Recorded verification decisions cannot be updated, deleted, published, or revoked directly.',
      };
    }

    // 7. APPEAL_TRIBUNAL_DECISIONS
    case 'APPEAL_TRIBUNAL_DECISIONS': {
      if (action === 'READ') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'APPEAL_READ_OWN',
            qualifier: 'ALLOW (Own Appeal Outcome)',
            explanation: 'Appellants may read the status and outcome of their own appeal.',
          };
        }
        if (
          [
            'SENIOR_VERIFICATION_LEAD',
            'APPEAL_OFFICER',
            'SECURITY_COMPLIANCE_OFFICER',
            'GOVERNANCE_COMMITTEE',
            'FOUNDER',
          ].includes(effectiveRole)
        ) {
          return {
            allowed: true,
            ruleCode: 'APPEAL_READ_TRIBUNAL_OVERSIGHT',
            qualifier: 'ALLOW (Tribunal & Governance Oversight)',
            explanation: 'Appeal Officers and Governance oversight roles may inspect appeal tribunal records.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'APPEAL_READ_DENIED',
          qualifier: 'HARD_BLOCKED',
          explanation: 'Sponsors, commercial roles, standard reviewers, and public visitors cannot read appeal tribunal dossiers.',
        };
      }
      if (action === 'CREATE') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'APPEAL_FILE_OWN_REJECTED_SUBMISSION',
            qualifier: 'ALLOW (Own Rejected Submission Only)',
            explanation: 'Applicants may file an appeal on their own rejected submission.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'APPEAL_CREATE_DENIED',
          qualifier: 'PROHIBITED',
          explanation: 'Only the applicant of a rejected submission may initiate an appeal.',
        };
      }
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
      return {
        allowed: false,
        ruleCode: 'APPEAL_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Action (${action}) is not permitted on appeal tribunal records.`,
      };
    }

    // 8. BADGES_AND_CERTIFICATES
    case 'BADGES_AND_CERTIFICATES': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'CERT_PUBLIC_VERIFIER_READ',
          qualifier: 'ALLOW (Privacy-Filtered Public Projection)',
          explanation: 'Public certificates and 3D badges are readable via non-enumerable Verification IDs.',
        };
      }
      if (action === 'REVOKE') {
        if (
          ['SENIOR_VERIFICATION_LEAD', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
            effectiveRole
          )
        ) {
          return {
            allowed: true,
            ruleCode: 'CERT_REVOKE_DUAL_CONTROL_2P',
            qualifier: 'ALLOW (Requires Dual-Control 2P Sign-Off + Audit Reason)',
            explanation:
              'Post-issuance certificate revocation requires two distinct authorized principals and records a permanent revocation audit entry.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'CERT_REVOKE_DENIED',
          qualifier: 'PROHIBITED',
          explanation:
            'Only Dual-Control Governance + Senior Verification Lead can execute a formal certificate revocation.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'CERT_MANUAL_CREATE_OR_EDIT_DENIED',
        qualifier: 'HARD_BLOCKED',
        explanation:
          'Badges and certificates are issued automatically and exclusively upon human verification approval—never manually created, bought, or deleted.',
      };
    }

    // 9. VERIFIED_LEADERBOARDS
    case 'VERIFIED_LEADERBOARDS': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'PUBLIC_READ_ALLOWED',
          qualifier: 'ALLOW (Deterministic Verified Projection)',
          explanation: 'Verified leaderboards are readable by all roles.',
        };
      }
      return {
        allowed: false,
        ruleCode: 'INVARIANT_LEADERBOARD_NEVER_BOUGHT_OR_MANUALLY_EDITED',
        qualifier: 'HARD_DENY_ALL_ROLES',
        explanation:
          'Leaderboard standings are computed deterministically from VALID opt-in certificates. No role can manually create, update, approve, or purchase leaderboard rankings.',
      };
    }

    // 10. COMMUNITY_STORIES_AND_COMMENTS
    case 'COMMUNITY_STORIES_AND_COMMENTS': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'STORIES_PUBLIC_READ',
          qualifier: 'ALLOW (Published Stories)',
          explanation: 'Published expedition stories are readable by all roles.',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE' || action === 'DELETE') {
        if (['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'STORIES_AUTHOR_MANAGE_OWN',
            qualifier: 'ALLOW (Own Expedition Stories Only)',
            explanation: 'Adventurers may author, edit, or delete their own expedition stories.',
          };
        }
      }
      if (action === 'REVOKE') {
        if (
          ['SECURITY_COMPLIANCE_OFFICER', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
            effectiveRole
          )
        ) {
          return {
            allowed: true,
            ruleCode: 'STORIES_MODERATION_REVOKE',
            qualifier: 'ALLOW (Safety & Abuse Moderation)',
            explanation: 'Authorized moderation roles may remove abusive or fraudulent community content.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'STORIES_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Role (${role}) cannot execute (${action}) on community stories.`,
      };
    }

    // 11. GUIDE_MARKETPLACE_LISTINGS
    case 'GUIDE_MARKETPLACE_LISTINGS': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'GUIDE_DIRECTORY_PUBLIC_READ',
          qualifier: 'ALLOW (Vetted Guide Directory)',
          explanation: 'Verified guide listings are readable by all roles.',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        if (effectiveRole === 'VERIFIED_GUIDE') {
          return {
            allowed: true,
            ruleCode: 'GUIDE_MANAGE_OWN_LISTING',
            qualifier: 'ALLOW (Own Guide Profile Only)',
            explanation: 'Verified Guides may create and update their own service listings.',
          };
        }
      }
      if (action === 'APPROVE' || action === 'REJECT' || action === 'REVOKE') {
        if (
          ['SECURITY_COMPLIANCE_OFFICER', 'GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(
            effectiveRole
          )
        ) {
          return {
            allowed: true,
            ruleCode: 'GUIDE_LICENSE_VETTING_GOVERNANCE',
            qualifier: 'ALLOW (Official License Verification)',
            explanation: 'Compliance and Governance roles vet and approve or revoke guide credentials.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'GUIDE_MARKETPLACE_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Role (${role}) cannot execute (${action}) on guide marketplace listings.`,
      };
    }

    // 12. ORGANIZATIONS_AND_PARTNERS
    case 'ORGANIZATIONS_AND_PARTNERS': {
      if (action === 'READ') {
        return {
          allowed: true,
          ruleCode: 'PARTNERS_PUBLIC_READ',
          qualifier: 'ALLOW (MOU-Verified Partners Only)',
          explanation: 'Verified organizations and destination partners are readable by all roles.',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        if (['ORGANIZATION_ADMIN', 'DESTINATION_PARTNER'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'PARTNER_MANAGE_OWN_PROFILE',
            qualifier: 'ALLOW (Own Organization/Partner Dossier)',
            explanation: 'Organization and Partner admins may submit and update their own institutional profiles.',
          };
        }
      }
      if (action === 'APPROVE' || action === 'REJECT' || action === 'REVOKE') {
        if (['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'PARTNER_MOU_DUAL_CONTROL_APPROVAL',
            qualifier: 'ALLOW (Requires Verified Written Authorization)',
            explanation: 'Governance verifies written MOUs before approving or revoking partner status.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'PARTNERS_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Role (${role}) cannot execute (${action}) on organizations and partners.`,
      };
    }

    // 13. SPONSORS_AND_CAMPAIGNS
    case 'SPONSORS_AND_CAMPAIGNS': {
      if (action === 'READ') {
        if (
          [
            'SPONSOR_ACCOUNT',
            'SECURITY_COMPLIANCE_OFFICER',
            'GOVERNANCE_COMMITTEE',
            'FOUNDER',
          ].includes(effectiveRole)
        ) {
          return {
            allowed: true,
            ruleCode: 'SPONSOR_CAMPAIGN_SCOPED_READ',
            qualifier: 'ALLOW (Own Campaign / Governance Compliance)',
            explanation: 'Sponsors may view their own campaigns; Compliance and Governance audit all placements.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'SPONSOR_INTERNAL_CAMPAIGN_READ_DENIED',
          qualifier: 'PROHIBITED',
          explanation:
            'Verification officers, appeal officers, and general users do not access internal sponsor campaign consoles (Commercial Firewall).',
        };
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        if (effectiveRole === 'SPONSOR_ACCOUNT') {
          return {
            allowed: true,
            ruleCode: 'SPONSOR_SUBMIT_CAMPAIGN_DRAFT',
            qualifier: 'ALLOW (Subject to Mandatory SPONSORED Disclosure)',
            explanation: 'Sponsor accounts may draft commercial placement proposals.',
          };
        }
      }
      if (
        action === 'APPROVE' ||
        action === 'REJECT' ||
        action === 'PUBLISH' ||
        action === 'REVOKE'
      ) {
        if (['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'SPONSOR_GOVERNANCE_COMPLIANCE_GATE',
            qualifier: 'ALLOW (Commercial Firewall & Disclosure Audit)',
            explanation: 'Governance approves, publishes, or revokes sponsor placements after compliance review.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'SPONSOR_ACTION_DENIED',
        qualifier: 'PROHIBITED',
        explanation: `Role (${role}) cannot execute (${action}) on sponsor campaigns.`,
      };
    }

    // 14. USER_ROLES_AND_PERMISSIONS
    case 'USER_ROLES_AND_PERMISSIONS': {
      if (action === 'READ') {
        if (
          [
            'SECURITY_COMPLIANCE_OFFICER',
            'PLATFORM_SYSADMIN',
            'GOVERNANCE_COMMITTEE',
            'FOUNDER',
          ].includes(effectiveRole)
        ) {
          return {
            allowed: true,
            ruleCode: 'ROLE_MATRIX_READ_OVERSIGHT',
            qualifier: 'ALLOW (Security & Governance Oversight)',
            explanation: 'Security, SysAdmin, and Governance roles may audit user role assignments.',
          };
        }
        return {
          allowed: false,
          ruleCode: 'ROLE_MATRIX_READ_DENIED',
          qualifier: 'PROHIBITED',
          explanation: 'Standard, commercial, and public roles cannot read internal user role assignments.',
        };
      }
      if (action === 'UPDATE' || action === 'APPROVE' || action === 'REVOKE') {
        if (['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole)) {
          return {
            allowed: true,
            ruleCode: 'ROLE_ASSIGNMENT_DUAL_CONTROL_2P',
            qualifier: 'ALLOW (Requires Dual-Control 2P Governance Sign-Off)',
            explanation:
              'Assigning or revoking privileged staff roles requires Dual-Control Governance authorization.',
          };
        }
      }
      return {
        allowed: false,
        ruleCode: 'ROLE_ESCALATION_BLOCKED',
        qualifier: 'HARD_BLOCKED',
        explanation: `Privilege escalation prevention blocks (${role}) from executing (${action}) on user roles.`,
      };
    }
  }
}
