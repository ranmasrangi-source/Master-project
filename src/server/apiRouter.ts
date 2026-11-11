import express, { Request, Response } from 'express';
import { GoogleGenAI } from '@google/genai';
import { DESTINATIONS_100_CATALOG } from '../data/destinations100';
import { evaluateRbacPermission, ResourceDomain } from '../data/governanceAndPhases';
import { ActionVerb, UserRole } from '../types/platform';

export const apiRouter = express.Router();

apiRouter.use(express.json());

// 1. Constitutional Health & Hard-Lock Status Endpoint
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    platform: '0 TO 8848 — Global Adventure Achievement Platform',
    domain: 'https://0to8848official.com',
    constitutionalInvariants: {
      achievementsEarnedNeverBought: true,
      humanVerificationMandatory: true,
      aiAdvisoryOnlyNeverApproves: true,
      commercialFirewallEnforced: true,
      standardBadgesAndCertificatesFree: true,
      paymentsEnabled: false,
      blockchainMintingEnabled: false,
    },
    catalogCount: DESTINATIONS_100_CATALOG.length,
    timestampUtc: new Date().toISOString(),
  });
});

// 2. 100 Global Destinations Server Endpoint
apiRouter.get('/destinations', (req: Request, res: Response) => {
  const { region, stage, publicOnly } = req.query;
  let results = [...DESTINATIONS_100_CATALOG];

  if (publicOnly === 'true') {
    results = results.filter((d) => d.researchStage === '5_PUBLISHED');
  }
  if (region && region !== 'ALL') {
    results = results.filter((d) => d.region === region);
  }
  if (stage && stage !== 'ALL') {
    results = results.filter((d) => d.researchStage === stage);
  }

  res.json({
    total: results.length,
    destinations: results,
  });
});

// 3. Server-Side RBAC Policy Enforcement Endpoint
apiRouter.post('/rbac/evaluate', (req: Request, res: Response) => {
  const { role, resource, action } = req.body as {
    role: UserRole;
    resource: ResourceDomain;
    action: ActionVerb;
  };
  if (!role || !resource || !action) {
    res.status(400).json({ error: 'Missing role, resource, or action parameter.' });
    return;
  }
  const evaluation = evaluateRbacPermission(role, resource, action);
  res.status(evaluation.allowed ? 200 : 403).json(evaluation);
});

// 4. Phase 17 Hard-Locked Payment Endpoint (Enforces PAYMENTS_ENABLED = FALSE)
apiRouter.post('/payments/checkout', (_req: Request, res: Response) => {
  res.status(503).json({
    error: 'PAYMENT_COLLECTION_DISABLED_BY_CONSTITUTIONAL_LOCK',
    code: 'PHASE_17_HARD_LOCK',
    paymentsEnabled: false,
    message:
      'All real payment collection is hard-disabled until company registration, legal review, financial compliance, payment-provider approval, and security readiness are formally confirmed. Standard digital badges and certificates are permanently free.',
  });
});

// 5. Phase 18 Hard-Locked Blockchain Minting Endpoint (Enforces BLOCKCHAIN_MINTING_ENABLED = FALSE)
apiRouter.post('/blockchain/mint', (_req: Request, res: Response) => {
  res.status(503).json({
    error: 'BLOCKCHAIN_MINTING_DISABLED_BY_CONSTITUTIONAL_LOCK',
    code: 'PHASE_18_HARD_LOCK',
    blockchainMintingEnabled: false,
    message:
      'The primary platform database is authoritative. Optional Soulbound credential minting is hard-disabled until legal approval, smart contract security audit, and formal Founder authorization are obtained.',
  });
});

// 6. Advisory Server-Side Gemini Safety & Telemetry Brief (Strictly Non-Decisional)
apiRouter.post('/ai/advisory-brief', async (req: Request, res: Response) => {
  const { destinationCode, destinationName, elevationM, routeName } = req.body as {
    destinationCode?: string;
    destinationName?: string;
    elevationM?: number;
    routeName?: string;
  };

  if (!destinationName) {
    res.status(400).json({ error: 'destinationName is required' });
    return;
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    res.json({
      source: 'DETERMINISTIC_FORENSIC_FALLBACK (Correction 2.10 Resilience Mode)',
      advisoryOnly: true,
      canApproveAchievements: false,
      summary: `Contextual verification brief for ${destinationName} (${elevationM}m via ${routeName}): Reviewers must verify continuous GNSS/barometric track intersection within the summit geofence, inspect raw EXIF solar azimuth & horizon landmarks, and confirm official permit documentation. AI output is strictly advisory.`,
    });
    return;
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `You are an advisory cartographic and mountaineering forensics assistant for the 0 TO 8848 Verification Department. Provide a concise 3-bullet forensic verification & safety briefing for human reviewers evaluating an ascent of ${destinationName} (${destinationCode}, ${elevationM}m) via ${routeName}. State clearly that final verification approval is strictly reserved for human Verification Officers.`,
    });

    res.json({
      source: 'GEMINI_3_FLASH_SERVER_ADVISORY',
      advisoryOnly: true,
      canApproveAchievements: false,
      summary:
        response.text ||
        `Advisory brief for ${destinationName}: Verify GNSS/barometric track, EXIF timestamps, and official permit.`,
    });
  } catch {
    res.json({
      source: 'DETERMINISTIC_FORENSIC_FALLBACK (Correction 2.10 Resilience Mode)',
      advisoryOnly: true,
      canApproveAchievements: false,
      summary: `Contextual verification brief for ${destinationName} (${elevationM}m via ${routeName}): Human Verification Officers must corroborate GPX telemetry, barometric altitude, raw EXIF metadata, and official permits.`,
    });
  }
});
