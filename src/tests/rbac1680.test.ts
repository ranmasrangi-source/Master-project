import { describe, expect, it } from 'vitest';
import {
  ALL_ACTION_VERBS,
  ALL_RESOURCE_DOMAINS,
  ALL_USER_ROLES,
  evaluateRbacPermission,
  ResourceDomain,
} from '../data/governanceAndPhases';
import { ActionVerb, UserRole } from '../types/platform';

/**
 * Independent Reference Specification for the 1,680-permutation RBAC matrix
 * (15 Roles × 14 Resource Domains × 8 Action Verbs = 1,680).
 * Used to verify that evaluateRbacPermission enforces strict deny-by-default
 * without any permissive catch-all fallback.
 */
function expectedReferencePolicyAllow(
  role: UserRole,
  resource: ResourceDomain,
  action: ActionVerb
): boolean {
  const effectiveRole: UserRole =
    role === 'PREMIUM_MEMBER_FUTURE' ? 'REGISTERED_ADVENTURER' : role;

  switch (resource) {
    case 'APPEND_ONLY_AUDIT_LOGS':
      if (action === 'READ') {
        return [
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
          'PLATFORM_SYSADMIN',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      return false;

    case 'PUBLIC_DESTINATIONS_STAGE_5':
      if (action === 'READ') return true;
      if (action === 'PUBLISH' || action === 'REVOKE') {
        return effectiveRole === 'GOVERNANCE_COMMITTEE' || effectiveRole === 'FOUNDER';
      }
      return false;

    case 'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4':
      if (action === 'READ') {
        return [
          'DESTINATION_RESEARCHER',
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        return [
          'DESTINATION_RESEARCHER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'APPROVE' || action === 'PUBLISH') {
        return effectiveRole === 'GOVERNANCE_COMMITTEE' || effectiveRole === 'FOUNDER';
      }
      return false;

    case 'ACHIEVEMENT_SUBMISSIONS':
      if (action === 'READ') {
        return [
          'REGISTERED_ADVENTURER',
          'VERIFIED_GUIDE',
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        return ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole);
      }
      return false;

    case 'PRIVATE_EVIDENCE_VAULT':
      if (action === 'READ') {
        return [
          'REGISTERED_ADVENTURER',
          'VERIFIED_GUIDE',
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE') {
        return ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole);
      }
      return false;

    case 'VERIFICATION_DECISIONS':
      if (action === 'READ') {
        return [
          'REGISTERED_ADVENTURER',
          'VERIFIED_GUIDE',
          'VERIFICATION_OFFICER',
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE' || action === 'APPROVE' || action === 'REJECT') {
        return (
          effectiveRole === 'VERIFICATION_OFFICER' ||
          effectiveRole === 'SENIOR_VERIFICATION_LEAD'
        );
      }
      return false;

    case 'APPEAL_TRIBUNAL_DECISIONS':
      if (action === 'READ') {
        return [
          'REGISTERED_ADVENTURER',
          'VERIFIED_GUIDE',
          'SENIOR_VERIFICATION_LEAD',
          'APPEAL_OFFICER',
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE') {
        return ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole);
      }
      if (action === 'APPROVE' || action === 'REJECT' || action === 'UPDATE') {
        return effectiveRole === 'APPEAL_OFFICER';
      }
      return false;

    case 'BADGES_AND_CERTIFICATES':
      if (action === 'READ') return true;
      if (action === 'REVOKE') {
        return [
          'SENIOR_VERIFICATION_LEAD',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      return false;

    case 'VERIFIED_LEADERBOARDS':
      return action === 'READ';

    case 'COMMUNITY_STORIES_AND_COMMENTS':
      if (action === 'READ') return true;
      if (action === 'CREATE' || action === 'UPDATE' || action === 'DELETE') {
        return ['REGISTERED_ADVENTURER', 'VERIFIED_GUIDE'].includes(effectiveRole);
      }
      if (action === 'REVOKE') {
        return [
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      return false;

    case 'GUIDE_MARKETPLACE_LISTINGS':
      if (action === 'READ') return true;
      if (action === 'CREATE' || action === 'UPDATE') {
        return effectiveRole === 'VERIFIED_GUIDE';
      }
      if (action === 'APPROVE' || action === 'REJECT' || action === 'REVOKE') {
        return [
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      return false;

    case 'ORGANIZATIONS_AND_PARTNERS':
      if (action === 'READ') return true;
      if (action === 'CREATE' || action === 'UPDATE') {
        return ['ORGANIZATION_ADMIN', 'DESTINATION_PARTNER'].includes(effectiveRole);
      }
      if (action === 'APPROVE' || action === 'REJECT' || action === 'REVOKE') {
        return ['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole);
      }
      return false;

    case 'SPONSORS_AND_CAMPAIGNS':
      if (action === 'READ') {
        return [
          'SPONSOR_ACCOUNT',
          'SECURITY_COMPLIANCE_OFFICER',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'CREATE' || action === 'UPDATE') {
        return effectiveRole === 'SPONSOR_ACCOUNT';
      }
      if (
        action === 'APPROVE' ||
        action === 'REJECT' ||
        action === 'PUBLISH' ||
        action === 'REVOKE'
      ) {
        return ['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole);
      }
      return false;

    case 'USER_ROLES_AND_PERMISSIONS':
      if (action === 'READ') {
        return [
          'SECURITY_COMPLIANCE_OFFICER',
          'PLATFORM_SYSADMIN',
          'GOVERNANCE_COMMITTEE',
          'FOUNDER',
        ].includes(effectiveRole);
      }
      if (action === 'UPDATE' || action === 'APPROVE' || action === 'REVOKE') {
        return ['GOVERNANCE_COMMITTEE', 'FOUNDER'].includes(effectiveRole);
      }
      return false;
  }
}

describe('SEC-RBAC-001: Full 1,680-Permutation RBAC Matrix Suite (15 Roles × 14 Resources × 8 Verbs)', () => {
  it('verifies exact dimensions: 15 roles, 14 resource domains, 8 action verbs = 1,680 permutations', () => {
    expect(ALL_USER_ROLES).toHaveLength(15);
    expect(ALL_RESOURCE_DOMAINS).toHaveLength(14);
    expect(ALL_ACTION_VERBS).toHaveLength(8);
    expect(ALL_USER_ROLES.length * ALL_RESOURCE_DOMAINS.length * ALL_ACTION_VERBS.length).toBe(1680);
  });

  it('exhaustively validates all 1,680 (role, resource, verb) permutations against the reference policy with zero catch-all fallback', () => {
    let evaluatedCount = 0;
    let allowedCount = 0;
    let deniedCount = 0;

    for (const role of ALL_USER_ROLES) {
      for (const resource of ALL_RESOURCE_DOMAINS) {
        for (const verb of ALL_ACTION_VERBS) {
          evaluatedCount += 1;
          const result = evaluateRbacPermission(role, resource, verb);
          const expectedAllow = expectedReferencePolicyAllow(role, resource, verb);

          expect(
            result.allowed,
            `Mismatch for (${role}, ${resource}, ${verb}) — got ${result.allowed} (${result.ruleCode}), expected ${expectedAllow}`
          ).toBe(expectedAllow);

          // Ensure no permissive catch-all rule code exists
          expect(result.ruleCode).not.toBe('RBAC-GEN-READ-200');
          expect(result.qualifier.length).toBeGreaterThan(0);
          expect(result.explanation.length).toBeGreaterThan(10);

          if (result.allowed) {
            allowedCount += 1;
          } else {
            deniedCount += 1;
          }
        }
      }
    }

    expect(evaluatedCount).toBe(1680);
    expect(allowedCount + deniedCount).toBe(1680);
    // Majority of the 1,680 permutations must be denied by default
    expect(deniedCount).toBeGreaterThan(1350);
  });

  it('enforces constitutional commercial firewall: Sponsors, Partners, Guides, Org Admins, SysAdmins, and Founder cannot approve/reject verification decisions', () => {
    const nonVerificationRoles: UserRole[] = [
      'PUBLIC_VISITOR',
      'REGISTERED_ADVENTURER',
      'PREMIUM_MEMBER_FUTURE',
      'VERIFIED_GUIDE',
      'ORGANIZATION_ADMIN',
      'DESTINATION_PARTNER',
      'SPONSOR_ACCOUNT',
      'DESTINATION_RESEARCHER',
      'APPEAL_OFFICER',
      'SECURITY_COMPLIANCE_OFFICER',
      'PLATFORM_SYSADMIN',
      'GOVERNANCE_COMMITTEE',
      'FOUNDER',
    ];

    for (const role of nonVerificationRoles) {
      for (const verb of [
        'CREATE',
        'UPDATE',
        'DELETE',
        'APPROVE',
        'REJECT',
        'PUBLISH',
        'REVOKE',
      ] as ActionVerb[]) {
        const res = evaluateRbacPermission(role, 'VERIFICATION_DECISIONS', verb);
        expect(res.allowed).toBe(false);
      }
    }
  });

  it('blocks PUBLIC_VISITOR, SPONSOR_ACCOUNT, and DESTINATION_PARTNER from reading private resources (Private Evidence Vault, Draft Destinations, Audit Logs, User Roles, Submissions)', () => {
    const publicAndCommercialRoles: UserRole[] = [
      'PUBLIC_VISITOR',
      'SPONSOR_ACCOUNT',
      'DESTINATION_PARTNER',
    ];
    const sensitiveResources: ResourceDomain[] = [
      'PRIVATE_EVIDENCE_VAULT',
      'DRAFT_RESEARCH_DESTINATIONS_STAGES_1_4',
      'APPEND_ONLY_AUDIT_LOGS',
      'USER_ROLES_AND_PERMISSIONS',
      'VERIFICATION_DECISIONS',
      'APPEAL_TRIBUNAL_DECISIONS',
      'ACHIEVEMENT_SUBMISSIONS',
    ];

    for (const role of publicAndCommercialRoles) {
      for (const resource of sensitiveResources) {
        const readEval = evaluateRbacPermission(role, resource, 'READ');
        expect(readEval.allowed, `${role} must NOT read ${resource}`).toBe(false);
      }
    }
  });
});
