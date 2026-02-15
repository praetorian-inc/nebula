# Privileged Authentication Administrator Escalation

**Method:** `PrivilegedAuthenticationAdmin`
**Category:** Directory Role Escalation

## Overview

Privileged Authentication Administrator can reset passwords and authentication methods for **ANY user** including Global Administrators, enabling account takeover of the most privileged accounts in the tenant.

## Escalation Path

```
User → [HAS_PERMISSION: Privileged Authentication Administrator] → Tenant
     → [CAN_ESCALATE: PrivilegedAuthenticationAdmin] → ALL Users (including Global Admins)
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Privileged Authentication Administrator"` OR
- `templateId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"`

**Target:** ALL users in tenant:
- Resource type: `microsoft.directoryservices/users`
- **No privilege restrictions** - can target Global Administrators

**Condition:** "Can reset passwords and authentication methods for ANY user including Global Administrators"

## Attack Scenario

1. **Attacker compromises** user with Privileged Authentication Administrator role
2. **Attacker identifies** Global Administrator accounts via enumeration
3. **Attacker resets** Global Admin password and/or disables MFA
4. **Attacker logs in** as Global Administrator with new credentials
5. **Result:** Complete tenant compromise

## Edge Properties

```cypher
{
  method: "PrivilegedAuthenticationAdmin",
  category: "DirectoryRole",
  condition: "Can reset passwords and authentication methods for ANY user including Global Administrators",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
// Find users who can reset Global Admin passwords
MATCH (attacker:Resource)-[esc:CAN_ESCALATE]->(target:Resource)
WHERE esc.method = "PrivilegedAuthenticationAdmin"
  AND EXISTS {
    MATCH (target)-[p:HAS_PERMISSION]->(:Resource)
    WHERE p.roleName = "Global Administrator"
  }
RETURN attacker.displayName as attacker,
       target.displayName as global_admin_target,
       target.userPrincipalName as email
ORDER BY attacker.displayName
```

## Why This Role Is Dangerous

**Unrestricted Password Reset:**
- Can reset passwords for Global Administrators
- Can disable MFA for any user
- Can modify authentication methods (FIDO2, phone, email)
- No "admin unit" restrictions apply

**Difference from Authentication Administrator:**
- Authentication Administrator: Can only target non-admin users
- Privileged Authentication Administrator: Can target **all** users including admins

## Mitigation

- **PIM (Privileged Identity Management):** Require JIT activation with approval workflow
- **Conditional Access:** Require MFA + compliant device + trusted location
- **Monitoring:** Alert on password resets for privileged accounts
- **Emergency Access:** Ensure break-glass accounts cannot be reset by this role
- **Limit Assignments:** Minimize permanent Privileged Authentication Admin assignments

## Related Documentation

- [Authentication Administrator](authentication-administrator.md) - Limited version (non-admin users only)
- [Global Administrator](global-administrator.md) - Target of this escalation
- [HAS_PERMISSION: Directory Roles](../HAS_PERMISSION/directory-roles.md) - How role is granted

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedPrivilegedAuthAdminQuery()` - line 4000
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
