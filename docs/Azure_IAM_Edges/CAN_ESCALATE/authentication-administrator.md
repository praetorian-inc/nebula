# Authentication Administrator Escalation

**Method:** `AuthenticationAdmin`
**Category:** Directory Role Escalation

## Overview

Authentication Administrator can reset authentication methods including passwords and MFA for **non-administrator users**, enabling account takeover.

## Escalation Path

```
User → [HAS_PERMISSION: Authentication Administrator] → Tenant
     → [CAN_ESCALATE: AuthenticationAdmin] → Non-Admin Users Only
     → Reset password/MFA → Account takeover
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Authentication Administrator"` OR
- `templateId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"`

**Target:** Non-administrator users only:
- Resource type: `microsoft.directoryservices/users`
- **Filter:** Excludes users with any "administrator" role
  ```cypher
  AND NOT EXISTS {
    (escalate_target)-[admin_perm:HAS_PERMISSION]->(:Resource)
    WHERE toLower(admin_perm.roleName) CONTAINS "administrator"
  }
  ```

**Condition:** "Can reset authentication methods including passwords and MFA for non-administrator users"

## Attack Scenario

1. **Attacker compromises** user with Authentication Administrator role
2. **Attacker enumerates** non-admin users with valuable access
3. **Attacker resets** target user's password and disables MFA
4. **Attacker logs in** as target user
5. **Result:** Account takeover and lateral movement

## Edge Properties

```cypher
{
  method: "AuthenticationAdmin",
  category: "DirectoryRole",
  condition: "Can reset authentication methods including passwords and MFA for non-administrator users",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
MATCH (admin:Resource)-[esc:CAN_ESCALATE]->(user:Resource)
WHERE esc.method = "AuthenticationAdmin"
RETURN admin.displayName as auth_admin,
       count(user) as targetable_users
ORDER BY targetable_users DESC
```

## Authentication Management Capabilities

**Can Modify:**
- Passwords (reset)
- Multi-factor authentication methods
- FIDO2 security keys
- Microsoft Authenticator app
- Phone/SMS authentication
- Email authentication

**Cannot Modify:**
- Admin user authentication
- Conditional Access policies
- Authentication method policies (tenant-level)

## Difference from Privileged Authentication Administrator

**Authentication Administrator:**
- ❌ Cannot target users with admin roles
- ✅ Can target all other users

**Privileged Authentication Administrator:**
- ✅ Can target **all** users including Global Administrators
- ✅ Unrestricted password reset capability

## Mitigation

- **PIM:** Require activation for Authentication Administrator role
- **Monitoring:** Alert on authentication resets for sensitive users
- **Conditional Access:** Require MFA + compliant device for auth management
- **Privileged Access:** Minimize non-admin users with sensitive access
- **Audit:** Review Authentication Administrator assignments quarterly

## Related Documentation

- [Privileged Authentication Administrator](privileged-authentication-administrator.md) - Unrestricted version
- [User Administrator](user-administrator.md) - Similar scope, different capabilities
- [../../Azure_IAM_Nodes/user.md](../../Azure_IAM_Nodes/user.md) - User node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedAuthenticationAdminQuery()` - line 4106
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
