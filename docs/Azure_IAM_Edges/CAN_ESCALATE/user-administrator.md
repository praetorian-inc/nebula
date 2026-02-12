# User Administrator Escalation

**Method:** `UserAdministrator`
**Category:** Directory Role Escalation

## Overview

User Administrator can reset passwords and modify properties of **non-administrator users**, enabling account takeover of users without admin roles.

## Escalation Path

```
User → [HAS_PERMISSION: User Administrator] → Tenant
     → [CAN_ESCALATE: UserAdministrator] → Non-Admin Users Only
     → Reset password → Account takeover → Lateral movement
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "User Administrator"` OR
- `templateId = "fe930be7-5e62-47db-91af-98c3a49a38b1"`

**Target:** Non-administrator users only:
- Resource type: `microsoft.directoryservices/users`
- **Filter:** Excludes users with any "administrator" role
  ```cypher
  AND NOT EXISTS {
    (escalate_target)-[admin_perm:HAS_PERMISSION]->(:Resource)
    WHERE toLower(admin_perm.roleName) CONTAINS "administrator"
  }
  ```

**Condition:** "Can reset passwords and modify properties of non-administrator users"

## Attack Scenario

1. **Attacker compromises** user with User Administrator role
2. **Attacker enumerates** non-admin users with valuable access:
   - Users with Azure RBAC roles (Owner, Contributor)
   - Users with Graph API application permissions
   - Users with sensitive data access
3. **Attacker resets** target user's password
4. **Attacker accesses** target user's resources
5. **Result:** Lateral movement and data access

## Edge Properties

```cypher
{
  method: "UserAdministrator",
  category: "DirectoryRole",
  condition: "Can reset passwords and modify properties of non-administrator users",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
// Find User Admins and high-value non-admin users they can compromise
MATCH (admin:Resource)-[esc:CAN_ESCALATE]->(user:Resource)
WHERE esc.method = "UserAdministrator"
  AND EXISTS {
    MATCH (user)-[p:HAS_PERMISSION]->(:Resource)
    WHERE p.permission IN ["Owner", "Contributor", "User Access Administrator"]
  }
RETURN admin.displayName as user_admin,
       user.displayName as high_value_target,
       user.userPrincipalName as email,
       collect(DISTINCT p.permission) as azure_roles
```

## Scope Limitation

**Can Target:**
- Standard users
- Users with Azure RBAC roles
- Users with application-level permissions

**Cannot Target:**
- Users with any directory role containing "administrator"
- Global Administrators
- Privileged Role Administrators
- Other admin role holders

## Difference from Authentication Administrator

**User Administrator:**
- ✅ Reset passwords for non-admin users
- ✅ Modify user properties (department, job title, etc.)
- ✅ Create/delete non-admin users
- ❌ Cannot target admin users

**Authentication Administrator:**
- ✅ Reset authentication methods for non-admin users
- ✅ Includes MFA reset
- ❌ Cannot target admin users

## Mitigation

- **PIM:** Require activation for User Administrator role
- **Monitoring:** Alert on password resets for high-value users
- **Privileged Access:** Grant Azure RBAC via groups, not direct assignment
- **Audit:** Review User Administrator assignments
- **Conditional Access:** Require strong auth for user management

## Related Documentation

- [Authentication Administrator](authentication-administrator.md) - Similar scope, different capabilities
- [Privileged Authentication Administrator](privileged-authentication-administrator.md) - Unrestricted version
- [../../Azure_IAM_Nodes/user.md](../../Azure_IAM_Nodes/user.md) - User node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedUserAdminQuery()` - line 4084
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
