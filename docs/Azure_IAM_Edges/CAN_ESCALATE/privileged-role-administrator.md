# Privileged Role Administrator Escalation

**Method:** `PrivilegedRoleAdmin`
**Category:** Directory Role Escalation

## Overview

Privileged Role Administrator can assign Global Administrator or any other directory role to any principal, enabling complete tenant compromise.

## Escalation Path

```
User → [HAS_PERMISSION: Privileged Role Administrator] → Tenant
     → [CAN_ESCALATE: PrivilegedRoleAdmin] → All Principals (Users, Groups, SPs)
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Privileged Role Administrator"` OR
- `templateId = "e8611ab8-c189-46e8-94e1-60213ab1f814"`

**Target:** All principals in tenant:
- Users (`microsoft.directoryservices/users`)
- Service Principals (`microsoft.directoryservices/serviceprincipals`)
- Groups (`microsoft.directoryservices/groups`)

**Condition:** "Privileged Role Administrator can assign Global Administrator or any other directory role to any principal"

## Attack Scenario

1. **Attacker compromises** user with Privileged Role Administrator role
2. **Attacker assigns** Global Administrator role to their own account
3. **Attacker gains** complete tenant control via Global Admin privileges
4. **Alternative:** Assign privileged roles to service principals they control

## Edge Properties

```cypher
{
  method: "PrivilegedRoleAdmin",
  category: "DirectoryRole",
  condition: "Privileged Role Administrator can assign Global Administrator or any other directory role to any principal",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
MATCH (user:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "PrivilegedRoleAdmin"
RETURN user.displayName as attacker,
       target.displayName as target,
       target.resourceType as target_type,
       r.condition as escalation_path
```

## Mitigation

- **PIM (Privileged Identity Management):** Require activation for Privileged Role Administrator
- **Conditional Access:** Require MFA + compliant device for role activation
- **Monitoring:** Alert on Privileged Role Administrator assignments
- **Break-Glass:** Limit permanent assignments, use JIT access

## Related Documentation

- [Global Administrator](global-administrator.md) - What attackers can do after role assignment
- [HAS_PERMISSION: Directory Roles](../HAS_PERMISSION/directory-roles.md) - How role is initially granted
- [../../Azure_IAM_Nodes/user.md](../../Azure_IAM_Nodes/user.md) - User node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedPrivilegedRoleAdminQuery()` - line 3978
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
