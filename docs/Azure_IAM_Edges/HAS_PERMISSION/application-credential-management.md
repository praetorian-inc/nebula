# Application Credential Management Permission

**Edge Type:** `HAS_PERMISSION`
**Permission:** `ApplicationCredentialManagement`
**Source:** `DirectoryRole`
**Roles:** Application Administrator, Cloud Application Administrator

---

## Overview

Principals with Application Administrator or Cloud Application Administrator roles can manage application credentials (secrets and certificates), providing a critical privilege escalation vector.

**Implementation:** `createApplicationCredentialPermissionEdges()` (neo4j_importer.go:3747)

---

## Edge Creation Logic

### Data Collection (collector.go:3830-3870)

The collector queries directory role members and enriches with credential management permissions:

```go
// For principals with App Admin or Cloud App Admin roles
applicationCredentialPermissions := []map[string]interface{}{
    {
        "principalId":         member.Id,
        "principalType":       principalType,
        "targetResourceId":    tenantID,
        "targetResourceType":  "Microsoft.DirectoryServices/tenant",
        "permission":          "ApplicationCredentialManagement",
        "roleName":            roleName,  // Fixed: was "role"
        "roleTemplateId":      roleTemplateID,
    },
}
```

**Critical Field Names:**
- `roleName` (NOT "role") - matches importer expectations
- `principalId` (NOT "applicationId") - matches MERGE pattern

### Edge Creation (neo4j_importer.go:3747-3827)

```cypher
MATCH (principal:Resource {id: $principalId})
MATCH (tenant:Resource {resourceType: "Microsoft.DirectoryServices/tenant"})

MERGE (principal)-[r:HAS_PERMISSION {
    roleName: $roleName,
    permission: $permission
}]->(tenant)
ON CREATE SET
    r.principalType = $principalType,
    r.source = $source,
    r.targetResourceType = $targetResourceType,
    r.roleTemplateId = $roleTemplateId,
    r.createdAt = datetime()
ON MATCH SET
    r.roleName = $roleName,
    r.source = $source
```

**Uniqueness Constraint:** `{roleName, permission}` - Prevents duplicates when same principal has same permission

---

## Detection Queries

### Find All Application Credential Permissions

```cypher
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "ApplicationCredentialManagement"
  AND r.source = "DirectoryRole"
RETURN principal.displayName, r.roleName, tenant.displayName
ORDER BY principal.displayName
```

### Find Escalation Paths via App Credential Management

```cypher
MATCH (principal)-[perm:HAS_PERMISSION]->(tenant)
WHERE perm.permission = "ApplicationCredentialManagement"

MATCH (principal)-[esc:CAN_ESCALATE]->(target)
WHERE esc.method IN ["ApplicationAdministrator", "CloudApplicationAdministrator"]

RETURN principal.displayName,
       perm.roleName,
       count(DISTINCT target) as escalation_targets
ORDER BY escalation_targets DESC
```

---

## Example Scenario

**Setup:**
- Alice has Cloud Application Administrator role
- Tenant has 500 service principals with credentials

**Edge Created:**
```
(Alice)-[HAS_PERMISSION {
    permission: "ApplicationCredentialManagement",
    roleName: "Cloud Application Administrator",
    roleTemplateId: "158c047a-c907-4556-b7ef-446551a6b5f7",
    principalType: "User",
    source: "DirectoryRole",
    targetResourceType: "Microsoft.DirectoryServices/tenant"
}]->(Tenant)
```

**Escalation Logic (Phase 5):**
Because Alice has `ApplicationCredentialManagement` permission, escalation queries create CAN_ESCALATE edges to all service principals where Alice can add credentials and authenticate as them.

---

## Field Reference

| Property | Type | Required | Purpose |
|----------|------|----------|---------|
| `permission` | String | Yes | Always "ApplicationCredentialManagement" |
| `roleName` | String | Yes | Role granting permission (App Admin or Cloud App Admin) |
| `roleTemplateId` | String | Yes | Azure role template GUID |
| `principalType` | String | Yes | "User", "ServicePrincipal", or "Group" |
| `source` | String | Yes | Always "DirectoryRole" |
| `targetResourceType` | String | Yes | "Microsoft.DirectoryServices/tenant" |
| `createdAt` | DateTime | Yes | Edge creation timestamp |

---

## Bug History

### Bug #2: Field Name Mismatch (Fixed 2026-01-20)

**Symptom:** 24 items collected, 0 edges created

**Root Cause:** Collector used `"role": roleName` but importer expected `"roleName": roleName`

**Fix:** Changed collector.go:3857 from `"role"` to `"roleName"`

**Validation:** All 24 Application Credential permissions now create edges correctly

---

## Related Documentation

- [Application RBAC Management](application-rbac-management.md) - RBAC-based app permissions
- [Overview - iam-push Phase Architecture](../overview.md#iam-push-phase-architecture) - Complete implementation details
- [Analysis Examples](../analysis-examples.md) - Query patterns for analysis
