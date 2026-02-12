# Application RBAC Management Permission

**Edge Type:** `HAS_PERMISSION`
**Permission:** `ApplicationManagement`
**Source:** `DirectoryRole`
**Roles:** Application Administrator, Cloud Application Administrator, Application Developer (for owned apps)

---

## Overview

Principals with application management roles can manage Azure application registrations (app RBAC), including role assignments, permissions, and configuration.

**Implementation:** `createApplicationRBACPermissionEdges()` (neo4j_importer.go:3832)

---

## Edge Creation Logic

### Data Collection (collector.go:3872-3912)

The collector queries directory role members and enriches with application RBAC permissions for each managed application:

```go
// For each application the principal can manage
applicationRBACPermissions := []map[string]interface{}{
    {
        "principalId":         appID,     // Fixed: was "applicationId"
        "principalType":       "Application",
        "targetResourceId":    appID,
        "targetResourceType":  "Microsoft.DirectoryServices/servicePrincipal",
        "permission":          "ApplicationManagement",
        "roleName":            roleName,  // Fixed: was "role"
        "roleTemplateId":      roleTemplateID,
    },
}
```

**Critical Field Names:**
- `principalId` (NOT "applicationId") - matches importer expectations
- `roleName` (NOT "role") - matches MERGE pattern

**Data Volume:**
- 132 applications × 3 roles (App Admin, Cloud App Admin, App Developer) = 396 permissions

### Edge Creation (neo4j_importer.go:3832-3911)

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

**Uniqueness Constraint:** `{roleName, permission}` - Each app has up to 3 edges (one per role type)

---

## Detection Queries

### Find All Application RBAC Permissions

```cypher
MATCH (app:Resource)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "ApplicationManagement"
  AND r.source = "DirectoryRole"
RETURN app.displayName, r.roleName, tenant.displayName
ORDER BY app.displayName
```

**Expected Results:**
- Each application appears up to 3 times (App Admin, Cloud App Admin, App Developer)
- Total: ~396 edges (132 apps × 3 roles)

### Find Applications by Managing Role

```cypher
MATCH (app:Resource)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "ApplicationManagement"
  AND r.roleName = "Application Administrator"
RETURN app.displayName, r.roleName
```

### Find Escalation Paths via Application Management

```cypher
MATCH (app)-[perm:HAS_PERMISSION]->(tenant)
WHERE perm.permission = "ApplicationManagement"

MATCH (app)-[esc:CAN_ESCALATE]->(target)

RETURN app.displayName,
       perm.roleName,
       count(DISTINCT target) as escalation_targets
ORDER BY escalation_targets DESC
```

---

## Example Scenario

**Setup:**
- "Chariot-vw" application exists in tenant
- Application Administrator, Cloud Application Administrator, and Application Developer roles exist

**Edges Created (3 total):**

```
(Chariot-vw)-[HAS_PERMISSION {
    permission: "ApplicationManagement",
    roleName: "Application Administrator",
    roleTemplateId: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    principalType: "Application",
    source: "DirectoryRole"
}]->(Tenant)

(Chariot-vw)-[HAS_PERMISSION {
    permission: "ApplicationManagement",
    roleName: "Cloud Application Administrator",
    roleTemplateId: "158c047a-c907-4556-b7ef-446551a6b5f7",
    principalType: "Application",
    source: "DirectoryRole"
}]->(Tenant)

(Chariot-vw)-[HAS_PERMISSION {
    permission: "ApplicationManagement",
    roleName: "Application Developer",
    roleTemplateId: "cf1c38e5-3621-4004-a7cb-879624dced7c",
    principalType: "Application",
    source: "DirectoryRole"
}]->(Tenant)
```

**Why 3 Edges:**
- Application Administrator: Full application management
- Cloud Application Administrator: Cloud-only app management
- Application Developer: Owned application management

---

## Field Reference

| Property | Type | Required | Purpose |
|----------|------|----------|---------|
| `permission` | String | Yes | Always "ApplicationManagement" |
| `roleName` | String | Yes | Role granting permission |
| `roleTemplateId` | String | Yes | Azure role template GUID |
| `principalType` | String | Yes | "Application", "User", or "Group" |
| `source` | String | Yes | Always "DirectoryRole" |
| `targetResourceType` | String | Yes | "Microsoft.DirectoryServices/tenant" |
| `createdAt` | DateTime | Yes | Edge creation timestamp |

---

## Bug History

### Bug #3: Field Name Mismatch (Fixed 2026-01-20)

**Symptom:** 396 items collected, 132 edges created (data loss - only 1 edge per app instead of 3)

**Root Cause:** Collector used `"applicationId": appID` but importer expected `"principalId": appID`

**Secondary Issue:** Used `"role": roleName` but importer expected `"roleName": roleName`

**Fix:**
- Changed collector.go:3899 from `"applicationId"` to `"principalId"`
- Changed collector.go:3901 from `"role"` to `"roleName"`

**Validation:** All 396 Application RBAC permissions (132 apps × 3 roles) now create edges correctly

### Bug #4: MERGE Uniqueness Missing (Fixed 2026-01-20)

**Symptom:** 396 items collected → 132 edges created (only last role per app preserved, 264 lost)

**Root Cause:** MERGE pattern matched on (principal, target) only, missing `{roleName, permission}` uniqueness

**Original (Wrong):**
```cypher
MERGE (principal)-[r:HAS_PERMISSION]->(tenant)
SET r.roleName = ..., r.permission = ...
-- Result: Each app has only 1 edge (overwrites previous roles)
```

**Fixed:**
```cypher
MERGE (principal)-[r:HAS_PERMISSION {roleName: $roleName, permission: $permission}]->(tenant)
ON CREATE SET r.principalType = ..., r.source = ..., r.createdAt = datetime()
ON MATCH SET r.roleName = ..., r.source = ...
-- Result: Each app has up to 3 edges (one per unique roleName+permission)
```

**Validation:** Re-running iam-push creates no duplicates, all 396 edges preserved

---

## Related Documentation

- [Application Credential Management](application-credential-management.md) - Credential management permissions
- [Overview - iam-push Phase Architecture](../overview.md#iam-push-phase-architecture) - Complete implementation details
- [Analysis Examples](../analysis-examples.md) - Query patterns for analysis
