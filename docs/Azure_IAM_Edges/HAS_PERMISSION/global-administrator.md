# Global Administrator - HAS_PERMISSION Edge

**Edge Type:** `HAS_PERMISSION`
**Permission:** `Global Administrator`
**Role Template ID:** `62e90394-69f5-4237-9190-012177145e10`
**Source:** `DirectoryRole`

---

## Overview

HAS_PERMISSION edges represent the **current state** of Global Administrator role assignments in the tenant. These edges are factual data showing which principals currently have this role.

---

## Edge Creation Logic

### Data Collection (collector.go)

The collector queries Azure Active Directory for directory role members:

```go
// Query directory role members
directoryRoles := queryDirectoryRoles(graphClient)

// For each role member, create permission entry
for _, member := range role.Members {
    permission := map[string]interface{}{
        "principalId":         member.Id,
        "principalType":       determinePrincipalType(member),
        "targetResourceId":    tenantId,
        "targetResourceType":  "Microsoft.DirectoryServices/tenant",
        "permission":          role.DisplayName,
        "roleName":            role.DisplayName,
        "roleTemplateId":      role.RoleTemplateId,
    }
}
```

### Edge Creation (neo4j_importer.go:1626-1740)

**Phase 4 HAS_PERMISSION edge creation:**

```cypher
MATCH (principal:Resource {id: $principalId})
MATCH (tenant:Resource {resourceType: "Microsoft.DirectoryServices/tenant"})

MERGE (principal)-[r:HAS_PERMISSION {
    templateId: $roleTemplateId,
    permission: $permission
}]->(tenant)
ON CREATE SET
    r.principalType = $principalType,
    r.roleName = $roleName,
    r.source = $source,
    r.targetResourceType = $targetResourceType,
    r.roleTemplateId = $roleTemplateId,
    r.createdAt = datetime()
ON MATCH SET
    r.roleName = $roleName,
    r.source = $source
```

**Uniqueness Constraint:** `{templateId, permission}` - Each principal can have Global Administrator role only once

---

## Edge Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `templateId` | String | Yes | Role template GUID (part of uniqueness) |
| `permission` | String | Yes | "Global Administrator" (part of uniqueness) |
| `roleName` | String | Yes | "Global Administrator" |
| `roleTemplateId` | String | Yes | Same as templateId (62e90394-...) |
| `principalType` | String | Yes | "User", "ServicePrincipal", or "Group" |
| `source` | String | Yes | "DirectoryRole" |
| `targetResourceType` | String | Yes | "Microsoft.DirectoryServices/tenant" |
| `assignmentType` | String | Optional | "PIM", "Permanent", or "Eligible" (set by PIM enrichment) |
| `pimProcessed` | Boolean | Optional | true if PIM enrichment occurred |
| `createdAt` | DateTime | Yes | Edge creation timestamp |

---

## PIM Enrichment

**Function:** `createPIMEnrichedPermissionEdges()` (line 1756)

After HAS_PERMISSION edges are created, PIM enrichment adds metadata:

```cypher
-- Match existing Global Administrator HAS_PERMISSION edges
MATCH (principal:Resource {id: $principalId})-[r:HAS_PERMISSION]->(tenant:Resource)
WHERE r.templateId = $roleTemplateId

-- Add PIM properties
SET r.assignmentType = "PIM",
    r.pimProcessed = true
```

**Eligible-only assignments** (PIM eligible but not activated):

```cypher
-- Create HAS_PERMISSION for eligible assignments
CREATE (principal)-[r:HAS_PERMISSION]->(tenant)
SET r.assignmentType = "Eligible",
    r.roleName = "Global Administrator",
    r.templateId = "62e90394-69f5-4237-9190-012177145e10",
    r.pimProcessed = true,
    ...
```

**Non-PIM assignments marked as Permanent:**

```cypher
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.pimProcessed IS NULL
SET r.assignmentType = "Permanent"
```

---

## Query Examples

### Find All Global Administrator Assignments

```cypher
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "Global Administrator"
  AND r.source = "DirectoryRole"
RETURN principal.displayName,
       principal.resourceType,
       r.assignmentType,
       r.roleName
ORDER BY principal.displayName
```

### Find Active vs Eligible Assignments

```cypher
-- Active assignments (PIM or Permanent)
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "Global Administrator"
  AND r.assignmentType IN ["PIM", "Permanent"]
RETURN principal.displayName, r.assignmentType

-- Eligible-only (not activated)
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "Global Administrator"
  AND r.assignmentType = "Eligible"
RETURN principal.displayName
```

### Verify MERGE Uniqueness

```cypher
-- Check for duplicate Global Administrator edges (should return 0)
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.permission = "Global Administrator"
WITH principal, count(r) as edgeCount
WHERE edgeCount > 1
RETURN principal.displayName, edgeCount
```

**Expected:** 0 rows (no duplicates)

---

## Related Documentation

- **CAN_ESCALATE Analysis:** [CAN_ESCALATE/global-administrator.md](../CAN_ESCALATE/global-administrator.md) - Escalation logic and attack scenarios
- **Implementation:** [Overview - iam-push Phase Architecture](../overview.md#iam-push-phase-architecture)

---

## References

- [Microsoft Entra ID Global Administrator Role](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)
- [Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/)
