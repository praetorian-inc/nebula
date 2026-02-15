# Owner - HAS_PERMISSION Edge

**Edge Type:** `HAS_PERMISSION`
**Permission:** `Owner`
**Source:** `AzureRBAC`

---

## Overview

HAS_PERMISSION edges represent the **current state** of Owner role assignments across Azure scopes. These edges are factual data showing which principals currently have Owner role at which scopes.

---

## Edge Creation Logic

### Data Collection (collector.go)

The collector queries Azure RBAC assignments via Azure Resource Graph:

```go
// Query RBAC assignments at all scopes
rbacAssignments := queryAzureRBACAssignments(subscriptionId)

// For each Owner assignment
for _, assignment := range rbacAssignments {
    if assignment.RoleDefinitionName == "Owner" {
        permission := map[string]interface{}{
            "principalId":         assignment.PrincipalId,
            "principalType":       assignment.PrincipalType,
            "targetResourceId":    assignment.Scope,
            "targetResourceType":  determineResourceType(assignment.Scope),
            "permission":          "Owner",
            "roleDefinitionId":    assignment.RoleDefinitionId,
            "roleDefinitionName":  "Owner",
            "scope":               assignment.Scope,
        }
    }
}
```

### Edge Creation (neo4j_importer.go:2016-2140)

**Phase 4 HAS_PERMISSION edge creation:**

```cypher
MATCH (principal:Resource {id: $principalId})
MATCH (target:Resource {id: $targetResourceId})

MERGE (principal)-[r:HAS_PERMISSION {
    roleDefinitionId: $roleDefinitionId,
    permission: $permission
}]->(target)
ON CREATE SET
    r.principalType = $principalType,
    r.roleName = $roleName,
    r.source = $source,
    r.scope = $scope,
    r.targetResourceType = $targetResourceType,
    r.createdAt = datetime()
ON MATCH SET
    r.roleName = $roleName,
    r.source = $source
```

**Uniqueness Constraint:** `{roleDefinitionId, permission}` - Each principal-role-scope combination unique

---

## Edge Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `roleDefinitionId` | String | Yes | Role definition GUID (part of uniqueness) |
| `permission` | String | Yes | "Owner" (part of uniqueness) |
| `roleName` | String | Yes | "Owner" |
| `principalType` | String | Yes | "User", "ServicePrincipal", or "Group" |
| `source` | String | Yes | "AzureRBAC" |
| `scope` | String | Yes | Azure scope path (/, subscription, resource group, resource) |
| `targetResourceType` | String | Yes | Resource type at scope |
| `createdAt` | DateTime | Yes | Edge creation timestamp |

---

## Scope Hierarchy

Owner assignments can occur at multiple Azure scopes:

```
Tenant Root (/)
├── Management Groups
│   ├── Subscriptions
│   │   ├── Resource Groups
│   │   │   └── Resources (VMs, Storage, etc.)
```

**Each scope creates a separate HAS_PERMISSION edge:**

```cypher
-- Owner at Subscription level
(Alice)-[HAS_PERMISSION {
    permission: "Owner",
    scope: "/subscriptions/12345678-..."
}]->(Subscription)

-- Owner at Resource Group level
(Alice)-[HAS_PERMISSION {
    permission: "Owner",
    scope: "/subscriptions/12345678-.../resourceGroups/prod-rg"
}]->(ResourceGroup)
```

---

## Query Examples

### Find All Owner Assignments

```cypher
MATCH (principal)-[r:HAS_PERMISSION]->(target)
WHERE r.permission = "Owner"
  AND r.source = "AzureRBAC"
RETURN principal.displayName,
       r.scope,
       target.displayName
ORDER BY principal.displayName
```

### Find Owners by Scope Level

```cypher
-- Subscription-level Owners
MATCH (principal)-[r:HAS_PERMISSION]->(target)
WHERE r.permission = "Owner"
  AND r.scope STARTS WITH "/subscriptions/"
  AND NOT r.scope CONTAINS "/resourceGroups/"
RETURN principal.displayName, r.scope

-- Resource Group-level Owners
MATCH (principal)-[r:HAS_PERMISSION]->(target)
WHERE r.permission = "Owner"
  AND r.scope CONTAINS "/resourceGroups/"
  AND NOT r.scope CONTAINS "/providers/"
RETURN principal.displayName, r.scope
```

### Find High-Risk Owner Assignments

```cypher
-- Owners at Tenant Root or Management Group level
MATCH (principal)-[r:HAS_PERMISSION]->(target)
WHERE r.permission = "Owner"
  AND (r.scope = "/" OR r.scope CONTAINS "/providers/Microsoft.Management/managementGroups/")
RETURN principal.displayName, principal.resourceType, r.scope
```

---

## Idempotency Validation

```cypher
-- Check for duplicate Owner edges (should return 0)
MATCH (principal)-[r:HAS_PERMISSION]->(target)
WHERE r.permission = "Owner"
WITH principal, target, count(r) as edgeCount
WHERE edgeCount > 1
RETURN principal.displayName, target.displayName, edgeCount
```

**Expected:** 0 rows (MERGE uniqueness prevents duplicates)

---

## Related Documentation

- **CAN_ESCALATE Analysis:** [CAN_ESCALATE/owner.md](../CAN_ESCALATE/owner.md) - Escalation logic and attack scenarios
- **Implementation:** [Overview - iam-push Phase Architecture](../overview.md#iam-push-phase-architecture)

---

## References

- [Azure Built-in Roles - Owner](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner)
- [Azure RBAC Scope Hierarchy](https://docs.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
