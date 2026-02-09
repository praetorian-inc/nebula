# OWNS Edges - Ownership Relationships

This directory documents all OWNS relationship edges representing direct ownership of Entra ID objects.

## Overview

OWNS edges represent ownership relationships in Azure AD / Entra ID:
- Users/Service Principals who own applications
- Users/Service Principals who own groups
- Users/Service Principals who own service principals

**Edge Type:** `OWNS`

**Properties:**
- `source`: Source of ownership data (e.g., "ApplicationOwnership", "GroupOwnership", "ServicePrincipalOwnership")
- `createdAt`: Unix timestamp when edge was created during import

## Total Sub-types

**3 OWNS edge types** for Entra ID object ownership:

1. [application-ownership.md](application-ownership.md) - Owner → Application
2. [group-ownership.md](group-ownership.md) - Owner → Group
3. [service-principal-ownership.md](service-principal-ownership.md) - Owner → Service Principal

## Creation Phase

**Phase 2e:** Created after CONTAINS edges, before HAS_PERMISSION edges

All OWNS edges created from explicit ownership data collected from Microsoft Graph API.

## Common Pattern

All OWNS edges follow this structure:

```cypher
UNWIND $edges AS edge
MATCH (source {id: edge.sourceId})
MATCH (target {id: edge.targetId})
WHERE toLower(target.resourceType) = $targetType
MERGE (source)-[r:OWNS]->(target)
SET r.source = edge.source,
    r.createdAt = edge.createdAt
```

**Key Characteristics:**
- Explicit ownership data from Graph API
- Properties track data source and creation time
- Uses MERGE for idempotency
- Batch processed (1000 edges per transaction)
- Silent failure if nodes missing

## Ownership Privileges

Owners have administrative control over owned objects:

### Application Owners Can:
- Add/remove credentials (secrets, certificates)
- Modify application properties
- Delete application
- Assign additional owners
- **Privilege Escalation:** Add secrets to assume application identity

### Group Owners Can:
- Add/remove members
- Modify group properties
- Delete group
- Assign additional owners
- **Privilege Escalation:** Add self/others to privileged groups

### Service Principal Owners Can:
- Add/remove credentials (if not locked by policy)
- Modify SP properties
- Delete SP
- Assign additional owners
- **Privilege Escalation:** Add secrets to assume SP identity

## Source Data

**Location:** `consolidatedData["azure_ad"]`

- `applicationOwnership`: Array of {applicationId, ownerId, ownerType}
- `groupOwnership`: Array of {groupId, ownerId, ownerType}
- `servicePrincipalOwnership`: Array of {servicePrincipalId, ownerId, ownerType}

See [../data-schema.md](../data-schema.md) for complete schema.

## Escalation Impact

OWNS edges feed into privilege escalation analysis:

### Direct Impact
Owner can modify owned object to gain its permissions

### Example: Application Owner Escalation
```
User (Alice) -[OWNS]-> Application (MyApp) -[CONTAINS]-> ServicePrincipal (MyApp SP)

ServicePrincipal (MyApp SP) -[HAS_PERMISSION {permission: "Global Administrator"}]-> Tenant

Result: Alice can add secret to MyApp, authenticate as MyApp SP, gain Global Administrator
```

### CAN_ESCALATE Edges Created
See [../CAN_ESCALATE/](../CAN_ESCALATE/) for ownership-based escalation vectors:
- Service Principal Owner Add Secret
- Application Owner Add Secret
- Group Owner Add Member → Transitive Permissions

## Query Examples

### Find all owners
```cypher
MATCH (owner:Resource)-[r:OWNS]->(owned:Resource)
RETURN owner.displayName, owned.displayName, owned.resourceType
```

### Find applications with multiple owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(app:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
WITH app, count(owner) as owner_count
WHERE owner_count > 1
RETURN app.displayName, owner_count
ORDER BY owner_count DESC
```

### Find users who own privileged groups
```cypher
MATCH (user:Resource)-[:OWNS]->(group:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(user.resourceType) = "microsoft.directoryservices/users"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
  AND toLower(perm.roleName) CONTAINS "administrator"
RETURN user.displayName, group.displayName, perm.roleName
```

### Find escalation paths via ownership
```cypher
MATCH (user:Resource)-[:OWNS]->(app:Resource)-[:CONTAINS]->(sp:Resource)
MATCH (sp)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(user.resourceType) = "microsoft.directoryservices/users"
  AND toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN user.displayName as owner,
       app.displayName as owned_app,
       perm.permission as sp_permission,
       target.displayName as target
```

## Validation Queries

### Find owners who don't exist as nodes
```cypher
MATCH (owned:Resource)
WHERE EXISTS {
    MATCH (phantom)-[:OWNS]->(owned)
    WHERE NOT EXISTS {
        MATCH (phantom:Resource)
    }
}
RETURN owned.displayName, owned.resourceType
```

### Count ownership by type
```cypher
MATCH (owner:Resource)-[r:OWNS]->(owned:Resource)
RETURN owned.resourceType as owned_type,
       count(r) as ownership_count
ORDER BY ownership_count DESC
```

### Find circular ownership (groups)
```cypher
MATCH path = (group1:Resource)-[:OWNS*2..]->(group1)
WHERE toLower(group1.resourceType) = "microsoft.directoryservices/groups"
RETURN [node in nodes(path) | node.displayName] as circular_ownership
```

## Test Mapping

Each OWNS edge type should have test cases verifying:

1. **Edge Creation:** Edge created with correct properties
2. **Idempotency:** Re-running doesn't create duplicates
3. **Missing Nodes:** Graceful handling when owner/owned missing
4. **Properties:** source and createdAt set correctly
5. **Batch Processing:** Large ownership datasets handled efficiently
6. **Type Filtering:** Only correct target types matched

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Phase:** 2e (after CONTAINS edges)

**Functions:**
- `createApplicationOwnershipDirectEdges()` - line 2054
- `createGroupOwnershipDirectEdges()` - line 2081
- `createServicePrincipalOwnershipDirectEdges()` - line 2132

**Batch Size:** 1000 edges per transaction

## Related Documentation

- [../../Azure_IAM_Nodes/](../../Azure_IAM_Nodes/) - Node types that OWNS edges connect
- [../data-schema.md](../data-schema.md) - Source data for ownership
- [../CAN_ESCALATE/](../CAN_ESCALATE/) - Ownership-based escalation vectors
- [../HAS_PERMISSION/](../HAS_PERMISSION/) - Potential permissions via ownership
- [../overview.md](../overview.md#owns-edges) - OWNS edge architecture
