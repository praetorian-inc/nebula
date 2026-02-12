# CONTAINS Edges - Hierarchy & Containment

This directory documents all CONTAINS relationship edges representing Azure resource hierarchy and containment.

## Overview

CONTAINS edges represent structural relationships in Azure:
- **Hierarchy:** Management groups, subscriptions, resource groups
- **Containment:** Resources within containers, identities within groups
- **Ownership:** Application-to-SP, MI-to-SP relationships

**Edge Type:** `CONTAINS`

**Properties:** None (CONTAINS is a pure structural relationship with no additional metadata)

## Total Sub-types

**8 CONTAINS edge types** across three categories:

### Azure Management Hierarchy (4 types)

1. [tenant-to-root-mg.md](tenant-to-root-mg.md) - Tenant → Root Management Group
2. [mg-to-child-mg.md](mg-to-child-mg.md) - Management Group → Child Management Groups
3. [mg-to-subscription.md](mg-to-subscription.md) - Management Group → Subscriptions
4. [subscription-to-rg.md](subscription-to-rg.md) - Subscription → Resource Groups

### Resource Hierarchy (1 type)

5. [rg-to-resource.md](rg-to-resource.md) - Resource Group → Azure Resources

**Note:** Azure Resource → System-Assigned MI is a CAN_ESCALATE edge (IMDS token theft), not CONTAINS.

### Identity Relationships (3 types)

6. [group-to-member.md](group-to-member.md) - Group → Members (users, groups, SPs)
7. [application-to-sp.md](application-to-sp.md) - Application → Service Principal
8. [mi-to-sp.md](mi-to-sp.md) - Managed Identity → Service Principal

## Creation Phase

**Phase 2a:** `createContainsEdges()` - line 1113

All CONTAINS edges created after node creation (Phase 1-3) completes.

## Common Pattern

All CONTAINS edges follow this structure:

```cypher
MATCH (parent:Resource {...})
MATCH (child:Resource {...})
MERGE (parent)-[r:CONTAINS]->(child)
```

**Key Characteristics:**
- No properties on edge (pure structural)
- Uses MERGE for idempotency
- Requires both parent and child nodes to exist
- Silent failure if nodes missing (no error logged)

## Query Examples

### Find direct children
```cypher
MATCH (parent:Resource)-[:CONTAINS]->(child:Resource)
WHERE parent.id = $parentId
RETURN child.displayName, child.resourceType
```

### Find all descendants (recursive)
```cypher
MATCH (ancestor:Resource)-[:CONTAINS*]->(descendant:Resource)
WHERE ancestor.id = $ancestorId
RETURN descendant.displayName, descendant.resourceType
```

### Count depth in hierarchy
```cypher
MATCH path = (root:Resource)-[:CONTAINS*]->(node:Resource)
WHERE root.isRoot = true AND node.id = $nodeId
RETURN length(path) as depth
```

## Validation Queries

### Verify all subscriptions have parent MGs
```cypher
MATCH (sub:Resource:Hierarchy)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND NOT (:Resource)-[:CONTAINS]->(sub)
RETURN sub.subscriptionId as orphaned_subscription
```

### Verify all resources have parent RGs
```cypher
MATCH (resource:Resource:AzureResource)
WHERE NOT (:Resource)-[:CONTAINS]->(resource)
  AND NOT toLower(resource.resourceType) CONTAINS "managedidentity/systemassigned"
RETURN resource.displayName, resource.resourceType as orphaned_resource
```

### Find broken hierarchy chains
```cypher
MATCH (node:Resource:Hierarchy)
WHERE NOT (node.isRoot = true)
  AND NOT (:Resource)-[:CONTAINS]->(node)
RETURN node.displayName, node.resourceType as broken_chain
```

## Test Mapping

Each CONTAINS edge type should have test cases verifying:

1. **Edge Creation:** Edge created between correct nodes
2. **Idempotency:** Re-running doesn't create duplicates
3. **Missing Nodes:** Graceful handling when parent/child missing
4. **Filtering:** Correct node types matched
5. **Batch Processing:** Large datasets handled efficiently

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Phase:** 2a (after all node creation)

**Functions:**
- `createTenantToRootMGEdge()` - line 1130
- `createManagementGroupToManagementGroupContains()` - line 1184
- `createManagementGroupToSubscriptionContains()` - line 1261
- `createTenantToOrphanSubscriptionContains()` - line 1332
- `createSubscriptionToResourceGroupContains()` - line 1418
- `createResourceGroupToResourceContains()` - line 1455
- `createManagedIdentityToServicePrincipalContains()` - line 1496
- `createGroupMemberContains()` - line 1566
- `createApplicationToServicePrincipalContains()` - line 1629

## Related Documentation

- [../../Azure_IAM_Nodes/](../../Azure_IAM_Nodes/) - Node types that CONTAINS edges connect
- [../data-schema.md](../data-schema.md) - Source data for edge creation
- [../overview.md](../overview.md#contains-edges) - CONTAINS edge architecture
