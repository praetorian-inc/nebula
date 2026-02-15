# Node Types - Azure IAM Graph

This directory documents all 11 node types created by the Azure IAM module.

## Overview

All nodes share the unified `Resource` label plus additional categorical labels. The MERGE key for all nodes is the `id` property (normalized to lowercase).

## Node Categories

### Identity Nodes (4 types)
Represent Azure AD / Entra ID identity objects:

- [user.md](user.md) - User accounts
- [group.md](group.md) - Security and Microsoft 365 groups
- [service-principal.md](service-principal.md) - Service principals (app identities)
- [application.md](application.md) - Application registrations

### Hierarchy Nodes (4 types)
Represent Azure management hierarchy:

- [tenant.md](tenant.md) - Azure AD tenant (root)
- [management-group.md](management-group.md) - Management groups
- [subscription.md](subscription.md) - Azure subscriptions
- [resource-group.md](resource-group.md) - Resource groups

### Azure Resource Nodes (3 types)
Represent Azure resources:

- [azure-resource.md](azure-resource.md) - Security-relevant Azure resources (VMs, storage, etc.)
- [user-assigned-mi.md](user-assigned-mi.md) - User-assigned managed identities
- [system-assigned-mi.md](system-assigned-mi.md) - System-assigned managed identities (synthetic)

## Common Properties

All nodes share these base properties:

| Property | Type | Required | Notes |
|----------|------|----------|-------|
| `id` | string | ✅ | MERGE key, normalized lowercase |
| `resourceType` | string | ✅ | Azure resource type (e.g., "Microsoft.DirectoryServices/users") |
| `displayName` | string | ✅ | Human-readable name |
| `metadata` | string (JSON) | ✅ | JSON string with additional properties |

## Node Creation Process

**Phase 1:** Identity Resources (line 605)
- Users, Groups, Service Principals, Applications

**Phase 2:** Hierarchy Resources (line 805)
- Tenant, Management Groups, Subscriptions, Resource Groups

**Phase 3:** Azure Resources (line 1035)
- Azure resources (filtered by security relevance)
- System-assigned managed identities (synthetic, created via Cypher)

## Batch Processing

All nodes created in batches of 1000 using this pattern:

```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Label1:Label2 {id: resource.id})
ON CREATE SET
    r.resourceType = resource.resourceType,
    r.displayName = resource.displayName,
    r.metadata = COALESCE(resource.metadata, '{}'),
    ... (type-specific properties) ...
ON MATCH SET
    r.displayName = resource.displayName,
    r.metadata = COALESCE(resource.metadata, '{}'),
    r.accountEnabled = resource.accountEnabled
```

**ON CREATE:** Sets all properties from source data
**ON MATCH:** Updates only displayName, metadata, and accountEnabled

## Data Source

All nodes created from consolidated JSON data structure:

- **Identity nodes:** `consolidatedData["azure_ad"]`
- **Hierarchy nodes:** `consolidatedData["collection_metadata"]`, `consolidatedData["management_groups"]`, `consolidatedData["azure_resources"]`
- **Azure resource nodes:** `consolidatedData["azure_resources"][subscriptionId]["azureResources"]`

See [data-schema.md](../Azure_IAM_Edges/data-schema.md) for complete JSON structure.

## Test Mapping

Each node type should have test cases verifying:

1. **Creation:** Node created with correct labels
2. **Properties:** All properties set correctly
3. **Conditional Logic:** Optional fields handled properly
4. **Idempotency:** Re-running doesn't create duplicates
5. **Missing Data:** Graceful handling of missing source data

## Helper Functions

**normalizeResourceId()** - Converts IDs to lowercase for case-insensitive matching

**toJSONString()** - Converts maps to JSON strings for metadata properties

**processIdentityData()** - Extracts managed identity properties from nested objects

## Related Documentation

- [../Azure_IAM_Edges/data-schema.md](../Azure_IAM_Edges/data-schema.md) - JSON input format
- [../Azure_IAM_Edges/CONTAINS/](../Azure_IAM_Edges/CONTAINS/) - Hierarchy relationships between nodes
- [../Azure_IAM_Edges/HAS_PERMISSION/](../Azure_IAM_Edges/HAS_PERMISSION/) - Permission assignments
- [../Azure_IAM_Edges/overview.md](../Azure_IAM_Edges/overview.md) - Graph architecture overview
