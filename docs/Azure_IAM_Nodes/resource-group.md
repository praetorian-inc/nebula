# Resource Group Nodes

Azure resource groups for organizing resources.

## Node Labels

- `Resource` (shared)
- `Hierarchy` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `rgMap["id"]` | ✅ | Normalized resource group ID |
| `resourceType` | string | Constant | ✅ | `"Microsoft.Resources/resourceGroups"` |
| `displayName` | string | `rgMap["name"]` | ✅ | Lowercase RG name |
| `resourceGroupName` | string | `rgMap["name"]` | ✅ | Lowercase RG name |
| `subscriptionId` | string | Parent subscription | ✅ | Subscription GUID |
| `location` | string | `rgMap["location"]` | ❌ | Azure region |
| `metadata` | string (JSON) | Computed | ✅ | JSON with resourceGroupName, subscriptionId, location |

## MERGE Key

```cypher
{id: toLower($rgId)}
```

**Uniqueness:** One node per resource group

## Source Data

**Location:** `consolidatedData["azure_resources"][subscriptionId]["azureResourceGroups"]`

**Example:**
```json
{
  "azure_resources": {
    "subscription-guid-123": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/subscription-guid-123/resourceGroups/production-rg",
          "name": "production-rg",
          "type": "microsoft.resources/resourcegroups",
          "location": "eastus",
          "tags": {
            "environment": "production",
            "cost-center": "engineering"
          },
          "properties": {
            "provisioningState": "Succeeded"
          }
        }
      ]
    }
  }
}
```

## Creation Logic

**Function:** `createHierarchyResources()` - line 805

**Batch Size:** 1000 resource groups per transaction

**Processing:**
```go
// Extract RGs from each subscription's data
for subscriptionID, subData := range azureResources {
    subMap := subData.(map[string]interface{})
    resourceGroups := getArrayValue(subMap, "azureResourceGroups")

    for _, rgData := range resourceGroups {
        rgMap := rgData.(map[string]interface{})
        rgId := getStringValue(rgMap, "id")
        rgName := getStringValue(rgMap, "name")

        // Skip if missing required fields
        if rgId == "" || rgName == "" {
            continue
        }

        // Normalize name to lowercase for consistency
        rgNameLower := strings.ToLower(rgName)

        // Create resource group node
    }
}
```

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Hierarchy {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.Resources/resourceGroups",
    r.displayName = resource.displayName,
    r.resourceGroupName = resource.resourceGroupName,
    r.subscriptionId = resource.subscriptionId,
    r.location = resource.location,
    r.metadata = COALESCE(resource.metadata, '{}')
```

## Conditional Logic

### Name Normalization

```go
// Normalize resource group name to lowercase for consistency
rgNameLower := strings.ToLower(rgMap["name"].(string))

rgResource["displayName"] = rgNameLower
rgResource["resourceGroupName"] = rgNameLower
```

**Why:** Ensures consistent naming in graph (Azure is case-insensitive for RG names)

### Deduplication

```go
// Use map to deduplicate by normalized ID
seen := make(map[string]bool)

normalizedId := normalizeResourceId(rgId)
if seen[normalizedId] {
    continue // Skip duplicate
}
seen[normalizedId] = true
```

### Skip Empty Names

```go
// Only create if both ID and name are not empty
if rgId == "" || rgName == "" {
    l.Logger.Warn("Skipping resource group with empty ID or name")
    continue
}
```

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/rg-to-resource.md) - Azure resources

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/subscription-to-rg.md) - Parent subscription

## Resource Group in Hierarchy

Resource groups are logical containers for Azure resources:

```
Subscription
  ├─ Resource Group: production-rg
  │    ├─ Virtual Machine: web-vm-01
  │    ├─ Storage Account: prodstorage001
  │    └─ SQL Database: prod-db
  └─ Resource Group: development-rg
       ├─ Virtual Machine: dev-vm-01
       └─ Storage Account: devstorage001
```

**Key Characteristics:**
- **Logical Container:** Groups related resources for management
- **Lifecycle:** Resources in same RG typically share same lifecycle
- **RBAC Scope:** Permissions can be assigned at RG level
- **Location:** RG has location metadata (resources can be in different locations)
- **Tagging:** Tags applied to RG for organization and cost tracking

## Query Examples

### Find all resource groups
```cypher
MATCH (rg:Resource:Hierarchy)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, rg.location, rg.subscriptionId
```

### Find resource groups in a subscription
```cypher
MATCH (sub:Resource:Hierarchy)-[:CONTAINS]->(rg:Resource:Hierarchy)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND sub.subscriptionId = "subscription-guid-123"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, rg.location
```

### Find resource groups by location
```cypher
MATCH (rg:Resource:Hierarchy)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND rg.location = "eastus"
RETURN rg.displayName, rg.subscriptionId
```

### Count resources per resource group
```cypher
MATCH (rg:Resource:Hierarchy)-[:CONTAINS]->(resource:Resource:AzureResource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, count(resource) as resource_count
ORDER BY resource_count DESC
```

### Find empty resource groups (no resources)
```cypher
MATCH (rg:Resource:Hierarchy)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND NOT (rg)-[:CONTAINS]->(:Resource:AzureResource)
RETURN rg.displayName, rg.location
```

### Find resource groups with RBAC assignments
```cypher
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(rg:Resource:Hierarchy)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND perm.source = "RBAC"
RETURN rg.displayName, principal.displayName, perm.roleName
```

## Test Cases

### Test 1: Resource Group Creation - Required Fields
**Input:**
```json
{
  "azure_resources": {
    "sub-test-001": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/sub-test-001/resourceGroups/test-rg",
          "name": "test-rg",
          "type": "microsoft.resources/resourcegroups"
        }
      ]
    }
  }
}
```

**Expected:**
- Node created with labels: `Resource:Hierarchy`
- `id = "/subscriptions/sub-test-001/resourcegroups/test-rg"` (lowercase)
- `displayName = "test-rg"` (lowercase)
- `resourceGroupName = "test-rg"` (lowercase)
- `subscriptionId = "sub-test-001"`
- `resourceType = "Microsoft.Resources/resourceGroups"`

### Test 2: Resource Group with Location
**Input:**
```json
{
  "azure_resources": {
    "sub-test-002": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/sub-test-002/resourceGroups/eastus-rg",
          "name": "eastus-rg",
          "type": "microsoft.resources/resourcegroups",
          "location": "eastus"
        }
      ]
    }
  }
}
```

**Expected:**
- `location = "eastus"`
- Metadata contains location field

### Test 3: Case Normalization
**Input:**
```json
{
  "azure_resources": {
    "sub-test-003": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/sub-test-003/resourceGroups/Production-RG",
          "name": "Production-RG"
        }
      ]
    }
  }
}
```

**Expected:**
- `displayName = "production-rg"` (normalized to lowercase)
- `resourceGroupName = "production-rg"` (normalized to lowercase)
- ID normalized to lowercase

### Test 4: Deduplication
**Input:**
```json
{
  "azure_resources": {
    "sub-test-004": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/sub-test-004/resourceGroups/duplicate-rg",
          "name": "duplicate-rg"
        },
        {
          "id": "/subscriptions/sub-test-004/resourceGroups/duplicate-rg",
          "name": "duplicate-rg"
        }
      ]
    }
  }
}
```

**Expected:**
- Only one node created (deduplicated by normalized ID)
- No duplicate nodes

### Test 5: Empty Name Handling
**Input:**
```json
{
  "azure_resources": {
    "sub-test-005": {
      "azureResourceGroups": [
        {
          "id": "/subscriptions/sub-test-005/resourceGroups/",
          "name": ""
        }
      ]
    }
  }
}
```

**Expected:**
- No node created (skipped due to empty name)
- No errors thrown
- Warning logged

### Test 6: Idempotency
**Action:** Run import twice with same RG data

**Expected:**
- Only one node created per RG
- No duplicate nodes
- Properties unchanged on second run

### Test 7: Multiple RGs in Same Subscription
**Input:**
```json
{
  "azure_resources": {
    "sub-test-007": {
      "azureResourceGroups": [
        {"id": "/subscriptions/sub-test-007/resourceGroups/rg-1", "name": "rg-1"},
        {"id": "/subscriptions/sub-test-007/resourceGroups/rg-2", "name": "rg-2"},
        {"id": "/subscriptions/sub-test-007/resourceGroups/rg-3", "name": "rg-3"}
      ]
    }
  }
}
```

**Expected:**
- Three RG nodes created
- All have same subscriptionId
- Each has unique displayName

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createHierarchyResources()` starting at line 805

**Batch Processing:** Resource groups processed in batches of 1000

**Deduplication:** Uses map to track seen IDs within subscription

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#51-azureresourcegroups-array) - JSON input format
- [Subscription Nodes](subscription.md) - Parent nodes
- [Azure Resource Nodes](azure-resource.md) - Child nodes
- [Subscription CONTAINS RG](../Azure_IAM_Edges/CONTAINS/subscription-to-rg.md) - Parent edge
- [RG CONTAINS Resource](../Azure_IAM_Edges/CONTAINS/rg-to-resource.md) - Child edges
- [HAS_PERMISSION RBAC](../Azure_IAM_Edges/HAS_PERMISSION/owner.md) - RG-level permissions
