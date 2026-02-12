# Subscription Nodes

Azure subscriptions.

## Node Labels

- `Resource` (shared)
- `Hierarchy` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | Computed | ✅ | `/subscriptions/{subscriptionId}` |
| `resourceType` | string | Constant | ✅ | `"Microsoft.Resources/subscriptions"` |
| `displayName` | string | Computed | ✅ | `"Subscription {subscriptionId}"` |
| `subscriptionId` | string | Map key | ✅ | Subscription GUID |
| `metadata` | string (JSON) | Computed | ✅ | JSON with subscriptionId |

## MERGE Key

```cypher
{id: "/subscriptions/" + toLower($subscriptionId)}
```

**Uniqueness:** One node per subscription

## Source Data

**Location:** Keys from `consolidatedData["azure_resources"]` map

**Example:**
```json
{
  "azure_resources": {
    "subscription-guid-123": {
      "subscriptionRoleAssignments": [...],
      "azureResourceGroups": [...],
      "azureResources": [...]
    },
    "subscription-guid-456": {
      ...
    }
  }
}
```

**Important:** Subscription IDs are the map keys, not nested in data structure.

## Creation Logic

**Function:** `createHierarchyResources()` - line 805

**Batch Size:** 1000 subscriptions per transaction

**Processing:**
```go
// Extract subscription IDs from azure_resources map keys
azureResources := getMapValue(consolidatedData, "azure_resources")
for subscriptionID := range azureResources {
    subscriptionResource := map[string]interface{}{
        "id": fmt.Sprintf("/subscriptions/%s", normalizeResourceId(subscriptionID)),
        "resourceType": "Microsoft.Resources/subscriptions",
        "displayName": fmt.Sprintf("Subscription %s", subscriptionID),
        "subscriptionId": subscriptionID,
        "metadata": toJSONString(map[string]interface{}{
            "subscriptionId": subscriptionID,
        }),
    }
    // Add to batch
}
```

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Hierarchy {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.Resources/subscriptions",
    r.displayName = resource.displayName,
    r.subscriptionId = resource.subscriptionId,
    r.metadata = COALESCE(resource.metadata, '{}')
```

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/subscription-to-rg.md) - Resource groups

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/mg-to-subscription.md) - Parent management group

## Subscription in Hierarchy

Subscriptions are the billing and resource boundary in Azure:

```
Management Group
  └─ Subscription
       ├─ Resource Group A
       │    ├─ Virtual Machine
       │    └─ Storage Account
       └─ Resource Group B
            └─ SQL Database
```

**Key Characteristics:**
- **Billing Boundary:** All resources in subscription share same billing
- **RBAC Scope:** Permissions can be assigned at subscription level
- **Policy Scope:** Azure Policy can be applied at subscription level
- **Resource Limit:** Azure quotas apply per subscription

## Query Examples

### Find all subscriptions
```cypher
MATCH (sub:Resource:Hierarchy)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN sub.displayName, sub.subscriptionId
```

### Find subscriptions under a management group
```cypher
MATCH (mg:Resource:Hierarchy)-[:CONTAINS]->(sub:Resource:Hierarchy)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN mg.displayName as management_group, sub.subscriptionId
```

### Find all resource groups in a subscription
```cypher
MATCH (sub:Resource:Hierarchy)-[:CONTAINS]->(rg:Resource:Hierarchy)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND sub.subscriptionId = "subscription-guid-123"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, rg.location
```

### Count resources per subscription
```cypher
MATCH (sub:Resource:Hierarchy)-[:CONTAINS*]->(resource:Resource:AzureResource)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN sub.subscriptionId, count(resource) as resource_count
ORDER BY resource_count DESC
```

### Find subscriptions with RBAC assignments
```cypher
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(sub:Resource:Hierarchy)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND perm.source = "RBAC"
RETURN sub.subscriptionId, principal.displayName, perm.roleName
```

## Test Cases

### Test 1: Subscription Creation - Single Subscription
**Input:**
```json
{
  "azure_resources": {
    "sub-test-001": {
      "azureResourceGroups": [],
      "azureResources": []
    }
  }
}
```

**Expected:**
- Node created with labels: `Resource:Hierarchy`
- `id = "/subscriptions/sub-test-001"` (lowercase)
- `subscriptionId = "sub-test-001"`
- `displayName = "Subscription sub-test-001"`
- `resourceType = "Microsoft.Resources/subscriptions"`
- Metadata contains subscriptionId

### Test 2: Multiple Subscriptions
**Input:**
```json
{
  "azure_resources": {
    "sub-test-002": {...},
    "sub-test-003": {...},
    "sub-test-004": {...}
  }
}
```

**Expected:**
- Three subscription nodes created
- Each with unique ID based on subscription GUID
- No duplicates

### Test 3: Subscription with Parent MG
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/subscriptions/sub-test-005",
      "name": "sub-test-005",
      "type": "microsoft.resources/subscriptions",
      "ParentId": "/providers/Microsoft.Management/managementGroups/parent-mg"
    }
  ],
  "azure_resources": {
    "sub-test-005": {...}
  }
}
```

**Expected:**
- Subscription node created
- MG CONTAINS Subscription edge created (via separate function)
- Edge links parent-mg → sub-test-005

### Test 4: Subscription ID Case Normalization
**Input:**
```json
{
  "azure_resources": {
    "SUB-TEST-006-UPPER": {...}
  }
}
```

**Expected:**
- `id = "/subscriptions/sub-test-006-upper"` (normalized to lowercase)
- `subscriptionId = "SUB-TEST-006-UPPER"` (preserved as-is)
- `displayName = "Subscription SUB-TEST-006-UPPER"` (preserves original casing)

### Test 5: Idempotency
**Action:** Run import twice with same subscription data

**Expected:**
- Only one node created per subscription
- No duplicate nodes
- Properties unchanged on second run

### Test 6: Empty Subscription (No Resources)
**Input:**
```json
{
  "azure_resources": {
    "sub-test-007": {
      "azureResourceGroups": [],
      "azureResources": [],
      "subscriptionRoleAssignments": []
    }
  }
}
```

**Expected:**
- Subscription node created successfully
- No resource group nodes (empty array)
- No Azure resource nodes (empty array)
- No errors during import

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createHierarchyResources()` starting at line 805

**Batch Processing:** Subscriptions processed in batches of 1000

**Key Code:**
```go
// Iterate over azure_resources map keys to get subscription IDs
azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
for subscriptionID := range azureResources {
    // Create subscription node
}
```

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#5-azure_resources-object) - JSON input format
- [Management Group Nodes](management-group.md) - Parent nodes
- [Resource Group Nodes](resource-group.md) - Child nodes
- [MG CONTAINS Subscription](../Azure_IAM_Edges/CONTAINS/mg-to-subscription.md) - Parent edge
- [Subscription CONTAINS RG](../Azure_IAM_Edges/CONTAINS/subscription-to-rg.md) - Child edges
- [HAS_PERMISSION RBAC](../Azure_IAM_Edges/HAS_PERMISSION/owner.md) - Subscription-level permissions
