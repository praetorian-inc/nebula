# Management Group CONTAINS Subscriptions

Hierarchical relationship from management groups to subscriptions, representing organizational structure.

## Edge Type

`CONTAINS`

## Direction

Management Group → Subscription

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents subscription assignment to management groups in Azure's organizational hierarchy. Each subscription belongs to exactly one management group.

## Source & Target Nodes

**Source:** [Management Group Node](../../Azure_IAM_Nodes/management-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Management/managementGroups"`

**Target:** [Subscription Node](../../Azure_IAM_Nodes/subscription.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Resources/subscriptions"`

## Creation Logic

**Two Functions Handle Different Cases:**

### 1. Subscriptions in Non-Root Management Groups

**Function:** `createManagementGroupToSubscriptionContains()` - line 1261

**Data Extraction:**
```go
// Subscriptions are in management_groups array with ParentId
for _, item := range managementGroups {
    itemType := getStringValue(itemMap, "type")
    itemName := getStringValue(itemMap, "name")  // subscription ID
    parentId := getStringValue(itemMap, "ParentId")

    if itemType == "microsoft.resources/subscriptions" && parentId != "" {
        // Extract MG ID from parent path
        // ParentId format: "/providers/Microsoft.Management/managementGroups/{mgId}"
    }
}
```

**Cypher:**
```cypher
MATCH (mg:Resource)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
AND mg.id = "/providers/microsoft.management/managementgroups/" + $mgId
MATCH (subscription:Resource {id: "/subscriptions/" + $subscriptionId})
WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
MERGE (mg)-[:CONTAINS]->(subscription)
```

**Processing:** Individual edge creation per subscription (not batched)

### 2. Orphan Subscriptions (No Management Group Assignment)

**Function:** `createTenantToOrphanSubscriptionContains()` - line 1332

**Purpose:** Subscriptions without explicit MG assignment are attached to root MG

**Data Extraction:**
```go
// Build list of subscriptions already in management groups
subscriptionsInMGs := make(map[string]bool)
for _, item := range managementGroups {
    if itemType == "microsoft.resources/subscriptions" && parentId != "" {
        subscriptionsInMGs[itemName] = true
    }
}

// Find subscriptions NOT in the map
for subscriptionId := range azureResources {
    if !subscriptionsInMGs[subscriptionId] {
        orphanSubscriptions = append(orphanSubscriptions, subscriptionId)
    }
}
```

**Cypher:**
```cypher
MATCH (rootMg:Resource)
WHERE toLower(rootMg.resourceType) = "microsoft.management/managementgroups"
AND rootMg.id = "/providers/microsoft.management/managementgroups/" + $tenantId
MATCH (subscription:Resource)
WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
AND LAST(SPLIT(subscription.id, "/")) IN $orphanSubscriptions
MERGE (rootMg)-[:CONTAINS]->(subscription)
```

**Processing:** Batch operation (all orphans in one transaction)

## Matching Logic

### Management Group Matching
- Match by full path: `/providers/microsoft.management/managementgroups/{mgId}`
- Case-insensitive resourceType comparison
- For orphans: match root MG by tenant ID

### Subscription Matching
- Match by ID pattern: `/subscriptions/{subscriptionId}`
- Case-insensitive resourceType comparison

### ParentId Extraction
```go
// Handle two ParentId formats:
// 1. Full path: "/providers/Microsoft.Management/managementGroups/mg-001"
// 2. Short name: "mg-001"

if strings.Contains(parentId, "/providers/Microsoft.Management/managementGroups/") {
    parts := strings.Split(parentId, "/")
    parentMgId = parts[len(parts)-1]  // Extract last segment
} else {
    parentMgId = parentId  // Use as-is
}
```

## Source Data

**Location:** `consolidatedData["management_groups"]` and `consolidatedData["azure_resources"]`

**Schema:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-guid-001",
      "ParentId": "/providers/Microsoft.Management/managementGroups/prod-mg"
    },
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-guid-002",
      "ParentId": "dev-mg"
    }
  ],
  "azure_resources": {
    "sub-guid-001": { "azureResources": [...] },
    "sub-guid-002": { "azureResources": [...] },
    "sub-guid-orphan": { "azureResources": [...] }
  }
}
```

**Fields:**
- `type`: Must be `"microsoft.resources/subscriptions"`
- `name`: Subscription ID (GUID)
- `ParentId`: Parent management group path or ID

## Conditional Logic

### Prerequisites
- Management group node must exist (created in Phase 1-3)
- Subscription node must exist (created in Phase 1-3)

### Filtering for Non-Root Assignments
- Skip if `type != "microsoft.resources/subscriptions"`
- Skip if `name` (subscription ID) is empty
- Skip if `ParentId` is empty

### Orphan Detection Logic
1. Build set of subscriptions with explicit MG parents
2. Iterate all subscriptions from `azure_resources` keys
3. Subscriptions NOT in set are orphans
4. Attach orphans to root management group

### Silent Failure
If MG or subscription node missing, edge is not created (no error logged)

## Hierarchy Position

```
Tenant
  └─ Root Management Group (mgId = tenantId)
       ├─ Production MG
       │    ├─ Subscription A (explicitly assigned)
       │    └─ Subscription B (explicitly assigned)
       ├─ Development MG
       │    └─ Subscription C (explicitly assigned)
       └─ Subscription D (orphan - no explicit assignment)
```

**Key Characteristics:**
- **One Parent:** Each subscription has exactly one parent MG
- **Default Assignment:** Orphan subscriptions assigned to root MG
- **Billing Boundary:** Subscriptions represent billing and resource boundaries

## Query Examples

### Find all subscriptions in a management group
```cypher
MATCH (mg:Resource)-[:CONTAINS]->(sub:Resource)
WHERE mg.managementGroupId = "prod-mg"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN sub.subscriptionId, sub.displayName
```

### Find management group of a subscription
```cypher
MATCH (mg:Resource)-[:CONTAINS]->(sub:Resource)
WHERE sub.subscriptionId = "sub-guid-001"
  AND toLower(mg.resourceType) = "microsoft.management/managementgroups"
RETURN mg.displayName, mg.managementGroupId, mg.isRoot
```

### Find orphan subscriptions (attached to root MG)
```cypher
MATCH (rootMg:Resource)-[:CONTAINS]->(sub:Resource)
WHERE rootMg.isRoot = true
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND toLower(rootMg.resourceType) = "microsoft.management/managementgroups"
RETURN sub.subscriptionId, sub.displayName
```

### Find subscriptions without MG parents (broken hierarchy)
```cypher
MATCH (sub:Resource)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND NOT (:Resource)-[:CONTAINS]->(sub)
RETURN sub.subscriptionId, sub.displayName
```

### Count subscriptions per management group
```cypher
MATCH (mg:Resource)-[:CONTAINS]->(sub:Resource)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN mg.displayName,
       mg.managementGroupId,
       count(sub) as subscription_count
ORDER BY subscription_count DESC
```

## Test Cases

### Test 1: Subscription in Non-Root MG - Normal Case
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-test-001",
      "ParentId": "/providers/Microsoft.Management/managementGroups/prod-mg"
    }
  ]
}
```

**Expected:**
- MG node exists with `managementGroupId = "prod-mg"`
- Subscription node exists with `subscriptionId = "sub-test-001"`
- CONTAINS edge: prod-mg → sub-test-001

**Verification:**
```cypher
MATCH (mg {managementGroupId: "prod-mg"})-[r:CONTAINS]->(sub {subscriptionId: "sub-test-001"})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Short-Form ParentId
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-test-002",
      "ParentId": "dev-mg"
    }
  ]
}
```

**Expected:**
- ParentId "dev-mg" extracted and used for matching
- CONTAINS edge created successfully

### Test 3: Orphan Subscription (No ParentId)
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-with-parent",
      "ParentId": "prod-mg"
    }
  ],
  "azure_resources": {
    "sub-with-parent": {},
    "sub-orphan": {}
  },
  "collection_metadata": {
    "tenant_id": "tenant-test-003"
  }
}
```

**Expected:**
- sub-with-parent: CONTAINS edge to prod-mg
- sub-orphan: CONTAINS edge to root MG (mgId = tenant-test-003)
- Orphan detection logic identifies sub-orphan

**Verification:**
```cypher
MATCH (rootMg {isRoot: true})-[:CONTAINS]->(orphan {subscriptionId: "sub-orphan"})
RETURN count(orphan) as orphan_count
// Expected: orphan_count = 1
```

### Test 4: Idempotency
**Action:** Run import twice with same subscription assignment

**Expected:**
- Only one edge created per MG-subscription pair (MERGE ensures idempotency)
- No duplicate edges

### Test 5: Multiple Subscriptions in Same MG
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-a",
      "ParentId": "prod-mg"
    },
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-b",
      "ParentId": "prod-mg"
    },
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-c",
      "ParentId": "prod-mg"
    }
  ]
}
```

**Expected:**
- 3 CONTAINS edges created, all from prod-mg
- Each subscription has independent edge

**Verification:**
```cypher
MATCH (mg {managementGroupId: "prod-mg"})-[:CONTAINS]->(sub)
RETURN count(sub) as subscription_count
// Expected: subscription_count = 3
```

### Test 6: Missing Management Group Node
**Setup:** Delete MG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Subscription node unaffected

### Test 7: Missing Subscription Node
**Setup:** Delete subscription node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- MG node unaffected

### Test 8: Mixed Array (Subscriptions and MGs Together)
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/prod-mg",
      "ResourceType": "ManagementGroup"
    },
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-test-008",
      "ParentId": "/providers/Microsoft.Management/managementGroups/prod-mg"
    }
  ]
}
```

**Expected:**
- MG node created (processed by different function)
- Subscription node created (processed by different function)
- CONTAINS edge: prod-mg → sub-test-008 created by this function
- Type filtering ensures correct processing

### Test 9: Empty Subscription ID (Skip)
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "",
      "ParentId": "prod-mg"
    }
  ]
}
```

**Expected:**
- Edge skipped (empty name validation)
- No edge created
- No errors

### Test 10: Empty ParentId (Becomes Orphan)
**Input:**
```json
{
  "management_groups": [
    {
      "type": "microsoft.resources/subscriptions",
      "name": "sub-test-010",
      "ParentId": ""
    }
  ],
  "azure_resources": {
    "sub-test-010": {}
  },
  "collection_metadata": {
    "tenant_id": "tenant-test-010"
  }
}
```

**Expected:**
- Skipped by createManagementGroupToSubscriptionContains (empty ParentId)
- Processed by createTenantToOrphanSubscriptionContains
- CONTAINS edge created to root MG

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Functions:**
- `createManagementGroupToSubscriptionContains()` starting at line 1261 (explicit assignments)
- `createTenantToOrphanSubscriptionContains()` starting at line 1332 (orphans)

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:**
- Explicit assignments: Individual transactions per subscription
- Orphan assignments: Single batch transaction for all orphans

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:**
- Empty subscription IDs filtered during extraction
- Empty ParentIds cause subscription to be treated as orphan
- Type filtering ensures only subscriptions processed

## Azure Behavior Notes

**Default Assignment:**
- Every Azure tenant has a root management group
- Subscriptions without explicit assignment default to root MG
- Root MG ID always equals tenant ID

**One Parent Rule:**
- Each subscription can belong to only one management group at a time
- Moving a subscription changes the CONTAINS relationship
- Re-import required to reflect subscription moves

## Related Documentation

- [Management Group Node](../../Azure_IAM_Nodes/management-group.md) - Source node
- [Subscription Node](../../Azure_IAM_Nodes/subscription.md) - Target node
- [Tenant CONTAINS Root MG](tenant-to-root-mg.md) - Root of hierarchy
- [MG CONTAINS Child MG](mg-to-child-mg.md) - MG hierarchy
- [Subscription CONTAINS RG](subscription-to-rg.md) - Next level down
- [../overview.md](../overview.md) - Hierarchy overview
