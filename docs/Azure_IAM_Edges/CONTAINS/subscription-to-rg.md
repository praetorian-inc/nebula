# Subscription CONTAINS Resource Groups

Hierarchical relationship from subscriptions to resource groups.

## Edge Type

`CONTAINS`

## Direction

Subscription → Resource Group

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents the containment of resource groups within subscriptions. Resource groups are logical containers for resources within a subscription boundary.

## Source & Target Nodes

**Source:** [Subscription Node](../NODES/subscription.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Resources/subscriptions"`

**Target:** [Resource Group Node](../NODES/resource-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Resources/resourceGroups"`

## Creation Logic

**Function:** `createSubscriptionToResourceGroupContains()` - line 1418

**Cypher:**
```cypher
MATCH (subscription:Resource)
WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
MATCH (rg:Resource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
AND rg.id STARTS WITH subscription.id + "/resourcegroups/"
MERGE (subscription)-[:CONTAINS]->(rg)
```

**Key Logic:**
- No explicit data extraction (graph-based matching)
- Uses ID path pattern matching
- RG ID format: `/subscriptions/{subId}/resourcegroups/{rgName}`
- Subscription ID format: `/subscriptions/{subId}`

## Matching Logic

### Subscription Matching
- Match all subscription nodes by resourceType
- Case-insensitive comparison

### Resource Group Matching
- Match all resource group nodes by resourceType
- Filter by ID pattern: RG ID must start with subscription ID + "/resourcegroups/"
- Case-insensitive comparison

### ID Pattern Matching
```cypher
rg.id STARTS WITH subscription.id + "/resourcegroups/"
```

**Examples:**
- Subscription: `/subscriptions/sub-001`
- RG: `/subscriptions/sub-001/resourcegroups/prod-rg` ✅ Match
- RG: `/subscriptions/sub-002/resourcegroups/dev-rg` ❌ No match (different subscription)

## Source Data

**No explicit source data** - relationships derived from node IDs

**Implicit Data:**
- Resource group nodes created with full ARM resource IDs
- Subscription nodes created with `/subscriptions/{id}` format
- ID hierarchy encodes containment relationship

## Conditional Logic

### Prerequisites
- Subscription nodes must exist (created in Phase 1-3)
- Resource group nodes must exist (created in Phase 1-3)

### Pattern Matching
- RG ID must conform to Azure ARM path format
- Subscription ID extracted from RG path prefix
- No explicit data validation (relies on ID format correctness)

### Silent Failure
If no matching subscription found for RG, no edge created (no error logged)

## Hierarchy Position

```
Management Group
  └─ Subscription A
       ├─ Resource Group 1
       ├─ Resource Group 2
       └─ Resource Group 3
```

**Key Characteristics:**
- **One Parent:** Each RG belongs to exactly one subscription
- **Logical Container:** RGs organize resources within subscription
- **Billing Tag:** Resources billed at subscription level, tagged by RG

## Query Examples

### Find all resource groups in a subscription
```cypher
MATCH (sub:Resource)-[:CONTAINS]->(rg:Resource)
WHERE sub.subscriptionId = "sub-001"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, rg.location
```

### Find subscription of a resource group
```cypher
MATCH (sub:Resource)-[:CONTAINS]->(rg:Resource)
WHERE rg.displayName = "prod-rg"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN sub.subscriptionId, sub.displayName
```

### Count resource groups per subscription
```cypher
MATCH (sub:Resource)-[:CONTAINS]->(rg:Resource)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN sub.subscriptionId,
       sub.displayName,
       count(rg) as rg_count
ORDER BY rg_count DESC
```

### Find resource groups without parent subscriptions (broken hierarchy)
```cypher
MATCH (rg:Resource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND NOT (:Resource)-[:CONTAINS]->(rg)
RETURN rg.displayName, rg.id
```

### Find subscriptions with no resource groups (empty subscriptions)
```cypher
MATCH (sub:Resource)
WHERE toLower(sub.resourceType) = "microsoft.resources/subscriptions"
  AND NOT (sub)-[:CONTAINS]->(:Resource {resourceType: ~"(?i).*resourcegroups"})
RETURN sub.subscriptionId, sub.displayName
```

### Find resource groups by location
```cypher
MATCH (sub:Resource)-[:CONTAINS]->(rg:Resource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND rg.location = "eastus"
RETURN sub.subscriptionId, rg.displayName, rg.location
```

## Test Cases

### Test 1: Subscription-RG Relationship - Normal Case
**Input:**
- Subscription node: `id = "/subscriptions/sub-test-001"`
- RG node: `id = "/subscriptions/sub-test-001/resourcegroups/test-rg"`

**Expected:**
- CONTAINS edge: Subscription → RG

**Verification:**
```cypher
MATCH (sub {id: "/subscriptions/sub-test-001"})-[r:CONTAINS]->(rg {displayName: "test-rg"})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Multiple RGs in Same Subscription
**Input:**
- Subscription node: `id = "/subscriptions/sub-test-002"`
- RG nodes:
  - `id = "/subscriptions/sub-test-002/resourcegroups/rg-a"`
  - `id = "/subscriptions/sub-test-002/resourcegroups/rg-b"`
  - `id = "/subscriptions/sub-test-002/resourcegroups/rg-c"`

**Expected:**
- 3 CONTAINS edges created, all from same subscription
- Each RG has independent edge

**Verification:**
```cypher
MATCH (sub {id: "/subscriptions/sub-test-002"})-[:CONTAINS]->(rg)
RETURN count(rg) as rg_count
// Expected: rg_count = 3
```

### Test 3: RGs in Different Subscriptions
**Input:**
- Subscription A: `id = "/subscriptions/sub-a"`
- Subscription B: `id = "/subscriptions/sub-b"`
- RG 1: `id = "/subscriptions/sub-a/resourcegroups/rg-1"`
- RG 2: `id = "/subscriptions/sub-b/resourcegroups/rg-2"`

**Expected:**
- CONTAINS edge: sub-a → rg-1
- CONTAINS edge: sub-b → rg-2
- NO cross-subscription edges

**Verification:**
```cypher
MATCH (subA {id: "/subscriptions/sub-a"})-[:CONTAINS]->(rgA)
MATCH (subB {id: "/subscriptions/sub-b"})-[:CONTAINS]->(rgB)
RETURN count(rgA) as subA_rgs, count(rgB) as subB_rgs
// Expected: subA_rgs = 1, subB_rgs = 1
```

### Test 4: Idempotency
**Action:** Run import twice with same nodes

**Expected:**
- Only one edge created per subscription-RG pair (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (sub {id: "/subscriptions/sub-test-004"})-[r:CONTAINS]->(rg {displayName: "test-rg"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing Subscription Node
**Setup:** Delete subscription node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for RG)
- No errors logged
- RG node unaffected

### Test 6: Missing RG Node
**Setup:** Delete RG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for subscription)
- No errors logged
- Subscription node unaffected

### Test 7: Case Insensitivity
**Input:**
- Subscription node with mixed case resourceType: `"Microsoft.Resources/Subscriptions"`
- RG node with mixed case resourceType: `"Microsoft.Resources/ResourceGroups"`

**Expected:**
- Case-insensitive matching succeeds
- CONTAINS edge created successfully

### Test 8: Malformed RG ID (No Match)
**Input:**
- Subscription node: `id = "/subscriptions/sub-test-008"`
- RG node: `id = "/resourcegroups/test-rg"` (missing subscription prefix)

**Expected:**
- No CONTAINS edge created (ID pattern doesn't match)
- RG remains orphaned

### Test 9: Graph-Based Matching (No Source Data)
**Verification:**
- No explicit relationship data in consolidatedData
- All edges derived from node ID patterns
- Works correctly even with empty input data (as long as nodes exist)

### Test 10: Empty Subscription (No RGs)
**Input:**
- Subscription node: `id = "/subscriptions/sub-empty"`
- No RG nodes with matching subscription prefix

**Expected:**
- No edges created for this subscription
- Subscription node exists with no outgoing CONTAINS edges to RGs

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createSubscriptionToResourceGroupContains()` starting at line 1418

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single transaction (graph-based pattern matching, no batching needed)

**Method:** Pure Cypher pattern matching (no Go data extraction)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist or IDs malformed), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes or malformed IDs logged separately during node creation

**Robustness:** ID pattern matching handles minor variations in casing via toLower()

## Azure Behavior Notes

**ARM Resource IDs:**
- Azure uses hierarchical resource IDs
- Format encodes containment: `/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}`
- Graph matching exploits this hierarchy

**Resource Group Uniqueness:**
- RG names must be unique within a subscription
- RG names can be duplicated across subscriptions
- Full ID (including subscription) ensures global uniqueness

**Billing Hierarchy:**
- All resources in an RG billed to parent subscription
- RG provides cost allocation and access control boundary
- Deleting RG deletes all contained resources

## Related Documentation

- [Subscription Node](../NODES/subscription.md) - Source node
- [Resource Group Node](../NODES/resource-group.md) - Target node
- [MG CONTAINS Subscription](mg-to-subscription.md) - Parent edge
- [RG CONTAINS Resource](rg-to-resource.md) - Child edges
- [../overview.md](../overview.md) - Hierarchy overview
