# Management Group CONTAINS Child Management Groups

Hierarchical relationship between parent and child management groups.

## Edge Type

`CONTAINS`

## Direction

Parent Management Group → Child Management Groups

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents the management group hierarchy in Azure, allowing nested organizational structures for policy and access control.

## Source & Target Nodes

**Source:** [Management Group Node](../../Azure_IAM_Nodes/management-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Management/managementGroups"`

**Target:** [Management Group Node](../../Azure_IAM_Nodes/management-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Management/managementGroups"`
- Property: Child MG has `parentId` pointing to parent MG

## Creation Logic

**Function:** `createManagementGroupToManagementGroupContains()` - line 1184

**Data Extraction:**
```go
// Extract parent-child relationships from management_groups array
for _, mgData := range managementGroups {
    if resourceType == "ManagementGroup" {
        parentId := getStringValue(mgMap, "ParentId")
        mgId := getStringValue(mgMap, "id")
        // Create relationship mapping
    }
}
```

**Cypher:**
```cypher
UNWIND $relationships as rel
MATCH (parentMg:Resource)
WHERE toLower(parentMg.resourceType) = "microsoft.management/managementgroups"
AND parentMg.id = rel.parentMgId
MATCH (childMg:Resource)
WHERE toLower(childMg.resourceType) = "microsoft.management/managementgroups"
AND childMg.id = rel.childMgId
MERGE (parentMg)-[:CONTAINS]->(childMg)
```

**Batch Processing:** All relationships processed in single transaction (no explicit batching)

## Matching Logic

### Parent Matching
- Match by `id` field
- Case-insensitive resourceType comparison
- Verify resourceType = `"microsoft.management/managementgroups"`

### Child Matching
- Match by `id` field
- Case-insensitive resourceType comparison
- Verify resourceType = `"microsoft.management/managementgroups"`
- Filter to exclude subscriptions (which may be mixed in same array)

### ParentId Normalization
```go
// Convert parent ID to full path format
if strings.HasPrefix(parentId, "/providers/Microsoft.Management/managementGroups/") {
    fullParentId = parentId
} else {
    fullParentId = "/providers/Microsoft.Management/managementGroups/" + parentId
}
```

## Source Data

**Location:** `consolidatedData["management_groups"]`

**Schema:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/child-mg-001",
      "name": "child-mg-001",
      "type": "Microsoft.Management/managementGroups",
      "ResourceType": "ManagementGroup",
      "ParentId": "/providers/Microsoft.Management/managementGroups/parent-mg-001",
      "properties": {
        "displayName": "Child Management Group 001",
        "parent": {
          "name": "parent-mg-001"
        }
      }
    }
  ]
}
```

**Fields:**
- `id`: Full resource ID of child MG
- `ParentId`: Full resource ID or short name of parent MG
- `ResourceType`: Must be `"ManagementGroup"` (not `"Subscription"`)

## Conditional Logic

### Prerequisites
- Parent MG node must exist (created in Phase 1-3)
- Child MG node must exist (created in Phase 1-3)

### Filtering
- Skip if `ResourceType != "ManagementGroup"` (excludes subscriptions)
- Skip if `parentId` is empty
- Skip if `mgId` is empty

### Silent Failure
If either parent or child node missing, edge is not created (no error logged)

## Hierarchy Position

```
Tenant (root of all)
  └─ Root Management Group (mgId = tenantId, isRoot = true)
       ├─ Management Group A (ParentId = Root MG)
       │    ├─ Management Group A1 (ParentId = MG A)
       │    └─ Management Group A2 (ParentId = MG A)
       └─ Management Group B (ParentId = Root MG)
            └─ Management Group B1 (ParentId = MG B)
```

**Key Characteristics:**
- **Multi-Level:** Supports deep nesting (up to 6 levels in Azure)
- **Tree Structure:** Each MG has exactly one parent (except root)
- **Bidirectional Properties:** Child stores `parentId`, parent doesn't store children list

## Query Examples

### Find direct children of a management group
```cypher
MATCH (parentMg:Resource)-[:CONTAINS]->(childMg:Resource)
WHERE parentMg.managementGroupId = "parent-mg-id"
  AND toLower(childMg.resourceType) = "microsoft.management/managementgroups"
RETURN childMg.displayName, childMg.managementGroupId
```

### Find all descendants (recursive)
```cypher
MATCH (ancestor:Resource)-[:CONTAINS*]->(descendant:Resource)
WHERE ancestor.managementGroupId = "parent-mg-id"
  AND toLower(descendant.resourceType) = "microsoft.management/managementgroups"
RETURN descendant.displayName, descendant.managementGroupId
```

### Count depth in hierarchy
```cypher
MATCH path = (rootMG:Resource)-[:CONTAINS*]->(mg:Resource)
WHERE rootMG.isRoot = true
  AND mg.managementGroupId = "target-mg-id"
  AND toLower(mg.resourceType) = "microsoft.management/managementgroups"
RETURN length(path) as depth
```

### Find parent of a management group
```cypher
MATCH (parentMg:Resource)-[:CONTAINS]->(childMg:Resource)
WHERE childMg.managementGroupId = "child-mg-id"
  AND toLower(parentMg.resourceType) = "microsoft.management/managementgroups"
RETURN parentMg.displayName, parentMg.managementGroupId
```

### Find management groups with no children (leaf MGs)
```cypher
MATCH (mg:Resource)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND NOT (mg)-[:CONTAINS]->(:Resource {resourceType: ~"(?i).*managementgroups"})
RETURN mg.displayName, mg.managementGroupId
```

## Test Cases

### Test 1: Parent-Child Relationship - Normal Case
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/parent-mg",
      "name": "parent-mg",
      "ResourceType": "ManagementGroup"
    },
    {
      "id": "/providers/Microsoft.Management/managementGroups/child-mg",
      "name": "child-mg",
      "ResourceType": "ManagementGroup",
      "ParentId": "/providers/Microsoft.Management/managementGroups/parent-mg"
    }
  ]
}
```

**Expected:**
- Parent MG node exists
- Child MG node exists
- CONTAINS edge: Parent MG → Child MG

**Verification:**
```cypher
MATCH (parent {managementGroupId: "parent-mg"})-[r:CONTAINS]->(child {managementGroupId: "child-mg"})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Multi-Level Hierarchy
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/level1",
      "name": "level1",
      "ResourceType": "ManagementGroup",
      "ParentId": "/providers/Microsoft.Management/managementGroups/root-mg"
    },
    {
      "id": "/providers/Microsoft.Management/managementGroups/level2",
      "name": "level2",
      "ResourceType": "ManagementGroup",
      "ParentId": "/providers/Microsoft.Management/managementGroups/level1"
    }
  ]
}
```

**Expected:**
- Root MG → Level1 MG edge
- Level1 MG → Level2 MG edge
- Recursive traversal: Root MG →* Level2 MG (depth = 2)

### Test 3: ParentId Normalization
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/child-mg",
      "name": "child-mg",
      "ResourceType": "ManagementGroup",
      "ParentId": "parent-mg"
    }
  ]
}
```

**Expected:**
- ParentId normalized to `/providers/Microsoft.Management/managementGroups/parent-mg`
- Edge created successfully despite short-form parent ID

### Test 4: Idempotency
**Action:** Run import twice with same hierarchy data

**Expected:**
- Only one edge created per parent-child pair (MERGE ensures idempotency)
- No duplicate edges

### Test 5: Missing Parent Node
**Setup:** Delete parent MG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Child MG node unaffected

### Test 6: Missing Child Node
**Setup:** Delete child MG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Parent MG node unaffected

### Test 7: Mixed Array (Subscriptions Filtered Out)
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/parent-mg",
      "name": "parent-mg",
      "ResourceType": "ManagementGroup"
    },
    {
      "id": "/subscriptions/sub-001",
      "name": "sub-001",
      "type": "microsoft.resources/subscriptions",
      "ParentId": "/providers/Microsoft.Management/managementGroups/parent-mg"
    }
  ]
}
```

**Expected:**
- Parent MG node created
- Subscription node created
- NO MG-to-MG edge created (subscription filtered out by ResourceType check)
- MG-to-Subscription edge created separately by different function

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createManagementGroupToManagementGroupContains()` starting at line 1184

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single batch (all relationships in one transaction)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:** Empty IDs and non-ManagementGroup types filtered during data extraction

## Related Documentation

- [Management Group Node](../../Azure_IAM_Nodes/management-group.md) - Source and target node
- [Tenant CONTAINS Root MG](tenant-to-root-mg.md) - Parent edge (root)
- [MG CONTAINS Subscription](mg-to-subscription.md) - Child edges (subscriptions)
- [../overview.md](../overview.md) - Hierarchy overview
