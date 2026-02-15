# Management Group Nodes

Azure management groups for organizing subscriptions.

## Node Labels

- `Resource` (shared)
- `Hierarchy` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | Computed | ✅ | `/providers/Microsoft.Management/managementGroups/{mgId}` |
| `resourceType` | string | Constant | ✅ | `"Microsoft.Management/managementGroups"` |
| `displayName` | string | `properties.displayName` | ✅ | Management group display name |
| `tenantId` | string | From collection metadata | ✅ | Parent tenant ID |
| `managementGroupId` | string | `name` field | ✅ | MG name/ID |
| `parentId` | string | `properties.parent.name` | ⚠️ | Parent MG ID (NULL for root) |
| `childrenCount` | integer | Computed | ✅ | Length of children array |
| `isRoot` | boolean | Computed | ⚠️ | `true` only for tenant root group |
| `metadata` | string (JSON) | Computed | ✅ | JSON with managementGroupId, parentId, childrenCount |

## MERGE Key

```cypher
{id: toLower($mgId)}
```

Where `$mgId = "/providers/Microsoft.Management/managementGroups/" + $managementGroupId`

**Uniqueness:** One node per management group

## Source Data

**Location:** `consolidatedData["management_groups"]` (array mixing MGs and subscriptions)

**Example:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/production-mg",
      "name": "production-mg",
      "type": "microsoft.management/managementgroups",
      "properties": {
        "displayName": "Production Management Group",
        "parent": {
          "name": "tenant-root-group"
        },
        "details": {
          "updatedTime": "2024-01-15T10:30:00Z"
        }
      }
    }
  ]
}
```

## Creation Logic

**Function:** `createHierarchyResources()` - line 805

**Batch Size:** 1000 management groups per transaction

**Processing:**
1. Filter array for `type == "microsoft.management/managementgroups"`
2. Skip subscriptions mixed in array
3. Create nodes
4. Create root MG separately (special case)

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Hierarchy {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.Management/managementGroups",
    r.displayName = resource.displayName,
    r.tenantId = resource.tenantId,
    r.managementGroupId = resource.managementGroupId,
    r.parentId = resource.parentId,
    r.childrenCount = resource.childrenCount,
    r.metadata = COALESCE(resource.metadata, '{}')
```

## Root Management Group

**Special Case:** Every Azure tenant has a root management group with these characteristics:

| Property | Value |
|----------|-------|
| `id` | `/providers/Microsoft.Management/managementGroups/{tenantId}` |
| `managementGroupId` | Same as tenant ID |
| `displayName` | `"Tenant Root Group"` |
| `isRoot` | `true` |
| `parentId` | NULL |

**Creation:**
```go
// Always create root MG if tenant exists
rootMGResource := map[string]interface{}{
    "id": fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", tenantID),
    "resourceType": "Microsoft.Management/managementGroups",
    "displayName": "Tenant Root Group",
    "managementGroupId": tenantID,
    "tenantId": tenantID,
    "isRoot": true,
}
```

## Conditional Logic

### Parent ID Extraction

```go
// Extract parentId from nested properties.parent.name
parentId := ""
if properties, ok := mgMap["properties"].(map[string]interface{}); ok {
    if parent, ok := properties["parent"].(map[string]interface{}); ok {
        if parentName, ok := parent["name"].(string); ok {
            parentId = parentName
        }
    }
}
```

### Type Filtering

```go
// Only process management groups, skip subscriptions
mgType := strings.ToLower(getStringValue(mgMap, "type"))
if mgType != "microsoft.management/managementgroups" {
    continue // Skip subscription entries
}
```

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/mg-to-child-mg.md) - Child management groups
- [CONTAINS](../Azure_IAM_Edges/CONTAINS/mg-to-subscription.md) - Subscriptions

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/tenant-to-root-mg.md) - Parent tenant (root MG only)
- [CONTAINS](../Azure_IAM_Edges/CONTAINS/mg-to-child-mg.md) - Parent management group

## Management Group Hierarchy

Management groups form a tree structure:

```
Tenant
  └─ Tenant Root Group (isRoot=true)
       ├─ Platform MG
       │    ├─ Management Subscription
       │    └─ Connectivity Subscription
       ├─ Landing Zones MG
       │    ├─ Corp MG
       │    │    ├─ Prod Subscription
       │    │    └─ Dev Subscription
       │    └─ Online MG
       │         └─ Web Subscription
       └─ Sandbox MG
            └─ Sandbox Subscription
```

## Query Examples

### Find all management groups
```cypher
MATCH (mg:Resource:Hierarchy)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
RETURN mg.displayName, mg.managementGroupId, mg.parentId
```

### Find root management group
```cypher
MATCH (mg:Resource:Hierarchy)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND mg.isRoot = true
RETURN mg.displayName, mg.managementGroupId
```

### Find direct children of a management group
```cypher
MATCH (parent:Resource:Hierarchy)-[:CONTAINS]->(child:Resource)
WHERE toLower(parent.resourceType) = "microsoft.management/managementgroups"
  AND parent.managementGroupId = "production-mg"
RETURN child.displayName, child.resourceType
```

### Find all subscriptions under a management group (recursive)
```cypher
MATCH (mg:Resource:Hierarchy)-[:CONTAINS*]->(sub:Resource:Hierarchy)
WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND mg.managementGroupId = "landing-zones"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN sub.displayName, sub.subscriptionId
```

### Find management group depth (distance from root)
```cypher
MATCH path = (root:Resource:Hierarchy)-[:CONTAINS*]->(mg:Resource:Hierarchy)
WHERE root.isRoot = true
  AND toLower(mg.resourceType) = "microsoft.management/managementgroups"
  AND mg.managementGroupId = "production-mg"
RETURN length(path) as depth
```

## Test Cases

### Test 1: Root Management Group Creation
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "test-tenant-001"
  },
  "management_groups": []
}
```

**Expected:**
- Root MG created automatically
- `id = "/providers/Microsoft.Management/managementGroups/test-tenant-001"`
- `managementGroupId = "test-tenant-001"`
- `displayName = "Tenant Root Group"`
- `isRoot = true`
- `parentId` not set (NULL)

### Test 2: Child Management Group Creation
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/production-mg",
      "name": "production-mg",
      "type": "microsoft.management/managementgroups",
      "properties": {
        "displayName": "Production Management Group",
        "parent": {
          "name": "tenant-root-group"
        }
      }
    }
  ]
}
```

**Expected:**
- Node created with labels: `Resource:Hierarchy`
- `managementGroupId = "production-mg"`
- `displayName = "Production Management Group"`
- `parentId = "tenant-root-group"`
- `isRoot` not set (NULL or false)

### Test 3: Nested Management Groups
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/landing-zones",
      "name": "landing-zones",
      "type": "microsoft.management/managementgroups",
      "properties": {
        "displayName": "Landing Zones",
        "parent": {"name": "root"}
      }
    },
    {
      "id": "/providers/Microsoft.Management/managementGroups/corp",
      "name": "corp",
      "type": "microsoft.management/managementgroups",
      "properties": {
        "displayName": "Corp",
        "parent": {"name": "landing-zones"}
      }
    }
  ]
}
```

**Expected:**
- Two MG nodes created
- `landing-zones` has `parentId = "root"`
- `corp` has `parentId = "landing-zones"`
- MG CONTAINS edges created for parent-child relationships

### Test 4: Mixed Array (MGs and Subscriptions)
**Input:**
```json
{
  "management_groups": [
    {
      "id": "/providers/Microsoft.Management/managementGroups/mg-test",
      "name": "mg-test",
      "type": "microsoft.management/managementgroups",
      "properties": {"displayName": "Test MG"}
    },
    {
      "id": "/subscriptions/sub-guid",
      "name": "sub-guid",
      "type": "microsoft.resources/subscriptions",
      "ParentId": "/providers/Microsoft.Management/managementGroups/mg-test"
    }
  ]
}
```

**Expected:**
- Only MG node created (subscription filtered out during MG processing)
- Subscription node created separately via subscription processing
- MG CONTAINS subscription edge created via separate function

### Test 5: Idempotency
**Action:** Run import twice with same MG data

**Expected:**
- Only one node created per MG
- No duplicate nodes
- Properties unchanged on second run

### Test 6: Case Insensitive Type Matching
**Input:**
```json
{
  "management_groups": [
    {
      "type": "Microsoft.Management/managementGroups",
      "name": "case-test",
      "properties": {"displayName": "Case Test"}
    }
  ]
}
```

**Expected:**
- Node created successfully (type comparison is case-insensitive)
- `resourceType = "Microsoft.Management/managementGroups"` (preserves original casing)

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createHierarchyResources()` starting at line 805

**Batch Processing:** Management groups processed in batches of 1000

**Root MG Creation:** Created separately before processing management_groups array

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#4-management_groups-array) - JSON input format
- [Tenant Node](tenant.md) - Parent of root MG
- [Subscription Nodes](subscription.md) - Children of MGs
- [Tenant CONTAINS Root MG](../Azure_IAM_Edges/CONTAINS/tenant-to-root-mg.md) - Parent edge
- [MG CONTAINS Child MG](../Azure_IAM_Edges/CONTAINS/mg-to-child-mg.md) - Hierarchy edges
- [MG CONTAINS Subscription](../Azure_IAM_Edges/CONTAINS/mg-to-subscription.md) - Subscription edges
