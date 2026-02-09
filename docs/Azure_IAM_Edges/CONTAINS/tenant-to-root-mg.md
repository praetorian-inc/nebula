# Tenant CONTAINS Root Management Group

Relationship from Azure AD tenant to the root management group.

## Edge Type

`CONTAINS`

## Direction

Tenant → Root Management Group

## Properties

None (structural relationship only)

## Purpose

Connects the Azure AD tenant (identity root) to the root management group (resource hierarchy root).

## Source & Target Nodes

**Source:** [Tenant Node](../NODES/tenant.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.DirectoryServices/tenant"`

**Target:** [Root Management Group Node](../NODES/management-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Management/managementGroups"`
- Property: `isRoot = true`

## Creation Logic

**Function:** `createTenantToRootMGEdge()` - line 1130

**Cypher:**
```cypher
MATCH (tenant:Resource {id: toLower($tenantId)})
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
MATCH (rootMG:Resource)
WHERE toLower(rootMG.resourceType) = "microsoft.management/managementgroups"
  AND rootMG.isRoot = true
  AND rootMG.tenantId = toLower($tenantId)
MERGE (tenant)-[r:CONTAINS]->(rootMG)
RETURN count(r) as created_count
```

**Result:** Returns count of edges created (should be 1)

## Matching Logic

### Tenant Matching
- Match by tenant ID
- Verify resourceType
- Case-insensitive comparison

### Root MG Matching
- Match by `isRoot = true` property
- Verify resourceType
- Match tenantId to tenant
- Case-insensitive comparison

## Source Data

**Tenant ID:** `consolidatedData["collection_metadata"]["tenant_id"]`

**No explicit edge data** - relationship inferred from hierarchy structure

## Conditional Logic

### Prerequisites
- Tenant node must exist (created in Phase 2)
- Root MG node must exist (created in Phase 2)

### Silent Failure
If either node missing, no edge created (no error logged)

## Hierarchy Position

```
Tenant (root of all)
  └─ Root Management Group (mgId = tenantId, isRoot = true)
       ├─ Management Group A
       └─ Management Group B
```

**Key Characteristics:**
- **Single Edge:** One tenant → one root MG
- **Always Exists:** Every Azure tenant has a root MG
- **Entry Point:** Starting point for management group hierarchy traversal

## Query Examples

### Verify tenant-to-root-MG edge exists
```cypher
MATCH (tenant:Resource)-[r:CONTAINS]->(rootMG:Resource)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
  AND rootMG.isRoot = true
RETURN tenant.displayName, rootMG.displayName
```

### Find root MG from tenant
```cypher
MATCH (tenant:Resource {tenantId: $tenantId})-[:CONTAINS]->(rootMG:Resource)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
RETURN rootMG.displayName, rootMG.managementGroupId
```

### Traverse from tenant to all MGs
```cypher
MATCH (tenant:Resource)-[:CONTAINS*]->(mg:Resource)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
  AND toLower(mg.resourceType) = "microsoft.management/managementgroups"
RETURN count(mg) as total_management_groups
```

## Test Cases

### Test 1: Edge Creation - Normal Case
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "test-tenant-001"
  }
}
```

**Expected:**
- Tenant node created with `id = "test-tenant-001"`
- Root MG created with `managementGroupId = "test-tenant-001"`, `isRoot = true`
- CONTAINS edge: Tenant → Root MG

**Verification:**
```cypher
MATCH (tenant {id: "test-tenant-001"})-[r:CONTAINS]->(rootMG {isRoot: true})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Idempotency
**Action:** Run import twice with same tenant data

**Expected:**
- Only one edge created (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (tenant {id: "test-tenant-002"})-[r:CONTAINS]->(rootMG {isRoot: true})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 3: Missing Tenant Node
**Setup:** Delete tenant node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged

### Test 4: Missing Root MG Node
**Setup:** Delete root MG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged

### Test 5: Case Insensitive Matching
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "TENANT-TEST-005-UPPER"
  }
}
```

**Expected:**
- Tenant ID normalized to lowercase
- Edge created successfully despite case differences
- Matching uses `toLower()` for case-insensitive comparison

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createTenantToRootMGEdge()` starting at line 1130

**Phase:** 2a (after node creation)

**Batch Processing:** Single edge (not batched)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

## Related Documentation

- [Tenant Node](../NODES/tenant.md) - Source node
- [Management Group Node](../NODES/management-group.md) - Target node (root MG)
- [MG CONTAINS Child MG](mg-to-child-mg.md) - Next level in hierarchy
- [MG CONTAINS Subscription](mg-to-subscription.md) - Subscription attachment
- [../overview.md](../overview.md) - Hierarchy overview
