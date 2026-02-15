# Service Principal Ownership Edges

Ownership relationship from users/service principals to service principals.

## Edge Type

`OWNS`

## Direction

Owner (User/Service Principal) → Service Principal

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `source` | string | `"ServicePrincipalOwnership"` - indicates data source |
| `createdAt` | integer | Unix timestamp when edge was created during import |

## Purpose

Represents ownership of Entra ID service principals. Owners have administrative control over the SP including credential management (if not locked by policy).

## Source & Target Nodes

**Source:** [User Node](../../Azure_IAM_Nodes/user.md) or [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/users"` or `"Microsoft.DirectoryServices/serviceprincipals"`

**Target:** [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/serviceprincipals"`

## Creation Logic

**Function:** `createServicePrincipalOwnershipDirectEdges()` - line 3730

**Cypher:**
```cypher
UNWIND $edges AS edge
MATCH (source {id: edge.sourceId})
MATCH (target {id: edge.targetId})
WHERE toLower(target.resourceType) = "microsoft.directoryservices/serviceprincipals"
MERGE (source)-[r:OWNS]->(target)
SET r.source = edge.source,
    r.createdAt = edge.createdAt
RETURN count(r) as created
```

**Batch Size:** 1000 edges per transaction

## Data Extraction Logic

```go
// From servicePrincipalOwnership array
edge := map[string]interface{}{
    "sourceId":  ownerID,                   // From ownerId field
    "targetId":  servicePrincipalID,        // From servicePrincipalId field
    "source":    "ServicePrincipalOwnership",
    "createdAt": currentTime,
}
```

## Source Data

**Location:** `consolidatedData["azure_ad"]["servicePrincipalOwnership"]`

**Schema:**
```json
{
  "servicePrincipalOwnership": [
    {
      "servicePrincipalId": "sp-guid-001",
      "ownerId": "owner-guid-001",
      "ownerType": "User"  // or "ServicePrincipal"
    }
  ]
}
```

**Fields:**
- `servicePrincipalId`: Target service principal's ID
- `ownerId`: Owner's ID (user or service principal)
- `ownerType`: Type of owner (informational, not stored on edge)

## Conditional Logic

### Prerequisites
- Owner node (user or SP) must exist (created in Phase 1-3)
- Service principal node must exist (created in Phase 1-3)

### Validation
- Skip if `servicePrincipalId` is empty
- Skip if `ownerId` is empty
- MATCH filters target by resourceType to ensure correct node type

### Silent Failure
If either source or target node missing, edge is not created (no error logged)

## Owner Privileges

**Service principal owners can:**
- ✅ Add secrets and certificates (if not locked by policy)
- ✅ Modify service principal properties
- ✅ Delete the service principal
- ✅ Assign additional owners
- ⚠️ **Privilege Escalation:** Add secret to assume SP identity and gain its permissions

**Important:** Some service principals (especially managed identities and first-party SPs) may have credential management locked by organizational policy.

## Escalation Scenario

```
User (Alice) -[OWNS]-> ServicePrincipal (MyApp-SP)

ServicePrincipal (MyApp-SP) -[HAS_PERMISSION {permission: "User.ReadWrite.All"}]-> Tenant

Attack Path:
1. Alice adds a secret to MyApp-SP
2. Alice authenticates as MyApp-SP using the secret
3. Alice gains User.ReadWrite.All permission via SP identity
```

**Impact:** Owner can escalate to any permission held by the service principal.

## SP Types and Ownership

| SP Type | Ownership Common? | Credential Control | Escalation Risk |
|---------|-------------------|-------------------|-----------------|
| **Application** | Yes | Usually allowed | High (if SP has privileges) |
| **ManagedIdentity** | Rare | Usually locked | Medium (policy-dependent) |
| **Legacy** | Rare | Varies | Low (usually limited permissions) |

## Query Examples

### Find all service principal owners
```cypher
MATCH (owner:Resource)-[r:OWNS]->(sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN owner.displayName as owner,
       owner.resourceType as owner_type,
       sp.displayName as service_principal,
       sp.servicePrincipalType as sp_type,
       r.source as data_source
```

### Find service principals with multiple owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
WITH sp, count(owner) as owner_count, collect(owner.displayName) as owners
WHERE owner_count > 1
RETURN sp.displayName as service_principal,
       sp.servicePrincipalType as sp_type,
       owner_count,
       owners
ORDER BY owner_count DESC
```

### Find privileged SPs with owners (escalation risk)
```cypher
MATCH (owner:Resource)-[:OWNS]->(sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND (
    toLower(perm.permission) CONTAINS "readwrite" OR
    toLower(perm.roleName) CONTAINS "administrator"
  )
RETURN owner.displayName as owner,
       sp.displayName as privileged_sp,
       perm.permission as permission,
       perm.roleName as role,
       target.displayName as target
```

### Find service principals owned by other SPs (rare)
```cypher
MATCH (ownerSP:Resource)-[r:OWNS]->(targetSP:Resource)
WHERE toLower(ownerSP.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(targetSP.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN ownerSP.displayName as owner_sp,
       targetSP.displayName as owned_sp,
       targetSP.servicePrincipalType as owned_sp_type
```

### Find application SPs with owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(sp.servicePrincipalType) = "application"
RETURN owner.displayName as owner,
       owner.resourceType as owner_type,
       sp.displayName as application_sp,
       sp.appId as app_id
```

### Find managed identity SPs with owners (unusual)
```cypher
MATCH (owner:Resource)-[:OWNS]->(sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(sp.servicePrincipalType) = "managedidentity"
RETURN owner.displayName as owner,
       sp.displayName as managed_identity_sp,
       sp.id as sp_id
```

## Test Cases

### Test 1: SP Ownership - Normal Case
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "sp-test-001",
        "ownerId": "user-test-001",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- User node exists with `id = "user-test-001"`
- Service Principal node exists with `id = "sp-test-001"`
- OWNS edge created: User → Service Principal
- Edge properties: `source = "ServicePrincipalOwnership"`, `createdAt` set

**Verification:**
```cypher
MATCH (user {id: "user-test-001"})-[r:OWNS]->(sp {id: "sp-test-001"})
RETURN count(r) as edge_count,
       r.source as source,
       r.createdAt as created_at
// Expected: edge_count = 1, source = "ServicePrincipalOwnership", created_at = timestamp
```

### Test 2: Service Principal as Owner (Rare)
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "sp-target",
        "ownerId": "sp-owner",
        "ownerType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- Owner SP node exists with `id = "sp-owner"`
- Target SP node exists with `id = "sp-target"`
- OWNS edge created: SP → SP

### Test 3: Multiple Owners for Same SP
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "sp-test-003",
        "ownerId": "user-owner-1",
        "ownerType": "User"
      },
      {
        "servicePrincipalId": "sp-test-003",
        "ownerId": "user-owner-2",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- 2 OWNS edges created, both pointing to same SP
- Each owner has independent OWNS relationship

**Verification:**
```cypher
MATCH (owner)-[:OWNS]->(sp {id: "sp-test-003"})
RETURN count(owner) as owner_count
// Expected: owner_count = 2
```

### Test 4: Idempotency
**Action:** Run import twice with same ownership data

**Expected:**
- Only one edge created per owner-SP pair (MERGE ensures idempotency)
- No duplicate edges
- Properties unchanged on second run

**Verification:**
```cypher
MATCH (user {id: "user-test-004"})-[r:OWNS]->(sp {id: "sp-test-004"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing Owner Node
**Setup:** Delete owner node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- SP node unaffected

### Test 6: Missing SP Node
**Setup:** Delete SP node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Owner node unaffected

### Test 7: Empty SP ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "",
        "ownerId": "user-test-007",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- Edge skipped during data extraction
- No edge created
- No errors

### Test 8: Empty Owner ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "sp-test-008",
        "ownerId": "",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- Edge skipped during data extraction
- No edge created
- No errors

### Test 9: Batch Processing (Large Dataset)
**Input:** 3000 ownership entries

**Expected:**
- Processed in 3 batches (1000 per batch)
- All edges created successfully
- Total count matches input count
- No memory issues

### Test 10: Privileged SP Ownership (Escalation Risk)
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipalOwnership": [
      {
        "servicePrincipalId": "high-priv-sp",
        "ownerId": "low-priv-user",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- OWNS edge: low-priv-user → high-priv-sp
- If high-priv-sp has dangerous permissions, CAN_ESCALATE edge created in Phase 5

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createServicePrincipalOwnershipDirectEdges()` starting at line 3730

**Phase:** 2e (after CONTAINS edges, before HAS_PERMISSION edges)

**Batch Processing:** 1000 edges per transaction

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:** Empty IDs are filtered during data extraction (no Cypher execution attempted)

## Policy Considerations

**Credential Management Locks:**
- Some organizations lock credential management on service principals
- Managed identity SPs often have credentials locked
- First-party Microsoft SPs typically have credentials locked
- Policy locks are NOT reflected in graph data (requires runtime testing)

**Ownership Implications:**
- Ownership doesn't guarantee credential add capability
- Escalation risk depends on both ownership AND policy settings
- CAN_ESCALATE edges assume credential add is possible

## Related Documentation

- [User Node](../../Azure_IAM_Nodes/user.md) - Source node (user owners)
- [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md) - Source and target node
- [Application CONTAINS SP](../CONTAINS/application-to-sp.md) - Application relationship
- [MI CONTAINS SP](../CONTAINS/mi-to-sp.md) - Managed identity relationship
- [CAN_ESCALATE via SP Owner](../CAN_ESCALATE/) - Escalation analysis
- [../overview.md](../overview.md#owns-edges) - OWNS edge architecture
