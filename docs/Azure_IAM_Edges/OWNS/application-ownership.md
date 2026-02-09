# Application Ownership Edges

Ownership relationship from users/service principals to applications.

## Edge Type

`OWNS`

## Direction

Owner (User/Service Principal) → Application

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `source` | string | `"ApplicationOwnership"` - indicates data source |
| `createdAt` | integer | Unix timestamp when edge was created during import |

## Purpose

Represents ownership of Entra ID applications. Owners have full administrative control over the application including credential management.

## Source & Target Nodes

**Source:** [User Node](../../Azure_IAM_Nodes/user.md) or [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/users"` or `"Microsoft.DirectoryServices/serviceprincipals"`

**Target:** [Application Node](../../Azure_IAM_Nodes/application.md)
- Labels: `Resource:Identity` (NOT Principal)
- Type: `"Microsoft.DirectoryServices/applications"`

## Creation Logic

**Function:** `createApplicationOwnershipDirectEdges()` - line 3557

**Cypher:**
```cypher
UNWIND $edges AS edge
MATCH (source {id: edge.sourceId})
MATCH (target {id: edge.targetId})
WHERE toLower(target.resourceType) = "microsoft.directoryservices/applications"
MERGE (source)-[r:OWNS]->(target)
SET r.source = edge.source,
    r.createdAt = edge.createdAt
RETURN count(r) as created
```

**Batch Size:** 500 edges per transaction

## Data Extraction Logic

```go
// From applicationOwnership array
edge := map[string]interface{}{
    "sourceId":  ownerID,           // From ownerId field
    "targetId":  applicationID,      // From applicationId field
    "source":    "ApplicationOwnership",
    "createdAt": currentTime,
}
```

## Source Data

**Location:** `consolidatedData["azure_ad"]["applicationOwnership"]`

**Schema:**
```json
{
  "applicationOwnership": [
    {
      "applicationId": "app-guid-001",
      "ownerId": "owner-guid-001",
      "ownerType": "User"  // or "ServicePrincipal"
    }
  ]
}
```

**Fields:**
- `applicationId`: Target application's ID
- `ownerId`: Owner's ID (user or service principal)
- `ownerType`: Type of owner (informational, not stored on edge)

## Conditional Logic

### Prerequisites
- Owner node (user or SP) must exist (created in Phase 1-3)
- Application node must exist (created in Phase 1-3)

### Validation
- Skip if `applicationId` is empty
- Skip if `ownerId` is empty
- MATCH filters target by resourceType to ensure correct node type

### Silent Failure
If either source or target node missing, edge is not created (no error logged)

## Owner Privileges

**Application owners can:**
- ✅ Add secrets and certificates to the application
- ✅ Modify application configuration (redirect URIs, API permissions)
- ✅ Delete the application
- ✅ Assign additional owners
- ⚠️ **Privilege Escalation:** Add secret to assume application's backing service principal identity

## Escalation Scenario

```
User (Alice) -[OWNS]-> Application (MyApp)

Application (MyApp) -[CONTAINS]-> ServicePrincipal (MyApp SP)

ServicePrincipal (MyApp SP) -[HAS_PERMISSION {permission: "Global Administrator"}]-> Tenant

Attack Path:
1. Alice adds a secret to MyApp
2. Alice authenticates as MyApp SP using the secret
3. Alice gains Global Administrator via MyApp SP's permissions
```

**Impact:** Owner can escalate to any permission held by the application's service principal.

## Query Examples

### Find all application owners
```cypher
MATCH (owner:Resource)-[r:OWNS]->(app:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN owner.displayName as owner,
       owner.resourceType as owner_type,
       app.displayName as application,
       r.source as data_source
```

### Find applications with multiple owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(app:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
WITH app, count(owner) as owner_count, collect(owner.displayName) as owners
WHERE owner_count > 1
RETURN app.displayName as application,
       owner_count,
       owners
ORDER BY owner_count DESC
```

### Find applications owned by service principals (unusual)
```cypher
MATCH (sp:Resource)-[r:OWNS]->(app:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN sp.displayName as service_principal_owner,
       app.displayName as application
```

### Find escalation paths via application ownership
```cypher
MATCH (user:Resource)-[:OWNS]->(app:Resource)-[:CONTAINS]->(sp:Resource)
MATCH (sp)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(user.resourceType) = "microsoft.directoryservices/users"
  AND toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN user.displayName as owner,
       app.displayName as owned_application,
       sp.displayName as backing_sp,
       perm.permission as sp_permission,
       target.displayName as permission_target
```

## Test Cases

### Test 1: Application Ownership - Normal Case
**Input:**
```json
{
  "azure_ad": {
    "applicationOwnership": [
      {
        "applicationId": "app-test-001",
        "ownerId": "user-test-001",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- User node exists with `id = "user-test-001"`
- Application node exists with `id = "app-test-001"`
- OWNS edge created: User → Application
- Edge properties: `source = "ApplicationOwnership"`, `createdAt` set

**Verification:**
```cypher
MATCH (user {id: "user-test-001"})-[r:OWNS]->(app {id: "app-test-001"})
RETURN count(r) as edge_count,
       r.source as source,
       r.createdAt as created_at
// Expected: edge_count = 1, source = "ApplicationOwnership", created_at = timestamp
```

### Test 2: Service Principal as Owner
**Input:**
```json
{
  "azure_ad": {
    "applicationOwnership": [
      {
        "applicationId": "app-test-002",
        "ownerId": "sp-test-002",
        "ownerType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- Service Principal node exists with `id = "sp-test-002"`
- Application node exists with `id = "app-test-002"`
- OWNS edge created: SP → Application

### Test 3: Multiple Owners for Same Application
**Input:**
```json
{
  "azure_ad": {
    "applicationOwnership": [
      {
        "applicationId": "app-test-003",
        "ownerId": "user-owner-1",
        "ownerType": "User"
      },
      {
        "applicationId": "app-test-003",
        "ownerId": "user-owner-2",
        "ownerType": "User"
      },
      {
        "applicationId": "app-test-003",
        "ownerId": "sp-owner-3",
        "ownerType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- 3 OWNS edges created, all pointing to same application
- Each owner has independent OWNS relationship

**Verification:**
```cypher
MATCH (owner)-[:OWNS]->(app {id: "app-test-003"})
RETURN count(owner) as owner_count
// Expected: owner_count = 3
```

### Test 4: Idempotency
**Action:** Run import twice with same ownership data

**Expected:**
- Only one edge created per owner-application pair (MERGE ensures idempotency)
- No duplicate edges
- Properties unchanged on second run

**Verification:**
```cypher
MATCH (user {id: "user-test-004"})-[r:OWNS]->(app {id: "app-test-004"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing Owner Node
**Setup:** Delete owner node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Application node unaffected

### Test 6: Missing Application Node
**Setup:** Delete application node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Owner node unaffected

### Test 7: Empty Application ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "applicationOwnership": [
      {
        "applicationId": "",
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
    "applicationOwnership": [
      {
        "applicationId": "app-test-008",
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
**Input:** 1500 ownership entries

**Expected:**
- Processed in 3 batches (500 per batch)
- All edges created successfully
- Total count matches input count
- No memory issues

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createApplicationOwnershipDirectEdges()` starting at line 3557

**Phase:** 2e (after CONTAINS edges, before HAS_PERMISSION edges)

**Batch Processing:** 500 edges per transaction

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:** Empty IDs are filtered during data extraction (no Cypher execution attempted)

## Related Documentation

- [User Node](../../Azure_IAM_Nodes/user.md) - Source node (user owners)
- [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md) - Source node (SP owners)
- [Application Node](../../Azure_IAM_Nodes/application.md) - Target node
- [Application CONTAINS SP](../CONTAINS/application-to-sp.md) - Backing SP relationship
- [CAN_ESCALATE via Application Owner](../CAN_ESCALATE/) - Escalation analysis
- [../overview.md](../overview.md#owns-edges) - OWNS edge architecture
