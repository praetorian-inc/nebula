# Application CONTAINS Service Principal

Relationship from Entra ID applications to their backing service principals.

## Edge Type

`CONTAINS`

## Direction

Application → Service Principal

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents the relationship between an Entra ID application registration and its backing service principal. Every application has a corresponding service principal that represents the application's identity in the directory.

## Source & Target Nodes

**Source:** [Application Node](../NODES/application.md)
- Labels: `Resource:Identity` (NOT Principal - applications cannot receive permissions directly)
- Type: `"Microsoft.DirectoryServices/applications"`
- Property: `appId` (GUID)

**Target:** [Service Principal Node](../NODES/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/serviceprincipals"`
- Property: `appId` (GUID - matches application's appId)

## Creation Logic

**Function:** `createApplicationToServicePrincipalContains()` - line 1629

**Cypher:**
```cypher
MATCH (app:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
MATCH (sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
AND app.appId = sp.appId
MERGE (app)-[:CONTAINS]->(sp)
```

**Key Logic:**
- No explicit data extraction (graph-based matching)
- Matches by `appId` property (shared between application and SP)
- Pure Cypher pattern matching

## Matching Logic

### Application Matching
- Match all application nodes by resourceType
- Case-insensitive comparison

### Service Principal Matching
- Match all service principal nodes by resourceType
- Filter by matching `appId` property
- Case-insensitive comparison

### AppId-Based Matching
```cypher
app.appId = sp.appId
```

**Key Property:** `appId` is the shared identifier linking application to SP
- Application has `appId` property
- Service principal has `appId` property
- Both IDs are identical GUIDs

## Source Data

**No explicit source data** - relationships derived from node properties

**Implicit Data:**
- Applications created with `appId` property
- Service principals created with `appId` property
- Property matching connects application to backing SP

## Conditional Logic

### Prerequisites
- Application node must exist (created in Phase 1-3)
- Service principal node must exist (created in Phase 1-3)

### Property Matching
- Application and SP must have matching `appId` values
- No type filtering beyond resourceType

### Silent Failure
If no matching SP found for application (or vice versa), no edge created (no error logged)

## Application vs Service Principal

| Aspect | Application | Service Principal |
|--------|-------------|-------------------|
| **Purpose** | Registration/definition | Runtime identity |
| **Location** | Home tenant only | Created in each tenant where app is used |
| **Permissions** | Requested permissions | Granted permissions (via consent) |
| **Principal** | NOT a principal (cannot receive permissions) | IS a principal (can receive permissions) |
| **Labels** | `Resource:Identity` | `Resource:Identity:Principal` |
| **Credentials** | Manages secrets/certificates | Uses credentials to authenticate |
| **RBAC** | Cannot be assigned RBAC roles directly | Can be assigned RBAC roles |
| **Example** | "MyApp" application registration | "MyApp" service principal |

## Relationship Semantics

```
Application (MyApp)
  └─ Service Principal (MyApp SP)
       └─ Receives permissions via HAS_PERMISSION edges
```

**Key Characteristics:**
- **One-to-One:** Each application has exactly one backing SP in its home tenant
- **Multi-Tenant:** Multi-tenant apps have one application + one SP per tenant where installed
- **Immutable Link:** Application and SP connected via immutable `appId` GUID

## Permission Model

**Applications cannot receive permissions directly:**
```cypher
// ❌ INVALID: Application as permission target
(actor)-[HAS_PERMISSION]->(application)  // Applications don't receive permissions

// ✅ VALID: Service Principal as permission target
(actor)-[HAS_PERMISSION]->(servicePrincipal)  // SPs receive permissions
```

**Why the distinction matters:**
- Applications are *definitions* (what permissions the app needs)
- Service principals are *identities* (what permissions are actually granted)
- Permissions flow to SPs, not applications

## Query Examples

### Find service principal for an application
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
WHERE app.displayName = "MyApp"
  AND toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN sp.displayName, sp.appId, sp.servicePrincipalType
```

### Find application for a service principal
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
WHERE sp.displayName = "MyApp"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN app.displayName, app.appId
```

### Find all application-SP pairs
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN app.displayName as application,
       sp.displayName as service_principal,
       app.appId as shared_app_id
```

### Find applications without backing SPs (incomplete registration)
```cypher
MATCH (app:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND NOT (app)-[:CONTAINS]->(:Resource {resourceType: ~"(?i).*serviceprincipals"})
RETURN app.displayName, app.appId
```

### Find service principals without parent applications
```cypher
MATCH (sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND NOT (:Resource)-[:CONTAINS]->(sp)
  AND toLower(sp.servicePrincipalType) = "application"
RETURN sp.displayName, sp.appId, sp.servicePrincipalType
```

### Find permissions granted to application's service principal
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
MATCH (sp)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE app.displayName = "MyApp"
RETURN perm.permission,
       perm.permissionType,
       target.displayName as target
```

### Find owners who can modify application (and thus control SP)
```cypher
MATCH (owner:Resource)-[:OWNS]->(app:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN owner.displayName as owner,
       app.displayName as application,
       sp.displayName as service_principal
```

## Test Cases

### Test 1: Application-SP Relationship - Normal Case
**Input:**
- Application node:
  - `displayName = "MyApp"`
  - `appId = "app-guid-001"`
- Service Principal node:
  - `displayName = "MyApp"`
  - `appId = "app-guid-001"`

**Expected:**
- CONTAINS edge: Application → Service Principal

**Verification:**
```cypher
MATCH (app {appId: "app-guid-001"})-[r:CONTAINS]->(sp {appId: "app-guid-001"})
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Multiple Applications (No Cross-Links)
**Input:**
- App A: `appId = "app-a"`
- App B: `appId = "app-b"`
- SP A: `appId = "app-a"`
- SP B: `appId = "app-b"`

**Expected:**
- CONTAINS edge: App A → SP A
- CONTAINS edge: App B → SP B
- NO cross-links (App A → SP B or App B → SP A)

**Verification:**
```cypher
MATCH (appA {appId: "app-a"})-[:CONTAINS]->(spA)
MATCH (appB {appId: "app-b"})-[:CONTAINS]->(spB)
WHERE toLower(spA.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(spB.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN spA.appId as sp_a_appid,
       spB.appId as sp_b_appid
// Expected: sp_a_appid = "app-a", sp_b_appid = "app-b"
```

### Test 3: Idempotency
**Action:** Run import twice with same nodes

**Expected:**
- Only one edge created per application-SP pair (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (app {appId: "app-test-003"})-[r:CONTAINS]->(sp {appId: "app-test-003"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 4: Missing Application Node
**Setup:** Delete application node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for SP)
- No errors logged
- SP node unaffected

### Test 5: Missing Service Principal Node
**Setup:** Delete SP node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for application)
- No errors logged
- Application node unaffected

### Test 6: Managed Identity SP (No Application Link)
**Input:**
- Service Principal node:
  - `servicePrincipalType = "ManagedIdentity"`
  - `appId = "mi-app-id"`
- No corresponding application node

**Expected:**
- No CONTAINS edge created (managed identities don't have application registrations)
- MI SP remains unlinked to application

**Note:** Managed identities have SPs but no application registrations, so this is expected.

### Test 7: First-Party Microsoft SP (No Application Access)
**Input:**
- Service Principal node:
  - `appId = "00000003-0000-0000-c000-000000000000"` (Microsoft Graph)
- No corresponding application node (first-party app)

**Expected:**
- No CONTAINS edge created (no application node in collected data)
- First-party SPs exist without user-accessible application registrations

### Test 8: Case Insensitivity
**Input:**
- Application node: `resourceType = "Microsoft.DirectoryServices/Applications"`
- SP node: `resourceType = "Microsoft.DirectoryServices/ServicePrincipals"`

**Expected:**
- Case-insensitive matching succeeds
- CONTAINS edge created successfully

### Test 9: AppId Mismatch (No Link)
**Input:**
- Application node: `appId = "app-001"`
- Service Principal node: `appId = "app-002"`

**Expected:**
- No CONTAINS edge created (appId values don't match)
- Application and SP remain unlinked

### Test 10: Graph-Based Matching (No Source Data)
**Verification:**
- No explicit relationship data in consolidatedData
- All edges derived from node `appId` properties
- Works correctly even with empty input data (as long as nodes exist with matching appIds)

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createApplicationToServicePrincipalContains()` starting at line 1629

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single transaction (graph-based pattern matching, no batching needed)

**Method:** Pure Cypher pattern matching (no Go data extraction)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist or appIds don't match), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Property Matching:** Relies on exact match of `appId` property between application and SP

## Azure Behavior Notes

**Application Registration:**
- Creating an application automatically creates a backing SP in home tenant
- Application registration defines app properties, requested permissions
- Service principal represents the app's identity and granted permissions

**Multi-Tenant Applications:**
- One application registration in publisher tenant
- One service principal in each tenant where app is installed
- Each SP in other tenants links to the same appId

**Deletion Behavior:**
- Deleting application typically deletes backing SP
- Deleting SP doesn't delete application registration
- Graph import reflects current state at collection time

## Related Documentation

- [Application Node](../NODES/application.md) - Source node
- [Service Principal Node](../NODES/service-principal.md) - Target node
- [OWNS Application](../OWNS/application-ownership.md) - Application ownership
- [CAN_ESCALATE](../CAN_ESCALATE/) - Application owner escalation vectors
- [../overview.md](../overview.md) - Hierarchy overview
