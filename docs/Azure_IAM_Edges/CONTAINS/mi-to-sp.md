# Managed Identity CONTAINS Service Principal

Relationship from managed identity resources to their backing service principals.

## Edge Type

`CONTAINS`

## Direction

Managed Identity → Service Principal

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents the relationship between a managed identity (user-assigned or system-assigned) and its backing service principal. Every managed identity has a corresponding service principal that represents the identity in Entra ID.

## Source & Target Nodes

**Source:** [User-Assigned MI Node](../../Azure_IAM_Nodes/user-assigned-mi.md) or [System-Assigned MI Node](../../Azure_IAM_Nodes/system-assigned-mi.md)
- Labels: `Resource:AzureResource`
- Types:
  - `"Microsoft.ManagedIdentity/userAssignedIdentities"` (real resource)
  - `"Microsoft.ManagedIdentity/systemAssigned"` (synthetic node)
- Property: `principalId` (GUID - links to SP)

**Target:** [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/serviceprincipals"`
- Property: `id` matches MI's `principalId`
- Property: `servicePrincipalType = "ManagedIdentity"`

## Creation Logic

**Function:** `createManagedIdentityToServicePrincipalContains()` - line 1496

**Cypher:**
```cypher
MATCH (mi:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
AND mi.principalId IS NOT NULL
MATCH (sp:Resource {id: mi.principalId})
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
MERGE (mi)-[:CONTAINS]->(sp)
```

**Key Logic:**
- No explicit data extraction (graph-based matching)
- Matches MI's `principalId` to SP's `id` property
- Supports both user-assigned and system-assigned managed identities
- Pure Cypher pattern matching

## Matching Logic

### Managed Identity Matching
- Match by resourceType containing "managedidentity"
- Includes both:
  - `Microsoft.ManagedIdentity/userAssignedIdentities`
  - `Microsoft.ManagedIdentity/systemAssigned`
- Must have `principalId` property set

### Service Principal Matching
- Match by `id` equal to MI's `principalId`
- Verify resourceType = serviceprincipals
- Typically has `servicePrincipalType = "ManagedIdentity"`

### PrincipalId-Based Matching
```cypher
sp.id = mi.principalId
```

**Key Property:** `principalId` is the bridge
- Managed identity has `principalId` property (GUID)
- Service principal has `id` property (GUID)
- MI's principalId equals SP's id

## Source Data

**No explicit source data** - relationships derived from node properties

**Implicit Data:**
- User-assigned MIs created from `azure_resources` with `principalId` property
- System-assigned MIs created synthetically with `principalId` from parent resource
- Service principals created from `azure_ad` with identity markers
- Property matching connects MI to backing SP

## Conditional Logic

### Prerequisites
- Managed identity node must exist (created in Phase 1-3)
- Service principal node must exist (created in Phase 1-3)

### Filtering
- MI must have `principalId` property (not NULL)
- MI resourceType must contain "managedidentity"

### Silent Failure
If no matching SP found for MI (or vice versa), no edge created (no error logged)

## Managed Identity Types

### User-Assigned Managed Identity
```
User-Assigned MI Resource
  ├─ Azure Resource: Real ARM resource
  ├─ principalId: GUID linking to SP
  ├─ Lifecycle: Independent from resources
  └─ Service Principal
       └─ servicePrincipalType: "ManagedIdentity"
```

### System-Assigned Managed Identity
```
System-Assigned MI (Synthetic Node)
  ├─ Azure Resource: Synthetic node created by importer
  ├─ principalId: Extracted from parent resource's identity property
  ├─ Lifecycle: Bound to parent resource
  └─ Service Principal
       └─ servicePrincipalType: "ManagedIdentity"
```

**Key Characteristics:**
- **One-to-One:** Each MI has exactly one backing SP
- **Immutable Link:** MI and SP connected via immutable principalId GUID
- **No Application:** MIs don't have application registrations (unlike regular apps)

## Managed Identity vs Application SP

| Aspect | Managed Identity SP | Application SP |
|--------|---------------------|----------------|
| **Backing Resource** | Managed Identity resource | Application registration |
| **Credentials** | No secrets (Azure-managed) | Secrets/certificates managed by owner |
| **servicePrincipalType** | `"ManagedIdentity"` | `"Application"` |
| **RBAC Assignment** | Can receive RBAC roles | Can receive RBAC roles |
| **Graph Permissions** | Can receive Graph API permissions | Can receive Graph API permissions |
| **Linked via** | `principalId` property | `appId` property |
| **Example** | VM system-assigned identity | "MyApp" service principal |

## Query Examples

### Find service principal for a managed identity
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE mi.displayName = "prod-vm-01 (System-Assigned)"
  AND toLower(mi.resourceType) CONTAINS "managedidentity"
RETURN sp.displayName, sp.id, sp.servicePrincipalType
```

### Find managed identity for a service principal
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE sp.id = "sp-principal-id-guid"
  AND toLower(sp.servicePrincipalType) = "managedidentity"
RETURN mi.displayName,
       mi.resourceType,
       mi.principalId,
       mi.metadata
```

### Find all MI-SP pairs
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN mi.displayName as managed_identity,
       sp.displayName as service_principal,
       mi.principalId as shared_principal_id,
       mi.resourceType as mi_type
```

### Find system-assigned MIs and their SPs
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN mi.displayName as system_mi,
       sp.displayName as service_principal,
       mi.principalId
```

### Find user-assigned MIs and their SPs
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) = "microsoft.managedidentity/userassignedidentities"
RETURN mi.displayName as user_assigned_mi,
       sp.displayName as service_principal,
       mi.principalId
```

### Find managed identities without backing SPs (broken link)
```cypher
MATCH (mi:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
  AND mi.principalId IS NOT NULL
  AND NOT (mi)-[:CONTAINS]->(:Resource {resourceType: ~"(?i).*serviceprincipals"})
RETURN mi.displayName, mi.principalId, mi.resourceType
```

### Find permissions granted to managed identity's service principal
```cypher
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
MATCH (sp)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE mi.displayName CONTAINS "System-Assigned"
RETURN mi.displayName as managed_identity,
       perm.permission,
       perm.roleName,
       target.displayName as target
```

### Find parent resources of system-assigned MIs
```cypher
MATCH (resource:Resource)-[escalate:CAN_ESCALATE]->(mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN resource.displayName as parent_resource,
       resource.resourceType as resource_type,
       mi.displayName as system_mi,
       sp.displayName as service_principal
```

## Test Cases

### Test 1: User-Assigned MI-SP Relationship - Normal Case
**Input:**
- User-assigned MI node:
  - `displayName = "prod-uami"`
  - `principalId = "principal-guid-001"`
  - `resourceType = "Microsoft.ManagedIdentity/userAssignedIdentities"`
- Service Principal node:
  - `id = "principal-guid-001"`
  - `servicePrincipalType = "ManagedIdentity"`

**Expected:**
- CONTAINS edge: MI → Service Principal

**Verification:**
```cypher
MATCH (mi {principalId: "principal-guid-001"})-[r:CONTAINS]->(sp {id: "principal-guid-001"})
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: System-Assigned MI-SP Relationship
**Input:**
- System-assigned MI node (synthetic):
  - `displayName = "test-vm (System-Assigned)"`
  - `principalId = "system-principal-002"`
  - `resourceType = "Microsoft.ManagedIdentity/systemAssigned"`
  - `metadata = '{"assignmentType":"System-Assigned","synthetic":true}'`
- Service Principal node:
  - `id = "system-principal-002"`
  - `servicePrincipalType = "ManagedIdentity"`

**Expected:**
- CONTAINS edge: System-Assigned MI → Service Principal

### Test 3: Multiple MIs (No Cross-Links)
**Input:**
- MI A: `principalId = "principal-a"`
- MI B: `principalId = "principal-b"`
- SP A: `id = "principal-a"`
- SP B: `id = "principal-b"`

**Expected:**
- CONTAINS edge: MI A → SP A
- CONTAINS edge: MI B → SP B
- NO cross-links (MI A → SP B or MI B → SP A)

**Verification:**
```cypher
MATCH (miA {principalId: "principal-a"})-[:CONTAINS]->(spA)
MATCH (miB {principalId: "principal-b"})-[:CONTAINS]->(spB)
WHERE toLower(spA.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(spB.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN spA.id as sp_a_id,
       spB.id as sp_b_id
// Expected: sp_a_id = "principal-a", sp_b_id = "principal-b"
```

### Test 4: Idempotency
**Action:** Run import twice with same nodes

**Expected:**
- Only one edge created per MI-SP pair (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (mi {principalId: "principal-test-004"})-[r:CONTAINS]->(sp {id: "principal-test-004"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing MI Node
**Setup:** Delete MI node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for SP)
- No errors logged
- SP node unaffected

### Test 6: Missing Service Principal Node
**Setup:** Delete SP node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for MI)
- No errors logged
- MI node unaffected

### Test 7: MI Without principalId (Skip)
**Input:**
- MI node without `principalId` property

**Expected:**
- No CONTAINS edge created (filter excludes MIs without principalId)
- MI remains unlinked

### Test 8: Application SP (No MI Link)
**Input:**
- Service Principal node:
  - `servicePrincipalType = "Application"`
  - `id = "app-sp-guid"`
- No corresponding MI node

**Expected:**
- No CONTAINS edge created (application SPs link to applications, not MIs)
- App SP remains unlinked to MI

### Test 9: Case Insensitivity
**Input:**
- MI node: `resourceType = "Microsoft.ManagedIdentity/UserAssignedIdentities"`
- SP node: `resourceType = "Microsoft.DirectoryServices/ServicePrincipals"`

**Expected:**
- Case-insensitive matching succeeds
- CONTAINS edge created successfully

### Test 10: PrincipalId Mismatch (No Link)
**Input:**
- MI node: `principalId = "principal-001"`
- Service Principal node: `id = "principal-002"`

**Expected:**
- No CONTAINS edge created (principalId and SP id don't match)
- MI and SP remain unlinked

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createManagedIdentityToServicePrincipalContains()` starting at line 1496

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single transaction (graph-based pattern matching, no batching needed)

**Method:** Pure Cypher pattern matching (no Go data extraction)

**Debug Logging:** Function includes debug queries to log MI resources found

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist or IDs don't match), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Property Matching:** Relies on exact match of MI's `principalId` to SP's `id`

## Azure Behavior Notes

**Managed Identity Lifecycle:**
- System-assigned: Created/deleted with parent resource
- User-assigned: Independent lifecycle, can be assigned to multiple resources
- Both types have backing service principals in Entra ID

**Credentials:**
- Managed identities have NO user-accessible secrets
- Azure manages credentials internally
- Authentication via Azure Instance Metadata Service (IMDS) or similar mechanisms

**Service Principal Creation:**
- Creating a managed identity automatically creates backing SP
- Deleting MI deletes backing SP
- Graph import reflects current state at collection time

## Related Documentation

- [User-Assigned MI Node](../../Azure_IAM_Nodes/user-assigned-mi.md) - Source node (user-assigned)
- [System-Assigned MI Node](../../Azure_IAM_Nodes/system-assigned-mi.md) - Source node (system-assigned)
- [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md) - Target node
- [CAN_ESCALATE](../CAN_ESCALATE/) - IMDS token theft vectors
- [../overview.md](../overview.md) - Hierarchy overview
