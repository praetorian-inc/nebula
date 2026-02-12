# Group Ownership Edges

Ownership relationship from users/service principals to groups.

## Edge Type

`OWNS`

## Direction

Owner (User/Service Principal) → Group

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `source` | string | `"GroupOwnership"` - indicates data source |
| `createdAt` | integer | Unix timestamp when edge was created during import |

## Purpose

Represents ownership of Entra ID groups. Owners have administrative control over the group including membership management.

## Source & Target Nodes

**Source:** [User Node](../../Azure_IAM_Nodes/user.md) or [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/users"` or `"Microsoft.DirectoryServices/serviceprincipals"`

**Target:** [Group Node](../../Azure_IAM_Nodes/group.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/groups"`

## Creation Logic

**Function:** `createGroupOwnershipDirectEdges()` - line 3643

**Cypher:**
```cypher
UNWIND $edges AS edge
MATCH (source {id: edge.sourceId})
MATCH (target {id: edge.targetId})
WHERE toLower(target.resourceType) = "microsoft.directoryservices/groups"
MERGE (source)-[r:OWNS]->(target)
SET r.source = edge.source,
    r.createdAt = edge.createdAt
RETURN count(r) as created
```

**Batch Size:** 1000 edges per transaction

## Data Extraction Logic

```go
// From groupOwnership array
edge := map[string]interface{}{
    "sourceId":  ownerID,           // From ownerId field
    "targetId":  groupID,            // From groupId field
    "source":    "GroupOwnership",
    "createdAt": currentTime,
}
```

## Source Data

**Location:** `consolidatedData["azure_ad"]["groupOwnership"]`

**Schema:**
```json
{
  "groupOwnership": [
    {
      "groupId": "group-guid-001",
      "ownerId": "owner-guid-001",
      "ownerType": "User"  // or "ServicePrincipal"
    }
  ]
}
```

**Fields:**
- `groupId`: Target group's ID
- `ownerId`: Owner's ID (user or service principal)
- `ownerType`: Type of owner (informational, not stored on edge)

## Conditional Logic

### Prerequisites
- Owner node (user or SP) must exist (created in Phase 1-3)
- Group node must exist (created in Phase 1-3)

### Validation
- Skip if `groupId` is empty
- Skip if `ownerId` is empty
- MATCH filters target by resourceType to ensure correct node type

### Silent Failure
If either source or target node missing, edge is not created (no error logged)

## Owner Privileges

**Group owners can:**
- ✅ Add and remove group members
- ✅ Modify group properties (displayName, description)
- ✅ Delete the group
- ✅ Assign additional owners
- ⚠️ **Privilege Escalation:** Add self or others to privileged groups to inherit permissions

## Escalation Scenario

```
User (Alice) -[OWNS]-> Group (Global Admins)

Group (Global Admins) -[HAS_PERMISSION {roleName: "Global Administrator"}]-> Tenant

Attack Path:
1. Alice adds herself to Global Admins group
2. Alice gains Global Administrator via group membership
```

**Impact:** Owner can escalate to any permission held by group members or assigned to the group.

## Query Examples

### Find all group owners
```cypher
MATCH (owner:Resource)-[r:OWNS]->(group:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN owner.displayName as owner,
       owner.resourceType as owner_type,
       group.displayName as group,
       r.source as data_source
```

### Find groups with multiple owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(group:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
WITH group, count(owner) as owner_count, collect(owner.displayName) as owners
WHERE owner_count > 1
RETURN group.displayName as group,
       owner_count,
       owners
ORDER BY owner_count DESC
```

### Find privileged groups with owners (escalation risk)
```cypher
MATCH (owner:Resource)-[:OWNS]->(group:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
  AND toLower(perm.roleName) CONTAINS "administrator"
RETURN owner.displayName as owner,
       group.displayName as privileged_group,
       perm.roleName as role,
       target.displayName as target
```

### Find groups owned by service principals (unusual)
```cypher
MATCH (sp:Resource)-[r:OWNS]->(group:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN sp.displayName as service_principal_owner,
       group.displayName as group
```

### Find security-enabled groups with owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(group:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
  AND group.securityEnabled = true
RETURN owner.displayName as owner,
       group.displayName as security_group,
       group.mailEnabled as mail_enabled
```

## Test Cases

### Test 1: Group Ownership - Normal Case
**Input:**
```json
{
  "azure_ad": {
    "groupOwnership": [
      {
        "groupId": "group-test-001",
        "ownerId": "user-test-001",
        "ownerType": "User"
      }
    ]
  }
}
```

**Expected:**
- User node exists with `id = "user-test-001"`
- Group node exists with `id = "group-test-001"`
- OWNS edge created: User → Group
- Edge properties: `source = "GroupOwnership"`, `createdAt` set

**Verification:**
```cypher
MATCH (user {id: "user-test-001"})-[r:OWNS]->(group {id: "group-test-001"})
RETURN count(r) as edge_count,
       r.source as source,
       r.createdAt as created_at
// Expected: edge_count = 1, source = "GroupOwnership", created_at = timestamp
```

### Test 2: Service Principal as Owner
**Input:**
```json
{
  "azure_ad": {
    "groupOwnership": [
      {
        "groupId": "group-test-002",
        "ownerId": "sp-test-002",
        "ownerType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- Service Principal node exists with `id = "sp-test-002"`
- Group node exists with `id = "group-test-002"`
- OWNS edge created: SP → Group

### Test 3: Multiple Owners for Same Group
**Input:**
```json
{
  "azure_ad": {
    "groupOwnership": [
      {
        "groupId": "group-test-003",
        "ownerId": "user-owner-1",
        "ownerType": "User"
      },
      {
        "groupId": "group-test-003",
        "ownerId": "user-owner-2",
        "ownerType": "User"
      },
      {
        "groupId": "group-test-003",
        "ownerId": "sp-owner-3",
        "ownerType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- 3 OWNS edges created, all pointing to same group
- Each owner has independent OWNS relationship

**Verification:**
```cypher
MATCH (owner)-[:OWNS]->(group {id: "group-test-003"})
RETURN count(owner) as owner_count
// Expected: owner_count = 3
```

### Test 4: Idempotency
**Action:** Run import twice with same ownership data

**Expected:**
- Only one edge created per owner-group pair (MERGE ensures idempotency)
- No duplicate edges
- Properties unchanged on second run

**Verification:**
```cypher
MATCH (user {id: "user-test-004"})-[r:OWNS]->(group {id: "group-test-004"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing Owner Node
**Setup:** Delete owner node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Group node unaffected

### Test 6: Missing Group Node
**Setup:** Delete group node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Owner node unaffected

### Test 7: Empty Group ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "groupOwnership": [
      {
        "groupId": "",
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
    "groupOwnership": [
      {
        "groupId": "group-test-008",
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

### Test 10: Privileged Group Ownership (Escalation Risk)
**Input:**
```json
{
  "azure_ad": {
    "groupOwnership": [
      {
        "groupId": "global-admins-group",
        "ownerId": "low-priv-user",
        "ownerType": "User"
      }
    ],
    "directoryRoleAssignments": [
      {
        "principalId": "global-admins-group",
        "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
        "roleName": "Global Administrator"
      }
    ]
  }
}
```

**Expected:**
- OWNS edge: low-priv-user → global-admins-group
- HAS_PERMISSION edge: global-admins-group → Tenant
- CAN_ESCALATE edge created in Phase 5 for escalation path

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createGroupOwnershipDirectEdges()` starting at line 3643

**Phase:** 2e (after CONTAINS edges, before HAS_PERMISSION edges)

**Batch Processing:** 1000 edges per transaction

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:** Empty IDs are filtered during data extraction (no Cypher execution attempted)

## Related Documentation

- [User Node](../../Azure_IAM_Nodes/user.md) - Source node (user owners)
- [Service Principal Node](../../Azure_IAM_Nodes/service-principal.md) - Source node (SP owners)
- [Group Node](../../Azure_IAM_Nodes/group.md) - Target node
- [Group CONTAINS Member](../CONTAINS/group-to-member.md) - Membership relationship
- [CAN_ESCALATE via Group Owner](../CAN_ESCALATE/) - Escalation analysis
- [../overview.md](../overview.md#owns-edges) - OWNS edge architecture
