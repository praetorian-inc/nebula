# Group CONTAINS Members

Membership relationship from Entra ID groups to their members.

## Edge Type

`CONTAINS`

## Direction

Group → Member (User/Group/Service Principal)

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents group membership in Entra ID (Azure AD). Groups can contain users, service principals, and other groups (nested groups), enabling transitive permission inheritance.

## Source & Target Nodes

**Source:** [Group Node](../NODES/group.md)
- Labels: `Resource:Identity:Principal`
- Type: `"Microsoft.DirectoryServices/groups"`

**Target:** [User Node](../NODES/user.md), [Group Node](../NODES/group.md), or [Service Principal Node](../NODES/service-principal.md)
- Labels: `Resource:Identity:Principal`
- Types:
  - `"Microsoft.DirectoryServices/users"`
  - `"Microsoft.DirectoryServices/groups"`
  - `"Microsoft.DirectoryServices/serviceprincipals"`

## Creation Logic

**Function:** `createGroupMemberContains()` - line 1566

**Data Extraction:**
```go
// Extract group memberships from azure_ad
for _, membership := range groupMemberships {
    groupId := getStringValue(membershipMap, "groupId")
    memberId := getStringValue(membershipMap, "memberId")

    if groupId != "" && memberId != "" {
        relationships = append(relationships, map[string]interface{}{
            "groupId":  groupId,
            "memberId": memberId,
        })
    }
}
```

**Cypher:**
```cypher
UNWIND $relationships AS rel
MATCH (group:Resource {id: rel.groupId})
MATCH (member:Resource {id: rel.memberId})
MERGE (group)-[:CONTAINS]->(member)
```

**Batch Processing:** Single batch (all relationships in one transaction)

## Matching Logic

### Group Matching
- Match by ID
- No type filtering (assumed to be group by data source)

### Member Matching
- Match by ID
- No type filtering (member can be user, group, or SP)

### Flexible Member Types
The CONTAINS edge supports three member types without explicit filtering:
- **Users:** Direct membership
- **Service Principals:** Direct membership
- **Groups:** Nested group membership (enables transitive permissions)

## Source Data

**Location:** `consolidatedData["azure_ad"]["groupMemberships"]`

**Schema:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-guid-001",
        "memberId": "user-guid-001",
        "memberType": "User"
      },
      {
        "groupId": "group-guid-001",
        "memberId": "sp-guid-001",
        "memberType": "ServicePrincipal"
      },
      {
        "groupId": "group-guid-001",
        "memberId": "nested-group-guid-001",
        "memberType": "Group"
      }
    ]
  }
}
```

**Fields:**
- `groupId`: Parent group's ID (GUID)
- `memberId`: Member's ID (GUID - user, SP, or group)
- `memberType`: Type of member (informational, not used in Cypher)

## Conditional Logic

### Prerequisites
- Group node must exist (created in Phase 1-3)
- Member node must exist (created in Phase 1-3)

### Validation
- Skip if `groupId` is empty
- Skip if `memberId` is empty

### Silent Failure
If either group or member node missing, edge is not created (no error logged)

## Membership Patterns

### Direct Membership
```
Group A
  ├─ User 1 (direct member)
  ├─ User 2 (direct member)
  └─ Service Principal 1 (direct member)
```

### Nested Groups
```
Group A (parent)
  └─ Group B (nested member)
       ├─ User 1 (transitive member of Group A)
       └─ User 2 (transitive member of Group A)
```

### Complex Hierarchies
```
Global Admins
  ├─ User (Alice) - direct member
  └─ IT Admins (nested group)
       ├─ User (Bob) - transitive member of Global Admins
       └─ Service Principal (Automation SP) - transitive member
```

**Key Characteristics:**
- **Transitive Permissions:** Nested groups inherit parent group's permissions
- **Multiple Membership:** Members can belong to multiple groups
- **Circular Prevention:** Azure prevents circular group memberships

## Transitive Permission Inheritance

Group membership enables transitive permission inheritance:

```cypher
// Direct permission via group
User -[CONTAINS]- Group -[HAS_PERMISSION]-> Tenant
// Result: User inherits Group's permissions

// Nested group transitive permission
User -[CONTAINS]- NestedGroup -[CONTAINS]- ParentGroup -[HAS_PERMISSION]-> Tenant
// Result: User inherits ParentGroup's permissions through NestedGroup
```

**See [HAS_PERMISSION](../HAS_PERMISSION/) for permission materialization logic.**

## Query Examples

### Find all members of a group
```cypher
MATCH (group:Resource)-[:CONTAINS]->(member:Resource)
WHERE group.displayName = "Global Admins"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN member.displayName,
       member.resourceType,
       member.userPrincipalName
```

### Find all groups a user belongs to (direct membership)
```cypher
MATCH (group:Resource)-[:CONTAINS]->(user:Resource)
WHERE user.userPrincipalName = "alice@contoso.com"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN group.displayName, group.id
```

### Find all groups a user belongs to (transitive via nested groups)
```cypher
MATCH (group:Resource)-[:CONTAINS*]->(user:Resource)
WHERE user.userPrincipalName = "alice@contoso.com"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN group.displayName, length(path) as depth
```

### Find nested groups (groups containing other groups)
```cypher
MATCH (parentGroup:Resource)-[:CONTAINS]->(nestedGroup:Resource)
WHERE toLower(parentGroup.resourceType) = "microsoft.directoryservices/groups"
  AND toLower(nestedGroup.resourceType) = "microsoft.directoryservices/groups"
RETURN parentGroup.displayName as parent,
       nestedGroup.displayName as nested
```

### Count members per group
```cypher
MATCH (group:Resource)-[:CONTAINS]->(member:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN group.displayName,
       count(member) as member_count,
       collect(DISTINCT member.resourceType) as member_types
ORDER BY member_count DESC
```

### Find service principals in groups
```cypher
MATCH (group:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND toLower(group.resourceType) = "microsoft.directoryservices/groups"
RETURN group.displayName as group,
       sp.displayName as service_principal,
       sp.servicePrincipalType
```

### Find users with transitive admin access via nested groups
```cypher
MATCH (group:Resource)-[:CONTAINS*]->(user:Resource)
MATCH (group)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(user.resourceType) = "microsoft.directoryservices/users"
  AND toLower(perm.roleName) CONTAINS "administrator"
RETURN user.displayName,
       group.displayName as admin_group,
       perm.roleName,
       length(path) as nesting_depth
```

### Find empty groups (no members)
```cypher
MATCH (group:Resource)
WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
  AND NOT (group)-[:CONTAINS]->(:Resource)
RETURN group.displayName, group.id
```

## Test Cases

### Test 1: User Membership - Normal Case
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-test-001",
        "memberId": "user-test-001",
        "memberType": "User"
      }
    ]
  }
}
```

**Expected:**
- Group node exists with `id = "group-test-001"`
- User node exists with `id = "user-test-001"`
- CONTAINS edge: Group → User

**Verification:**
```cypher
MATCH (group {id: "group-test-001"})-[r:CONTAINS]->(user {id: "user-test-001"})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Service Principal Membership
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-test-002",
        "memberId": "sp-test-002",
        "memberType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- CONTAINS edge: Group → Service Principal

### Test 3: Nested Group Membership
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "parent-group",
        "memberId": "nested-group",
        "memberType": "Group"
      },
      {
        "groupId": "nested-group",
        "memberId": "user-test-003",
        "memberType": "User"
      }
    ]
  }
}
```

**Expected:**
- CONTAINS edge: parent-group → nested-group
- CONTAINS edge: nested-group → user
- Transitive path: parent-group →* user (depth = 2)

**Verification:**
```cypher
MATCH path = (parent {id: "parent-group"})-[:CONTAINS*]->(user {id: "user-test-003"})
RETURN length(path) as depth
// Expected: depth = 2
```

### Test 4: Multiple Members in Same Group
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-test-004",
        "memberId": "user-a",
        "memberType": "User"
      },
      {
        "groupId": "group-test-004",
        "memberId": "user-b",
        "memberType": "User"
      },
      {
        "groupId": "group-test-004",
        "memberId": "sp-c",
        "memberType": "ServicePrincipal"
      }
    ]
  }
}
```

**Expected:**
- 3 CONTAINS edges created, all from same group
- Each member has independent edge

**Verification:**
```cypher
MATCH (group {id: "group-test-004"})-[:CONTAINS]->(member)
RETURN count(member) as member_count
// Expected: member_count = 3
```

### Test 5: User in Multiple Groups
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-a",
        "memberId": "user-test-005",
        "memberType": "User"
      },
      {
        "groupId": "group-b",
        "memberId": "user-test-005",
        "memberType": "User"
      },
      {
        "groupId": "group-c",
        "memberId": "user-test-005",
        "memberType": "User"
      }
    ]
  }
}
```

**Expected:**
- 3 CONTAINS edges created, all pointing to same user
- User belongs to 3 groups

**Verification:**
```cypher
MATCH (group)-[:CONTAINS]->(user {id: "user-test-005"})
RETURN count(group) as group_count
// Expected: group_count = 3
```

### Test 6: Idempotency
**Action:** Run import twice with same membership data

**Expected:**
- Only one edge created per group-member pair (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (group {id: "group-test-006"})-[r:CONTAINS]->(user {id: "user-test-006"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 7: Missing Group Node
**Setup:** Delete group node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Member node unaffected

### Test 8: Missing Member Node
**Setup:** Delete member node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently)
- No errors logged
- Group node unaffected

### Test 9: Empty Group ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "",
        "memberId": "user-test-009",
        "memberType": "User"
      }
    ]
  }
}
```

**Expected:**
- Edge skipped during data extraction
- No edge created
- No errors

### Test 10: Empty Member ID (Skip)
**Input:**
```json
{
  "azure_ad": {
    "groupMemberships": [
      {
        "groupId": "group-test-010",
        "memberId": "",
        "memberType": "User"
      }
    ]
  }
}
```

**Expected:**
- Edge skipped during data extraction
- No edge created
- No errors

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createGroupMemberContains()` starting at line 1566

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single batch (all relationships in one transaction)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes logged separately during node creation

**Validation:** Empty IDs filtered during data extraction (no Cypher execution attempted)

## Azure Behavior Notes

**Group Types:**
- Security groups can be assigned permissions
- Microsoft 365 groups cannot be assigned directory roles
- Dynamic groups have membership managed by rules (not reflected in graph)

**Nested Group Limits:**
- Azure supports nested groups
- Maximum nesting depth varies by scenario
- Circular memberships prevented by Azure

**Transitive Permissions:**
- Permissions assigned to parent group inherited by members
- Nested group members inherit parent group permissions
- Graph queries use `[:CONTAINS*]` for transitive traversal

## Related Documentation

- [Group Node](../NODES/group.md) - Source node
- [User Node](../NODES/user.md) - Target node (users)
- [Service Principal Node](../NODES/service-principal.md) - Target node (SPs)
- [HAS_PERMISSION](../HAS_PERMISSION/) - Permission inheritance
- [../overview.md](../overview.md) - Hierarchy overview
