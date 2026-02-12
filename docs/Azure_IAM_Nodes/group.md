# Group Nodes

Security groups and Microsoft 365 groups in Azure AD / Entra ID.

## Node Labels

- `Resource` (shared)
- `Identity` (category)
- `Principal` (can be assigned permissions)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `groupMap["id"]` | ✅ | Normalized to lowercase |
| `resourceType` | string | Constant | ✅ | `"Microsoft.DirectoryServices/groups"` |
| `displayName` | string | `groupMap["displayName"]` | ✅ | Group name |
| `description` | string | `groupMap["description"]` | ❌ | Group description |
| `securityEnabled` | boolean | `groupMap["securityEnabled"]` | ⚠️ | Only if exists |
| `mailEnabled` | boolean | `groupMap["mailEnabled"]` | ⚠️ | Only if exists |
| `metadata` | string (JSON) | Computed | ✅ | JSON with description, securityEnabled, mailEnabled, groupTypes |

## MERGE Key

```cypher
{id: toLower($groupId)}
```

**Uniqueness:** One group node per unique ID

## Source Data

**Location:** `consolidatedData["azure_ad"]["groups"]`

**Example:**
```json
{
  "groups": [
    {
      "id": "group-guid-123",
      "displayName": "Domain Admins",
      "description": "Administrative group for domain operations",
      "securityEnabled": true,
      "mailEnabled": false,
      "groupTypes": ["Unified"],
      "membershipRule": null,
      "createdDateTime": "2023-01-15T10:30:00Z"
    }
  ]
}
```

## Creation Logic

**Function:** `createIdentityResources()` - line 605

**Batch Size:** 1000 groups per transaction

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Identity:Principal {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.DirectoryServices/groups",
    r.displayName = resource.displayName,
    r.description = resource.description,
    r.securityEnabled = resource.securityEnabled,
    r.mailEnabled = resource.mailEnabled,
    r.metadata = COALESCE(resource.metadata, '{}')
ON MATCH SET
    r.displayName = resource.displayName,
    r.metadata = COALESCE(resource.metadata, '{}')
```

## Conditional Logic

### Security and Mail Flags

```go
// Only set if fields exist in source JSON
if securityEnabled, ok := groupMap["securityEnabled"]; ok {
    if securityBool, ok := securityEnabled.(bool); ok {
        groupResource["securityEnabled"] = securityBool
    }
}

if mailEnabled, ok := groupMap["mailEnabled"]; ok {
    if mailBool, ok := mailEnabled.(bool); ok {
        groupResource["mailEnabled"] = mailBool
    }
}
```

### Group Types Array

```go
// Extract groupTypes array if present
if groupTypes, ok := groupMap["groupTypes"]; ok {
    if groupTypesArray, ok := groupTypes.([]interface{}); ok {
        metadata["groupTypes"] = groupTypesArray
    }
}
```

## Metadata Composition

```go
metadata := map[string]interface{}{
    "description": groupMap["description"],
}

// Add optional fields only if present
if securityEnabled, ok := groupMap["securityEnabled"]; ok {
    metadata["securityEnabled"] = securityEnabled
}

if mailEnabled, ok := groupMap["mailEnabled"]; ok {
    metadata["mailEnabled"] = mailEnabled
}

if groupTypes, ok := groupMap["groupTypes"]; ok {
    metadata["groupTypes"] = groupTypes
}

groupResource["metadata"] = toJSONString(metadata)
```

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/group-to-member.md) - Group members
- [HAS_PERMISSION](../Azure_IAM_Edges/HAS_PERMISSION/) - Role assignments, RBAC grants
- [CAN_ESCALATE](../Azure_IAM_Edges/CAN_ESCALATE/) - Privilege escalation paths

### Incoming

- [OWNS](../Azure_IAM_Edges/OWNS/group-ownership.md) - Group owners
- [CONTAINS](../Azure_IAM_Edges/CONTAINS/group-to-member.md) - Nested group memberships
- [HAS_PERMISSION](../Azure_IAM_Edges/HAS_PERMISSION/) - Transitive permissions from other groups

## Query Examples

### Find all security groups
```cypher
MATCH (g:Resource:Identity:Principal)
WHERE toLower(g.resourceType) = "microsoft.directoryservices/groups"
  AND g.securityEnabled = true
RETURN g.displayName, g.description
```

### Find mail-enabled groups
```cypher
MATCH (g:Resource:Identity:Principal)
WHERE toLower(g.resourceType) = "microsoft.directoryservices/groups"
  AND g.mailEnabled = true
RETURN g.displayName, g.description
```

### Find groups with owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(g:Resource:Identity:Principal)
WHERE toLower(g.resourceType) = "microsoft.directoryservices/groups"
RETURN g.displayName, count(owner) as owner_count
ORDER BY owner_count DESC
```

### Find groups with members
```cypher
MATCH (g:Resource:Identity:Principal)-[:CONTAINS]->(member:Resource)
WHERE toLower(g.resourceType) = "microsoft.directoryservices/groups"
RETURN g.displayName, count(member) as member_count
ORDER BY member_count DESC
```

## Test Cases

### Test 1: Group Creation - Required Fields Only
**Input:**
```json
{
  "azure_ad": {
    "groups": [{
      "id": "group-test-001",
      "displayName": "Test Group"
    }]
  }
}
```

**Expected:**
- Node created with labels: `Resource:Identity:Principal`
- `id = "group-test-001"` (lowercase)
- `displayName = "Test Group"`
- `resourceType = "Microsoft.DirectoryServices/groups"`
- Optional fields not set

### Test 2: Group Creation - Security Group
**Input:**
```json
{
  "azure_ad": {
    "groups": [{
      "id": "group-test-002",
      "displayName": "Security Test Group",
      "description": "A test security group",
      "securityEnabled": true,
      "mailEnabled": false
    }]
  }
}
```

**Expected:**
- `securityEnabled = true`
- `mailEnabled = false`
- `description = "A test security group"`
- Metadata contains all fields

### Test 3: Group Creation - Microsoft 365 Group
**Input:**
```json
{
  "azure_ad": {
    "groups": [{
      "id": "group-test-003",
      "displayName": "M365 Test Group",
      "securityEnabled": true,
      "mailEnabled": true,
      "groupTypes": ["Unified"]
    }]
  }
}
```

**Expected:**
- `securityEnabled = true`
- `mailEnabled = true`
- Metadata contains `groupTypes: ["Unified"]`

### Test 4: Group Creation - Dynamic Group
**Input:**
```json
{
  "azure_ad": {
    "groups": [{
      "id": "group-test-004",
      "displayName": "Dynamic Test Group",
      "description": "Dynamic membership group",
      "securityEnabled": true,
      "mailEnabled": false,
      "groupTypes": ["DynamicMembership"],
      "membershipRule": "(user.department -eq \"IT\")"
    }]
  }
}
```

**Expected:**
- Metadata contains `groupTypes: ["DynamicMembership"]`
- `description` set correctly

### Test 5: Idempotency
**Action:** Run import twice with same group data

**Expected:**
- Only one node created
- ON MATCH updates displayName, metadata
- No duplicate nodes

### Test 6: Missing Optional Fields
**Input:**
```json
{
  "azure_ad": {
    "groups": [{
      "id": "group-test-005",
      "displayName": "Minimal Group"
    }]
  }
}
```

**Expected:**
- Node created successfully
- `securityEnabled` not set (NULL)
- `mailEnabled` not set (NULL)
- `description` not set (NULL)
- Metadata contains empty/minimal structure

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createIdentityResources()` starting at line 605

**Batch Processing:** Groups processed in batches of 1000

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#22-azure_adgroups-array) - JSON input format
- [Group CONTAINS Member](../Azure_IAM_Edges/CONTAINS/group-to-member.md) - Membership edges
- [Group Ownership](../Azure_IAM_Edges/OWNS/group-ownership.md) - Ownership edges
