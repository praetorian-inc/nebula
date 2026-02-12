# User Nodes

User accounts in Azure AD / Entra ID.

## Node Labels

- `Resource` (shared)
- `Identity` (category)
- `Principal` (can be assigned permissions)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `userMap["id"]` | ✅ | Normalized to lowercase |
| `resourceType` | string | Constant | ✅ | `"Microsoft.DirectoryServices/users"` |
| `displayName` | string | `userMap["displayName"]` | ✅ | Full name |
| `userPrincipalName` | string | `userMap["userPrincipalName"]` | ✅ | UPN (login name) |
| `mail` | string | `userMap["mail"]` | ❌ | Email address |
| `userType` | string | `userMap["userType"]` | ❌ | `"Member"` or `"Guest"` |
| `accountEnabled` | boolean | `userMap["accountEnabled"]` | ⚠️ | Only set if field exists in source |
| `metadata` | string (JSON) | Computed | ✅ | JSON with email, UPN, userType, accountEnabled |

## MERGE Key

```cypher
{id: toLower($userId)}
```

**Uniqueness:** One user node per unique ID

## Source Data

**Location:** `consolidatedData["azure_ad"]["users"]`

**Example:**
```json
{
  "users": [
    {
      "id": "user-guid-123",
      "displayName": "Alice Smith",
      "userPrincipalName": "alice@example.com",
      "mail": "alice@example.com",
      "userType": "Member",
      "accountEnabled": true,
      "jobTitle": "Security Engineer",
      "department": "IT Security"
    }
  ]
}
```

## Creation Logic

**Function:** `createIdentityResources()` - line 605

**Batch Size:** 1000 users per transaction

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Identity:Principal {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.DirectoryServices/users",
    r.displayName = resource.displayName,
    r.userPrincipalName = resource.userPrincipalName,
    r.mail = resource.mail,
    r.userType = resource.userType,
    r.accountEnabled = resource.accountEnabled,
    r.metadata = COALESCE(resource.metadata, '{}')
ON MATCH SET
    r.displayName = resource.displayName,
    r.metadata = COALESCE(resource.metadata, '{}'),
    r.accountEnabled = resource.accountEnabled
```

## Conditional Logic

### accountEnabled Property

```go
// Only set accountEnabled if field exists in source JSON
if accountEnabled, ok := userMap["accountEnabled"]; ok {
    if accountBool, ok := accountEnabled.(bool); ok {
        userResource["accountEnabled"] = accountBool
    }
}
```

**Why:** Some users may not have this field in source data

## Metadata Composition

```go
metadata := map[string]interface{}{
    "email": userMap["mail"],
    "userPrincipalName": userMap["userPrincipalName"],
    "userType": userMap["userType"],
}

// Add accountEnabled only if present
if accountEnabled, ok := userMap["accountEnabled"]; ok {
    metadata["accountEnabled"] = accountEnabled
}

userResource["metadata"] = toJSONString(metadata)
```

## Related Edges

### Outgoing

- [HAS_PERMISSION](../Azure_IAM_Edges/HAS_PERMISSION/) - Role assignments, RBAC grants
- [OWNS](../Azure_IAM_Edges/OWNS/) - Owned applications, groups, service principals
- [CAN_ESCALATE](../Azure_IAM_Edges/CAN_ESCALATE/) - Privilege escalation paths

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/group-to-member.md) - Group memberships

## Query Examples

### Find all users
```cypher
MATCH (u:Resource:Identity:Principal)
WHERE toLower(u.resourceType) = "microsoft.directoryservices/users"
RETURN u.displayName, u.userPrincipalName, u.accountEnabled
```

### Find disabled users
```cypher
MATCH (u:Resource:Identity:Principal)
WHERE toLower(u.resourceType) = "microsoft.directoryservices/users"
  AND u.accountEnabled = false
RETURN u.displayName, u.userPrincipalName
```

### Find guest users
```cypher
MATCH (u:Resource:Identity:Principal)
WHERE toLower(u.resourceType) = "microsoft.directoryservices/users"
  AND u.userType = "Guest"
RETURN u.displayName, u.userPrincipalName
```

## Test Cases

### Test 1: User Creation - Required Fields Only
**Input:**
```json
{
  "azure_ad": {
    "users": [{
      "id": "user-test-001",
      "displayName": "Test User",
      "userPrincipalName": "testuser@example.com"
    }]
  }
}
```

**Expected:**
- Node created with labels: `Resource:Identity:Principal`
- `id = "user-test-001"` (lowercase)
- `displayName = "Test User"`
- `userPrincipalName = "testuser@example.com"`
- `resourceType = "Microsoft.DirectoryServices/users"`
- `metadata` contains UPN

### Test 2: User Creation - All Fields
**Input:**
```json
{
  "azure_ad": {
    "users": [{
      "id": "user-test-002",
      "displayName": "Full Test User",
      "userPrincipalName": "fulltest@example.com",
      "mail": "fulltest@example.com",
      "userType": "Member",
      "accountEnabled": true
    }]
  }
}
```

**Expected:**
- All properties set including optional fields
- `accountEnabled = true`
- `userType = "Member"`
- `mail = "fulltest@example.com"`
- `metadata` contains all fields

### Test 3: User Creation - Disabled Account
**Input:**
```json
{
  "azure_ad": {
    "users": [{
      "id": "user-test-003",
      "displayName": "Disabled User",
      "userPrincipalName": "disabled@example.com",
      "accountEnabled": false
    }]
  }
}
```

**Expected:**
- `accountEnabled = false`
- Metadata reflects disabled state

### Test 4: User Creation - Guest User
**Input:**
```json
{
  "azure_ad": {
    "users": [{
      "id": "user-test-004",
      "displayName": "Guest User",
      "userPrincipalName": "guest_example.com#EXT#@tenant.onmicrosoft.com",
      "userType": "Guest"
    }]
  }
}
```

**Expected:**
- `userType = "Guest"`
- Metadata reflects guest status

### Test 5: Idempotency
**Action:** Run import twice with same user data

**Expected:**
- Only one node created
- ON MATCH updates displayName, metadata
- No duplicate nodes

### Test 6: Case Sensitivity
**Input:**
```json
{
  "azure_ad": {
    "users": [{
      "id": "USER-TEST-005",
      "displayName": "Case Test",
      "userPrincipalName": "casetest@EXAMPLE.COM"
    }]
  }
}
```

**Expected:**
- `id` normalized to lowercase: `"user-test-005"`
- UPN preserved as-is: `"casetest@EXAMPLE.COM"`

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createIdentityResources()` starting at line 605

**Batch Processing:** Users processed in batches of 1000

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#21-azure_adusers-array) - JSON input format
- [Service Principal Nodes](service-principal.md) - Related identity type
- [Group CONTAINS Member](../Azure_IAM_Edges/CONTAINS/group-to-member.md) - Group membership edges
