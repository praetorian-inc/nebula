# Service Principal Nodes

Service principals (application identities) in Azure AD / Entra ID.

## Node Labels

- `Resource` (shared)
- `Identity` (category)
- `Principal` (can be assigned permissions)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `spMap["id"]` | ✅ | Normalized to lowercase |
| `resourceType` | string | Constant | ✅ | `"Microsoft.DirectoryServices/servicePrincipals"` |
| `displayName` | string | `spMap["displayName"]` | ✅ | SP display name |
| `appId` | string | `spMap["appId"]` | ✅ | Application (client) ID |
| `servicePrincipalType` | string | `spMap["servicePrincipalType"]` | ❌ | `"Application"`, `"ManagedIdentity"`, etc. |
| `accountEnabled` | boolean | `spMap["accountEnabled"]` | ⚠️ | Only if exists |
| `metadata` | string (JSON) | Computed | ✅ | JSON with appId, servicePrincipalType, accountEnabled |

## MERGE Key

```cypher
{id: toLower($spId)}
```

**Uniqueness:** One service principal node per unique ID

## Source Data

**Location:** `consolidatedData["azure_ad"]["servicePrincipals"]`

**Example:**
```json
{
  "servicePrincipals": [
    {
      "id": "sp-guid-123",
      "appId": "app-client-id-456",
      "displayName": "My Application",
      "servicePrincipalType": "Application",
      "accountEnabled": true,
      "replyUrls": ["https://app.example.com/callback"],
      "signInAudience": "AzureADMyOrg"
    }
  ]
}
```

## Creation Logic

**Function:** `createIdentityResources()` - line 605

**Batch Size:** 1000 service principals per transaction

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Identity:Principal {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.DirectoryServices/servicePrincipals",
    r.displayName = resource.displayName,
    r.appId = resource.appId,
    r.servicePrincipalType = resource.servicePrincipalType,
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
if accountEnabled, ok := spMap["accountEnabled"]; ok {
    if accountBool, ok := accountEnabled.(bool); ok {
        spResource["accountEnabled"] = accountBool
    }
}
```

**Why:** Some service principals may not have this field

## Metadata Composition

```go
metadata := map[string]interface{}{
    "appId": spMap["appId"],
    "servicePrincipalType": spMap["servicePrincipalType"],
}

// Add accountEnabled only if present
if accountEnabled, ok := spMap["accountEnabled"]; ok {
    metadata["accountEnabled"] = accountEnabled
}

spResource["metadata"] = toJSONString(metadata)
```

## Related Edges

### Outgoing

- [HAS_PERMISSION](../HAS_PERMISSION/) - Role assignments, Graph API permissions
- [CAN_ESCALATE](../CAN_ESCALATE/) - Privilege escalation paths via permissions

### Incoming

- [OWNS](../OWNS/service-principal-ownership.md) - SP owners
- [CONTAINS](../CONTAINS/application-to-sp.md) - Parent application
- [CONTAINS](../CONTAINS/mi-to-sp.md) - Parent managed identity

## Service Principal Types

### Application
Regular application service principals created from app registrations.

**Type:** `"Application"`

**Characteristics:**
- Created from Application object
- Can have credentials (secrets, certificates)
- Can be assigned roles and permissions

### ManagedIdentity
Service principals backing managed identities.

**Type:** `"ManagedIdentity"`

**Characteristics:**
- System-assigned or user-assigned
- No credentials (Azure manages authentication)
- Linked to Azure resources

### Legacy
Legacy service principals (rare).

**Type:** `"Legacy"`

## Query Examples

### Find all service principals
```cypher
MATCH (sp:Resource:Identity:Principal)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN sp.displayName, sp.appId, sp.servicePrincipalType
```

### Find application service principals
```cypher
MATCH (sp:Resource:Identity:Principal)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND sp.servicePrincipalType = "Application"
RETURN sp.displayName, sp.appId
```

### Find managed identity service principals
```cypher
MATCH (sp:Resource:Identity:Principal)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND sp.servicePrincipalType = "ManagedIdentity"
RETURN sp.displayName, sp.appId
```

### Find disabled service principals
```cypher
MATCH (sp:Resource:Identity:Principal)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND sp.accountEnabled = false
RETURN sp.displayName, sp.appId
```

### Find service principals with parent applications
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource:Identity:Principal)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN app.displayName as application, sp.displayName as service_principal
```

### Find service principals with Graph API permissions
```cypher
MATCH (sp:Resource:Identity:Principal)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
  AND perm.source = "Microsoft Graph"
RETURN sp.displayName, perm.permission, perm.permissionType
```

## Test Cases

### Test 1: Service Principal Creation - Required Fields
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipals": [{
      "id": "sp-test-001",
      "appId": "app-id-001",
      "displayName": "Test Service Principal"
    }]
  }
}
```

**Expected:**
- Node created with labels: `Resource:Identity:Principal`
- `id = "sp-test-001"` (lowercase)
- `displayName = "Test Service Principal"`
- `appId = "app-id-001"`
- `resourceType = "Microsoft.DirectoryServices/servicePrincipals"`

### Test 2: Application Service Principal
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipals": [{
      "id": "sp-test-002",
      "appId": "app-id-002",
      "displayName": "Application SP",
      "servicePrincipalType": "Application",
      "accountEnabled": true
    }]
  }
}
```

**Expected:**
- `servicePrincipalType = "Application"`
- `accountEnabled = true`
- Metadata contains all fields

### Test 3: Managed Identity Service Principal
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipals": [{
      "id": "sp-test-003",
      "appId": "app-id-003",
      "displayName": "Managed Identity SP",
      "servicePrincipalType": "ManagedIdentity",
      "accountEnabled": true
    }]
  }
}
```

**Expected:**
- `servicePrincipalType = "ManagedIdentity"`
- `accountEnabled = true`

### Test 4: Disabled Service Principal
**Input:**
```json
{
  "azure_ad": {
    "servicePrincipals": [{
      "id": "sp-test-004",
      "appId": "app-id-004",
      "displayName": "Disabled SP",
      "servicePrincipalType": "Application",
      "accountEnabled": false
    }]
  }
}
```

**Expected:**
- `accountEnabled = false`
- Metadata reflects disabled state

### Test 5: Idempotency
**Action:** Run import twice with same SP data

**Expected:**
- Only one node created
- ON MATCH updates displayName, metadata, accountEnabled
- No duplicate nodes

### Test 6: appId Matching
**Input:**
Create both Application and Service Principal with same appId:
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-object-id",
      "appId": "shared-app-id",
      "displayName": "My App"
    }],
    "servicePrincipals": [{
      "id": "sp-object-id",
      "appId": "shared-app-id",
      "displayName": "My App"
    }]
  }
}
```

**Expected:**
- Two separate nodes created (different IDs)
- Application CONTAINS Service Principal edge created (matched by appId)

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createIdentityResources()` starting at line 605

**Batch Processing:** Service principals processed in batches of 1000

## Related Documentation

- [Data Schema](../data-schema.md#23-azure_adserviceprincipals-array) - JSON input format
- [Application Nodes](application.md) - Parent application objects
- [Application CONTAINS SP](../CONTAINS/application-to-sp.md) - Relationship edge
- [SP Ownership](../OWNS/service-principal-ownership.md) - Ownership edges
