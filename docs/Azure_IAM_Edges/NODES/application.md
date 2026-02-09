# Application Nodes

Application registrations in Azure AD / Entra ID.

## Node Labels

- `Resource` (shared)
- `Identity` (category)
- **NOT** `Principal` (applications themselves cannot be assigned permissions; their service principals can)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `appMap["id"]` | ✅ | Normalized to lowercase |
| `resourceType` | string | Constant | ✅ | `"Microsoft.DirectoryServices/applications"` |
| `displayName` | string | `appMap["displayName"]` | ✅ | Application name |
| `appId` | string | `appMap["appId"]` | ✅ | Application (client) ID |
| `signInAudience` | string | `appMap["signInAudience"]` | ❌ | `"AzureADMyOrg"`, `"AzureADMultipleOrgs"`, etc. |
| `credentialSummary_hasCredentials` | boolean | `appMap["credentialSummary_hasCredentials"]` | ✅ | Whether app has any credentials |
| `credentialSummary_totalCredentials` | integer | `appMap["credentialSummary_totalCredentials"]` | ✅ | Total credential count |
| `credentialSummary_passwordCredentials` | integer | `appMap["credentialSummary_passwordCredentials"]` | ⚠️ | Only if exists |
| `credentialSummary_keyCredentials` | integer | `appMap["credentialSummary_keyCredentials"]` | ⚠️ | Only if exists |
| `metadata` | string (JSON) | Computed | ✅ | JSON with appId, signInAudience |

## MERGE Key

```cypher
{id: toLower($appId)}
```

**Uniqueness:** One application node per unique ID

## Source Data

**Location:** `consolidatedData["azure_ad"]["applications"]`

**Example:**
```json
{
  "applications": [
    {
      "id": "app-object-id-123",
      "appId": "app-client-id-456",
      "displayName": "My Application",
      "signInAudience": "AzureADMyOrg",
      "keyCredentials": [
        {
          "keyId": "key-guid",
          "type": "AsymmetricX509Cert",
          "usage": "Verify"
        }
      ],
      "passwordCredentials": [
        {
          "keyId": "secret-guid",
          "displayName": "Client Secret"
        }
      ],
      "credentialSummary_hasCredentials": true,
      "credentialSummary_totalCredentials": 2,
      "credentialSummary_passwordCredentials": 1,
      "credentialSummary_keyCredentials": 1
    }
  ]
}
```

## Creation Logic

**Function:** `createIdentityResources()` - line 605

**Batch Size:** 1000 applications per transaction

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:Identity {id: resource.id})
ON CREATE SET
    r.resourceType = "Microsoft.DirectoryServices/applications",
    r.displayName = resource.displayName,
    r.appId = resource.appId,
    r.signInAudience = resource.signInAudience,
    r.credentialSummary_hasCredentials = resource.credentialSummary_hasCredentials,
    r.credentialSummary_totalCredentials = resource.credentialSummary_totalCredentials,
    r.credentialSummary_passwordCredentials = resource.credentialSummary_passwordCredentials,
    r.credentialSummary_keyCredentials = resource.credentialSummary_keyCredentials,
    r.metadata = COALESCE(resource.metadata, '{}')
ON MATCH SET
    r.displayName = resource.displayName,
    r.metadata = COALESCE(resource.metadata, '{}')
```

**Note:** Applications do NOT have the `Principal` label because they cannot directly receive permission assignments. Their corresponding service principals receive permissions.

## Conditional Logic

### Credential Summary Fields

```go
// credentialSummary_passwordCredentials only set if field present
if passwordCredentials, ok := appMap["credentialSummary_passwordCredentials"]; ok {
    appResource["credentialSummary_passwordCredentials"] = passwordCredentials
}

// credentialSummary_keyCredentials only set if field present
if keyCredentials, ok := appMap["credentialSummary_keyCredentials"]; ok {
    appResource["credentialSummary_keyCredentials"] = keyCredentials
}
```

**Why:** Credential summary fields are computed by the collector and may not always be present

## Metadata Composition

```go
metadata := map[string]interface{}{
    "appId": appMap["appId"],
    "signInAudience": appMap["signInAudience"],
}

appResource["metadata"] = toJSONString(metadata)
```

## Related Edges

### Outgoing

- [CONTAINS](../CONTAINS/application-to-sp.md) - Corresponding service principal

### Incoming

- [OWNS](../OWNS/application-ownership.md) - Application owners

## Application vs Service Principal

**Key Distinction:**

| Aspect | Application | Service Principal |
|--------|-------------|-------------------|
| **Purpose** | Template/definition | Runtime identity |
| **Scope** | Single tenant or multi-tenant | Per-tenant instance |
| **Permissions** | Defined on app | Granted to SP |
| **Labels** | `Resource:Identity` | `Resource:Identity:Principal` |
| **Can receive RBAC?** | No | Yes |
| **Credentials** | Stored here | Reference app credentials |

**Relationship:**
- One Application can have multiple Service Principals (one per tenant where it's installed)
- Service Principal references Application via `appId`
- Application CONTAINS Service Principal (in same tenant)

## Sign-In Audience Types

| Value | Meaning |
|-------|---------|
| `AzureADMyOrg` | Single tenant (organization only) |
| `AzureADMultipleOrgs` | Multi-tenant (any Azure AD org) |
| `AzureADandPersonalMicrosoftAccount` | Multi-tenant + personal Microsoft accounts |
| `PersonalMicrosoftAccount` | Personal Microsoft accounts only |

## Query Examples

### Find all applications
```cypher
MATCH (app:Resource:Identity)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN app.displayName, app.appId, app.signInAudience
```

### Find applications with credentials
```cypher
MATCH (app:Resource:Identity)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND app.credentialSummary_hasCredentials = true
RETURN app.displayName, app.credentialSummary_totalCredentials
```

### Find applications without credentials (orphaned)
```cypher
MATCH (app:Resource:Identity)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND (app.credentialSummary_hasCredentials = false OR app.credentialSummary_totalCredentials = 0)
RETURN app.displayName, app.appId
```

### Find multi-tenant applications
```cypher
MATCH (app:Resource:Identity)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND app.signInAudience IN ["AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"]
RETURN app.displayName, app.signInAudience
```

### Find applications with their service principals
```cypher
MATCH (app:Resource:Identity)-[:CONTAINS]->(sp:Resource:Identity:Principal)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN app.displayName, sp.displayName
```

### Find applications with owners
```cypher
MATCH (owner:Resource)-[:OWNS]->(app:Resource:Identity)
WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
RETURN app.displayName, owner.displayName as owner, owner.resourceType as owner_type
```

## Test Cases

### Test 1: Application Creation - Required Fields Only
**Input:**
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-test-001",
      "appId": "app-client-id-001",
      "displayName": "Test Application",
      "credentialSummary_hasCredentials": false,
      "credentialSummary_totalCredentials": 0
    }]
  }
}
```

**Expected:**
- Node created with labels: `Resource:Identity` (NOT `Principal`)
- `id = "app-test-001"` (lowercase)
- `displayName = "Test Application"`
- `appId = "app-client-id-001"`
- `resourceType = "Microsoft.DirectoryServices/applications"`
- `credentialSummary_hasCredentials = false`

### Test 2: Application with Credentials
**Input:**
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-test-002",
      "appId": "app-client-id-002",
      "displayName": "App with Credentials",
      "signInAudience": "AzureADMyOrg",
      "credentialSummary_hasCredentials": true,
      "credentialSummary_totalCredentials": 2,
      "credentialSummary_passwordCredentials": 1,
      "credentialSummary_keyCredentials": 1
    }]
  }
}
```

**Expected:**
- `credentialSummary_hasCredentials = true`
- `credentialSummary_totalCredentials = 2`
- `credentialSummary_passwordCredentials = 1`
- `credentialSummary_keyCredentials = 1`
- Metadata contains appId and signInAudience

### Test 3: Multi-Tenant Application
**Input:**
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-test-003",
      "appId": "app-client-id-003",
      "displayName": "Multi-Tenant App",
      "signInAudience": "AzureADMultipleOrgs",
      "credentialSummary_hasCredentials": true,
      "credentialSummary_totalCredentials": 1
    }]
  }
}
```

**Expected:**
- `signInAudience = "AzureADMultipleOrgs"`
- Metadata reflects multi-tenant config

### Test 4: Application-SP Relationship
**Input:**
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-test-004",
      "appId": "shared-app-id",
      "displayName": "App with SP",
      "credentialSummary_hasCredentials": true,
      "credentialSummary_totalCredentials": 1
    }],
    "servicePrincipals": [{
      "id": "sp-test-004",
      "appId": "shared-app-id",
      "displayName": "App with SP"
    }]
  }
}
```

**Expected:**
- Two separate nodes created
- Application CONTAINS Service Principal edge created (matched by appId)

### Test 5: Idempotency
**Action:** Run import twice with same application data

**Expected:**
- Only one node created
- ON MATCH updates displayName, metadata
- No duplicate nodes

### Test 6: Missing Credential Summary
**Input:**
```json
{
  "azure_ad": {
    "applications": [{
      "id": "app-test-005",
      "appId": "app-client-id-005",
      "displayName": "App Without Credential Summary"
    }]
  }
}
```

**Expected:**
- Node created successfully
- `credentialSummary_*` fields not set (NULL)
- No errors during import

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createIdentityResources()` starting at line 605

**Batch Processing:** Applications processed in batches of 1000

## Related Documentation

- [Data Schema](../data-schema.md#24-azure_adapplications-array) - JSON input format
- [Service Principal Nodes](service-principal.md) - Runtime identity
- [Application CONTAINS SP](../CONTAINS/application-to-sp.md) - Relationship edge
- [Application Ownership](../OWNS/application-ownership.md) - Ownership edges
