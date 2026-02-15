# Tenant Node

Azure AD / Entra ID tenant (root of the hierarchy).

## Node Labels

- `Resource` (shared)
- `Hierarchy` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `tenantID` | ✅ | Normalized tenant GUID |
| `resourceType` | string | Constant | ✅ | `"Microsoft.DirectoryServices/tenant"` |
| `displayName` | string | Constant or metadata | ✅ | `"Azure AD Tenant"` or custom name |
| `tenantId` | string | `tenantID` | ✅ | Lowercase tenant GUID |
| `metadata` | string (JSON) | Computed | ✅ | JSON with tenantId, domain, displayName, country |

## MERGE Key

```cypher
{id: toLower($tenantId)}
```

**Uniqueness:** One tenant node per Azure AD tenant

## Source Data

**Location:** `consolidatedData["collection_metadata"]["tenant_id"]`

**Example:**
```json
{
  "collection_metadata": {
    "tenant_id": "tenant-guid-123",
    "domain": "example.com",
    "display_name": "Example Organization",
    "country": "US",
    "collection_timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Creation Logic

**Function:** `createHierarchyResources()` - line 805

**Single Node:** Only one tenant node per collection

**Cypher Pattern:**
```cypher
MERGE (r:Resource:Hierarchy {id: toLower($tenantId)})
ON CREATE SET
    r.resourceType = "Microsoft.DirectoryServices/tenant",
    r.displayName = "Azure AD Tenant",
    r.tenantId = toLower($tenantId),
    r.metadata = $metadata
```

## Conditional Logic

### Display Name

```go
displayName := "Azure AD Tenant" // Default

// Use custom name from metadata if available
if collectionMetadata, ok := consolidatedData["collection_metadata"].(map[string]interface{}); ok {
    if displayNameFromMeta, ok := collectionMetadata["display_name"].(string); ok && displayNameFromMeta != "" {
        displayName = displayNameFromMeta
    }
}
```

### Metadata Enrichment

```go
metadata := map[string]interface{}{
    "tenantId": strings.ToLower(tenantID),
}

// Add optional fields from collection metadata
if domain, ok := collectionMetadata["domain"].(string); ok && domain != "" {
    metadata["domain"] = domain
}

if displayName, ok := collectionMetadata["display_name"].(string); ok && displayName != "" {
    metadata["displayName"] = displayName
}

if country, ok := collectionMetadata["country"].(string); ok && country != "" {
    metadata["country"] = country
}
```

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/tenant-to-root-mg.md) - Root management group

### Incoming

None (tenant is the root of the hierarchy)

## Tenant as Root Node

The tenant node represents the top-level Azure AD organization and serves as the root of the entire Azure resource hierarchy:

```
Tenant
  └─ Root Management Group
       ├─ Management Group A
       │    ├─ Subscription 1
       │    └─ Subscription 2
       └─ Management Group B
            └─ Subscription 3
```

**Key Characteristics:**
- **Single Instance:** One tenant node per Azure AD organization
- **Root of Hierarchy:** No parent nodes, only children
- **Identity Scope:** All identities (users, groups, service principals) exist within this tenant
- **Permission Scope:** Directory roles granted at tenant level affect entire organization

## Query Examples

### Get tenant information
```cypher
MATCH (tenant:Resource:Hierarchy)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
RETURN tenant.displayName, tenant.tenantId, tenant.metadata
```

### Find root management group
```cypher
MATCH (tenant:Resource:Hierarchy)-[:CONTAINS]->(rootMG:Resource:Hierarchy)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
  AND toLower(rootMG.resourceType) = "microsoft.management/managementgroups"
  AND rootMG.isRoot = true
RETURN tenant.displayName, rootMG.displayName
```

### Count all management groups under tenant
```cypher
MATCH (tenant:Resource:Hierarchy)-[:CONTAINS*]->(mg:Resource:Hierarchy)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
  AND toLower(mg.resourceType) = "microsoft.management/managementgroups"
RETURN count(mg) as total_management_groups
```

### Count all subscriptions under tenant
```cypher
MATCH (tenant:Resource:Hierarchy)-[:CONTAINS*]->(sub:Resource:Hierarchy)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
  AND toLower(sub.resourceType) = "microsoft.resources/subscriptions"
RETURN count(sub) as total_subscriptions
```

### Find all users who can escalate to tenant control
```cypher
MATCH (user:Resource)-[r:CAN_ESCALATE]->(tenant:Resource:Hierarchy)
WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
RETURN user.displayName, r.method, r.condition
```

## Test Cases

### Test 1: Tenant Creation - Minimal
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "test-tenant-001"
  }
}
```

**Expected:**
- Node created with labels: `Resource:Hierarchy`
- `id = "test-tenant-001"` (lowercase)
- `tenantId = "test-tenant-001"`
- `displayName = "Azure AD Tenant"` (default)
- `resourceType = "Microsoft.DirectoryServices/tenant"`
- Metadata contains tenantId

### Test 2: Tenant Creation - With Metadata
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "test-tenant-002",
    "domain": "example.com",
    "display_name": "Example Organization",
    "country": "US"
  }
}
```

**Expected:**
- `displayName = "Azure AD Tenant"` (uses default, not metadata display_name)
- Metadata contains:
  - `tenantId: "test-tenant-002"`
  - `domain: "example.com"`
  - `displayName: "Example Organization"`
  - `country: "US"`

### Test 3: Tenant ID Case Normalization
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": "TENANT-TEST-003-UPPER"
  }
}
```

**Expected:**
- `id = "tenant-test-003-upper"` (normalized to lowercase)
- `tenantId = "tenant-test-003-upper"` (normalized to lowercase)

### Test 4: Idempotency
**Action:** Run import twice with same tenant data

**Expected:**
- Only one tenant node created
- ON MATCH doesn't update (tenant properties static)
- No duplicate nodes

### Test 5: Empty Tenant ID
**Input:**
```json
{
  "collection_metadata": {
    "tenant_id": ""
  }
}
```

**Expected:**
- No tenant node created (function exits early if tenant_id is empty)
- No errors thrown

### Test 6: Missing collection_metadata
**Input:**
```json
{
  "azure_ad": {},
  "pim": {},
  "management_groups": [],
  "azure_resources": {}
}
```

**Expected:**
- No tenant node created
- No errors thrown
- Log warning about missing tenant_id

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createHierarchyResources()` starting at line 805

**Batch Processing:** Single node (not batched)

**Early Exit Condition:**
```go
if tenantID == "" {
    l.Logger.Warn("No tenant ID found in collection metadata, skipping tenant node creation")
    return nil
}
```

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#1-collection_metadata-object) - JSON input format
- [Root Management Group](management-group.md) - Child node
- [Tenant CONTAINS Root MG](../Azure_IAM_Edges/CONTAINS/tenant-to-root-mg.md) - Hierarchy edge
- [CAN_ESCALATE to Tenant](../Azure_IAM_Edges/CAN_ESCALATE/global-administrator.md) - Privilege escalation
