# System-Assigned Managed Identity Nodes (Synthetic)

System-assigned managed identities created automatically with Azure resources.

## Node Labels

- `Resource` (shared)
- `AzureResource` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | Computed | ✅ | `/virtual/managedidentity/system/{principalId}` (synthetic path) |
| `resourceType` | string | Constant | ✅ | `"Microsoft.ManagedIdentity/systemAssigned"` |
| `displayName` | string | Computed | ✅ | `{resource.displayName} (System-Assigned)` |
| `principalId` | string | `resource.identityPrincipalId` | ✅ | MI principal ID |
| `subscriptionId` | string | Inherited | ✅ | From parent resource |
| `location` | string | Inherited | ⚠️ | From parent resource |
| `resourceGroup` | string | Inherited | ⚠️ | From parent resource |
| `metadata` | string | Constant | ✅ | `'{"assignmentType":"System-Assigned","synthetic":true}'` |

## MERGE Key

```cypher
{id: "/virtual/managedidentity/system/" + $principalId}
```

**Uniqueness:** One synthetic MI node per unique principal ID

## Source Data

**NOT from JSON data** - Created via Cypher query that matches existing Azure resource nodes.

**Derived From:**
Azure resources with `identityType` containing `"SystemAssigned"` and `identityPrincipalId` set.

## Creation Logic

**Function:** `createSystemAssignedManagedIdentityResources()` - line 1092

**Method:** Pure Cypher query (no batch data)

**Cypher Pattern:**
```cypher
MATCH (resource:Resource)
WHERE toLower(resource.identityType) CONTAINS "systemassigned"
  AND resource.identityPrincipalId IS NOT NULL
  AND NOT toLower(resource.resourceType) CONTAINS "managedidentity"
WITH resource
MERGE (mi:Resource:AzureResource {id: "/virtual/managedidentity/system/" + resource.identityPrincipalId})
ON CREATE SET
    mi.resourceType = "Microsoft.ManagedIdentity/systemAssigned",
    mi.displayName = resource.displayName + " (System-Assigned)",
    mi.principalId = resource.identityPrincipalId,
    mi.subscriptionId = resource.subscriptionId,
    mi.location = resource.location,
    mi.resourceGroup = resource.resourceGroup,
    mi.metadata = '{"assignmentType":"System-Assigned","synthetic":true}'
RETURN count(mi) as created_count
```

## Why Synthetic?

System-assigned managed identities don't exist as standalone Azure resources. They are:

1. **Lifecycle-Bound:** Created/deleted with parent resource
2. **Not Addressable:** No ARM resource ID
3. **Identity Property:** Exist only as `identity` property on parent resource

**Problem:** Neo4j graph needs discrete nodes for relationships (e.g., MI → SP, Resource → MI)

**Solution:** Importer creates synthetic MI nodes with virtual IDs based on `principalId`

## Conditional Logic

### Filter Criteria

```cypher
WHERE toLower(resource.identityType) CONTAINS "systemassigned"
  AND resource.identityPrincipalId IS NOT NULL
  AND NOT toLower(resource.resourceType) CONTAINS "managedidentity"
```

**Filters:**
1. Resource must have `identityType` containing `"systemassigned"` (case-insensitive)
2. Resource must have `identityPrincipalId` set (not NULL)
3. Resource must NOT already be a managed identity (prevents recursion)

### Display Name Derivation

```cypher
mi.displayName = resource.displayName + " (System-Assigned)"
```

**Examples:**
- `"web-vm-01"` → `"web-vm-01 (System-Assigned)"`
- `"prod-app"` → `"prod-app (System-Assigned)"`

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/mi-to-sp.md) - Backing service principal

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/resource-to-system-mi.md) - Parent Azure resource
- [CAN_ESCALATE](../Azure_IAM_Edges/CAN_ESCALATE/) - From parent resource (via IMDS token theft)

## System-Assigned vs User-Assigned

| Aspect | System-Assigned | User-Assigned |
|--------|-----------------|---------------|
| **Lifecycle** | Tied to resource lifecycle | Independent from resource |
| **Reusability** | One per resource | Can be assigned to multiple resources |
| **Creation** | Automatic with resource | Explicitly created as resource |
| **Resource Type** | `Microsoft.ManagedIdentity/systemAssigned` | `Microsoft.ManagedIdentity/userAssignedIdentities` |
| **Node Source** | Synthetic (Cypher query) | Azure resource data |
| **synthetic** | `true` | `false` |
| **ID Pattern** | `/virtual/managedidentity/system/{principalId}` | `/subscriptions/.../userAssignedIdentities/{name}` |
| **Azure ARM ID** | None (virtual) | Yes (real resource) |

## Identity Extraction Process

**Step 1:** `processIdentityData()` extracts identity from resource (line 3234)

```go
// During Azure resource creation
if identity, ok := resourceMap["identity"]; ok {
    identityMap := identity.(map[string]interface{})
    identityType := getStringValue(identityMap, "type")

    if strings.Contains(identityType, "SystemAssigned") {
        // Extract principalId for system-assigned MI
        resourceMap["identityPrincipalId"] = getStringValue(identityMap, "principalId")
    }
}
```

**Step 2:** Resource node created with identity properties

**Step 3:** Cypher query creates synthetic MI node based on `identityPrincipalId`

**Step 4:** CONTAINS edge created: Resource → System-Assigned MI

## Query Examples

### Find all system-assigned managed identities
```cypher
MATCH (smi:Resource:AzureResource)
WHERE toLower(smi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN smi.displayName, smi.principalId
```

### Find parent resources of system-assigned MIs
```cypher
MATCH (resource:Resource:AzureResource)-[:CONTAINS]->(smi:Resource:AzureResource)
WHERE toLower(smi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN resource.displayName as parent_resource,
       smi.displayName as managed_identity,
       resource.resourceType as resource_type
```

### Find system-assigned MIs with backing SPs
```cypher
MATCH (smi:Resource:AzureResource)-[:CONTAINS]->(sp:Resource:Identity:Principal)
WHERE toLower(smi.resourceType) = "microsoft.managedidentity/systemassigned"
  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
RETURN smi.displayName, sp.displayName, sp.appId
```

### Find system-assigned MIs with permissions
```cypher
MATCH (smi:Resource:AzureResource)-[:CONTAINS]->(sp:Resource:Identity:Principal)
MATCH (sp)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE toLower(smi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN smi.displayName as managed_identity,
       perm.permission as permission,
       target.displayName as target
```

### Find VMs with system-assigned identities
```cypher
MATCH (vm:Resource:AzureResource)-[:CONTAINS]->(smi:Resource:AzureResource)
WHERE toLower(vm.resourceType) = "microsoft.compute/virtualmachines"
  AND toLower(smi.resourceType) = "microsoft.managedidentity/systemassigned"
RETURN vm.displayName as vm_name, smi.principalId
```

### Compare system vs user-assigned MIs
```cypher
MATCH (mi:Resource:AzureResource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
RETURN mi.resourceType,
       count(mi) as count,
       collect(mi.displayName)[0..5] as sample_names
```

## Test Cases

### Test 1: System-Assigned MI Creation from VM
**Input:**
```json
{
  "azure_resources": {
    "sub-test-001": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-001/.../virtualMachines/test-vm",
          "name": "test-vm",
          "type": "Microsoft.Compute/virtualMachines",
          "identity": {
            "type": "SystemAssigned",
            "principalId": "system-principal-001"
          }
        }
      ]
    }
  }
}
```

**Expected:**
- VM node created with `identityPrincipalId = "system-principal-001"`
- Synthetic MI node created with:
  - `id = "/virtual/managedidentity/system/system-principal-001"`
  - `displayName = "test-vm (System-Assigned)"`
  - `principalId = "system-principal-001"`
  - `resourceType = "Microsoft.ManagedIdentity/systemAssigned"`
  - `metadata = '{"assignmentType":"System-Assigned","synthetic":true}'`
- CONTAINS edge: VM → System-Assigned MI

### Test 2: System + User-Assigned Combination
**Input:**
```json
{
  "azure_resources": {
    "sub-test-002": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-002/.../virtualMachines/hybrid-vm",
          "name": "hybrid-vm",
          "type": "Microsoft.Compute/virtualMachines",
          "identity": {
            "type": "SystemAssigned,UserAssigned",
            "principalId": "system-principal-002",
            "userAssignedIdentities": {
              "/subscriptions/sub-test-002/.../uami-1": {}
            }
          }
        }
      ]
    }
  }
}
```

**Expected:**
- VM node created with:
  - `identityType = "SystemAssigned,UserAssigned"`
  - `identityPrincipalId = "system-principal-002"`
  - `userAssignedIdentities = [uami-1-id]`
- Synthetic system-assigned MI created
- CAN_ESCALATE edges: VM → System MI, VM → User MI

### Test 3: Multiple Resources with Same Principal ID (Deduplication)
**Input:**
```json
{
  "azure_resources": {
    "sub-test-003": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-003/.../vm-1",
          "name": "vm-1",
          "type": "Microsoft.Compute/virtualMachines",
          "identity": {"type": "SystemAssigned", "principalId": "shared-principal"}
        },
        {
          "id": "/subscriptions/sub-test-003/.../vm-2",
          "name": "vm-2",
          "type": "Microsoft.Compute/virtualMachines",
          "identity": {"type": "SystemAssigned", "principalId": "shared-principal"}
        }
      ]
    }
  }
}
```

**Expected:**
- Two VM nodes created
- **Only one** synthetic MI node created (MERGE on principalId)
- Display name from first match: `"vm-1 (System-Assigned)"`
- Both VMs CONTAIN the same MI node

### Test 4: No Identity (Skip)
**Input:**
```json
{
  "azure_resources": {
    "sub-test-004": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-004/.../storage-no-id",
          "name": "storage-no-id",
          "type": "Microsoft.Storage/storageAccounts"
        }
      ]
    }
  }
}
```

**Expected:**
- Storage account node created
- No synthetic MI created (no identityPrincipalId)
- No errors

### Test 5: User-Assigned MI Resource (Excluded)
**Input:**
```json
{
  "azure_resources": {
    "sub-test-005": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-005/.../uami-real",
          "name": "uami-real",
          "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
          "properties": {"principalId": "uami-principal"}
        }
      ]
    }
  }
}
```

**Expected:**
- User-assigned MI node created (real resource)
- No synthetic system-assigned MI created (filter excludes managedidentity types)

### Test 6: Idempotency
**Action:** Run import twice with same VM data

**Expected:**
- Only one synthetic MI node created per principalId
- MERGE ensures no duplicates
- Properties unchanged on second run

### Test 7: Property Inheritance
**Input:**
```json
{
  "azure_resources": {
    "sub-test-007": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-007/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app",
          "name": "test-app",
          "type": "Microsoft.Web/sites",
          "location": "westus",
          "resourceGroup": "test-rg",
          "identity": {
            "type": "SystemAssigned",
            "principalId": "app-principal"
          }
        }
      ]
    }
  }
}
```

**Expected:**
- Synthetic MI inherits properties from parent:
  - `subscriptionId = "sub-test-007"`
  - `location = "westus"`
  - `resourceGroup = "test-rg"`

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createSystemAssignedManagedIdentityResources()` starting at line 1092

**Method:** Single Cypher query (no batch processing, graph-based generation)

**Timing:** Executed after Azure resource nodes created (requires parent nodes to exist)

## Related Documentation

- [Azure Resource Nodes](azure-resource.md) - Parent resources
- [User-Assigned MI Nodes](user-assigned-mi.md) - Comparison
- [processIdentityData()](azure-resource.md#identity-processing) - Identity extraction
- [Resource CONTAINS System MI](../Azure_IAM_Edges/CONTAINS/resource-to-system-mi.md) - Parent edge
- [MI CONTAINS SP](../Azure_IAM_Edges/CONTAINS/mi-to-sp.md) - Backing SP edge
- [CAN_ESCALATE IMDS](../Azure_IAM_Edges/CAN_ESCALATE/) - Token theft vectors
