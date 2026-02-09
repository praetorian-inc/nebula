# Azure Resource Nodes

Security-relevant Azure resources (VMs, storage accounts, key vaults, etc.).

## Node Labels

- `Resource` (shared)
- `AzureResource` (category)

## Properties

| Property | Type | Source | Required | Notes |
|----------|------|--------|----------|-------|
| `id` | string | `resourceMap["id"]` | ✅ | Normalized resource ID |
| `resourceType` | string | `resourceMap["type"]` | ✅ | Azure resource type |
| `displayName` | string | `resourceMap["name"]` | ✅ | Resource name |
| `location` | string | `resourceMap["location"]` | ⚠️ | Azure region (if present) |
| `subscriptionId` | string | Parent subscription | ✅ | Subscription GUID |
| `resourceGroup` | string | `resourceMap["resourceGroup"]` | ⚠️ | RG name (if present) |
| `identityType` | string | Extracted via `processIdentityData()` | ⚠️ | `"SystemAssigned"`, `"UserAssigned"`, etc. |
| `identityPrincipalId` | string | Extracted via `processIdentityData()` | ⚠️ | System-assigned MI principal ID |
| `userAssignedIdentities` | array | Extracted via `processIdentityData()` | ⚠️ | Array of user-assigned MI resource IDs |
| `principalId` | string | `resourceMap["properties"]["principalId"]` | ⚠️ | For managed identities only |
| `metadata` | string (JSON) | Computed | ⚠️ | For managed identities: JSON with assignmentType, synthetic |

## MERGE Key

```cypher
{id: toLower($resourceId)}
```

**Uniqueness:** One node per Azure resource

## Source Data

**Location:** `consolidatedData["azure_resources"][subscriptionId]["azureResources"]`

**Example:**
```json
{
  "azure_resources": {
    "subscription-guid-123": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-guid/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-vm-01",
          "name": "web-vm-01",
          "type": "Microsoft.Compute/virtualMachines",
          "location": "eastus",
          "resourceGroup": "prod-rg",
          "identity": {
            "type": "SystemAssigned",
            "principalId": "principal-guid-123"
          },
          "properties": {
            "vmId": "vm-guid",
            "hardwareProfile": {"vmSize": "Standard_D2s_v3"}
          }
        }
      ]
    }
  }
}
```

## Creation Logic

**Function:** `createAzureResourceNodes()` - line 1035

**Batch Size:** 1000 resources per transaction

**Security Filter:** Only these resource types are imported:

```go
securityRelevantTypes := []string{
    "microsoft.compute/virtualmachines",
    "microsoft.containerservice/managedclusters",
    "microsoft.storage/storageaccounts",
    "microsoft.keyvault/vaults",
    "microsoft.sql/servers",
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.web/sites",
    "microsoft.logic/workflows",
    "microsoft.cognitiveservices/accounts",
    "microsoft.automation/automationaccounts",
    "microsoft.recoveryservices/vaults",
    "microsoft.managedidentity/userassignedidentities",
    "microsoft.network/virtualnetworkgateways",
    "microsoft.network/applicationgateways",
    "microsoft.network/azurefirewalls",
}
```

**Processing:**
```go
for subscriptionID, subData := range azureResources {
    resources := getArrayValue(subMap, "azureResources")

    for _, resourceData := range resources {
        resourceMap := resourceData.(map[string]interface{})
        resourceType := strings.ToLower(getStringValue(resourceMap, "type"))

        // Filter: only security-relevant types
        if !isSecurityRelevant(resourceType) {
            continue
        }

        // Extract identity properties
        processIdentityData(resourceMap)

        // Create resource node
    }
}
```

**Cypher Pattern:**
```cypher
UNWIND $resources AS resource
MERGE (r:Resource:AzureResource {id: resource.id})
ON CREATE SET
    r.resourceType = resource.resourceType,
    r.displayName = resource.displayName,
    r.location = resource.location,
    r.subscriptionId = resource.subscriptionId,
    r.resourceGroup = resource.resourceGroup,
    r.identityType = resource.identityType,
    r.identityPrincipalId = resource.identityPrincipalId,
    r.userAssignedIdentities = resource.userAssignedIdentities,
    r.principalId = resource.principalId,
    r.metadata = COALESCE(resource.metadata, '{}')
```

## Identity Processing

**Function:** `processIdentityData()` - line 3234

Azure resources can have managed identities attached. The importer extracts identity properties from nested `identity` object:

### Step 1: Extract Identity Type

```go
if identity, ok := resourceMap["identity"]; ok {
    identityMap := identity.(map[string]interface{})
    identityType := getStringValue(identityMap, "type")

    if identityType != "None" && identityType != "" {
        resourceMap["identityType"] = identityType
    }
}
```

### Step 2: Extract System-Assigned Principal ID

```go
// If SystemAssigned (alone or combined with UserAssigned)
if strings.Contains(identityType, "SystemAssigned") {
    resourceMap["identityPrincipalId"] = getStringValue(identityMap, "principalId")
}
```

### Step 3: Extract User-Assigned Identities

```go
// If UserAssigned
if strings.Contains(identityType, "UserAssigned") {
    if userIdentities, ok := identityMap["userAssignedIdentities"]; ok {
        userIdMap := userIdentities.(map[string]interface{})

        // Extract resource IDs from map keys
        userAssignedMIResourceIds := []string{}
        for resourceId := range userIdMap {
            normalizedId := normalizeResourceId(resourceId)
            userAssignedMIResourceIds = append(userAssignedMIResourceIds, normalizedId)
        }

        resourceMap["userAssignedIdentities"] = userAssignedMIResourceIds
    }
}
```

### Step 4: Delete Complex Identity Object

```go
// Remove complex identity object for Neo4j compatibility
delete(resourceMap, "identity")
```

## Identity Type Values

| Value | Meaning | Properties Set |
|-------|---------|----------------|
| `"SystemAssigned"` | System-assigned MI only | `identityPrincipalId` |
| `"UserAssigned"` | User-assigned MIs only | `userAssignedIdentities` array |
| `"SystemAssigned,UserAssigned"` | Both types | `identityPrincipalId` + `userAssignedIdentities` |
| `"None"` or NULL | No identity | No identity properties |

## Related Edges

### Outgoing

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/resource-to-system-mi.md) - System-assigned managed identity (synthetic)
- [CAN_ESCALATE](../Azure_IAM_Edges/CAN_ESCALATE/) - To user-assigned MIs (via IMDS token theft)

### Incoming

- [CONTAINS](../Azure_IAM_Edges/CONTAINS/rg-to-resource.md) - Parent resource group

## Resource Types by Category

### Compute
- `microsoft.compute/virtualmachines` - Virtual machines
- `microsoft.containerservice/managedclusters` - AKS clusters
- `microsoft.web/sites` - App Services / Function Apps
- `microsoft.logic/workflows` - Logic Apps

### Storage
- `microsoft.storage/storageaccounts` - Storage accounts
- `microsoft.recoveryservices/vaults` - Recovery Services vaults

### Data
- `microsoft.sql/servers` - SQL servers
- `microsoft.dbforpostgresql/flexibleservers` - PostgreSQL servers
- `microsoft.dbformysql/flexibleservers` - MySQL servers
- `microsoft.documentdb/databaseaccounts` - Cosmos DB accounts

### Security
- `microsoft.keyvault/vaults` - Key vaults

### Networking
- `microsoft.network/virtualnetworkgateways` - VPN gateways
- `microsoft.network/applicationgateways` - Application gateways
- `microsoft.network/azurefirewalls` - Azure Firewalls

### Identity
- `microsoft.managedidentity/userassignedidentities` - User-assigned MIs

### Automation
- `microsoft.automation/automationaccounts` - Automation accounts
- `microsoft.cognitiveservices/accounts` - Cognitive Services accounts

## Query Examples

### Find all Azure resources
```cypher
MATCH (r:Resource:AzureResource)
RETURN r.displayName, r.resourceType, r.location
```

### Find VMs with system-assigned identities
```cypher
MATCH (vm:Resource:AzureResource)
WHERE toLower(vm.resourceType) = "microsoft.compute/virtualmachines"
  AND vm.identityPrincipalId IS NOT NULL
RETURN vm.displayName, vm.identityPrincipalId
```

### Find resources with user-assigned identities
```cypher
MATCH (resource:Resource:AzureResource)
WHERE resource.userAssignedIdentities IS NOT NULL
  AND size(resource.userAssignedIdentities) > 0
RETURN resource.displayName, resource.resourceType, resource.userAssignedIdentities
```

### Find Key Vaults
```cypher
MATCH (kv:Resource:AzureResource)
WHERE toLower(kv.resourceType) = "microsoft.keyvault/vaults"
RETURN kv.displayName, kv.location, kv.subscriptionId
```

### Find resources by location
```cypher
MATCH (r:Resource:AzureResource)
WHERE r.location = "eastus"
RETURN r.displayName, r.resourceType
```

### Find resources with their resource groups
```cypher
MATCH (rg:Resource:Hierarchy)-[:CONTAINS]->(resource:Resource:AzureResource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName as resource_group, resource.displayName as resource_name
```

### Find resources that can be compromised for IMDS access
```cypher
MATCH (resource:Resource:AzureResource)-[r:CAN_ESCALATE]->(mi:Resource)
WHERE r.method IN ["ResourceAttachedIdentity", "ResourceAttachedUserAssignedIdentity"]
RETURN resource.displayName, resource.resourceType, mi.displayName as managed_identity
```

## Test Cases

### Test 1: VM with System-Assigned Identity
**Input:**
```json
{
  "azure_resources": {
    "sub-test-001": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-001/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm",
          "name": "test-vm",
          "type": "Microsoft.Compute/virtualMachines",
          "location": "eastus",
          "resourceGroup": "test-rg",
          "identity": {
            "type": "SystemAssigned",
            "principalId": "system-mi-principal-001"
          }
        }
      ]
    }
  }
}
```

**Expected:**
- Node created with labels: `Resource:AzureResource`
- `identityType = "SystemAssigned"`
- `identityPrincipalId = "system-mi-principal-001"`
- `identity` object removed from final properties
- System-assigned MI node created separately

### Test 2: Resource with User-Assigned Identities
**Input:**
```json
{
  "azure_resources": {
    "sub-test-002": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-002/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app",
          "name": "test-app",
          "type": "Microsoft.Web/sites",
          "location": "westus",
          "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {
              "/subscriptions/sub-test-002/resourceGroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-1": {},
              "/subscriptions/sub-test-002/resourceGroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-2": {}
            }
          }
        }
      ]
    }
  }
}
```

**Expected:**
- `identityType = "UserAssigned"`
- `userAssignedIdentities = ["/subscriptions/sub-test-002/.../uami-1", "/subscriptions/sub-test-002/.../uami-2"]`
- Both resource IDs normalized to lowercase

### Test 3: Resource with Both Identity Types
**Input:**
```json
{
  "azure_resources": {
    "sub-test-003": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-003/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/hybrid-vm",
          "name": "hybrid-vm",
          "type": "Microsoft.Compute/virtualMachines",
          "identity": {
            "type": "SystemAssigned,UserAssigned",
            "principalId": "system-principal-003",
            "userAssignedIdentities": {
              "/subscriptions/sub-test-003/.../uami-1": {}
            }
          }
        }
      ]
    }
  }
}
```

**Expected:**
- `identityType = "SystemAssigned,UserAssigned"`
- `identityPrincipalId = "system-principal-003"`
- `userAssignedIdentities = ["/subscriptions/sub-test-003/.../uami-1"]`

### Test 4: Non-Security-Relevant Resource (Filtered)
**Input:**
```json
{
  "azure_resources": {
    "sub-test-004": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-004/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet",
          "name": "test-vnet",
          "type": "Microsoft.Network/virtualNetworks"
        }
      ]
    }
  }
}
```

**Expected:**
- No node created (virtualNetworks not in security-relevant filter)
- No errors thrown

### Test 5: Resource Without Identity
**Input:**
```json
{
  "azure_resources": {
    "sub-test-005": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-005/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage",
          "name": "teststorage",
          "type": "Microsoft.Storage/storageAccounts",
          "location": "eastus"
        }
      ]
    }
  }
}
```

**Expected:**
- Node created successfully
- No identity properties set (all NULL)
- No system-assigned MI created

### Test 6: User-Assigned Managed Identity Resource
**Input:**
```json
{
  "azure_resources": {
    "sub-test-006": {
      "azureResources": [
        {
          "id": "/subscriptions/sub-test-006/resourceGroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-test",
          "name": "uami-test",
          "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
          "location": "eastus",
          "properties": {
            "principalId": "uami-principal-006"
          }
        }
      ]
    }
  }
}
```

**Expected:**
- Node created with `Resource:AzureResource` labels
- `principalId = "uami-principal-006"` (for linking to SP)
- Metadata indicates user-assigned MI

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createAzureResourceNodes()` starting at line 1035

**Helper Function:** `processIdentityData()` starting at line 3234

**Batch Processing:** Resources processed in batches of 1000

**Security Filter:** Only 17 resource types imported

## Related Documentation

- [Data Schema](../Azure_IAM_Edges/data-schema.md#52-azureresources-array) - JSON input format
- [Resource Group Nodes](resource-group.md) - Parent nodes
- [System-Assigned MI Nodes](system-assigned-mi.md) - Created from identity properties
- [User-Assigned MI Nodes](user-assigned-mi.md) - Linked via userAssignedIdentities
- [RG CONTAINS Resource](../Azure_IAM_Edges/CONTAINS/rg-to-resource.md) - Parent edge
- [Resource CONTAINS System MI](../Azure_IAM_Edges/CONTAINS/resource-to-system-mi.md) - Identity edge
