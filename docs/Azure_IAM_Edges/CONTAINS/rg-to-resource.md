# Resource Group CONTAINS Azure Resources

Hierarchical relationship from resource groups to Azure resources.

## Edge Type

`CONTAINS`

## Direction

Resource Group → Azure Resource

## Properties

None (CONTAINS is a pure structural relationship with no additional metadata)

## Purpose

Represents the containment of Azure resources within resource groups. Resource groups are logical containers that hold related resources for an Azure solution.

## Source & Target Nodes

**Source:** [Resource Group Node](../../Azure_IAM_Nodes/resource-group.md)
- Labels: `Resource:Hierarchy`
- Type: `"Microsoft.Resources/resourceGroups"`

**Target:** [Azure Resource Node](../../Azure_IAM_Nodes/azure-resource.md)
- Labels: `Resource:AzureResource`
- Type: Security-relevant types (VMs, storage accounts, key vaults, etc.)
- **Excludes:** Subscriptions, resource groups, tenant nodes

## Creation Logic

**Function:** `createResourceGroupToResourceContains()` - line 1455

**Cypher:**
```cypher
MATCH (rg:Resource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
MATCH (resource:Resource)
WHERE toLower(resource.resourceType) STARTS WITH "microsoft."
AND toLower(resource.resourceType) <> "microsoft.resources/subscriptions"
AND toLower(resource.resourceType) <> "microsoft.resources/resourcegroups"
AND toLower(resource.resourceType) <> "microsoft.directoryservices/tenant"
AND resource.resourceGroup IS NOT NULL
AND resource.resourceGroup = rg.displayName
MERGE (rg)-[:CONTAINS]->(resource)
```

**Key Logic:**
- No explicit data extraction (graph-based matching)
- Matches resources by `resourceGroup` property against RG `displayName`
- Filters out hierarchy nodes (subscriptions, RGs, tenant)

## Matching Logic

### Resource Group Matching
- Match all RG nodes by resourceType
- Use `displayName` for resource matching

### Resource Matching
- Must have `resourceGroup` property set
- resourceType must start with `"microsoft."`
- Exclude hierarchy types (subscriptions, resource groups, tenant)
- `resourceGroup` name must match RG `displayName`

### Property-Based Matching
```cypher
resource.resourceGroup = rg.displayName
```

**Note:** Matches by name, not ID. Resource stores RG name, not full RG ID.

## Source Data

**No explicit source data** - relationships derived from resource properties

**Implicit Data:**
- Resources created with `resourceGroup` property extracted from resource ID
- Resource groups created with normalized `displayName`
- Property matching connects resources to parent RG

## Conditional Logic

### Prerequisites
- Resource group nodes must exist (created in Phase 1-3)
- Azure resource nodes must exist (created in Phase 1-3)

### Resource Filtering
```cypher
WHERE toLower(resource.resourceType) STARTS WITH "microsoft."
AND toLower(resource.resourceType) <> "microsoft.resources/subscriptions"
AND toLower(resource.resourceType) <> "microsoft.resources/resourcegroups"
AND toLower(resource.resourceType) <> "microsoft.directoryservices/tenant"
AND resource.resourceGroup IS NOT NULL
```

**Included:** All security-relevant Azure resources
**Excluded:**
- Subscriptions (hierarchy node, not a resource)
- Resource groups (hierarchy node, not a resource)
- Tenant (hierarchy node, not a resource)
- Resources without `resourceGroup` property

### Silent Failure
If no matching RG found for resource, no edge created (no error logged)

## Hierarchy Position

```
Subscription
  └─ Resource Group (prod-rg)
       ├─ Virtual Machine
       ├─ Storage Account
       ├─ Key Vault
       └─ Network Security Group
```

**Key Characteristics:**
- **One Parent:** Each resource belongs to exactly one RG
- **Lifecycle Bound:** Deleting RG deletes all contained resources
- **RBAC Boundary:** Permissions can be assigned at RG level

## Security-Relevant Resource Types

**Included Resource Types (17 types):**
- `Microsoft.Compute/virtualMachines` - VMs
- `Microsoft.Storage/storageAccounts` - Storage
- `Microsoft.KeyVault/vaults` - Key Vaults
- `Microsoft.Sql/servers` - SQL Servers
- `Microsoft.DBforMySQL/flexibleServers` - MySQL
- `Microsoft.DBforPostgreSQL/flexibleServers` - PostgreSQL
- `Microsoft.ContainerService/managedClusters` - AKS
- `Microsoft.Web/sites` - App Services
- `Microsoft.ManagedIdentity/userAssignedIdentities` - User-assigned MIs
- `Microsoft.Network/virtualNetworks` - Virtual Networks
- `Microsoft.Network/networkSecurityGroups` - NSGs
- `Microsoft.Network/publicIPAddresses` - Public IPs
- `Microsoft.ContainerRegistry/registries` - Container Registries
- `Microsoft.Compute/disks` - Managed Disks
- `Microsoft.Automation/automationAccounts` - Automation Accounts
- `Microsoft.OperationalInsights/workspaces` - Log Analytics
- `Microsoft.Insights/components` - Application Insights

See [Azure Resource Node documentation](../../Azure_IAM_Nodes/azure-resource.md#security-relevant-resource-types) for filtering logic.

## Query Examples

### Find all resources in a resource group
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(resource:Resource)
WHERE rg.displayName = "prod-rg"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN resource.displayName,
       resource.resourceType,
       resource.location
```

### Find resource group of a resource
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(resource:Resource)
WHERE resource.displayName = "prod-vm-01"
  AND toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName, rg.location
```

### Count resources per resource group
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(resource:Resource:AzureResource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
RETURN rg.displayName,
       rg.subscriptionId,
       count(resource) as resource_count
ORDER BY resource_count DESC
```

### Find resources without parent RGs (orphaned resources)
```cypher
MATCH (resource:Resource:AzureResource)
WHERE NOT (:Resource)-[:CONTAINS]->(resource)
RETURN resource.displayName,
       resource.resourceType,
       resource.resourceGroup
```

### Find empty resource groups (no resources)
```cypher
MATCH (rg:Resource)
WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
  AND NOT (rg)-[:CONTAINS]->(:Resource:AzureResource)
RETURN rg.displayName, rg.location, rg.subscriptionId
```

### Find resources by type in resource group
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(resource:Resource)
WHERE rg.displayName = "prod-rg"
  AND toLower(resource.resourceType) = "microsoft.compute/virtualmachines"
RETURN resource.displayName, resource.location
```

### Find all VMs across all resource groups
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(vm:Resource)
WHERE toLower(vm.resourceType) = "microsoft.compute/virtualmachines"
RETURN rg.displayName as resource_group,
       vm.displayName as vm_name,
       vm.location
```

## Test Cases

### Test 1: RG-Resource Relationship - Normal Case
**Input:**
- RG node: `displayName = "prod-rg"`
- Resource node:
  - `resourceType = "Microsoft.Compute/virtualMachines"`
  - `resourceGroup = "prod-rg"`

**Expected:**
- CONTAINS edge: RG → Resource

**Verification:**
```cypher
MATCH (rg {displayName: "prod-rg"})-[r:CONTAINS]->(vm {resourceType: ~"(?i).*virtualmachines"})
RETURN count(r) as edge_count
// Expected: edge_count = 1
```

### Test 2: Multiple Resources in Same RG
**Input:**
- RG node: `displayName = "prod-rg"`
- Resource nodes:
  - VM: `resourceGroup = "prod-rg"`
  - Storage: `resourceGroup = "prod-rg"`
  - KeyVault: `resourceGroup = "prod-rg"`

**Expected:**
- 3 CONTAINS edges created, all from same RG
- Each resource has independent edge

**Verification:**
```cypher
MATCH (rg {displayName: "prod-rg"})-[:CONTAINS]->(resource)
RETURN count(resource) as resource_count
// Expected: resource_count = 3
```

### Test 3: Resources in Different RGs
**Input:**
- RG A: `displayName = "rg-a"`
- RG B: `displayName = "rg-b"`
- Resource 1: `resourceGroup = "rg-a"`
- Resource 2: `resourceGroup = "rg-b"`

**Expected:**
- CONTAINS edge: rg-a → resource-1
- CONTAINS edge: rg-b → resource-2
- NO cross-RG edges

**Verification:**
```cypher
MATCH (rgA {displayName: "rg-a"})-[:CONTAINS]->(r1)
MATCH (rgB {displayName: "rg-b"})-[:CONTAINS]->(r2)
RETURN count(r1) as rg_a_resources, count(r2) as rg_b_resources
// Expected: rg_a_resources = 1, rg_b_resources = 1
```

### Test 4: Idempotency
**Action:** Run import twice with same nodes

**Expected:**
- Only one edge created per RG-resource pair (MERGE ensures idempotency)
- No duplicate edges

**Verification:**
```cypher
MATCH (rg {displayName: "test-rg"})-[r:CONTAINS]->(resource {displayName: "test-vm"})
RETURN count(r) as edge_count
// Expected: edge_count = 1 (not 2)
```

### Test 5: Missing RG Node
**Setup:** Delete RG node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for resource)
- No errors logged
- Resource node unaffected

### Test 6: Missing Resource Node
**Setup:** Delete resource node before edge creation phase

**Expected:**
- No edge created (MATCH fails silently for RG)
- No errors logged
- RG node unaffected

### Test 7: Resource Without resourceGroup Property
**Input:**
- Resource node without `resourceGroup` property set

**Expected:**
- No CONTAINS edge created (filter excludes resources without property)
- Resource remains orphaned

### Test 8: Hierarchy Nodes Excluded
**Input:**
- Subscription node with `resourceGroup = "some-rg"`
- RG node with `resourceGroup = "parent-rg"`
- Tenant node

**Expected:**
- NO CONTAINS edges to hierarchy nodes
- Type filters exclude subscriptions, RGs, tenant

**Verification:**
```cypher
MATCH (rg:Resource)-[:CONTAINS]->(hierarchyNode:Resource)
WHERE toLower(hierarchyNode.resourceType) IN [
  "microsoft.resources/subscriptions",
  "microsoft.resources/resourcegroups",
  "microsoft.directoryservices/tenant"
]
RETURN count(hierarchyNode) as invalid_edges
// Expected: invalid_edges = 0
```

### Test 9: Case Insensitivity
**Input:**
- RG node: `displayName = "PROD-RG"` (uppercase)
- Resource node: `resourceGroup = "prod-rg"` (lowercase)

**Expected:**
- Match succeeds (property comparison is case-sensitive in Neo4j)
- Edge created if names match exactly

**Note:** RG names normalized to lowercase during creation, so this case shouldn't occur in practice.

### Test 10: Non-Microsoft Resource Types (Excluded)
**Input:**
- Resource node: `resourceType = "CustomProvider/customType"`

**Expected:**
- No CONTAINS edge created (filter requires "microsoft." prefix)
- Only Microsoft resource types included

## Implementation

**File:** `nebula/pkg/links/azure/iam/neo4j_importer.go`

**Function:** `createResourceGroupToResourceContains()` starting at line 1455

**Phase:** 2a (after node creation, part of createContainsEdges)

**Batch Processing:** Single transaction (graph-based pattern matching, no batching needed)

**Method:** Pure Cypher pattern matching (no Go data extraction)

## Error Handling

**Silent Failure:** If MATCH fails (nodes don't exist or properties don't match), no edge created and no error logged

**Why:** Allows partial imports to succeed; missing nodes or mismatched properties logged separately during node creation

**Property Matching:** Relies on exact match of resource's `resourceGroup` property to RG's `displayName`

## Azure Behavior Notes

**Resource Group Lifecycle:**
- All resources MUST belong to a resource group
- Deleting a resource group deletes ALL contained resources
- Resources cannot exist without a parent RG

**Naming Constraints:**
- RG names must be unique within a subscription
- RG names are case-insensitive in Azure
- Resource `resourceGroup` property stores RG name (not ID)

**RBAC Inheritance:**
- Permissions assigned at RG level inherited by all resources
- Resource-level permissions override RG-level permissions
- RBAC edges created separately in Phase 2b-2d

## Related Documentation

- [Resource Group Node](../../Azure_IAM_Nodes/resource-group.md) - Source node
- [Azure Resource Node](../../Azure_IAM_Nodes/azure-resource.md) - Target node
- [Subscription CONTAINS RG](subscription-to-rg.md) - Parent edge
- [../overview.md](../overview.md) - Hierarchy overview
