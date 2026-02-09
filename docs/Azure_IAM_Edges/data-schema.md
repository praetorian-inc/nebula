# Azure IAM Data Schema - JSON Contract

This document defines the complete JSON data contract between the Azure IAM collector and Neo4j importer.

## Overview

The collector produces a JSON file with this structure that the importer consumes to create the graph.

## Top-Level Structure

```json
{
  "collection_metadata": { ... },
  "azure_ad": { ... },
  "pim": { ... },
  "management_groups": [ ... ],
  "azure_resources": { ... }
}
```

**File Flow:**
```
collector.go (Process)
  → l.Send(consolidatedData) at line 298
  → RuntimeJSONOutputter writes to file

neo4j_importer.go (Process)
  → loadConsolidatedData() reads JSON file
  → l.consolidatedData = parsed JSON
```

---

## 1. collection_metadata (object)

Metadata about the collection run.

**Structure:**
```json
{
  "tenant_id": "string",
  "collection_timestamp": "2006-01-02T15:04:05Z",
  "subscriptions_processed": int,
  "domain": "string",
  "display_name": "string",
  "collector_versions": {
    "nebula_collector": "comprehensive",
    "graph_collector": "completed",
    "pim_collector": "completed",
    "azurerm_collector": "completed"
  },
  "data_summary": {
    "total_azure_ad_objects": int,
    "total_pim_objects": int,
    "total_management_groups": int,
    "total_azurerm_objects": int,
    "total_objects": int
  }
}
```

**Required Fields:**
- `tenant_id`: Azure AD tenant GUID

**Optional Fields:**
- `domain`: Tenant domain name
- `display_name`: Tenant display name
- `collection_timestamp`: When collection occurred
- `subscriptions_processed`: Number of subscriptions collected

**Used By:**
- [Tenant node creation](NODES/tenant.md)
- [Root Management Group creation](NODES/management-group.md)

---

## 2. azure_ad (object)

Contains all Azure AD / Entra ID identity and permission data.

### 2.1 azure_ad.users (array)

**Structure:**
```json
{
  "users": [
    {
      "id": "string",
      "displayName": "string",
      "userPrincipalName": "string",
      "mail": "string",
      "jobTitle": "string",
      "department": "string",
      "accountEnabled": boolean,
      "userType": "string",
      "createdDateTime": "string"
    }
  ]
}
```

**Required Fields:**
- `id`: User object ID (GUID)
- `displayName`: User display name
- `userPrincipalName`: User UPN

**Optional Fields:**
- `mail`: Email address
- `userType`: "Member" or "Guest"
- `accountEnabled`: Account status
- Other metadata fields

**Used By:** [User node creation](NODES/user.md)

---

### 2.2 azure_ad.groups (array)

**Structure:**
```json
{
  "groups": [
    {
      "id": "string",
      "displayName": "string",
      "description": "string",
      "groupTypes": ["string"],
      "membershipRule": "string",
      "mailEnabled": boolean,
      "securityEnabled": boolean,
      "createdDateTime": "string"
    }
  ]
}
```

**Required Fields:**
- `id`: Group object ID (GUID)
- `displayName`: Group display name

**Optional Fields:**
- `description`: Group description
- `securityEnabled`: Security group flag
- `mailEnabled`: Mail-enabled flag
- `groupTypes`: Array of group types

**Used By:** [Group node creation](NODES/group.md)

---

### 2.3 azure_ad.servicePrincipals (array)

**Structure:**
```json
{
  "servicePrincipals": [
    {
      "id": "string",
      "appId": "string",
      "displayName": "string",
      "servicePrincipalType": "string",
      "accountEnabled": boolean,
      "createdDateTime": "string"
    }
  ]
}
```

**Required Fields:**
- `id`: Service Principal object ID (GUID)
- `appId`: Application (client) ID
- `displayName`: SP display name

**Optional Fields:**
- `servicePrincipalType`: "Application", "ManagedIdentity", etc.
- `accountEnabled`: Account status

**Used By:** [Service Principal node creation](NODES/service-principal.md)

---

### 2.4 azure_ad.applications (array)

**Structure:**
```json
{
  "applications": [
    {
      "id": "string",
      "appId": "string",
      "displayName": "string",
      "signInAudience": "string",
      "keyCredentials": [object],
      "passwordCredentials": [object],
      "credentialSummary_hasCredentials": boolean,
      "credentialSummary_totalCredentials": int,
      "credentialSummary_passwordCredentials": int,
      "credentialSummary_keyCredentials": int
    }
  ]
}
```

**Required Fields:**
- `id`: Application object ID (GUID)
- `appId`: Application (client) ID
- `displayName`: Application display name

**Optional Fields:**
- `signInAudience`: "AzureADMyOrg", etc.
- `credentialSummary_*`: Credential counts

**Used By:** [Application node creation](NODES/application.md)

---

### 2.5 azure_ad.groupMemberships (array)

**Structure:**
```json
{
  "groupMemberships": [
    {
      "groupId": "string",
      "memberId": "string",
      "memberType": "string"
    }
  ]
}
```

**Required Fields:**
- `groupId`: Group object ID
- `memberId`: Member object ID
- `memberType`: "User", "Group", "ServicePrincipal"

**Used By:** [Group CONTAINS Member edge](CONTAINS/group-to-member.md)

---

### 2.6 azure_ad.groupOwnership (array)

**Structure:**
```json
{
  "groupOwnership": [
    {
      "groupId": "string",
      "ownerId": "string",
      "ownerType": "string"
    }
  ]
}
```

**Used By:** [Group ownership edge](OWNS/group-ownership.md)

---

### 2.7 azure_ad.servicePrincipalOwnership (array)

**Structure:**
```json
{
  "servicePrincipalOwnership": [
    {
      "servicePrincipalId": "string",
      "ownerId": "string",
      "ownerType": "string"
    }
  ]
}
```

**Used By:** [Service Principal ownership edge](OWNS/service-principal-ownership.md)

---

### 2.8 azure_ad.applicationOwnership (array)

**Structure:**
```json
{
  "applicationOwnership": [
    {
      "applicationId": "string",
      "ownerId": "string",
      "ownerType": "string"
    }
  ]
}
```

**Used By:** [Application ownership edge](OWNS/application-ownership.md)

---

### 2.9 azure_ad.directoryRoleAssignments (array)

**Structure:**
```json
{
  "directoryRoleAssignments": [
    {
      "id": "string",
      "principalId": "string",
      "principalType": "string",
      "roleDefinitionId": "string",
      "directoryScopeId": "string"
    }
  ]
}
```

**Used By:** [HAS_PERMISSION edge creation](HAS_PERMISSION/)

---

### 2.10 azure_ad.oauth2PermissionGrants (array)

**Structure:**
```json
{
  "oauth2PermissionGrants": [
    {
      "id": "string",
      "clientId": "string",
      "consentType": "string",
      "principalId": "string",
      "resourceId": "string",
      "scope": "string"
    }
  ]
}
```

**Used By:** [HAS_PERMISSION Graph API permissions](HAS_PERMISSION/)

---

### 2.11 azure_ad.appRoleAssignments (array)

**Structure:**
```json
{
  "appRoleAssignments": [
    {
      "id": "string",
      "principalId": "string",
      "principalType": "string",
      "resourceId": "string",
      "appRoleId": "string"
    }
  ]
}
```

**Used By:** [HAS_PERMISSION Graph API permissions](HAS_PERMISSION/)

---

## 3. pim (object)

Privileged Identity Management data.

**Structure:**
```json
{
  "eligible_assignments": [
    {
      "id": "string",
      "principalId": "string",
      "roleDefinitionId": "string",
      "directoryScopeId": "string",
      "startDateTime": "string",
      "endDateTime": "string",
      "assignmentType": "Eligible"
    }
  ],
  "active_assignments": [
    {
      "id": "string",
      "principalId": "string",
      "roleDefinitionId": "string",
      "directoryScopeId": "string",
      "startDateTime": "string",
      "endDateTime": "string",
      "assignmentType": "Active"
    }
  ]
}
```

**Used By:** [PIM enrichment of HAS_PERMISSION edges](overview.md#pim-privileged-identity-management-enrichment)

---

## 4. management_groups (array)

Management group hierarchy containing BOTH management groups AND subscriptions with parent references.

**Structure:**
```json
[
  {
    "id": "/providers/Microsoft.Management/managementGroups/my-mg",
    "name": "my-mg",
    "type": "microsoft.management/managementgroups",
    "properties": {
      "displayName": "Production Management Group",
      "parent": {
        "name": "parent-mg-id"
      }
    }
  },
  {
    "id": "/subscriptions/sub-guid",
    "name": "sub-guid",
    "type": "microsoft.resources/subscriptions",
    "ParentId": "/providers/Microsoft.Management/managementGroups/parent-mg"
  }
]
```

**Used By:**
- [Management Group node creation](NODES/management-group.md)
- [MG CONTAINS Child MG edges](CONTAINS/mg-to-child-mg.md)
- [MG CONTAINS Subscription edges](CONTAINS/mg-to-subscription.md)

---

## 5. azure_resources (object)

Per-subscription map of Azure RM resources and RBAC. Keys are subscription GUIDs.

**Structure:**
```json
{
  "subscription-guid": {
    "subscriptionRoleAssignments": [ ... ],
    "resourceGroupRoleAssignments": [ ... ],
    "resourceLevelRoleAssignments": [ ... ],
    "azureResourceGroups": [ ... ],
    "azureResources": [ ... ],
    "azureRoleDefinitions": [ ... ]
  }
}
```

---

### 5.1 azureResourceGroups (array)

**Structure:**
```json
{
  "azureResourceGroups": [
    {
      "id": "/subscriptions/sub-guid/resourceGroups/my-rg",
      "name": "my-rg",
      "type": "microsoft.resources/resourcegroups",
      "location": "eastus"
    }
  ]
}
```

**Used By:** [Resource Group node creation](NODES/resource-group.md)

---

### 5.2 azureResources (array)

**Structure:**
```json
{
  "azureResources": [
    {
      "id": "/subscriptions/sub-guid/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
      "name": "vm1",
      "type": "Microsoft.Compute/virtualMachines",
      "location": "eastus",
      "resourceGroup": "my-rg",
      "identity": {
        "type": "SystemAssigned",
        "principalId": "principal-guid"
      },
      "properties": { ... }
    }
  ]
}
```

**Security-Relevant Types Only:**
Only these resource types are imported:
- `microsoft.compute/virtualmachines`
- `microsoft.containerservice/managedclusters`
- `microsoft.storage/storageaccounts`
- `microsoft.keyvault/vaults`
- `microsoft.sql/servers`
- `microsoft.dbforpostgresql/flexibleservers`
- `microsoft.dbformysql/flexibleservers`
- `microsoft.documentdb/databaseaccounts`
- `microsoft.web/sites`
- `microsoft.logic/workflows`
- `microsoft.cognitiveservices/accounts`
- `microsoft.automation/automationaccounts`
- `microsoft.recoveryservices/vaults`
- `microsoft.managedidentity/userassignedidentities`
- `microsoft.network/virtualnetworkgateways`
- `microsoft.network/applicationgateways`
- `microsoft.network/azurefirewalls`

**Used By:** [Azure Resource node creation](NODES/azure-resource.md)

---

### 5.3 subscriptionRoleAssignments (array)

**Structure:**
```json
{
  "subscriptionRoleAssignments": [
    {
      "id": "/subscriptions/sub-guid/providers/Microsoft.Authorization/roleAssignments/assignment-guid",
      "name": "assignment-guid",
      "properties": {
        "principalId": "string",
        "principalType": "string",
        "roleDefinitionId": "/subscriptions/sub-guid/providers/Microsoft.Authorization/roleDefinitions/role-guid",
        "scope": "/subscriptions/sub-guid"
      }
    }
  ]
}
```

**Used By:** [HAS_PERMISSION Azure RBAC edges](HAS_PERMISSION/owner.md)

---

### 5.4 resourceGroupRoleAssignments (array)

Same structure as subscriptionRoleAssignments, but scope is resource group level.

---

### 5.5 resourceLevelRoleAssignments (array)

Same structure as subscriptionRoleAssignments, but scope is individual resource level.

---

## Importer Access Patterns

The importer accesses data using these helper methods:

```go
// Get top-level objects
tenantID := l.getStringValue(l.getMapValue(l.consolidatedData, "collection_metadata"), "tenant_id")
azureADData := l.getMapValue(l.consolidatedData, "azure_ad")
pimData := l.getMapValue(l.consolidatedData, "pim")
managementGroups := l.getArrayValue(l.consolidatedData, "management_groups")
azureResources := l.getMapValue(l.consolidatedData, "azure_resources")

// Get arrays within azure_ad
users := l.getArrayValue(azureADData, "users")
groups := l.getArrayValue(azureADData, "groups")

// Get subscription data
for subscriptionID, subData := range azureResources {
    subMap := subData.(map[string]interface{})
    resources := l.getArrayValue(subMap, "azureResources")
}
```

**Helper Functions:**
- `getMapValue(data, key)` → `map[string]interface{}`
- `getArrayValue(data, key)` → `[]interface{}`
- `getStringValue(data, key)` → `string`
- `getBoolValue(data, key)` → `bool`
- `getIntValue(data, key)` → `int`

---

## Validation

The importer expects:
1. **Exact field names** - any deviation breaks import
2. **Case-insensitive type matching** - all resource types normalized to lowercase
3. **Optional fields** - gracefully handles missing optional fields
4. **ID normalization** - all IDs converted to lowercase for matching

---

## Test Fixture Creation

When creating test fixtures:

1. **Minimal valid structure:**
```json
{
  "collection_metadata": {
    "tenant_id": "test-tenant-id"
  },
  "azure_ad": {
    "users": [],
    "groups": [],
    "servicePrincipals": [],
    "applications": []
  },
  "pim": {
    "eligible_assignments": [],
    "active_assignments": []
  },
  "management_groups": [],
  "azure_resources": {}
}
```

2. **Add entities** to appropriate arrays
3. **Ensure IDs are consistent** across relationships
4. **Use lowercase for resource types** to match importer expectations

---

## Related Documentation

- [Node Types](NODES/) - How nodes are created from this data
- [Edge Types](CONTAINS/) - How edges are created from this data
- [Collector Implementation](../../pkg/links/azure/iam/collector.go) - Data collection code
- [Importer Implementation](../../pkg/links/azure/iam/neo4j_importer.go) - Data parsing code
