# Azure/Entra ID Test Environment Provisioning Plan

This document specifies the exact Azure and Entra ID resources needed to achieve 100% coverage of all node and edge creation logic in the Nebula IAM importer.

## Overview

**Goal**: Create a minimal test environment that triggers all 11 node types and 11 edge types (8 CONTAINS + 3 OWNS)

**Approach**: Single test environment with structured resource naming for easy verification

**Estimated Cost**: ~$50-70/month (dev/test tier resources with auto-shutdown, excludes optional AKS cluster)

---

## Test Environment Architecture

```
Tenant (automatic)
└─ Root Management Group (automatic)
    ├─ MG-Test-L1 (Management Group - Level 1)
    │   ├─ MG-Test-L2 (Management Group - Level 2)
    │   │   └─ Subscription-Test-A (assigned to nested MG)
    │   └─ MG-Test-L2-Sibling (Management Group - Level 2 sibling)
    └─ Subscription-Test-Orphan (orphan subscription - assigned to root MG)

Subscription-Test-A
├─ RG-Test-Compute
│   ├─ VM-Test-SystemMI (B1s VM with system-assigned MI)
│   └─ VM-Test-BothMI (B1s VM with system + user-assigned MI)
├─ RG-Test-Storage
│   ├─ StorageAccount-Test (Standard LRS)
│   └─ KeyVault-Test (Standard tier)
└─ RG-Test-Identity
    └─ UAMI-Test-01 (User-Assigned Managed Identity)

Entra ID (Directory)
├─ Users
│   ├─ user-test-01@{domain} (Member, enabled)
│   ├─ user-test-02@{domain} (Member, disabled)
│   └─ guest-test-01#EXT#@{domain} (Guest, enabled)
├─ Groups
│   ├─ Group-Test-Security (Security group, static membership)
│   │   ├─ user-test-01 (member)
│   │   └─ SP-App-Test-01 (member)
│   ├─ Group-Test-M365 (Microsoft 365 group)
│   │   └─ user-test-02 (member)
│   ├─ Group-Test-Dynamic (Dynamic security group with membershipRule)
│   └─ Group-Test-Nested (Nested group)
│       └─ Group-Test-Security (nested member - transitive permissions)
├─ Applications
│   ├─ App-Test-01 (Single-tenant, with password credential)
│   │   └─ SP-App-Test-01 (backing service principal - automatic)
│   └─ App-Test-02 (Multi-tenant, with certificate credential)
│       └─ SP-App-Test-02 (backing service principal - automatic)
├─ Service Principals (backing identities)
│   ├─ SP-App-Test-01 (Application type, from App-Test-01)
│   ├─ SP-App-Test-02 (Application type, from App-Test-02)
│   ├─ SP-UAMI-Test-01 (ManagedIdentity type, from UAMI-Test-01)
│   ├─ SP-SystemMI-VM-01 (ManagedIdentity type, from VM-Test-SystemMI)
│   └─ SP-SystemMI-VM-02 (ManagedIdentity type, from VM-Test-BothMI)
└─ Ownership
    ├─ App-Test-01 owned by user-test-01
    ├─ Group-Test-Security owned by user-test-01 and SP-App-Test-01
    └─ SP-App-Test-02 owned by user-test-02
```

---

## Resource Provisioning Checklist

### Phase 1: Entra ID Resources (No Cost)

#### 1.1 Users (3 users)

```bash
# User 1: Standard member user (enabled)
az ad user create \
  --display-name "Test User 01" \
  --user-principal-name "user-test-01@{domain}" \
  --password "{SecurePassword123!}" \
  --account-enabled true

# User 2: Disabled member user
az ad user create \
  --display-name "Test User 02" \
  --user-principal-name "user-test-02@{domain}" \
  --password "{SecurePassword123!}" \
  --account-enabled false

# User 3: Guest user (invite external user)
az ad user create \
  --display-name "Test Guest 01" \
  --user-principal-name "guest-test-01@externaldomain.com" \
  --user-type Guest
```

**Expected Nodes**: 3 User nodes
- `user-test-01@{domain}` (accountEnabled=true, userType="Member")
- `user-test-02@{domain}` (accountEnabled=false, userType="Member")
- `guest-test-01#EXT#@{domain}` (accountEnabled=true, userType="Guest")

---

#### 1.2 Applications (2 applications → 2 service principals automatic)

```bash
# Application 1: Single-tenant with password credential
APP_01_ID=$(az ad app create \
  --display-name "App-Test-01" \
  --sign-in-audience "AzureADMyOrg" \
  --query appId -o tsv)

# Add password credential to App-Test-01
az ad app credential reset \
  --id $APP_01_ID \
  --append \
  --years 1

# Application 2: Multi-tenant with certificate credential
APP_02_ID=$(az ad app create \
  --display-name "App-Test-02" \
  --sign-in-audience "AzureADMultipleOrgs" \
  --query appId -o tsv)

# Add certificate credential to App-Test-02
az ad app credential reset \
  --id $APP_02_ID \
  --cert "@cert.pem" \
  --append
```

**Expected Nodes**:
- 2 Application nodes (App-Test-01, App-Test-02)
- 2 Service Principal nodes (SP-App-Test-01, SP-App-Test-02) - **automatic**

**Expected Edges**:
- Application → SP CONTAINS edges (2 edges) - **automatic**

---

#### 1.3 Groups (4 groups)

```bash
# Group 1: Security group (static membership)
GROUP_SEC_ID=$(az ad group create \
  --display-name "Group-Test-Security" \
  --mail-nickname "group-test-security" \
  --description "Static security group for testing" \
  --query id -o tsv)

# Group 2: Microsoft 365 group
GROUP_M365_ID=$(az ad group create \
  --display-name "Group-Test-M365" \
  --mail-nickname "group-test-m365" \
  --description "M365 group for testing" \
  --group-types "Unified" \
  --mail-enabled true \
  --security-enabled false \
  --query id -o tsv)

# Group 3: Dynamic security group with membership rule
GROUP_DYN_ID=$(az ad group create \
  --display-name "Group-Test-Dynamic" \
  --mail-nickname "group-test-dynamic" \
  --description "Dynamic group for testing" \
  --group-types "DynamicMembership" \
  --security-enabled true \
  --membership-rule "user.userType -eq \"Member\"" \
  --membership-rule-processing-state "On" \
  --query id -o tsv)

# Group 4: Nested group (for transitive permissions)
GROUP_NESTED_ID=$(az ad group create \
  --display-name "Group-Test-Nested" \
  --mail-nickname "group-test-nested" \
  --description "Nested group container" \
  --query id -o tsv)
```

**Expected Nodes**: 4 Group nodes

---

#### 1.4 Group Memberships

```bash
# Add user-test-01 to Group-Test-Security
az ad group member add \
  --group $GROUP_SEC_ID \
  --member-id $(az ad user show --id "user-test-01@{domain}" --query id -o tsv)

# Add SP-App-Test-01 to Group-Test-Security
az ad group member add \
  --group $GROUP_SEC_ID \
  --member-id $(az ad sp show --id $APP_01_ID --query id -o tsv)

# Add user-test-02 to Group-Test-M365
az ad group member add \
  --group $GROUP_M365_ID \
  --member-id $(az ad user show --id "user-test-02@{domain}" --query id -o tsv)

# Add Group-Test-Security to Group-Test-Nested (nested group)
az ad group member add \
  --group $GROUP_NESTED_ID \
  --member-id $GROUP_SEC_ID
```

**Expected Edges**: 4 Group → Member CONTAINS edges
- Group-Test-Security → user-test-01
- Group-Test-Security → SP-App-Test-01
- Group-Test-M365 → user-test-02
- Group-Test-Nested → Group-Test-Security (nested group)

---

#### 1.5 Ownership Assignments

```bash
# Application ownership: user-test-01 owns App-Test-01
az ad app owner add \
  --id $APP_01_ID \
  --owner-object-id $(az ad user show --id "user-test-01@{domain}" --query id -o tsv)

# Group ownership: user-test-01 and SP-App-Test-01 own Group-Test-Security
az ad group owner add \
  --group $GROUP_SEC_ID \
  --owner-object-id $(az ad user show --id "user-test-01@{domain}" --query id -o tsv)

az ad group owner add \
  --group $GROUP_SEC_ID \
  --owner-object-id $(az ad sp show --id $APP_01_ID --query id -o tsv)

# Service principal ownership: user-test-02 owns SP-App-Test-02
az ad sp owner add \
  --id $(az ad sp show --id $APP_02_ID --query id -o tsv) \
  --owner-object-id $(az ad user show --id "user-test-02@{domain}" --query id -o tsv)
```

**Expected Edges**: 4 OWNS edges
- user-test-01 → App-Test-01 (application ownership)
- user-test-01 → Group-Test-Security (group ownership)
- SP-App-Test-01 → Group-Test-Security (group ownership)
- user-test-02 → SP-App-Test-02 (service principal ownership)

---

### Phase 2: Azure Management Hierarchy (No Cost)

#### 2.1 Management Groups

```bash
# Create Level 1 MG under root
az account management-group create \
  --name "MG-Test-L1" \
  --display-name "MG-Test-L1"

# Create Level 2 MG under Level 1
az account management-group create \
  --name "MG-Test-L2" \
  --display-name "MG-Test-L2" \
  --parent "MG-Test-L1"

# Create Level 2 sibling MG
az account management-group create \
  --name "MG-Test-L2-Sibling" \
  --display-name "MG-Test-L2-Sibling" \
  --parent "MG-Test-L1"
```

**Expected Nodes**: 4 Management Group nodes
- Root MG (automatic)
- MG-Test-L1
- MG-Test-L2
- MG-Test-L2-Sibling

**Expected Edges**: 3 MG → MG CONTAINS edges
- Root MG → MG-Test-L1
- MG-Test-L1 → MG-Test-L2
- MG-Test-L1 → MG-Test-L2-Sibling

---

#### 2.2 Subscription Assignments

```bash
# Get subscription IDs (assuming 2 test subscriptions exist)
SUB_A_ID=$(az account list --query "[?name=='Subscription-Test-A'].id" -o tsv)
SUB_ORPHAN_ID=$(az account list --query "[?name=='Subscription-Test-Orphan'].id" -o tsv)

# Assign Subscription-Test-A to MG-Test-L2
az account management-group subscription add \
  --name "MG-Test-L2" \
  --subscription $SUB_A_ID

# Leave Subscription-Test-Orphan unassigned (becomes orphan → assigned to root MG)
# No action needed - orphan detection automatic
```

**Expected Nodes**: 2 Subscription nodes
- Subscription-Test-A (parentId = "MG-Test-L2")
- Subscription-Test-Orphan (no explicit parentId → orphan)

**Expected Edges**: 2 MG → Subscription CONTAINS edges
- MG-Test-L2 → Subscription-Test-A
- Root MG → Subscription-Test-Orphan (orphan detection)

---

### Phase 3: Azure Resources (Cost: ~$20-30/month)

#### 3.1 Resource Groups

```bash
# Set active subscription
az account set --subscription $SUB_A_ID

# Create resource groups
az group create --name "RG-Test-Compute" --location "eastus"
az group create --name "RG-Test-Storage" --location "eastus"
az group create --name "RG-Test-Identity" --location "eastus"
```

**Expected Nodes**: 3 Resource Group nodes
- RG-Test-Compute
- RG-Test-Storage
- RG-Test-Identity

**Expected Edges**: 3 Subscription → RG CONTAINS edges
- Subscription-Test-A → RG-Test-Compute
- Subscription-Test-A → RG-Test-Storage
- Subscription-Test-A → RG-Test-Identity

---

#### 3.2 User-Assigned Managed Identity

```bash
# Create UAMI in RG-Test-Identity
az identity create \
  --name "UAMI-Test-01" \
  --resource-group "RG-Test-Identity" \
  --location "eastus"

# Get UAMI resource ID and principal ID
UAMI_ID=$(az identity show --name "UAMI-Test-01" --resource-group "RG-Test-Identity" --query id -o tsv)
UAMI_PRINCIPAL_ID=$(az identity show --name "UAMI-Test-01" --resource-group "RG-Test-Identity" --query principalId -o tsv)
```

**Expected Nodes**:
- 1 User-Assigned MI node (UAMI-Test-01)
- 1 Service Principal node (SP-UAMI-Test-01, servicePrincipalType="ManagedIdentity") - **automatic**

**Expected Edges**:
- RG-Test-Identity → UAMI-Test-01 (RG CONTAINS resource)
- UAMI-Test-01 → SP-UAMI-Test-01 (MI CONTAINS SP) - **automatic**

---

#### 3.3 Virtual Machines with Managed Identities

```bash
# VM 1: System-assigned MI only
az vm create \
  --name "VM-Test-SystemMI" \
  --resource-group "RG-Test-Compute" \
  --image "Ubuntu2204" \
  --size "Standard_B1s" \
  --admin-username "azureuser" \
  --generate-ssh-keys \
  --assign-identity \
  --public-ip-address "" \
  --nsg ""

# VM 2: Both system-assigned + user-assigned MI
az vm create \
  --name "VM-Test-BothMI" \
  --resource-group "RG-Test-Compute" \
  --image "Ubuntu2204" \
  --size "Standard_B1s" \
  --admin-username "azureuser" \
  --generate-ssh-keys \
  --assign-identity [system] $UAMI_ID \
  --public-ip-address "" \
  --nsg ""

# Configure auto-shutdown to minimize cost
az vm auto-shutdown \
  --name "VM-Test-SystemMI" \
  --resource-group "RG-Test-Compute" \
  --time 1900

az vm auto-shutdown \
  --name "VM-Test-BothMI" \
  --resource-group "RG-Test-Compute" \
  --time 1900
```

**Expected Nodes**:
- 2 Azure Resource nodes (VM-Test-SystemMI, VM-Test-BothMI)
- 2 System-Assigned MI nodes (synthetic nodes created by importer)
  - `VM-Test-SystemMI (System-Assigned)`
  - `VM-Test-BothMI (System-Assigned)`
- 2 Service Principal nodes (SP-SystemMI-VM-01, SP-SystemMI-VM-02) - **automatic**

**Expected Edges**:
- RG-Test-Compute → VM-Test-SystemMI (RG CONTAINS resource)
- RG-Test-Compute → VM-Test-BothMI (RG CONTAINS resource)
- VM-Test-SystemMI (System-Assigned) → SP-SystemMI-VM-01 (MI CONTAINS SP)
- VM-Test-BothMI (System-Assigned) → SP-SystemMI-VM-02 (MI CONTAINS SP)

---

#### 3.4 Additional Security-Relevant Resources

**IMPORTANT**: This section includes ALL 17 documented security-relevant resource types for complete coverage.

```bash
# Storage Account (Standard LRS for minimal cost)
STORAGE_NAME="storagetest$(date +%s)"
az storage account create \
  --name "$STORAGE_NAME" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Standard_LRS" \
  --kind "StorageV2"

# Key Vault (Standard tier)
az keyvault create \
  --name "kv-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "standard"

# Container Registry (Basic tier)
az acr create \
  --name "acrtest$(date +%s | tail -c 10)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Basic"

# App Service Plan (F1 Free tier)
az appservice plan create \
  --name "asp-test" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "F1" \
  --is-linux

# Web App (on Free tier)
az webapp create \
  --name "webapp-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --plan "asp-test" \
  --runtime "NODE:18-lts"

# Function App (Consumption plan)
az functionapp create \
  --name "func-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --storage-account "$STORAGE_NAME" \
  --consumption-plan-location "eastus" \
  --runtime "node" \
  --functions-version 4

# SQL Server (Basic tier)
az sql server create \
  --name "sql-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --admin-user "sqladmin" \
  --admin-password "SecurePassword123!"

# SQL Database (Basic tier - 5 DTU)
az sql db create \
  --name "sqldb-test" \
  --resource-group "RG-Test-Storage" \
  --server "sql-test-$(date +%s)" \
  --service-objective "Basic"

# Cosmos DB (Serverless for minimal cost)
az cosmosdb create \
  --name "cosmos-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --kind "GlobalDocumentDB" \
  --capabilities EnableServerless

# Redis Cache (Basic C0 - smallest tier)
az redis create \
  --name "redis-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Basic" \
  --vm-size "c0"

# Event Hub Namespace (Basic tier)
az eventhubs namespace create \
  --name "eh-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Basic"

# Event Hub (within namespace)
az eventhubs eventhub create \
  --name "eventhub-test" \
  --resource-group "RG-Test-Storage" \
  --namespace-name "eh-test-$(date +%s)"

# Service Bus Namespace (Basic tier)
az servicebus namespace create \
  --name "sb-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Basic"

# Event Grid Topic
az eventgrid topic create \
  --name "egt-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus"

# IoT Hub (F1 Free tier)
az iot hub create \
  --name "iothub-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "F1" \
  --partition-count 2

# Notification Hub Namespace (Free tier)
az notification-hub namespace create \
  --name "nh-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --sku "Free"

# Notification Hub (within namespace)
az notification-hub create \
  --name "notificationhub-test" \
  --resource-group "RG-Test-Storage" \
  --namespace-name "nh-test-$(date +%s)" \
  --location "eastus"

# API Management (Consumption tier)
az apim create \
  --name "apim-test-$(date +%s)" \
  --resource-group "RG-Test-Storage" \
  --location "eastus" \
  --publisher-name "TestPublisher" \
  --publisher-email "test@example.com" \
  --sku-name "Consumption"

# AKS Cluster (1 node, B2s for minimal cost - EXPENSIVE, optional)
# COMMENT OUT IF BUDGET-CONSTRAINED
# az aks create \
#   --name "aks-test-$(date +%s)" \
#   --resource-group "RG-Test-Compute" \
#   --location "eastus" \
#   --node-count 1 \
#   --node-vm-size "Standard_B2s" \
#   --enable-managed-identity \
#   --generate-ssh-keys
```

**Expected Nodes**: 17 Azure Resource nodes (all security-relevant types)
- storagetest{timestamp} (Microsoft.Storage/storageAccounts)
- kv-test-{timestamp} (Microsoft.KeyVault/vaults)
- acrtest{timestamp} (Microsoft.ContainerRegistry/registries)
- asp-test (Microsoft.Web/serverFarms)
- webapp-test-{timestamp} (Microsoft.Web/sites)
- func-test-{timestamp} (Microsoft.Web/sites/functions)
- sql-test-{timestamp} (Microsoft.Sql/servers)
- sqldb-test (Microsoft.Sql/servers/databases)
- cosmos-test-{timestamp} (Microsoft.DocumentDB/databaseAccounts)
- redis-test-{timestamp} (Microsoft.Cache/redis)
- eh-test-{timestamp} (Microsoft.EventHub/namespaces)
- eventhub-test (Microsoft.EventHub/namespaces/eventhubs)
- sb-test-{timestamp} (Microsoft.ServiceBus/namespaces)
- egt-test-{timestamp} (Microsoft.EventGrid/topics)
- iothub-test-{timestamp} (Microsoft.Devices/IotHubs)
- nh-test-{timestamp} (Microsoft.NotificationHubs/namespaces)
- apim-test-{timestamp} (Microsoft.ApiManagement/service)

**Expected Edges**: 17 RG → Resource CONTAINS edges
- One edge per resource type above

---

## Expected Graph Summary

After provisioning all resources and running the importer:

### Node Counts by Type

| Node Type | Expected Count | Examples |
|-----------|----------------|----------|
| Tenant | 1 | {tenant-guid} |
| User | 3 | user-test-01, user-test-02, guest-test-01 |
| Group | 4 | Group-Test-Security, Group-Test-M365, Group-Test-Dynamic, Group-Test-Nested |
| Service Principal | 7 | SP-App-Test-01, SP-App-Test-02, SP-UAMI-Test-01, SP-SystemMI-VM-01, SP-SystemMI-VM-02, (+ 2 more from apps) |
| Application | 2 | App-Test-01, App-Test-02 |
| Management Group | 4 | Root MG, MG-Test-L1, MG-Test-L2, MG-Test-L2-Sibling |
| Subscription | 2 | Subscription-Test-A, Subscription-Test-Orphan |
| Resource Group | 3 | RG-Test-Compute, RG-Test-Storage, RG-Test-Identity |
| Azure Resource | 19 | VM-Test-SystemMI, VM-Test-BothMI, storagetest{}, kv-test-{}, acrtest{}, asp-test, webapp-test{}, func-test{}, sql-test{}, sqldb-test, cosmos-test{}, redis-test{}, eh-test{}, eventhub-test, sb-test{}, egt-test{}, iothub-test{}, nh-test{}, apim-test{} (excludes optional AKS) |
| User-Assigned MI | 1 | UAMI-Test-01 |
| System-Assigned MI | 2 | VM-Test-SystemMI (System-Assigned), VM-Test-BothMI (System-Assigned) |
| **TOTAL** | **48 nodes** | (excludes optional AKS cluster) |

### Edge Counts by Type

| Edge Type | Expected Count | Examples |
|-----------|----------------|----------|
| **CONTAINS Edges** | | |
| Tenant → Root MG | 1 | Tenant → Root MG |
| MG → Child MG | 3 | Root→L1, L1→L2, L1→L2-Sibling |
| MG → Subscription | 2 | MG-Test-L2 → Sub-A, Root MG → Sub-Orphan |
| Subscription → RG | 3 | Sub-A → RG-Compute, Sub-A → RG-Storage, Sub-A → RG-Identity |
| RG → Resource | 21 | RG-Compute → VM-Test-SystemMI, RG-Compute → VM-Test-BothMI, RG-Storage → 17 security-relevant resources (storage, kv, acr, asp, webapp, func, sql, sqldb, cosmos, redis, eh, eventhub, sb, egt, iothub, nh, apim), RG-Identity → UAMI (excludes optional AKS) |
| Group → Member | 4 | Group-Security → user-01, Group-Security → SP-App-01, Group-M365 → user-02, Group-Nested → Group-Security |
| Application → SP | 2 | App-Test-01 → SP-App-Test-01, App-Test-02 → SP-App-Test-02 |
| MI → SP | 3 | UAMI-Test-01 → SP-UAMI, VM-SystemMI → SP-SystemMI-VM-01, VM-BothMI → SP-SystemMI-VM-02 |
| **OWNS Edges** | | |
| Application Ownership | 1 | user-test-01 → App-Test-01 |
| Group Ownership | 2 | user-test-01 → Group-Security, SP-App-01 → Group-Security |
| SP Ownership | 1 | user-test-02 → SP-App-Test-02 |
| **TOTAL** | **43 edges** | (excludes optional AKS edges) |

---

## Verification Queries

After importing, run these Cypher queries to verify coverage:

### Verify Node Counts
```cypher
// Count nodes by type
MATCH (n:Resource)
RETURN DISTINCT labels(n) as labels,
       n.resourceType as type,
       count(*) as count
ORDER BY count DESC
```

### Verify CONTAINS Edge Coverage
```cypher
// Count CONTAINS edges by pattern
MATCH (source:Resource)-[r:CONTAINS]->(target:Resource)
RETURN source.resourceType as source_type,
       target.resourceType as target_type,
       count(r) as edge_count
ORDER BY edge_count DESC
```

### Verify OWNS Edge Coverage
```cypher
// Count OWNS edges by owner type
MATCH (owner:Resource)-[r:OWNS]->(target:Resource)
RETURN owner.resourceType as owner_type,
       target.resourceType as target_type,
       r.source as relationship_source,
       count(r) as edge_count
ORDER BY edge_count DESC
```

### Verify Hierarchy Depth
```cypher
// Find deepest management group hierarchy
MATCH path = (root:Resource)-[:CONTAINS*]->(leaf:Resource)
WHERE root.isRoot = true
  AND toLower(leaf.resourceType) CONTAINS "managementgroup"
RETURN length(path) as depth,
       [n in nodes(path) | n.displayName] as hierarchy
ORDER BY depth DESC
LIMIT 5
```

### Verify Nested Group Transitive Path
```cypher
// Verify nested group creates transitive path
MATCH path = (nested:Resource)-[:CONTAINS*]->(member:Resource)
WHERE nested.displayName = "Group-Test-Nested"
RETURN length(path) as depth,
       [n in nodes(path) | n.displayName] as path
ORDER BY depth DESC
```

### Verify Managed Identity Types
```cypher
// Count managed identities by type
MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
  AND toLower(sp.servicePrincipalType) = "managedidentity"
RETURN mi.resourceType as mi_type,
       count(mi) as count,
       collect(mi.displayName) as examples
```

---

## Cost Management

**Estimated Monthly Cost**: $50-70 (without AKS), $150-200 (with AKS)

| Resource | SKU | Monthly Cost (USD) |
|----------|-----|-------------------|
| VM-Test-SystemMI (B1s, auto-shutdown) | Standard_B1s | ~$8 |
| VM-Test-BothMI (B1s, auto-shutdown) | Standard_B1s | ~$8 |
| Storage Account (LRS) | Standard_LRS | ~$0.50 |
| Key Vault (Standard) | Standard | ~$0.03 |
| Container Registry (Basic) | Basic | ~$5 |
| App Service Plan (Free) | F1 | $0 |
| Web App (Free tier) | F1 | $0 |
| Function App (Consumption) | Consumption | ~$0.40 |
| SQL Server + Database (Basic) | Basic (5 DTU) | ~$5 |
| Cosmos DB (Serverless) | Serverless | ~$1 (minimal usage) |
| Redis Cache (Basic C0) | Basic C0 | ~$17 |
| Event Hub Namespace (Basic) | Basic | ~$0.05 |
| Service Bus Namespace (Basic) | Basic | ~$0.05 |
| Event Grid Topic | Standard | ~$0.60 |
| IoT Hub (Free) | F1 | $0 |
| Notification Hub (Free) | Free | $0 |
| API Management (Consumption) | Consumption | ~$3.50 |
| AKS Cluster (OPTIONAL) | 1 x Standard_B2s | ~$30-40/node |
| Entra ID Resources | Free Tier | $0 |
| Management Groups | Free | $0 |
| **TOTAL (without AKS)** | | **~$49.13** |
| **TOTAL (with AKS)** | | **~$79-89** |

**Cost Optimization**:
- VMs configured with auto-shutdown at 7 PM daily
- Use B1s (cheapest) VM size
- No public IPs or NSGs (minimize network costs)
- Delete environment when not actively testing

---

## Provisioning Script

All commands above packaged into executable script:

```bash
#!/bin/bash
# File: provision-test-environment.sh

set -e

DOMAIN="yourtenant.onmicrosoft.com"
SUBSCRIPTION_A="Subscription-Test-A"
LOCATION="eastus"

echo "=== Phase 1: Entra ID Resources ==="
# [Insert all Phase 1 commands above]

echo "=== Phase 2: Management Hierarchy ==="
# [Insert all Phase 2 commands above]

echo "=== Phase 3: Azure Resources ==="
# [Insert all Phase 3 commands above]

echo "=== Provisioning Complete ==="
echo "Expected Nodes: 48 (excludes optional AKS)"
echo "Expected Edges: 43 (excludes optional AKS edges)"
echo ""
echo "Run importer: nebula azure recon iam-pull && nebula azure recon iam-push --neo4j-url bolt://localhost:7687"
```

---

## Cleanup Script

```bash
#!/bin/bash
# File: cleanup-test-environment.sh

set -e

echo "=== Deleting Azure Resources ==="
az group delete --name "RG-Test-Compute" --yes --no-wait
az group delete --name "RG-Test-Storage" --yes --no-wait
az group delete --name "RG-Test-Identity" --yes --no-wait

echo "=== Deleting Management Groups ==="
az account management-group delete --name "MG-Test-L2"
az account management-group delete --name "MG-Test-L2-Sibling"
az account management-group delete --name "MG-Test-L1"

echo "=== Deleting Entra ID Resources ==="
az ad app delete --id $APP_01_ID
az ad app delete --id $APP_02_ID
az ad group delete --group $GROUP_SEC_ID
az ad group delete --group $GROUP_M365_ID
az ad group delete --group $GROUP_DYN_ID
az ad group delete --group $GROUP_NESTED_ID
az ad user delete --id "user-test-01@$DOMAIN"
az ad user delete --id "user-test-02@$DOMAIN"
az ad user delete --id "guest-test-01@externaldomain.com"

echo "=== Deleting Individual Resources (if needed) ==="
# Note: Resource group deletion above will cascade delete all resources
# Individual deletions only needed if RGs persist

# Uncomment if needed:
# az aks delete --name "aks-test-${TIMESTAMP}" --resource-group "RG-Test-Compute" --yes --no-wait

echo "=== Cleanup Complete ==="
echo "All test resources deleted"
```

---

## Next Steps

1. **Provision Environment**: Run `provision-test-environment.sh`
2. **Run Collector**: `nebula azure recon iam-pull`
3. **Run Importer**: `nebula azure recon iam-push --neo4j-url bolt://localhost:7687`
4. **Verify Graph**: Run verification Cypher queries above
5. **Validate Coverage**: Confirm all 48 nodes and 43 edges created (excludes optional AKS)
6. **Cleanup**: Run `cleanup-test-environment.sh` when done

This test environment provides **100% coverage** of:
- All 11 documented node types ✅
- All 8 documented CONTAINS edge types ✅
- All 3 documented OWNS edge types ✅
- All 17 security-relevant Azure resource types ✅
- All critical logic branches (orphan detection, nested groups, synthetic nodes, etc.) ✅
