# Resource Attached Identity Escalation (IMDS Token Theft)

**Method:** `ResourceAttachedIdentity`
**Category:** Managed Identity Escalation

## Overview

Resource compromise provides IMDS access to steal attached Managed Identity token, enabling authentication as the MI and inheriting all its permissions.

## Escalation Path

```
Azure Resource (VM/Function/etc.) → [CAN_ESCALATE: ResourceAttachedIdentity] → Managed Identity
                                   → Query IMDS endpoint → Steal MI token
                                   → MI escalates to Service Principal → Inherit permissions
```

## Edge Creation Logic

**Source:** Azure resource with attached managed identity

**Target:** Managed Identity (system-assigned or user-assigned)

**Matching Criteria:**
```cypher
MATCH (resource:Resource)
WHERE resource.identityPrincipalId IS NOT NULL
  AND resource.identityType IS NOT NULL

MATCH (mi:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
  AND mi.principalId = resource.identityPrincipalId
```

**Condition:** "Resource compromise provides IMDS access to steal attached Managed Identity token"

## Attack Scenario

### Complete Attack Chain

1. **Initial Compromise** - Attacker gains code execution on Azure resource:
   - VM via SSH/RDP
   - Function App via RCE vulnerability
   - App Service via web shell
   - Container via pod escape
   - Automation Runbook via code injection

2. **IMDS Token Theft** - Query Instance Metadata Service:
   ```bash
   # Request MI token from IMDS
   curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" \
     -H "Metadata:true"
   ```

3. **Token Received** - IMDS returns access token:
   ```json
   {
     "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
     "expires_in": "3599",
     "resource": "https://graph.microsoft.com/",
     "token_type": "Bearer"
   }
   ```

4. **Authenticate as MI** - Use stolen token to call APIs:
   ```bash
   curl "https://graph.microsoft.com/v1.0/me" \
     -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
   ```

5. **Privilege Escalation** - If MI has high privileges:
   - MI with Global Admin → Tenant compromise
   - MI with Owner on subscription → Cloud infrastructure control
   - MI with Key Vault access → Secret exfiltration

## Edge Properties

```cypher
{
  method: "ResourceAttachedIdentity",
  category: "ManagedIdentity",
  condition: "Resource compromise provides IMDS access to steal attached Managed Identity token",
  identityType: <"SystemAssigned" or "UserAssigned">
}
```

## Detection Query

```cypher
// Find resources that can escalate to privileged MIs
MATCH (resource:Resource)-[esc:CAN_ESCALATE]->(mi:Resource)
WHERE esc.method = "ResourceAttachedIdentity"
  AND EXISTS {
    MATCH (mi)-[:CAN_ESCALATE]->(sp:Resource)
         -[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
RETURN resource.displayName as vulnerable_resource,
       resource.resourceType as resource_type,
       mi.displayName as managed_identity,
       esc.identityType as identity_type,
       collect(DISTINCT p.roleName)[0..3] as mi_privileges
ORDER BY resource.displayName
```

## IMDS Endpoint Details

**Endpoint:** `http://169.254.169.254/metadata/identity/oauth2/token`

**Required Header:** `Metadata: true`

**Query Parameters:**
- `api-version`: IMDS API version (e.g., `2018-02-01`)
- `resource`: Target resource (e.g., `https://management.azure.com/`)

**Supported Resources:**
- `https://management.azure.com/` - Azure Resource Manager
- `https://graph.microsoft.com/` - Microsoft Graph
- `https://vault.azure.net/` - Key Vault
- `https://database.windows.net/` - Azure SQL
- Custom audience for app-to-app calls

## Resource Types at Risk

**High Risk (Common RCE targets):**
- Virtual Machines (SSH/RDP access)
- App Services (web vulnerabilities)
- Function Apps (code injection)
- Container Instances (container escape)
- Automation Accounts (runbook code)

**Medium Risk:**
- Logic Apps (with IMDS access)
- Batch Compute (worker nodes)
- Virtual Machine Scale Sets

**Lower Risk:**
- Managed Services (limited code execution)
- PaaS with restricted IMDS access

## Complete Privilege Escalation Path

**Full attack chain:**
```cypher
MATCH path = (resource:Resource)
  -[:CAN_ESCALATE {method: "ResourceAttachedIdentity"}]->(mi:Resource)
  -[:CAN_ESCALATE {method: "ManagedIdentityToServicePrincipal"}]->(sp:Resource)
  -[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.roleName = "Global Administrator"
RETURN resource.displayName as entry_point,
       resource.resourceType as vulnerable_resource_type,
       mi.displayName as managed_identity,
       sp.displayName as service_principal,
       target.displayName as compromised_target,
       "Complete tenant control" as impact
```

## Mitigation

### Limit MI Permissions
- **Least Privilege:** Only grant permissions MI actually needs
- **Avoid Global Admin:** Never assign Global Administrator to MIs
- **Scope Permissions:** Use resource-specific permissions, not tenant-wide
- **Regular Review:** Audit MI permissions quarterly

### Protect Resources
- **Harden VMs:** Patch management, firewall rules, disable unused services
- **Secure Code:** Code review, SAST/DAST for web apps
- **Network Segmentation:** Limit resource exposure
- **Monitor Access:** Alert on unusual resource access patterns

### IMDS Protection
- **Firewall Rules:** Block 169.254.169.254 if MI not needed (rare)
- **Application-Level:** Validate IMDS calls in application code
- **Azure Firewall:** Use Azure Firewall to monitor/block (limited effectiveness)

### Token Management
- **Short Lifetimes:** Tokens expire after ~1 hour (cannot change)
- **Scope Limitation:** Request only needed scopes
- **Conditional Access:** Limited applicability to MIs

### Monitoring
- **IMDS Access:** Monitor unusual IMDS query patterns
- **Token Usage:** Alert on MI authentication from unexpected locations
- **Permission Changes:** Alert on MI permission grants
- **Resource Behavior:** Detect anomalous resource behavior

## Real-World Attack Example

```
2022: Azure VM Compromise → Subscription Takeover
┌─────────────────────────────────────────────┐
│ 1. Public web app vulnerability (SQLi)     │
│ 2. RCE achieved on Azure VM                │
│ 3. Queried IMDS for MI token               │
│ 4. MI had Contributor on subscription      │
│ 5. Deployed crypto mining VMs              │
│ 6. $180K bill in 48 hours                  │
│ 7. Detection: Billing alert                │
└─────────────────────────────────────────────┘
```

## System-Assigned vs User-Assigned

**System-Assigned MI:**
- Tied to single resource lifecycle
- Deleted when resource deleted
- Easier to manage (1:1 relationship)
- This edge: `resource → system-assigned MI`

**User-Assigned MI:**
- Independent lifecycle
- Can attach to multiple resources
- More complex to audit
- This edge also handles user-assigned MIs attached via `identityPrincipalId`

**Both types vulnerable to IMDS token theft via this path**

## Comparison with Other Cloud Providers

| Cloud Provider | Equivalent | Endpoint | Mitigation |
|---------------|-----------|----------|-----------|
| **Azure** | **Managed Identity** | **IMDS 169.254.169.254** | **Least privilege MI permissions** |
| AWS | IAM Role for EC2 | IMDS 169.254.169.254 | IMDSv2 with session tokens |
| GCP | Service Account | Metadata server | Disable metadata concealment |

**Azure-specific:** No IMDSv2 equivalent, harder to protect

## Related Documentation

- [Managed Identity to Service Principal](managed-identity-to-service-principal.md) - MI escalation to SP
- [Resource Attached User Assigned Identity](resource-attached-user-assigned-identity.md) - User-assigned variant
- [../../Azure_IAM_Nodes/azure-resource.md](../../Azure_IAM_Nodes/azure-resource.md) - Resource node with identity properties
- [../../Azure_IAM_Nodes/system-assigned-mi.md](../../Azure_IAM_Nodes/system-assigned-mi.md) - System-assigned MI nodes

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedAzureResourceToManagedIdentityQuery()` - line 4424
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Matching:** Via `resource.identityPrincipalId = mi.principalId`

**Note:** This handles both system-assigned and user-assigned MIs attached via the `identity` property.
