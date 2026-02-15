# Managed Identity to Service Principal Escalation

**Method:** `ManagedIdentityToServicePrincipal`
**Category:** Managed Identity Escalation

## Overview

Managed Identity compromise (via IMDS token theft from attached resource) provides access to the backing Service Principal and all its permissions.

## Escalation Path

```
Managed Identity → [CONTAINS] → Service Principal
                 → [CAN_ESCALATE: ManagedIdentityToServicePrincipal] → Service Principal
                 → Steal MI token from IMDS → Authenticate as SP → Inherit SP permissions
```

## Edge Creation Logic

**Source:** Managed Identity resource (user-assigned or system-assigned)

**Target:** Service Principal linked via CONTAINS edge

**Relationship:**
```cypher
(mi:Resource)-[:CONTAINS]->(sp:Resource)
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
→ Creates: (mi)-[:CAN_ESCALATE]->(sp)
```

**Condition:** "Managed Identity compromise (via IMDS token theft from attached resource) provides access to Service Principal and all its permissions"

## Conceptual Model

**Managed Identity Architecture:**
```
Azure Resource (VM, Function, etc.)
  └─ Has Managed Identity attached
       └─ MI is backed by Service Principal
            └─ SP has permissions (roles, Graph API, etc.)
```

**This edge represents:**
- MI is backed by a Service Principal
- MI token = SP access token
- MI compromise = SP compromise
- Structural identity relationship

## Attack Scenarios

### Scenario 1: VM with System-Assigned MI
```
1. Attacker compromises VM
2. Queries IMDS endpoint for MI token:
   curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" -H "Metadata:true"
3. Receives access token for MI's Service Principal
4. Uses token to call Microsoft Graph
5. Inherits SP's permissions (e.g., Global Administrator)
```

### Scenario 2: Function App with User-Assigned MI
```
1. Attacker exploits RCE vulnerability in Function App
2. Queries IMDS for user-assigned MI token
3. Authenticates as MI's Service Principal
4. Accesses resources via SP permissions
```

### Scenario 3: Container with Workload Identity
```
1. Attacker compromises container
2. Uses workload identity federation
3. Obtains token for MI
4. Escalates to SP permissions
```

## Edge Properties

```cypher
{
  method: "ManagedIdentityToServicePrincipal",
  category: "ManagedIdentity",
  condition: "Managed Identity compromise (via IMDS token theft from attached resource) provides access to Service Principal and all its permissions"
}
```

## Detection Query

```cypher
// Find Managed Identities that escalate to privileged SPs
MATCH (mi:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "ManagedIdentityToServicePrincipal"
  AND EXISTS {
    MATCH (sp)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
WITH mi, sp, collect(DISTINCT p.roleName)[0..3] as sp_roles
MATCH (resource:Resource)-[:CAN_ESCALATE]->(mi)
RETURN mi.displayName as managed_identity,
       mi.principalId as mi_principal_id,
       sp.displayName as backing_sp,
       sp.appId as sp_app_id,
       sp_roles as privileges,
       count(resource) as attached_to_resources
ORDER BY attached_to_resources DESC
```

## IMDS Token Theft

**Instance Metadata Service (IMDS):**
- Azure service accessible from within VMs/containers
- Provides MI access tokens
- No authentication required (trust based on network location)
- Link-local address: `169.254.169.254`

**Token Theft Command:**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata:true"
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": "3599",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

## Why This Edge Exists

**Graph Modeling:**
- Managed Identities are not standalone
- MIs are backed by Service Principals
- MI token = SP access token
- Need to model: "MI compromise = SP access"

**Attack Path Discovery:**
```cypher
// Path: VM → MI → SP → Global Admin
MATCH path = (vm:Resource)-[:CAN_ESCALATE*]->(sp:Resource)
            -[perm:HAS_PERMISSION]->(:Resource)
WHERE perm.roleName = "Global Administrator"
RETURN path
```

**Risk Assessment:**
- MIs with many attached resources = high exposure
- MIs with privileged SPs = high value targets
- This edge connects resource compromise to permission impact

## Managed Identity Types

**System-Assigned:**
```
Resource → Has identity property → System-Assigned MI (synthetic node)
         → CONTAINS → Service Principal
         → SP has permissions
```

**User-Assigned:**
```
User-Assigned MI Resource → Can attach to multiple resources
                          → CONTAINS → Service Principal
                          → SP has permissions
```

**Both types create this CAN_ESCALATE edge**

## Complete Attack Chain

**Full path from resource to permissions:**
```cypher
MATCH path = (resource:Resource)
  -[:CAN_ESCALATE {method: "ResourceAttachedIdentity"}]->(mi:Resource)
  -[:CAN_ESCALATE {method: "ManagedIdentityToServicePrincipal"}]->(sp:Resource)
  -[perm:HAS_PERMISSION]->(:Resource)
WHERE perm.roleName = "Global Administrator"
RETURN resource.displayName as compromised_resource,
       mi.displayName as managed_identity,
       sp.displayName as service_principal,
       "Global Administrator" as escalated_to
```

## Mitigation

**Limit MI Permissions:**
- Grant least privilege to MIs
- Avoid Global Administrator on MIs
- Use resource-specific permissions

**Protect Resources:**
- Minimize code execution risks on VMs/Functions
- Restrict network access to IMDS (if possible)
- Monitor IMDS access patterns

**Use Workload Identity Federation:**
- Eliminates long-lived credentials
- Short-lived tokens
- Better audit trail

**Monitor MI Usage:**
- Alert on MI token requests to high-value resources
- Monitor authentication patterns
- Review MI permission assignments

## Comparison with Application Identity

| Identity Type | Credential Storage | Compromise Method | Backing |
|---------------|-------------------|-------------------|---------|
| Application | Secrets/Certs | Credential theft | Service Principal |
| **Managed Identity** | **None (Azure-managed)** | **IMDS token theft** | **Service Principal** |

**Both are backed by SPs, different attack vectors**

## Real-World Attack

```
2023: VM Compromise → Global Admin
- Public-facing web app on VM
- SQL injection vulnerability
- RCE achieved via SQLi
- Queried IMDS for MI token
- MI's SP had Global Administrator
- Complete tenant takeover
- Lesson: Never grant Global Admin to MIs
```

## Related Documentation

- [Resource Attached Identity](resource-attached-identity.md) - How resources escalate to MIs
- [Resource Attached User Assigned Identity](resource-attached-user-assigned-identity.md) - User-assigned MI variant
- [../CONTAINS/mi-to-sp.md](../CONTAINS/mi-to-sp.md) - Structural MI→SP relationship
- [../../Azure_IAM_Nodes/user-assigned-mi.md](../../Azure_IAM_Nodes/user-assigned-mi.md) - User-assigned MI nodes
- [../../Azure_IAM_Nodes/system-assigned-mi.md](../../Azure_IAM_Nodes/system-assigned-mi.md) - System-assigned MI nodes

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedManagedIdentityToServicePrincipalQuery()` - line 4410
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Edge Creation:** Based on CONTAINS edges created in Phase 2a

**Note:** This edge models the identity backing relationship. The actual IMDS theft is modeled by Resource→MI CAN_ESCALATE edges.
