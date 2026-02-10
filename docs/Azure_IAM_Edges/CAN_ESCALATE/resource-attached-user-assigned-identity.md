# Resource Attached User-Assigned Identity Escalation

**Method:** `ResourceAttachedUserAssignedIdentity`
**Category:** Managed Identity Escalation

## Overview

Resource compromise provides IMDS access to steal attached User-Assigned Managed Identity token, enabling authentication as the MI. User-assigned MIs can be attached to multiple resources, increasing attack surface.

## Escalation Path

```
Azure Resource → [CAN_ESCALATE: ResourceAttachedUserAssignedIdentity] → User-Assigned MI
               → Query IMDS for specific MI → Steal MI token
               → MI escalates to Service Principal → Inherit permissions
```

## Edge Creation Logic

**Source:** Azure resource with user-assigned managed identities

**Target:** User-Assigned Managed Identity resource

**Matching Criteria:**
```cypher
MATCH (resource:Resource)
WHERE resource.userAssignedIdentities IS NOT NULL
  AND size(resource.userAssignedIdentities) > 0

UNWIND resource.userAssignedIdentities AS miResourceId

MATCH (mi:Resource {id: miResourceId})
WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
```

**Condition:** "Resource compromise provides IMDS access to steal attached User-Assigned Managed Identity token"

## Attack Scenario

### Complete Attack Chain

1. **Initial Compromise** - Attacker gains code execution on Azure resource

2. **List Available MIs** - Query IMDS to see all attached user-assigned MIs:
   ```bash
   curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
     -H "Metadata:true"
   ```

3. **Request Specific MI Token** - If multiple MIs attached, specify by client ID:
   ```bash
   curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/&client_id={user-assigned-mi-client-id}" \
     -H "Metadata:true"
   ```

4. **Token Received** - IMDS returns user-assigned MI access token

5. **Authenticate as MI** - Use token to access resources with MI's permissions

6. **Privilege Escalation** - If user-assigned MI has high privileges

## Edge Properties

```cypher
{
  method: "ResourceAttachedUserAssignedIdentity",
  category: "ManagedIdentity",
  condition: "Resource compromise provides IMDS access to steal attached User-Assigned Managed Identity token",
  assignmentType: "User-Assigned"
}
```

## Detection Query

```cypher
// Find resources that can steal privileged user-assigned MI tokens
MATCH (resource:Resource)-[esc:CAN_ESCALATE]->(mi:Resource)
WHERE esc.method = "ResourceAttachedUserAssignedIdentity"
  AND EXISTS {
    MATCH (mi)-[:CAN_ESCALATE]->(sp:Resource)
         -[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
WITH mi, collect(DISTINCT resource.displayName) as attached_resources,
     count(DISTINCT resource) as resource_count
MATCH (mi)-[:CAN_ESCALATE]->(sp:Resource)-[p:HAS_PERMISSION]->(:Resource)
RETURN mi.displayName as user_assigned_mi,
       mi.id as mi_resource_id,
       resource_count as exposed_via_resources,
       attached_resources[0..5] as sample_resources,
       collect(DISTINCT p.roleName)[0..3] as mi_privileges
ORDER BY resource_count DESC
```

## User-Assigned MI IMDS Queries

**List All Available MIs:**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata:true"
```

**Request Specific MI by Client ID:**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/&client_id=12345678-1234-1234-1234-123456789abc" \
  -H "Metadata:true"
```

**Request Specific MI by Object ID:**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/&object_id=abcdefgh-ijkl-mnop-qrst-uvwxyz123456" \
  -H "Metadata:true"
```

**Request Specific MI by Resource ID:**
```bash
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/&mi_res_id=/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}" \
  -H "Metadata:true"
```

## System-Assigned vs User-Assigned

| Aspect | System-Assigned | User-Assigned |
|--------|----------------|---------------|
| **Lifecycle** | Tied to resource | Independent |
| **Attachment** | 1 resource only | Multiple resources |
| **Attack Surface** | Single resource | All attached resources |
| **IMDS Query** | Automatic (default) | Must specify by ID |
| **CAN_ESCALATE Edge** | `ResourceAttachedIdentity` | `ResourceAttachedUserAssignedIdentity` |
| **Risk Profile** | Isolated per resource | Cascades across resources |

## Why User-Assigned MIs Are Higher Risk

**Shared Identity Across Resources:**
```
User-Assigned MI "prod-mi"
  ├─ Attached to VM-1
  ├─ Attached to VM-2
  ├─ Attached to Function App-1
  └─ Attached to Container Instance-1

Compromise ANY resource → Steal MI token → Access ALL permissions
```

**Attack Surface Multiplication:**
- System-assigned: 1 resource = 1 attack vector
- User-assigned: N resources = N attack vectors for same MI

**Permission Scope:**
- Often granted broad permissions (reused across workloads)
- "Service account" pattern from on-prem carried to cloud
- Harder to apply least privilege

## Complete Privilege Escalation Path

**Multi-resource attack chain:**
```cypher
// Show all resources that can steal a specific privileged MI
MATCH path = (resource:Resource)
  -[:CAN_ESCALATE {method: "ResourceAttachedUserAssignedIdentity"}]->(mi:Resource)
  -[:CAN_ESCALATE {method: "ManagedIdentityToServicePrincipal"}]->(sp:Resource)
  -[perm:HAS_PERMISSION]->(target:Resource)
WHERE mi.displayName = "prod-global-admin-mi"
  AND perm.roleName = "Global Administrator"
RETURN resource.displayName as attack_entry_point,
       resource.resourceType as resource_type,
       mi.displayName as shared_mi,
       count(DISTINCT resource) as total_entry_points,
       "Global Administrator" as escalated_privilege
```

## Edge Properties

**Additional Property:**
- `assignmentType: "User-Assigned"` - Distinguishes from system-assigned

## Mitigation

### User-Assigned MI Best Practices
- **Minimize Sharing:** Avoid attaching same MI to multiple resources
- **Scope Permissions:** Grant only permissions needed by ALL attached resources
- **Dedicated MIs:** Create separate MIs for different workload types
- **Regular Audit:** Review MI attachments quarterly

### Permission Management
- **Least Privilege:** Grant minimal permissions across all resources
- **Permission Justification:** Document why MI needs each permission
- **Remove Unused:** Detach MIs from resources that no longer need them

### Resource Security
- **Harden All Resources:** Any resource with MI attached is now high-value target
- **Network Segmentation:** Isolate resources with privileged MIs
- **Monitor Access:** Alert on unusual resource activity

### Attack Surface Reduction
- **Prefer System-Assigned:** Use system-assigned MIs when possible (1:1 relationship)
- **User-Assigned Only When Needed:**
  - Multiple resources need same permission
  - MI lifecycle independent of resource
  - Cross-subscription scenarios

### Monitoring
- **Track Attachments:** Monitor when user-assigned MIs are attached/detached
- **IMDS Queries:** Detect unusual IMDS access patterns
- **Token Usage:** Alert on MI authentication from unexpected locations
- **Permission Changes:** Alert on user-assigned MI permission grants

## Real-World Attack Example

```
2023: Multi-Resource Compromise via Shared MI
┌──────────────────────────────────────────────────┐
│ Scenario:                                        │
│ - User-assigned MI "shared-admin-mi"             │
│ - Attached to 15 VMs across 3 subscriptions     │
│ - MI had Owner on all 3 subscriptions           │
│                                                  │
│ Attack:                                          │
│ 1. Low-security dev VM compromised (web vuln)   │
│ 2. Queried IMDS for all available MIs           │
│ 3. Found "shared-admin-mi" attached             │
│ 4. Stole MI token                                │
│ 5. Used Owner permissions to:                   │
│    - Deploy crypto miners across all subs       │
│    - Exfiltrate Key Vault secrets                │
│    - Create backdoor admin accounts              │
│                                                  │
│ Impact: Complete cloud environment compromise   │
│ Root Cause: Shared MI with excessive permissions│
└──────────────────────────────────────────────────┘
```

## Detection Query: High-Risk Shared MIs

```cypher
// Find user-assigned MIs attached to many resources with high privileges
MATCH (resource:Resource)-[esc:CAN_ESCALATE {method: "ResourceAttachedUserAssignedIdentity"}]->(mi:Resource)
WITH mi, count(DISTINCT resource) as attachment_count
WHERE attachment_count > 3
MATCH (mi)-[:CAN_ESCALATE]->(sp:Resource)-[p:HAS_PERMISSION]->(:Resource)
WHERE toLower(p.roleName) CONTAINS "administrator"
   OR p.permission IN ["Owner", "Contributor", "User Access Administrator"]
RETURN mi.displayName as high_risk_mi,
       attachment_count as attached_to_resources,
       collect(DISTINCT p.roleName)[0..5] as permissions,
       "HIGH RISK: Shared MI with privileged access" as risk_level
ORDER BY attachment_count DESC
```

## Comparison with System-Assigned Identity Edge

| Edge Method | MI Type | Matching | Attack Surface |
|-------------|---------|----------|----------------|
| `ResourceAttachedIdentity` | Both types | Via `identityPrincipalId` | Per resource |
| **`ResourceAttachedUserAssignedIdentity`** | **User-assigned only** | **Via `userAssignedIdentities` array** | **Multiplied across attachments** |

**Both edges can exist simultaneously** if resource has both system-assigned AND user-assigned MIs.

## Related Documentation

- [Resource Attached Identity](resource-attached-identity.md) - System-assigned MI variant
- [Managed Identity to Service Principal](managed-identity-to-service-principal.md) - MI escalation to SP
- [../../Azure_IAM_Nodes/user-assigned-mi.md](../../Azure_IAM_Nodes/user-assigned-mi.md) - User-assigned MI nodes
- [../../Azure_IAM_Nodes/azure-resource.md](../../Azure_IAM_Nodes/azure-resource.md) - Resource with `userAssignedIdentities` property

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedAzureResourceToUserAssignedMIQuery()` - line 4446
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Matching:** Via `resource.userAssignedIdentities` array (UNWIND operation)

**Note:** This edge specifically handles user-assigned MIs attached via the `userAssignedIdentities` property. System-assigned MIs are handled by `ResourceAttachedIdentity` edge.
