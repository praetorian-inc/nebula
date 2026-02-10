# Azure Owner Role Escalation

**Method:** `AzureOwner`
**Category:** Azure RBAC Escalation

## Overview

Principal with Owner role at any scope (Management Group, Subscription, Resource Group) has full control over Azure resources within that scope and can assign roles, enabling privilege escalation.

## Escalation Path

```
Principal → [HAS_PERMISSION: Owner] → Scope (MG/Sub/RG)
          → [CAN_ESCALATE: AzureOwner] → All Resources in Scope
          → Assign roles → Grant Owner to self → Lateral escalation
```

## Edge Creation Logic

**Source:** Any principal with HAS_PERMISSION edge where:
- `roleName = "Owner"` OR
- `roleDefinitionId` contains `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` (Owner role GUID)

**Target:** All Azure resources in scope hierarchy:
- Traverses CONTAINS edges: `scope -[:CONTAINS*0..] -> resources`
- Includes scope itself (`*0..` means 0 or more hops)
- **Excludes directory objects** (no Entra ID users/groups/SPs)

**Condition:** "Owner role at any scope provides full control over Azure resources within that scope and can assign roles"

## Attack Scenarios

### Scenario 1: Subscription Owner → Key Vault Access
```
1. Owner at subscription level
2. Access any Key Vault in subscription
3. Extract secrets, certificates, connection strings
4. Pivot to other systems using stolen credentials
```

### Scenario 2: Owner → Managed Identity Credential Theft
```
1. Owner on resource with system-assigned MI
2. Read MI credentials from IMDS endpoint (requires code execution)
3. Authenticate as MI
4. Inherit MI's permissions (potentially Global Admin)
```

### Scenario 3: Owner → Role Assignment Escalation
```
1. Owner on resource group
2. Assign Owner role to different scope
3. Lateral movement to other resource groups/subscriptions
4. Expand blast radius
```

### Scenario 4: Owner → Resource Modification
```
1. Owner on VM
2. Install backdoor via VM extension
3. Maintain persistence
4. Pivot to network resources
```

## Edge Properties

```cypher
{
  method: "AzureOwner",
  category: "RBAC",
  condition: "Owner role at any scope provides full control over Azure resources within that scope and can assign roles",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: "Owner"
}
```

## Detection Query

```cypher
// Find Owners and critical resources they control
MATCH (principal:Resource)-[esc:CAN_ESCALATE]->(resource:Resource)
WHERE esc.method = "AzureOwner"
  AND toLower(resource.resourceType) IN [
    "microsoft.keyvault/vaults",
    "microsoft.compute/virtualmachines",
    "microsoft.storage/storageaccounts",
    "microsoft.resources/subscriptions"
  ]
RETURN principal.displayName as owner,
       resource.displayName as critical_resource,
       resource.resourceType as type,
       count(esc) as access_paths
ORDER BY access_paths DESC
```

## Owner Capabilities

**Full Resource Control:**
- Read all properties (including secrets)
- Modify configuration
- Delete resources
- Deploy new resources
- Access data plane (if supported by resource)

**Role Assignment:**
- Assign any role within scope
- Grant Owner to others
- Create custom roles
- Modify role assignments

**Cost Control:**
- Deploy expensive resources
- Crypto mining
- Resource exhaustion attacks

## Scope Hierarchy Impact

| Scope | Owner Can Escalate To |
|-------|----------------------|
| Management Group | All child MGs, subscriptions, RGs, resources |
| Subscription | All RGs and resources in subscription |
| Resource Group | All resources in RG only |
| Resource | That resource only (limited escalation) |

**Transitive Escalation:**
```
Owner on MG Root
→ CONTAINS → Subscription A
→ CONTAINS → RG 1
→ CONTAINS → Key Vault
Result: Can access all Key Vaults in entire tenant hierarchy
```

## High-Value Targets

**Resources to Target:**
1. **Key Vaults** - Secrets, certificates, keys
2. **Storage Accounts** - Data exfiltration, connection strings
3. **Virtual Machines** - Code execution, MI credential theft
4. **App Services** - Application secrets, connection strings
5. **Automation Accounts** - Runbook secrets
6. **DevOps** - Pipeline credentials, deployment keys

## Mitigation

- **Least Privilege:**
  - Use Contributor instead of Owner (no role assignment)
  - Scope to specific resource groups, not subscriptions
  - Time-bound assignments via PIM
- **PIM (Privileged Identity Management):**
  - Eligible assignments with approval
  - Maximum assignment duration (8 hours)
  - Justification required
- **Monitoring:**
  - Alert on Owner role assignments
  - Alert on Key Vault access by Owners
  - Alert on role assignment changes
- **Protected Resources:**
  - Resource locks (prevent deletion)
  - Azure Policy (prevent modification)
  - Private endpoints (limit access)
- **Regular Audit:**
  - Review Owner assignments quarterly
  - Remove unnecessary Owners
  - Migrate to Contributor where possible

## Difference from User Access Administrator

| Role | Can Modify Resources | Can Assign Roles |
|------|---------------------|------------------|
| Owner | ✅ Yes | ✅ Yes |
| Contributor | ✅ Yes | ❌ No |
| User Access Administrator | ❌ No | ✅ Yes |

**Owner = Contributor + User Access Administrator**

## Common Misconfigurations

**"DevOps pipeline needs Owner"**
- ❌ Over-privileged
- ✅ Use Contributor + specific permissions
- ✅ Use Managed Identity with scoped access

**"Admin needs Owner on subscription"**
- ❌ Too broad
- ✅ Owner on specific resource groups only
- ✅ Use PIM for subscription-level access

**"Break-glass account is Owner on MG root"**
- ⚠️ Acceptable for emergency access
- ✅ Monitor closely
- ✅ Use PIM with approval

## Real-World Attack Example

```
2022: Cloud Mining Attack
- Developer account had Owner on subscription
- Account compromised via phishing
- Attacker deployed GPU VMs in 15 regions
- $250K bill in 72 hours
- Detection: Billing alert
```

## Related Documentation

- [User Access Administrator](user-access-administrator.md) - Role assignment without resource control
- [../../Azure_IAM_Nodes/subscription.md](../../Azure_IAM_Nodes/subscription.md) - Subscription scope
- [../../Azure_IAM_Nodes/resource-group.md](../../Azure_IAM_Nodes/resource-group.md) - Resource group scope
- [../CONTAINS/](../CONTAINS/) - Hierarchy traversal for scope calculation

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedRBACOwnerQuery()` - line 4277
**Phase:** Phase 4 (CAN_ESCALATE edge creation)

**Key Implementation Detail:** Uses `CONTAINS*0..` for recursive scope traversal, meaning Owner at parent scope cascades to all children.
