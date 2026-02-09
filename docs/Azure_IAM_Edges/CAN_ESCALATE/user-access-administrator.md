# User Access Administrator Escalation

**Method:** `UserAccessAdmin`
**Category:** Azure RBAC Escalation

## Overview

Principal with User Access Administrator role can assign any Azure role within scope to compromise identities in that scope, enabling privilege escalation without resource modification capabilities.

## Escalation Path

```
Principal → [HAS_PERMISSION: User Access Administrator] → Scope
          → [CAN_ESCALATE: UserAccessAdmin] → All Resources in Scope
          → Assign Owner role to self → Full control
```

## Edge Creation Logic

**Source:** Any principal with HAS_PERMISSION edge where:
- `roleName = "User Access Administrator"` OR
- `roleDefinitionId` contains `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` (UAA role GUID)

**Target:** All Azure resources in scope hierarchy:
- Traverses CONTAINS edges: `scope -[:CONTAINS*0..] -> resources`
- Includes scope itself
- **Excludes directory objects** (no Entra ID users/groups/SPs)

**Condition:** "User Access Administrator can assign any Azure role within scope to compromise identities in that scope"

## Attack Scenarios

### Scenario 1: Self-Escalate to Owner
**Most common attack**
```
1. User Access Administrator on subscription
2. Assign Owner role to self at subscription level
3. Now have full control over all resources
4. Access Key Vaults, modify VMs, exfiltrate data
```

### Scenario 2: Grant Owner to External Account
**Persistence technique**
```
1. User Access Administrator on resource group
2. Create new service principal
3. Assign Owner role to SP
4. Use SP credentials for persistent access
5. Original UAA assignment can be removed - persistence maintained
```

### Scenario 3: Lateral Movement via Role Assignment
**Scope expansion**
```
1. User Access Administrator on RG-A
2. Enumerate other resource groups
3. User has Contributor on RG-B
4. Assign Owner to compromised account on RG-B
5. Expand access across multiple scopes
```

### Scenario 4: Privilege Escalation Chain
**Multi-hop escalation**
```
1. User Access Administrator on subscription
2. Assign Contributor to attacker account
3. Attacker deploys Function App with managed identity
4. Assigns managed identity Owner role
5. Code execution via Function → MI credentials → Owner access
```

## Edge Properties

```cypher
{
  method: "UserAccessAdmin",
  category: "RBAC",
  condition: "User Access Administrator can assign any Azure role within scope to compromise identities in that scope",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: "User Access Administrator"
}
```

## Detection Query

```cypher
// Find User Access Administrators and what they can escalate to
MATCH (principal:Resource)-[esc:CAN_ESCALATE]->(resource:Resource)
WHERE esc.method = "UserAccessAdmin"
WITH principal,
     count(DISTINCT resource) as controllable_resources,
     collect(DISTINCT resource.resourceType)[0..5] as sample_types
MATCH (principal)-[perm:HAS_PERMISSION]->(scope:Resource)
WHERE perm.roleName = "User Access Administrator"
RETURN principal.displayName as uaa_principal,
       principal.resourceType as principal_type,
       scope.displayName as scope,
       controllable_resources,
       sample_types
ORDER BY controllable_resources DESC
```

## Azure Role Assignment API

**Assign Role:**
```http
PUT https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments/{guid}?api-version=2022-04-01
Content-Type: application/json

{
  "properties": {
    "roleDefinitionId": "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "principalId": "{attacker-object-id}"
  }
}
```

**Note:** `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` = Owner role definition ID

## User Access Administrator Capabilities

**Can Do:**
- ✅ Assign any Azure role (Owner, Contributor, Reader, custom roles)
- ✅ Remove role assignments
- ✅ List role assignments
- ✅ Read role definitions
- ✅ Self-escalate to Owner

**Cannot Do:**
- ❌ Modify resources directly (VMs, storage, Key Vaults)
- ❌ Read resource properties
- ❌ Delete resources
- ❌ Deploy resources
- ❌ Access data plane

**Result:** One API call away from Owner (can do everything above)

## Why This Role Is Dangerous

**Self-Escalation:**
- Assign Owner to self → Full control
- One-step escalation
- No additional compromise needed

**Stealth:**
- Role assignments may not be monitored
- Looks like legitimate administrative action
- Can be done via API (bypasses portal auditing)

**Persistence:**
- Assign Owner to backdoor identity
- Remove original UAA assignment
- Maintain access via Owner
- Original detection missed

## Scope Impact

| Scope | Can Assign Roles To |
|-------|-------------------|
| Management Group | All descendant resources |
| Subscription | All RGs and resources in subscription |
| Resource Group | All resources in RG |
| Resource | That resource only |

**Management Group Owner Assignment:**
```
UAA on MG Root
→ Assign Owner to self on MG Root
→ Owner cascades to all subscriptions
→ Complete Azure environment control
```

## Mitigation

- **Least Privilege:**
  - Avoid granting User Access Administrator
  - Use specific role assignment permissions via custom roles
  - Scope to specific resource groups
- **PIM (Privileged Identity Management):**
  - Eligible assignments with approval workflow
  - Time-bound access (max 8 hours)
  - Justification required for activation
- **Monitoring:**
  - Alert on role assignments at high scopes (MG, Subscription)
  - Alert on Owner role assignments
  - Alert on User Access Administrator assignments
  - Monitor Azure Activity Log: `Microsoft.Authorization/roleAssignments/write`
- **Conditional Access:**
  - Require MFA for Azure management
  - Require compliant device
  - Block risky sign-ins
- **Regular Audit:**
  - Review User Access Administrator assignments monthly
  - Validate business justification
  - Remove unnecessary assignments

## Comparison with Owner

| Role | Resource Control | Role Assignment | Typical Use Case |
|------|-----------------|----------------|------------------|
| **Owner** | ✅ Full | ✅ Yes | Complete administrative control |
| **User Access Administrator** | ❌ None | ✅ Yes | Access management only (but can self-escalate) |
| **Contributor** | ✅ Full | ❌ No | Resource management without access control |

**In Practice:** User Access Administrator ≈ Owner (via self-escalation)

## Common Misconfigurations

**"Access team needs to grant access"**
- ❌ User Access Administrator is over-privileged
- ✅ Use PIM for JIT Owner assignments
- ✅ Use approval workflows

**"Break-glass account needs UAA"**
- ⚠️ Consider Owner instead (more obvious in audit)
- ✅ Or use PIM eligible Owner
- ✅ Monitor closely

**"Service principal for automation"**
- ❌ SP with UAA = persistent risk
- ✅ Use Managed Identity
- ✅ Scope to specific resource groups
- ✅ Use custom role with limited permissions

## Real-World Attack

```
2023: Insider Threat
- Developer had User Access Administrator on subscription
- Assigned Owner to personal account before leaving company
- Accessed company data for 3 months post-departure
- Exfiltrated customer data to competitor
- Detection: Manual role assignment audit
```

## Azure Activity Log Detection

**Monitor for:**
```json
{
  "operationName": {
    "value": "Microsoft.Authorization/roleAssignments/write"
  },
  "caller": "<user-access-admin-identity>",
  "properties": {
    "roleDefinitionId": "*8e3af657-a8ff-443c-a75c-2fe8c4bcb635*"
  }
}
```

Alert when User Access Administrator assigns Owner role.

## Related Documentation

- [Azure Owner](azure-owner.md) - Role typically assigned via this escalation
- [../../Azure_IAM_Nodes/subscription.md](../../Azure_IAM_Nodes/subscription.md) - Subscription scope
- [../../Azure_IAM_Nodes/management-group.md](../../Azure_IAM_Nodes/management-group.md) - Management group scope
- [../CONTAINS/](../CONTAINS/) - Hierarchy for scope traversal

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedRBACUserAccessAdminQuery()` - line 4299
**Phase:** Phase 4 (CAN_ESCALATE edge creation)

**Key Implementation Detail:** Uses same `CONTAINS*0..` traversal as Owner, reflecting that UAA can assign Owner at any descendant scope.
