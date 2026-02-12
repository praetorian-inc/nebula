# RoleManagement.ReadWrite.Directory Escalation

**Method:** `GraphRoleManagement`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `RoleManagement.ReadWrite.Directory` permission can directly assign Global Administrator or any directory role to any principal, enabling complete tenant compromise.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: RoleManagement.ReadWrite.Directory] → Microsoft Graph
                  → [CAN_ESCALATE: GraphRoleManagement] → All Principals
                  → Assign Global Admin role → Complete tenant control
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `source = "Microsoft Graph"`
- `permission = "RoleManagement.ReadWrite.Directory"`
- `permissionType = "Application"`
- `consentType = "AllPrincipals"`

**Target:** All principals in tenant:
- Users (`microsoft.directoryservices/users`)
- Service Principals (`microsoft.directoryservices/serviceprincipals`)
- Groups (`microsoft.directoryservices/groups`)

**Condition:** "Service Principal with RoleManagement.ReadWrite.Directory can directly assign Global Administrator or any directory role to any principal"

## Attack Scenario

1. **Attacker compromises** service principal with RoleManagement.ReadWrite.Directory
2. **Attacker authenticates** as SP using stolen credentials
3. **Attacker assigns** Global Administrator role to:
   - Their own user account, OR
   - Another SP they control, OR
   - A group they're a member of
4. **Attacker authenticates** with newly privileged identity
5. **Result:** Complete tenant compromise via Global Administrator

## Microsoft Graph API Call

```http
POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
Content-Type: application/json

{
  "principalId": "<attacker-user-or-sp-id>",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/"
}
```

**Note:** `62e90394-69f5-4237-9190-012177145e10` = Global Administrator template ID

## Edge Properties

```cypher
{
  method: "GraphRoleManagement",
  category: "GraphPermission",
  condition: "Service Principal with RoleManagement.ReadWrite.Directory can directly assign Global Administrator or any directory role to any principal",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SPs with RoleManagement.ReadWrite.Directory
MATCH (sp:Resource)-[esc:CAN_ESCALATE]->(target:Resource)
WHERE esc.method = "GraphRoleManagement"
RETURN sp.displayName as service_principal,
       sp.appId as app_id,
       count(target) as principals_can_escalate_to
ORDER BY principals_can_escalate_to DESC
```

## Why This Permission Is Critical

**Direct Role Assignment:**
- No intermediate steps required
- No approval workflow
- No PIM constraints
- Immediate privilege escalation

**Scope:**
- Can assign ANY directory role (not just Global Admin)
- Can target ANY principal (users, groups, SPs)
- Tenant-wide impact

**Common Misconfigurations:**
- Granted to automation SPs "for convenience"
- Used for "administrative dashboards"
- Legacy integrations with over-privileged access

## Real-World Examples

**Automation Gone Wrong:**
```
DevOps Pipeline SP → RoleManagement.ReadWrite.Directory
→ Credentials leaked in logs
→ Attacker assigns Global Admin
→ Complete tenant compromise
```

**Third-Party Integration:**
```
SaaS Connector SP → RoleManagement.ReadWrite.Directory
→ Vendor compromised
→ Supply chain attack
→ Tenant takeover
```

## Mitigation

- **Principle of Least Privilege:** Almost no legitimate use case requires this permission
- **Alternative:** Use PIM API (`PrivilegedAccess.ReadWrite.AzureAD`) for JIT activation
- **Monitoring:** Alert on ANY role assignments by SPs
- **Conditional Access:** N/A (Application permissions bypass CA)
- **Credential Protection:** Store SP secrets in Azure Key Vault with access policies
- **Regular Audit:** Review SPs with this permission monthly

## Related Documentation

- [AppRoleAssignment.ReadWrite.All](approleassignment-readwrite-all.md) - Can grant itself this permission
- [Directory.ReadWrite.All](directory-readwrite-all.md) - Broader but includes role assignment
- [Global Administrator](global-administrator.md) - Target role typically assigned
- [../../Azure_IAM_Nodes/service-principal.md](../../Azure_IAM_Nodes/service-principal.md) - SP node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphRoleManagementQuery()` - line 4131
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
