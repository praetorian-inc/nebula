# AppRoleAssignment.ReadWrite.All Escalation

**Method:** `GraphAppRoleAssignment`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `AppRoleAssignment.ReadWrite.All` permission can grant itself any Graph API permission including `RoleManagement.ReadWrite.Directory`, enabling self-escalation to tenant compromise.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: AppRoleAssignment.ReadWrite.All] → Microsoft Graph
                  → [CAN_ESCALATE: GraphAppRoleAssignment] → Self
                  → Grant RoleManagement.ReadWrite.Directory to self
                  → Assign Global Admin → Tenant compromise
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `source = "Microsoft Graph"`
- `permission = "AppRoleAssignment.ReadWrite.All"`
- `permissionType = "Application"`
- `consentType = "AllPrincipals"`

**Target:** Self (SP → SP)
- Creates CAN_ESCALATE edge from SP to itself
- Represents self-escalation capability

**Condition:** "Service Principal with AppRoleAssignment.ReadWrite.All can grant itself any permission including RoleManagement.ReadWrite.Directory"

## Attack Scenario

### Phase 1: Self-Grant Escalation Permission
1. **Attacker compromises** SP with AppRoleAssignment.ReadWrite.All
2. **Attacker grants** `RoleManagement.ReadWrite.Directory` to itself
   ```http
   POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-id}/appRoleAssignments
   {
     "principalId": "{sp-id}",
     "resourceId": "{microsoft-graph-sp-id}",
     "appRoleId": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
   }
   ```
3. **Permission is now active** - no approval required

### Phase 2: Tenant Compromise
4. **Attacker uses new permission** to assign Global Admin
   ```http
   POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
   {
     "principalId": "{attacker-user-id}",
     "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
     "directoryScopeId": "/"
   }
   ```
5. **Attacker authenticates** as Global Administrator
6. **Result:** Complete tenant control

## Microsoft Graph API Calls

**Grant Permission to Self:**
```http
POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-object-id}/appRoleAssignments
Content-Type: application/json

{
  "principalId": "{sp-object-id}",
  "resourceId": "{microsoft-graph-sp-id}",
  "appRoleId": "{desired-permission-id}"
}
```

**Common High-Value Permission IDs:**
- `9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8` = RoleManagement.ReadWrite.Directory
- `19dbc75e-c2e2-444c-a770-ec69d8559fc7` = Directory.ReadWrite.All
- `1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9` = Application.ReadWrite.All

## Edge Properties

```cypher
{
  method: "GraphAppRoleAssignment",
  category: "GraphPermission",
  condition: "Service Principal with AppRoleAssignment.ReadWrite.All can grant itself any permission including RoleManagement.ReadWrite.Directory",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SPs that can self-escalate
MATCH (sp:Resource)-[esc:CAN_ESCALATE]->(sp)
WHERE esc.method = "GraphAppRoleAssignment"
RETURN sp.displayName as self_escalating_sp,
       sp.appId as app_id,
       esc.condition as capability
```

## Why This Permission Is Uniquely Dangerous

**Self-Escalation:**
- No external dependencies
- No approval workflow
- No admin intervention required
- Immediate permission gain

**Stealth:**
- Can grant permissions silently
- May not trigger standard monitoring
- Looks like normal administrative action

**Unrestricted:**
- Can grant ANY Graph API permission
- Can grant to ANY service principal (not just self)
- Can grant delegated OR application permissions

## Real-World Attack Chain

```
1. Phishing → Compromise user with SP credentials
2. AppRoleAssignment.ReadWrite.All discovered
3. Grant RoleManagement.ReadWrite.Directory to self
4. Assign Global Administrator to attacker account
5. Exfiltrate data, create backdoors, maintain persistence
```

**Time to Compromise:** Minutes

## Additional Escalation Vectors

Beyond self-escalation, this permission enables:

**Grant to Other SPs:**
```
- Compromise low-privilege SP with AppRoleAssignment.ReadWrite.All
- Grant high privileges to another SP you control
- Use other SP for actual attacks
```

**Grant to Applications:**
```
- Grant permissions to application objects
- Service principals inherit app permissions
```

**Delegated Permission Grants:**
```
- Grant delegated permissions requiring admin consent
- Enable OAuth phishing attacks
```

## Mitigation

- **Critical Review:** Audit all SPs with this permission immediately
- **Remove:** Revoke unless absolutely justified
- **Alternative:** No safe alternative - this permission is inherently dangerous
- **Monitoring:** Alert on ANY app role assignments by SPs
- **Activity Logs:** Monitor `Add app role assignment to service principal`
- **Conditional Access:** N/A (Application permissions bypass CA)
- **Break-Glass:** Never grant to break-glass SPs

## Microsoft's Guidance

From Microsoft documentation:
> "This permission allows an app to manage permissions for all apps, including itself. This is a highly privileged permission and should only be granted to trusted apps."

**Translation:** Almost never grant this permission.

## Related Documentation

- [RoleManagement.ReadWrite.Directory](rolemanagement-readwrite-directory.md) - Permission typically granted via this escalation
- [Directory.ReadWrite.All](directory-readwrite-all.md) - Another common escalation target
- [Application.ReadWrite.All](application-readwrite-all.md) - Alternative escalation permission
- [../../Azure_IAM_Nodes/service-principal.md](../../Azure_IAM_Nodes/service-principal.md) - SP node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphAppRoleAssignmentQuery()` - line 4206
**Phase:** Phase 4 (CAN_ESCALATE edge creation)

## Notes

**Unique Edge Pattern:** This is the only CAN_ESCALATE edge that points from a node to itself (`sp → sp`), representing self-escalation capability.
