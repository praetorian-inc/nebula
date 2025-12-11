# RoleManagement.ReadWrite.Directory

## Description

Service Principals with the RoleManagement.ReadWrite.Directory Microsoft Graph API permission can directly assign directory roles, including Global Administrator, to any principal in the tenant.

## Edge Information

- **Attack Method**: GraphRoleManagement
- **Edge Category**: GraphPermission
- **From**: Service Principal with RoleManagement.ReadWrite.Directory application permission
- **To**: Any principal in the tenant

## Escalation Condition

Service Principal with RoleManagement.ReadWrite.Directory can directly assign Global Administrator or any directory role to any principal.

## Technical Details

### Detection Query
```cypher
MATCH (sp:Resource)-[perm:HAS_GRAPH_PERMISSION]->(target:Resource)
WHERE perm.permission = "RoleManagement.ReadWrite.Directory"
  AND perm.permissionType = "Application"
  AND perm.consentType = "AllPrincipals"
WITH sp
MATCH (escalate_target:Resource)
WHERE escalate_target <> sp
CREATE (sp)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "GraphRoleManagement",
    r.condition = "Service Principal with RoleManagement.ReadWrite.Directory can directly assign Global Administrator or any directory role to any principal",
    r.category = "GraphPermission"
```

### Prerequisites
- Service Principal must have RoleManagement.ReadWrite.Directory application permission
- Permission must be granted with "AllPrincipals" consent (not delegated)
- Permission type must be "Application" (not "Delegated")

### Attack Scenarios

1. **Direct Global Admin Assignment**: Assign Global Administrator role to attacker-controlled identity
2. **Privilege Escalation Chain**: Assign lesser admin roles → use those to escalate further
3. **Backdoor Creation**: Assign admin roles to hidden or service accounts
4. **Role Modification**: Modify existing role definitions to include dangerous permissions
5. **Emergency Access Abuse**: Create new admin accounts during incident response

### Microsoft Graph API Calls

The Service Principal can make calls such as:
```http
POST https://graph.microsoft.com/v1.0/directoryRoles/{role-id}/members
{
  "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/{principal-id}"
}
```

### Permission Scope

This permission allows:
- **Read**: All directory role assignments and definitions
- **Write**: Create, modify, and delete directory role assignments
- **Assign**: Any directory role to any principal
- **Modify**: Role definitions and their permissions

### Mitigation Strategies

1. **Avoid This Permission**: Never grant RoleManagement.ReadWrite.Directory unless absolutely necessary
2. **Use Delegated Permissions**: Prefer delegated over application permissions when possible
3. **Restrict Consent**: Require admin consent for this permission
4. **Regular Audits**: Monitor all applications with this permission
5. **Conditional Access**: Apply strict CA policies to applications with this permission
6. **Certificate-Based Auth**: Use certificate authentication instead of client secrets
7. **Short-Lived Tokens**: Implement token refresh strategies

### Detection and Monitoring

Monitor for:
- Applications requesting RoleManagement.ReadWrite.Directory permission
- Unexpected directory role assignments via Graph API
- Service Principal authentication followed by role assignment activities
- New applications being granted this permission
- Changes to directory role definitions

### Real-World Impact

Applications with this permission represent **Tier 0** compromise risk:
- Equivalent to having a Global Administrator in terms of escalation potential
- Can create persistent backdoors in the tenant
- Often overlooked compared to interactive admin accounts
- Frequently have weak authentication (client secrets vs. MFA)

### Related Edges

- [Directory.ReadWrite.All](directory-readwrite-all.md) - Can also manipulate role assignments
- [Global Administrator](../directory-roles/global-administrator.md) - Target of escalation
- [Application.ReadWrite.All](application-readwrite-all.md) - Can add credentials to SPs with this permission

## References

- [Microsoft Graph API Directory Role Assignments](https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members)
- [RoleManagement.ReadWrite.Directory Permission](https://docs.microsoft.com/en-us/graph/permissions-reference#role-management-permissions)