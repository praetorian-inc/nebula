# Global Administrator

## Description

The Global Administrator role provides complete control over the Entra ID tenant and can elevate to Owner on any Azure subscription. Principals with this role can escalate to compromise any resource in the entire tenant.

## Edge Information

- **Attack Method**: GlobalAdministrator
- **Edge Category**: DirectoryRole
- **From**: User or Service Principal with Global Administrator role
- **To**: Any resource in the tenant

## Escalation Condition

Global Administrator role provides complete tenant control and can elevate to Owner on any Azure subscription.

## Technical Details

### Detection Query
```cypher
MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.roleName = "Global Administrator" OR perm.templateId = "62e90394-69f5-4237-9190-012177145e10"
WITH user
MATCH (escalate_target:Resource)
WHERE escalate_target <> user
CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "GlobalAdministrator",
    r.condition = "Global Administrator role provides complete tenant control and can elevate to Owner on any Azure subscription",
    r.category = "DirectoryRole"
```

### Prerequisites
- Principal must have Global Administrator directory role assignment
- Role must be active (not just eligible through PIM)

### Attack Scenarios

1. **Complete Tenant Takeover**: Global Admin can modify any directory object, assign any role, access any resource
2. **Azure Subscription Elevation**: Can elevate to Owner role on any Azure subscription in the tenant
3. **Cross-Service Access**: Can access Exchange, SharePoint, Teams, and all other Microsoft 365 services
4. **Identity Management**: Can create, modify, or delete any user, group, or application
5. **Security Bypass**: Can disable security features, modify conditional access policies


### Mitigation Strategies

1. **Minimize Global Admins**: Limit the number of Global Administrator assignments
2. **Use Break-Glass Accounts**: Separate emergency access accounts with strong protection
3. **Enable PIM**: Use Privileged Identity Management for just-in-time access
4. **Monitor Global Admin Activity**: Alert on any Global Administrator actions
5. **Protect Global Admin Owners**: If Global Admin is a Service Principal, secure its owners
6. **Multi-Admin Authorization**: Require multiple admins for critical changes

### Related Edges

- [Privileged Role Administrator](privileged-role-administrator.md) - Can assign Global Administrator role
- [Application Administrator](application-administrator.md) - Can potentially escalate to Global Admin via application manipulation

## References

- [Microsoft Entra ID Global Administrator Role](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)
- [Azure Global Administrator Elevation](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin)