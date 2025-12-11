# Privileged Authentication Administrator

## Description

The Privileged Authentication Administrator can reset passwords and authentication methods for ANY user in the tenant, including Global Administrators. This role bypasses normal admin hierarchy restrictions.

## Edge Information

- **Attack Method**: PrivilegedAuthenticationAdmin
- **Edge Category**: DirectoryRole
- **From**: User or Service Principal with Privileged Authentication Administrator role
- **To**: Any user in the tenant

## Escalation Condition

Can reset passwords and authentication methods for ANY user including Global Administrators.

## Technical Details

### Detection Query
```cypher
MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.roleName = "Privileged Authentication Administrator" OR perm.templateId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
WITH user
MATCH (escalate_target:Resource)
WHERE escalate_target <> user AND escalate_target.resourceType = "Microsoft.DirectoryServices/users"
CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "PrivilegedAuthenticationAdmin",
    r.condition = "Can reset passwords and authentication methods for ANY user including Global Administrators",
    r.category = "DirectoryRole"
```

### Prerequisites
- Principal must have Privileged Authentication Administrator directory role assignment
- Target must be a user (cannot reset SP passwords)

### Attack Scenarios

1. **Global Administrator Takeover**: Reset Global Admin password → assume their identity → complete tenant control
2. **MFA Bypass**: Reset authentication methods including MFA → bypass security controls
3. **Identity Assumption**: Reset any user's password → assume their identity and privileges
4. **Privilege Escalation Chain**: Reset privileged user passwords → inherit their roles and permissions
5. **Emergency Access Abuse**: Use legitimate emergency access procedures for malicious purposes

### Specific Permissions

This role includes:
1. **`microsoft.directory/users/password/update`** - Reset any user's password
2. **`microsoft.directory/users/userPrincipalName/update`** - Modify user identities
3. **`microsoft.directory/bitlockerKeys/key/read`** - Access device encryption keys (Security Reader role)

### Mitigation Strategies

1. **Extreme Protection**: Treat Privileged Auth Admins like Global Admins
2. **Hardware MFA**: Require FIDO2/hardware tokens (cannot be reset)
3. **Separate Break-Glass**: Use dedicated emergency accounts
4. **Activity Monitoring**: Alert on any password reset activity
5. **Approval Workflows**: Require multi-person approval for password resets
6. **Time-Based Access**: Use PIM for just-in-time access only
7. **Network Restrictions**: Limit access to privileged admin workstations only

### Attack Detection

Monitor for:
- Password reset activities by Privileged Authentication Administrators
- Authentication method changes for privileged accounts
- Sign-ins immediately following password resets
- Multiple password resets in short time periods
- Password resets for Global Administrators or other privileged roles

### Related Edges

- [Global Administrator](global-administrator.md) - Can be compromised via password reset
- [User Administrator](user-administrator.md) - Similar but limited to non-admin users
- [Authentication Administrator](authentication-administrator.md) - Similar but limited to non-admin users

## References

- [Microsoft Entra ID Privileged Authentication Administrator Role](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-authentication-administrator)
- [Password Reset Capabilities in Entra ID](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)