---
id: TECH-004
name: Application Administrator Service Principal Escalation
category: directory-roles
subcategory: application-management
severity: high
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Application Administrator Service Principal Escalation

## Summary
Application Administrator can create app registrations and grant admin consent for privileged Graph API permissions, creating service principals with elevated privileges.

## Required Starting Permissions
- Application Administrator

## Attack Path
1. Authenticate as Application Administrator
2. Create new app registration in Azure AD
3. Request privileged Graph API permissions (Application type): RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All
4. Grant admin consent for requested permissions
5. Generate client secret for service principal
6. Authenticate as service principal using client credentials flow
7. Use Microsoft Graph API to assign directory roles or modify privileged users

## Target Privilege Gained
- Service principal with privileged Graph API permissions (RoleManagement.ReadWrite.Directory, etc.)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Application Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#application-administrator)
- [Microsoft Graph Permission Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
