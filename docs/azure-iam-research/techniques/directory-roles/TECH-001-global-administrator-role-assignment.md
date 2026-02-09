---
id: TECH-001
name: Global Administrator Role Assignment
category: directory-roles
subcategory: administrative-roles
severity: critical
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Global Administrator Role Assignment

## Summary
Global Administrator can manage all aspects of Azure AD and Microsoft services that use Azure AD identities. Can assign any role to any user, providing complete tenant control.

## Required Starting Permissions
- Any directory role with user management permissions

## Attack Path
1. Obtain any directory role with role assignment permissions (e.g., Privileged Role Administrator)
2. Assign Global Administrator role to controlled user account via Azure Portal or Graph API
3. Authenticate as newly promoted Global Administrator
4. Gain complete tenant control including all Azure AD, Exchange Online, SharePoint, Teams

## Target Privilege Gained
- Global Administrator (complete tenant control)

## Real-World Examples
- Red team engagement where Privileged Role Administrator was leveraged to assign Global Admin to test account

## References
- [Entra ID Built-in Roles - Global Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#global-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
