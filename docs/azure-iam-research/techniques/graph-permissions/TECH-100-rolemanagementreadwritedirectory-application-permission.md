---
id: TECH-100
name: RoleManagement.ReadWrite.Directory Application Permission
category: graph-permissions
subcategory: role-management
severity: critical
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# RoleManagement.ReadWrite.Directory Application Permission

## Summary
Allows an application to read and write all directory RBAC settings including role definitions and role assignments, enabling complete directory role manipulation.

## Required Starting Permissions
- Service principal with RoleManagement.ReadWrite.Directory application permission

## Attack Path
1. Authenticate as service principal with RoleManagement.ReadWrite.Directory
2. Use Microsoft Graph API to enumerate directory roles
3. Assign Global Administrator role to controlled user account via POST to /directoryRoles/{id}/members
4. Authenticate as newly promoted Global Administrator
5. Gain complete tenant control

## Target Privilege Gained
- Ability to assign Global Administrator or any directory role

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - RoleManagement.ReadWrite.Directory](https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreadwritedirectory)
- [Assign Directory Roles - Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/directoryrole-post-members)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
