---
id: TECH-101
name: AppRoleAssignment.ReadWrite.All Application Permission
category: graph-permissions
subcategory: permission-management
severity: critical
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# AppRoleAssignment.ReadWrite.All Application Permission

## Summary
Allows an application to manage app role assignments for any app, enabling privilege escalation by granting additional Graph permissions to service principals.

## Required Starting Permissions
- Service principal with AppRoleAssignment.ReadWrite.All

## Attack Path
1. Authenticate as service principal with AppRoleAssignment.ReadWrite.All
2. Use Graph API to identify Microsoft Graph service principal ID
3. Grant additional privileged Graph permissions to self (e.g., RoleManagement.ReadWrite.Directory)
4. Authenticate with new elevated permissions
5. Use newly acquired permissions for further escalation (e.g., role assignments)

## Target Privilege Gained
- Self-assignment of RoleManagement.ReadWrite.Directory or other privileged Graph permissions

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - AppRoleAssignment.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#approleassignmentreadwriteall)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
