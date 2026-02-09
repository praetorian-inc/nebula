---
id: TECH-104
name: GroupMember.ReadWrite.All Application Permission
category: graph-permissions
subcategory: group-modification
severity: high
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# GroupMember.ReadWrite.All Application Permission

## Summary
Allows an application to add and remove members from all groups, enabling privilege escalation via privileged group membership.

## Required Starting Permissions
- Service principal with GroupMember.ReadWrite.All

## Attack Path
1. Authenticate as service principal with GroupMember.ReadWrite.All
2. Enumerate groups with privileged role assignments (role-assignable groups)
3. Add controlled user account to privileged group via POST /groups/{id}/members
4. User inherits directory role or Azure RBAC role through group membership
5. Authenticate as user with inherited privileges
6. Leverage inherited role for further escalation

## Target Privilege Gained
- Membership in privileged groups with directory role assignments or Azure RBAC roles

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - GroupMember.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadwriteall)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
