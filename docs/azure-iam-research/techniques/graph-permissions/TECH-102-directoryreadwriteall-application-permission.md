---
id: TECH-102
name: Directory.ReadWrite.All Application Permission
category: graph-permissions
subcategory: directory-modification
severity: high
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Directory.ReadWrite.All Application Permission

## Summary
Allows an application to read and write all directory data including users, groups, and applications, enabling wide-ranging modification capabilities.

## Required Starting Permissions
- Service principal with Directory.ReadWrite.All

## Attack Path
1. Authenticate as service principal with Directory.ReadWrite.All
2. Identify privileged security groups with role assignments
3. Add controlled user to privileged group via PATCH /groups/{id}
4. Inherit directory role permissions through group membership
5. Alternatively, reset passwords for non-admin users
6. Leverage compromised accounts for lateral movement

## Target Privilege Gained
- Ability to modify users, groups, reset passwords, add group members

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - Directory.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#directoryreadwriteall)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
