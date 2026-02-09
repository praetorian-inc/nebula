---
id: TECH-006
name: Groups Administrator Privileged Group Membership
category: directory-roles
subcategory: group-management
severity: medium
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Groups Administrator Privileged Group Membership

## Summary
Groups Administrator can add members to any security group including those with privileged directory role assignments.

## Required Starting Permissions
- Groups Administrator

## Attack Path
1. Authenticate as Groups Administrator
2. Enumerate security groups with directory role assignments (role-assignable groups)
3. Add controlled user account to privileged group
4. Inherit directory role permissions through group membership
5. Authenticate as user with inherited role
6. Leverage inherited privileges for further escalation

## Target Privilege Gained
- Membership in privileged groups with directory role assignments

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Groups Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#groups-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
