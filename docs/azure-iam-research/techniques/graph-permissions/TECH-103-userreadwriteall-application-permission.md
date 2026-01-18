---
id: TECH-103
name: User.ReadWrite.All Application Permission
category: graph-permissions
subcategory: user-modification
severity: high
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# User.ReadWrite.All Application Permission

## Summary
Allows an application to read and write all user properties including password resets, enabling account takeover of user accounts.

## Required Starting Permissions
- Service principal with User.ReadWrite.All

## Attack Path
1. Authenticate as service principal with User.ReadWrite.All
2. Enumerate non-admin users with access to sensitive resources
3. Reset password for target user via PATCH /users/{id} with passwordProfile
4. Authenticate as compromised user
5. Access sensitive data or applications
6. Use compromised identity for social engineering attacks

## Target Privilege Gained
- Password control over all user accounts (excluding admins with stronger protections)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - User.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#userreadwriteall)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
