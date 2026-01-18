---
id: TECH-008
name: Authentication Administrator Password Reset for Non-Admins
category: directory-roles
subcategory: authentication-management
severity: low
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Authentication Administrator Password Reset for Non-Admins

## Summary
Authentication Administrator can reset authentication methods for non-admin users, enabling account takeover of users with sensitive data access.

## Required Starting Permissions
- Authentication Administrator

## Attack Path
1. Authenticate as Authentication Administrator
2. Identify non-admin users with access to sensitive data or applications
3. Reset authentication methods (password, MFA) for target users
4. Authenticate as compromised user
5. Access sensitive business data or applications
6. Use compromised identity for social engineering or data exfiltration

## Target Privilege Gained
- Credentials for non-admin user accounts

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Authentication Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#authentication-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
