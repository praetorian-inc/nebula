---
id: TECH-003
name: Privileged Authentication Administrator Password Reset
category: directory-roles
subcategory: authentication-management
severity: critical
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Privileged Authentication Administrator Password Reset

## Summary
Privileged Authentication Administrator can reset passwords and authentication methods for any user including Global Administrators, providing credential takeover path.

## Required Starting Permissions
- Privileged Authentication Administrator

## Attack Path
1. Authenticate as Privileged Authentication Administrator
2. Identify target administrator account (e.g., Global Administrator)
3. Reset password or register new authentication method for target via Azure Portal or Graph API
4. Authenticate as compromised administrator
5. Leverage administrator privileges for persistent access

## Target Privilege Gained
- Any user account credentials including Global Administrators

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Privileged Authentication Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-authentication-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
