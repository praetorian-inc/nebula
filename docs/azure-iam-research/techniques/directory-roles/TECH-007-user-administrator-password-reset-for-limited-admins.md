---
id: TECH-007
name: User Administrator Password Reset for Limited Admins
category: directory-roles
subcategory: user-management
severity: medium
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# User Administrator Password Reset for Limited Admins

## Summary
User Administrator can reset passwords for users with limited admin roles, enabling lateral movement to admin accounts.

## Required Starting Permissions
- User Administrator

## Attack Path
1. Authenticate as User Administrator
2. Identify users with limited admin roles within reset scope
3. Reset password for target limited admin account via Azure Portal
4. Authenticate as compromised admin
5. Leverage admin permissions for lateral movement within tenant

## Target Privilege Gained
- Credentials for limited admin roles (Helpdesk Administrator, Password Administrator, etc.)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - User Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#user-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
