---
id: TECH-002
name: Privileged Role Administrator to Global Admin
category: directory-roles
subcategory: administrative-roles
severity: critical
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Privileged Role Administrator to Global Admin

## Summary
Privileged Role Administrator can assign most directory roles including Global Administrator, effectively providing a path to full tenant compromise.

## Required Starting Permissions
- Privileged Role Administrator

## Attack Path
1. Authenticate as user with Privileged Role Administrator role
2. Use Azure Portal or Microsoft Graph API to assign Global Administrator role
3. Authenticate as newly elevated account
4. Exercise full tenant administrative control

## Target Privilege Gained
- Global Administrator or any directory role

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Privileged Role Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-role-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
