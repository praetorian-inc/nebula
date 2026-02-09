---
id: TECH-307
name: Cross-Tenant B2B Collaboration Abuse
category: cross-domain
subcategory: multi-tenant-abuse
severity: medium
mitre_attack: T1199
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Cross-Tenant B2B Collaboration Abuse

## Summary
Azure AD B2B guest users can be added to external tenants with privileged roles. Compromise of guest account in home tenant enables privilege escalation in resource tenant.

## Required Starting Permissions
- Compromised user account that is B2B guest in multiple tenants

## Attack Path
1. Compromise user account in home tenant
2. Enumerate tenants where user is invited as B2B guest
3. Authenticate to resource tenants using compromised credentials
4. Leverage roles and permissions granted to guest user in each tenant
5. Common misconfiguration: guests assigned administrative roles

## Target Privilege Gained
- Privileges granted to guest user in resource tenants

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure AD B2B Security](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
