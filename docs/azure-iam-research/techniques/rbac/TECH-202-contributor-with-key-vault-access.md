---
id: TECH-202
name: Contributor with Key Vault Access
category: rbac
subcategory: data-plane-access
severity: high
mitre_attack: T1555.005
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Contributor with Key Vault Access

## Summary
Contributor role combined with Key Vault access can expose stored credentials including service principal secrets and privileged account passwords.

## Required Starting Permissions
- Contributor + Key Vault access policies or RBAC permissions

## Attack Path
1. Authenticate with Contributor role
2. Enumerate Key Vaults in accessible subscriptions
3. Access Key Vault secrets containing service principal credentials or admin passwords
4. Use stolen credentials to authenticate as privileged identity
5. Leverage elevated access for further escalation

## Target Privilege Gained
- Service principal credentials, privileged user passwords, API keys

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Built-in Roles - Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#contributor)
- [Key Vault Security](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
