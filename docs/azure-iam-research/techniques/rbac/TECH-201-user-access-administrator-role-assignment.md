---
id: TECH-201
name: User Access Administrator Role Assignment
category: rbac
subcategory: azure-control-plane
severity: high
mitre_attack: T1098
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# User Access Administrator Role Assignment

## Summary
User Access Administrator can manage role assignments for Azure resources without full Owner permissions, enabling privilege escalation through role manipulation.

## Required Starting Permissions
- User Access Administrator at any scope

## Attack Path
1. Authenticate with User Access Administrator role
2. Assign Owner or Contributor role to controlled user or managed identity
3. Use elevated permissions to access sensitive resources
4. Assign privileged Graph API permissions to managed identities for Entra ID bridge

## Target Privilege Gained
- Owner or Contributor at subscription/management group, managed identity with Entra ID access

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Built-in Roles - User Access Administrator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
