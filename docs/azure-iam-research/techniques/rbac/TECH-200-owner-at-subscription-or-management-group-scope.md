---
id: TECH-200
name: Owner at Subscription or Management Group Scope
category: rbac
subcategory: azure-control-plane
severity: critical
mitre_attack: T1098
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Owner at Subscription or Management Group Scope

## Summary
Owner role at subscription or management group scope grants full access to all resources including role assignments, enabling privilege escalation across the Azure hierarchy.

## Required Starting Permissions
- Owner role at subscription or management group scope

## Attack Path
1. Authenticate with Owner role at subscription or management group
2. Assign Owner or User Access Administrator role to controlled identity at parent scope
3. Alternatively, assign privileged roles to managed identities
4. Use managed identity to access Entra ID if assigned appropriate permissions
5. Escalate within Azure or bridge to Entra ID tenant

## Target Privilege Gained
- User Access Administrator or Owner at higher scopes, potential Entra ID escalation via managed identities

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Built-in Roles - Owner](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
