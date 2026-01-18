---
id: TECH-005
name: Cloud Application Administrator Service Principal Escalation
category: directory-roles
subcategory: application-management
severity: high
mitre_attack: T1098.003
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Cloud Application Administrator Service Principal Escalation

## Summary
Similar to Application Administrator, Cloud Application Administrator can create apps and grant consent for escalation-capable Graph permissions.

## Required Starting Permissions
- Cloud Application Administrator

## Attack Path
1. Authenticate as Cloud Application Administrator
2. Create app registration or modify existing enterprise application
3. Request and grant admin consent for Graph API permissions with escalation potential
4. Generate service principal credentials (client secret or certificate)
5. Authenticate as service principal
6. Leverage Graph API permissions to escalate privileges

## Target Privilege Gained
- Service principal with privileged Graph API permissions

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Entra ID Built-in Roles - Cloud Application Administrator](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
