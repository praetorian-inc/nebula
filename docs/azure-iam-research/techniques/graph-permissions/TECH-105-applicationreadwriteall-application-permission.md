---
id: TECH-105
name: Application.ReadWrite.All Application Permission
category: graph-permissions
subcategory: application-management
severity: high
mitre_attack: T1098.001
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Application.ReadWrite.All Application Permission

## Summary
Allows an application to create and modify app registrations and service principals including adding credentials, enabling credential theft and permission escalation.

## Required Starting Permissions
- Service principal with Application.ReadWrite.All

## Attack Path
1. Authenticate as service principal with Application.ReadWrite.All
2. Enumerate existing service principals with privileged permissions
3. Add new client secret or certificate to target service principal via POST /servicePrincipals/{id}/addPassword
4. Authenticate as compromised service principal using stolen credentials
5. Leverage service principal's existing privileges for escalation

## Target Privilege Gained
- Ability to add credentials to existing privileged service principals

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft Graph Permissions - Application.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadwriteall)
- [Add Service Principal Password - Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
