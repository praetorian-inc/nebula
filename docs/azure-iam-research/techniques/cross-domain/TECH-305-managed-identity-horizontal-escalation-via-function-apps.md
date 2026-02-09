---
id: TECH-305
name: Managed Identity Horizontal Escalation via Function Apps
category: cross-domain
subcategory: managed-identity-abuse
severity: high
mitre_attack: T1078.004
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Managed Identity Horizontal Escalation via Function Apps

## Summary
Azure Function Apps and Logic Apps often have managed identities with broad permissions. Compromise of these serverless resources enables lateral movement and privilege escalation.

## Required Starting Permissions
- Contributor access to Function App or Logic App

## Attack Path
1. Identify Function Apps or Logic Apps with managed identities
2. Compromise Function App via deployment slot or application code access
3. Extract managed identity token from within Function App execution context
4. Use token to access Azure resources at managed identity's privilege level
5. Common misconfiguration: managed identity with Contributor at subscription scope

## Target Privilege Gained
- Managed identity permissions (often Contributor at subscription level)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Managed Identities Security](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
