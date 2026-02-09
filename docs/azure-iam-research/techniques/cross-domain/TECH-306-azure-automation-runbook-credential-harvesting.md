---
id: TECH-306
name: Azure Automation Runbook Credential Harvesting
category: cross-domain
subcategory: credential-theft
severity: high
mitre_attack: T1555.005
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Azure Automation Runbook Credential Harvesting

## Summary
Azure Automation accounts store credentials and certificates accessible to runbooks. Compromise of Automation account enables credential harvesting for privilege escalation.

## Required Starting Permissions
- Automation Contributor or higher on Automation Account

## Attack Path
1. Identify Azure Automation accounts with stored credentials
2. Create or modify runbook with access to automation variables and connections
3. Execute runbook to extract stored credentials
4. Use stolen credentials to authenticate as privileged service principals or user accounts
5. Escalate further using stolen identity permissions

## Target Privilege Gained
- Credentials stored in Automation account (service principals, connection strings, admin passwords)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Automation Security](https://learn.microsoft.com/en-us/azure/automation/automation-security-overview)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
