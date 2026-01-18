---
id: TECH-203
name: Automation Operator Runbook Execution
category: rbac
subcategory: automation-abuse
severity: medium
mitre_attack: T1078.004
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Automation Operator Runbook Execution

## Summary
Automation Account Operator can execute runbooks that may contain privileged credentials or perform privileged operations.

## Required Starting Permissions
- Automation Operator or Automation Job Operator

## Attack Path
1. Authenticate with Automation Operator role
2. Enumerate Automation Accounts and runbooks
3. Execute runbooks or review runbook code for embedded credentials
4. Extract service principal secrets or managed identity assignments
5. Use stolen credentials for privilege escalation

## Target Privilege Gained
- Credentials embedded in runbooks, managed identity permissions

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Automation Security](https://learn.microsoft.com/en-us/azure/automation/automation-security-overview)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
