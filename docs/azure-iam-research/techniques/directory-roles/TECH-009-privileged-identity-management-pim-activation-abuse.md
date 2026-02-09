---
id: TECH-009
name: Privileged Identity Management (PIM) Activation Abuse
category: directory-roles
subcategory: just-in-time-access
severity: medium
mitre_attack: T1078.004
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Privileged Identity Management (PIM) Activation Abuse

## Summary
Users with eligible role assignments in PIM can activate elevated privileges. Compromised eligible users can activate roles for privilege escalation with minimal detection.

## Required Starting Permissions
- User account with eligible PIM role assignments

## Attack Path
1. Compromise user account with eligible PIM role assignments
2. Activate eligible role (e.g., Global Administrator) through Azure Portal or PowerShell
3. Provide justification if required (often not validated)
4. Gain elevated privileges for duration of activation (typically 1-8 hours)
5. Perform malicious actions during activation window
6. Role automatically de-activates, reducing forensic evidence

## Target Privilege Gained
- Temporary activation of Global Administrator or other privileged roles

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Privileged Identity Management Overview](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
