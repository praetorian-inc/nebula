---
id: TECH-301
name: Azure AD Connect Sync Account Abuse
category: cross-domain
subcategory: hybrid-identity-abuse
severity: critical
mitre_attack: T1556.007
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Azure AD Connect Sync Account Abuse

## Summary
Azure AD Connect sync account has privileged permissions including password reset for all users. Compromise of on-premises AD Connect server enables credential theft and privilege escalation.

## Required Starting Permissions
- Administrator access to Azure AD Connect server

## Attack Path
1. Compromise on-premises server running Azure AD Connect
2. Extract sync account credentials from AD Connect configuration (encrypted in WID database or SQL)
3. Use tools like AADInternals to decrypt credentials
4. Authenticate as sync account to Azure AD
5. Reset passwords for Global Administrators or other privileged accounts
6. Authenticate with new passwords to gain administrative access

## Target Privilege Gained
- Password reset capability for all Azure AD users including Global Administrators

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [AADInternals - PowerShell Module](https://github.com/Gerenios/AADInternals)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
