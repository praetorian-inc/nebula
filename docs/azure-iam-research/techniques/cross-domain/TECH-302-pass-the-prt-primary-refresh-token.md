---
id: TECH-302
name: Pass-the-PRT (Primary Refresh Token)
category: cross-domain
subcategory: credential-theft
severity: high
mitre_attack: T1528
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Pass-the-PRT (Primary Refresh Token)

## Summary
Primary Refresh Token (PRT) is a long-lived authentication token issued to Windows 10+ devices. Stealing and replaying PRT enables authentication as the device user to Azure AD resources.

## Required Starting Permissions
- Local administrator on Azure AD-joined Windows device

## Attack Path
1. Gain local administrator access on Azure AD-joined Windows device
2. Extract PRT using Mimikatz, AADInternals, or direct LSASS memory access
3. Transfer PRT to attacker-controlled system
4. Use PRT to request access tokens for Azure AD applications
5. Access user's Microsoft 365, Azure portal, or other cloud resources

## Target Privilege Gained
- Authentication as device user to Azure AD resources and applications

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Pass-the-PRT Attack and Detection](https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30)
- [Primary Refresh Token Overview - Microsoft](https://learn.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
