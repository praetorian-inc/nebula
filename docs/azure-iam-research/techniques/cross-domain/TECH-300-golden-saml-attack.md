---
id: TECH-300
name: Golden SAML Attack
category: cross-domain
subcategory: federation-abuse
severity: critical
mitre_attack: T1606.002
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Golden SAML Attack

## Summary
Compromise Active Directory Federation Services (ADFS) to forge SAML tokens for any user, enabling authentication to Azure AD/Entra ID as any user including Global Administrators.

## Required Starting Permissions
- Administrator access to on-premises ADFS server

## Attack Path
1. Compromise on-premises Active Directory or ADFS server
2. Extract ADFS token-signing certificate from ADFS configuration database
3. Use ADFSSigningCertificate to forge SAML tokens for target admin users
4. Present forged SAML token to Azure AD for authentication
5. Gain access as Global Administrator or any privileged user

## Target Privilege Gained
- Global Administrator in Azure AD/Entra ID via forged SAML tokens

## Real-World Examples
- SolarWinds compromise (APT29/Cozy Bear) - forged SAML tokens used to access Microsoft cloud environments

## References
- [Golden SAML Revisited: The Solorigate Perspective](https://posts.specterops.io/golden-saml-revisited-the-solorigate-perspective-4d95fc398f85)
- [Solarwinds Advisory - CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
