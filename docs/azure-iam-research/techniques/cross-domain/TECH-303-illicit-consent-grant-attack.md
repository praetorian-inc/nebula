---
id: TECH-303
name: Illicit Consent Grant Attack
category: cross-domain
subcategory: consent-abuse
severity: high
mitre_attack: T1528
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Illicit Consent Grant Attack

## Summary
Trick users into granting OAuth consent to malicious applications, granting attacker access to user data and permissions without requiring password compromise.

## Required Starting Permissions
- Ability to register applications in Azure AD (by default, any user can)

## Attack Path
1. Register malicious application in attacker-controlled tenant or target tenant
2. Request high-privilege delegated permissions (Mail.Read, Files.ReadWrite.All, etc.)
3. Craft phishing link with OAuth authorization URL for malicious app
4. Send phishing email to target users
5. User clicks link and grants consent to malicious application
6. Attacker uses OAuth tokens to access user's Microsoft 365 data

## Target Privilege Gained
- Access to user email, files, and other resources via delegated permissions

## Real-World Examples
- 2020 - Multiple illicit consent grant campaigns targeting business users

## References
- [Maintaining Azure Persistence via Automation Accounts](https://www.netspi.com/blog/technical/cloud-penetration-testing/maintaining-azure-persistence-via-automation-accounts/)
- [Detect and Remediate Illicit Consent Grants - Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
