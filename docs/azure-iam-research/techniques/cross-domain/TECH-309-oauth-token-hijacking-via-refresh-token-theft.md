---
id: TECH-309
name: OAuth Token Hijacking via Refresh Token Theft
category: cross-domain
subcategory: credential-theft
severity: high
mitre_attack: T1528
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# OAuth Token Hijacking via Refresh Token Theft

## Summary
Long-lived refresh tokens can be stolen from user devices or storage and used to generate new access tokens indefinitely, enabling persistent unauthorized access.

## Required Starting Permissions
- Access to user device file system or memory

## Attack Path
1. Gain access to user's device (malware, physical access, or device compromise)
2. Extract OAuth refresh tokens from browser local storage, application data, or memory
3. Transfer refresh token to attacker-controlled system
4. Use refresh token to request new access tokens from Azure AD
5. Access user's resources with generated access tokens
6. Repeat token refresh before expiration to maintain persistent access

## Target Privilege Gained
- Long-term access to user's cloud resources via refresh token

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
