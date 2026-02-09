---
id: TECH-308
name: Service Principal Secret Rotation Bypass
category: cross-domain
subcategory: persistence
severity: medium
mitre_attack: T1098.001
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Service Principal Secret Rotation Bypass

## Summary
Service principals with permission to update their own credentials can maintain persistent access by continuously rotating secrets before detection.

## Required Starting Permissions
- Service principal with Application.ReadWrite.OwnedBy or Application.ReadWrite.All

## Attack Path
1. Compromise service principal with self-update permissions
2. Add new client secret or certificate credential
3. Before current credential expires, add another new credential
4. Rotate between multiple credentials to evade detection
5. Maintain persistent access despite security team attempts to revoke access

## Target Privilege Gained
- Persistent service principal access despite secret rotation policies

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure AD Application and Service Principal Attack Paths](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
