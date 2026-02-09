---
id: TECH-310
name: Conditional Access Policy Bypass via Compliant Device
category: cross-domain
subcategory: policy-bypass
severity: medium
mitre_attack: T1556.006
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Conditional Access Policy Bypass via Compliant Device

## Summary
Conditional access policies requiring compliant devices can be bypassed by compromising compliant devices or spoofing device compliance signals.

## Required Starting Permissions
- Access to Azure AD-joined compliant device

## Attack Path
1. Identify conditional access policies requiring device compliance
2. Compromise or gain access to Azure AD-joined compliant device
3. Extract device certificate and TPM-backed keys if possible
4. Authenticate from compromised compliant device
5. Bypass conditional access restrictions (MFA, IP restrictions, etc.)
6. Access resources that would otherwise be blocked

## Target Privilege Gained
- Bypass conditional access restrictions (MFA, location, device compliance)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Conditional Access Documentation](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
