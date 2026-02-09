---
id: TECH-000
name: Exfiltration Over Web Service
category: unknown
subcategory: general
severity: medium
mitre_attack: T1567
discovered_date: 2020-03-09T12:51:45.570Z
last_validated: 2025-10-24T17:48:42.061Z
sources:
---

# Exfiltration Over Web Service

## Summary
Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.

Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

## Required Starting Permissions
- [To be documented]

## Attack Path
[To be documented]

## Target Privilege Gained
- Unknown

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [To be added]

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
