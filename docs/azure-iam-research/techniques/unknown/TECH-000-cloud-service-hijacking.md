---
id: TECH-000
name: Cloud Service Hijacking
category: unknown
subcategory: general
severity: medium
mitre_attack: T1496.004
discovered_date: 2024-09-25T14:05:59.910Z
last_validated: 2025-04-15T22:03:40.356Z
sources:
---

# Cloud Service Hijacking

## Summary
Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability. 

For example, adversaries may leverage email and messaging services, such as AWS Simple Email Service (SES), AWS Simple Notification Service (SNS), SendGrid, and Twilio, in order to send large quantities of spam / [Phishing](https://attack.mitre.org/techniques/T1566) emails and SMS messages.(Citation: Invictus IR DangerDev 2024)(Citation: Permiso SES Abuse 2023)(Citation: SentinelLabs SNS Sender 2024) Alternatively, they may engage in LLMJacking by leveraging reverse proxies to hijack the power of cloud-hosted AI models.(Citation: Sysdig LLMJacking 2024)(Citation: Lacework LLMJacking 2024)

In some cases, adversaries may leverage services that the victim is already using. In others, particularly when the service is part of a larger cloud platform, they may first enable the service.(Citation: Sysdig LLMJacking 2024) Leveraging SaaS applications may cause the victim to incur significant financial costs, use up service quotas, and otherwise impact availability. 

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
