---
id: TECH-000
name: Cloud Service Discovery
category: unknown
subcategory: general
severity: medium
mitre_attack: T1526
discovered_date: 2019-08-30T13:01:10.120Z
last_validated: 2025-10-24T17:49:30.791Z
sources:
---

# Cloud Service Discovery

## Summary
An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Entra ID, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs.

Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Microsoft Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.(Citation: Azure - Resource Manager API)(Citation: Azure AD Graph API)

For example, Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.(Citation: Azure - Stormspotter)(Citation: GitHub Pacu)

Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses through [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001) or [Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008).

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
