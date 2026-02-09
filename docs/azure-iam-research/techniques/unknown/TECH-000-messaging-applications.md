---
id: TECH-000
name: Messaging Applications
category: unknown
subcategory: general
severity: medium
mitre_attack: T1213.005
discovered_date: 2024-08-30T13:50:42.023Z
last_validated: 2025-04-15T22:48:58.763Z
sources:
---

# Messaging Applications

## Summary
Adversaries may leverage chat and messaging applications, such as Microsoft Teams, Google Chat, and Slack, to mine valuable information.  

The following is a brief list of example information that may hold potential value to an adversary and may also be found on messaging applications: 

* Testing / development credentials (i.e., [Chat Messages](https://attack.mitre.org/techniques/T1552/008)) 
* Source code snippets 
* Links to network shares and other internal resources 
* Proprietary data(Citation: Guardian Grand Theft Auto Leak 2022)
* Discussions about ongoing incident response efforts(Citation: SC Magazine Ragnar Locker 2021)(Citation: Microsoft DEV-0537)

In addition to exfiltrating data from messaging applications, adversaries may leverage data from chat messages in order to improve their targeting - for example, by learning more about an environment or evading ongoing incident response efforts.(Citation: Sentinel Labs NullBulge 2024)(Citation: Permiso Scattered Spider 2023)

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
