---
id: TECH-000
name: Financial Theft
category: unknown
subcategory: general
severity: medium
mitre_attack: T1657
discovered_date: 2023-08-18T20:50:04.222Z
last_validated: 2025-04-15T22:36:03.465Z
sources:
---

# Financial Theft

## Summary
Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware,(Citation: FBI-ransomware) business email compromise (BEC) and fraud,(Citation: FBI-BEC) "pig butchering,"(Citation: wired-pig butchering) bank hacking,(Citation: DOJ-DPRK Heist) and exploiting cryptocurrency networks.(Citation: BBC-Ronin) 

Adversaries may [Compromise Accounts](https://attack.mitre.org/techniques/T1586) to conduct unauthorized transfers of funds.(Citation: Internet crime report 2022) In the case of business email compromise or email fraud, an adversary may utilize [Impersonation](https://attack.mitre.org/techniques/T1656) of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary.(Citation: FBI-BEC) This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft.(Citation: VEC)

Extortion by ransomware may occur, for example, when an adversary demands payment from a victim after [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) (Citation: NYT-Colonial) and [Exfiltration](https://attack.mitre.org/tactics/TA0010) of data, followed by threatening to leak sensitive data to the public unless payment is made to the adversary.(Citation: Mandiant-leaks) Adversaries may use dedicated leak sites to distribute victim data.(Citation: Crowdstrike-leaks)

Due to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and business disruption.(Citation: AP-NotPetya)

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
