---
id: TECH-000
name: Web Session Cookie
category: unknown
subcategory: general
severity: medium
mitre_attack: T1550.004
discovered_date: 2020-01-30T17:48:49.395Z
last_validated: 2025-10-24T17:49:20.943Z
sources:
  - MITRE ATT&CK Framework
---

# Web Session Cookie

## Summary
Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)

Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently. Cookies are often valid for an extended period of time, even if the web application is not actively used. After the cookie is obtained through [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) or [Web Cookies](https://attack.mitre.org/techniques/T1606/001), the adversary may then import the cookie into a browser they control and is then able to use the site or application as the user for as long as the session cookie is active. Once logged into the site, an adversary can access sensitive information, read email, or perform actions that the victim account has permissions to perform.

There have been examples of malware targeting session cookies to bypass multi-factor authentication systems.(Citation: Unit 42 Mac Crypto Cookies January 2019)

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
