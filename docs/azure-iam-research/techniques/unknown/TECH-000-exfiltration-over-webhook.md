---
id: TECH-000
name: Exfiltration Over Webhook
category: unknown
subcategory: general
severity: medium
mitre_attack: T1567.004
discovered_date: 2023-07-20T15:30:55.763Z
last_validated: 2025-04-15T19:58:26.901Z
sources:
---

# Exfiltration Over Webhook

## Summary
Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server.(Citation: RedHat Webhooks) Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello.(Citation: Discord Intro to Webhooks) When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. 

Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated [Automated Exfiltration](https://attack.mitre.org/techniques/T1020) of emails, chat messages, and other data.(Citation: Push Security SaaS Attacks Repository Webhooks) Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it.(Citation: Microsoft SQL Server)

Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.(Citation: CyberArk Labs Discord)(Citation: Talos Discord Webhook Abuse)(Citation: Checkmarx Webhooks)

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
