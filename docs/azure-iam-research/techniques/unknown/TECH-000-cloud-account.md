---
id: TECH-000
name: Cloud Account
category: unknown
subcategory: general
severity: medium
mitre_attack: T1087.004
discovered_date: 2020-02-21T21:08:36.570Z
last_validated: 2025-10-24T17:49:05.745Z
sources:
  - MITRE ATT&CK Framework
---

# Cloud Account

## Summary
Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application.

With authenticated access there are several tools that can be used to find accounts. The <code>Get-MsolRoleMember</code> PowerShell cmdlet can be used to obtain account names given a role or permissions group in Office 365.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance) The Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command <code>az ad user list</code> will list all users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018) 

The AWS command <code>aws iam list-users</code> may be used to obtain a list of users in the current account while <code>aws iam list-roles</code> can obtain IAM roles that have a specified path prefix.(Citation: AWS List Roles)(Citation: AWS List Users) In GCP, <code>gcloud iam service-accounts list</code> and <code>gcloud projects get-iam-policy</code> may be used to obtain a listing of service accounts and users in a project.(Citation: Google Cloud - IAM Servie Accounts List API)

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
