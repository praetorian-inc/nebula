---
id: TECH-000
name: Cloud Groups
category: unknown
subcategory: general
severity: medium
mitre_attack: T1069.003
discovered_date: 2020-02-21T21:15:33.222Z
last_validated: 2025-10-24T17:48:26.982Z
sources:
---

# Cloud Groups

## Summary
Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.

With authenticated access there are several tools that can be used to find permissions groups. The <code>Get-MsolRole</code> PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts (Citation: Microsoft Msolrole)(Citation: GitHub Raindance).

Azure CLI (AZ CLI) and the Google Cloud Identity Provider API also provide interfaces to obtain permissions groups. The command <code>az ad user get-member-groups</code> will list groups associated to a user account for Azure while the API endpoint <code>GET https://cloudidentity.googleapis.com/v1/groups</code> lists group resources available to a user for Google.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018)(Citation: Google Cloud Identity API Documentation) In AWS, the commands `ListRolePolicies` and `ListAttachedRolePolicies` allow users to enumerate the policies attached to a role.(Citation: Palo Alto Unit 42 Compromised Cloud Compute Credentials 2022)

Adversaries may attempt to list ACLs for objects to determine the owner and other accounts with access to the object, for example, via the AWS <code>GetBucketAcl</code> API (Citation: AWS Get Bucket ACL). Using this information an adversary can target accounts with permissions to a given object or leverage accounts they have already compromised to access the object.

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
