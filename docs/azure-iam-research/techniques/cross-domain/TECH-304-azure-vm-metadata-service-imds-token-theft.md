---
id: TECH-304
name: Azure VM Metadata Service (IMDS) Token Theft
category: cross-domain
subcategory: managed-identity-abuse
severity: high
mitre_attack: T1552.005
discovered_date: 2026-01-18
last_validated: 2026-01-18
sources:
---

# Azure VM Metadata Service (IMDS) Token Theft

## Summary
Azure VMs expose metadata service at 169.254.169.254 that provides managed identity access tokens. SSRF or VM compromise enables token theft for privilege escalation.

## Required Starting Permissions
- SSRF vulnerability or code execution on Azure VM with managed identity

## Attack Path
1. Identify SSRF vulnerability or achieve code execution on target Azure VM
2. Query Azure Instance Metadata Service at http://169.254.169.254/metadata/identity/oauth2/token
3. Include Metadata: true header in request
4. Extract OAuth access token for VM's managed identity
5. Use token to authenticate to Azure Resource Manager API
6. Leverage managed identity's RBAC permissions to access Azure resources

## Target Privilege Gained
- Managed identity permissions (can be Contributor, Reader, or custom RBAC roles)

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [Abusing Azure's Metadata Service](https://www.netspi.com/blog/technical/cloud-penetration-testing/abusing-azure-metadata-service/)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
