# Service Principal Add Secret Escalation

**Method:** `ServicePrincipalAddSecret`
**Category:** Application Ownership Escalation

## Overview

Owner of a Service Principal can add client secrets and modify SP configuration, enabling identity assumption and permission inheritance.

## Escalation Path

```
Owner → [OWNS] → Service Principal
      → [CAN_ESCALATE: ServicePrincipalAddSecret] → Service Principal
      → Add secret → Authenticate as SP → Inherit SP's permissions
```

## Edge Creation Logic

**Source:** Any principal (user, SP, group) with OWNS edge to SP

**Target:** Service Principal where:
- `resourceType = "microsoft.directoryservices/serviceprincipals"`
- Owner relationship established via OWNS edge

**Condition:** "Service Principal owner can add client secrets and modify SP configuration"

## Attack Scenario

1. **Attacker compromises** user account that owns a service principal
2. **Attacker enumerates** owned SPs and their permissions:
   ```powershell
   Get-AzureADServicePrincipal -Filter "displayName eq 'High Privilege SP'"
   Get-AzureADServicePrincipalPermissions
   ```
3. **Attacker adds** client secret to SP:
   ```powershell
   New-AzureADServicePrincipalPassword -ObjectId <sp-object-id>
   ```
4. **Attacker authenticates** as SP using new secret
5. **Attacker inherits** SP's permissions (potentially Global Administrator)

## Microsoft Graph API Call

**Add Secret:**
```http
POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-id}/addPassword
Content-Type: application/json

{
  "passwordCredential": {
    "displayName": "Backup Key",
    "endDateTime": "2025-12-31T00:00:00Z"
  }
}
```

**Add Certificate:**
```http
POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-id}/addKey
Content-Type: application/json

{
  "keyCredential": {
    "type": "AsymmetricX509Cert",
    "usage": "Verify",
    "key": "<base64-encoded-cert>"
  },
  "passwordCredential": null,
  "proof": "<proof-of-possession-token>"
}
```

## Edge Properties

```cypher
{
  method: "ServicePrincipalAddSecret",
  category: "ApplicationOwnership",
  condition: "Service Principal owner can add client secrets and modify SP configuration"
}
```

## Detection Query

```cypher
// Find owners who can escalate to privileged SPs
MATCH (owner:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "ServicePrincipalAddSecret"
  AND EXISTS {
    MATCH (sp)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
RETURN owner.displayName as owner,
       owner.resourceType as owner_type,
       sp.displayName as privileged_sp,
       sp.appId as app_id,
       collect(DISTINCT p.roleName)[0..3] as sp_roles
ORDER BY owner.displayName
```

## Why Ownership Is Dangerous

**No Additional Permissions Needed:**
- Ownership alone is sufficient
- No directory role required
- No Graph API permissions required

**Broad Ownership:**
- Users can own SPs
- Service Principals can own other SPs
- Groups can own SPs (members inherit ownership)

**No Policy Restrictions (Usually):**
- Unless ServicePrincipalEndUserLockConfiguration is set
- Rare in practice
- Easy to bypass

## SP Owner Capabilities

**Via Graph API:**
- Add client secrets (passwords)
- Add certificates
- Modify reply URLs
- Update application properties
- Add owners (grant ownership to others)
- Delete SP (denial of service)

**Via Azure Portal:**
- All of the above
- Plus UI-based management

## High-Value Owned SPs

**Target Service Principals:**
1. **Global Admin SPs** - Complete tenant control
2. **Automation Accounts** - Often over-privileged
3. **DevOps Pipeline SPs** - Code execution + secrets
4. **Legacy Apps** - Rarely audited, often privileged
5. **Third-Party SaaS** - Supply chain vector

## Mitigation

- **Ownership Audit:**
  - Review SP ownership quarterly
  - Remove unnecessary owners
  - Principle of least ownership
- **Privileged SP Protection:**
  - Limit ownership of high-privilege SPs
  - Use AAD groups for ownership (easier to audit)
  - ServicePrincipalLockConfiguration for critical SPs
- **Monitoring:**
  - Alert on credential additions to privileged SPs
  - Monitor `Add service principal credentials` activity
  - Review ownership changes
- **Ownership Governance:**
  - Require approval for SP ownership
  - Time-bound ownership via PIM (where supported)
  - Break-glass process for emergency access

## SP Lock Configuration

**Protect against owner credential addition:**
```powershell
Update-AzureADServicePrincipal -ObjectId <sp-id> `
  -ServicePrincipalLockConfiguration @{
    IsEnabled = $true
    AllProperties = $true
  }
```

**Effect:**
- ✅ Prevents credential addition by owners
- ✅ Prevents property modification
- ⚠️ Also prevents legitimate management
- ⚠️ Requires Global Admin to unlock

## Ownership Assignment Paths

**How does someone become an SP owner?**

1. **Creator becomes owner** (default)
2. **Explicitly added** via Graph API/Portal
3. **Group ownership** → members inherit
4. **Application ownership** → app owners → SP owners

## Comparison with Directory Roles

| Method | Scope | Requires |
|--------|-------|----------|
| SP Ownership | Owned SPs only | OWNS relationship |
| Application Administrator | All SPs | Directory role |
| Application.ReadWrite.All | All SPs | Graph permission |

**Ownership = Most targeted** (least privilege required)

## Real-World Attack

```
2023: Supply Chain Compromise
- Third-party vendor had ownership of client's SP
- Vendor compromised
- Attacker added secret to SP with Global Admin
- Used SP to exfiltrate data
- Persistence: 4 months undetected
- Detection: Manual security audit
```

## Related Documentation

- [Application Add Secret](application-add-secret.md) - Via application ownership
- [Application Administrator](application-administrator.md) - Via directory role
- [Application.ReadWrite.All](application-readwrite-all.md) - Via Graph permission
- [../OWNS/service-principal-ownership.md](../OWNS/service-principal-ownership.md) - Ownership edge creation
- [../../Azure_IAM_Nodes/service-principal.md](../../Azure_IAM_Nodes/service-principal.md) - SP node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedSPOwnerAddSecretQuery()` - line 4364
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Edge Creation:** Based on OWNS edges created in Phase 2e
