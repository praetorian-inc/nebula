# Application.ReadWrite.All Escalation

**Method:** `GraphApplicationReadWrite`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `Application.ReadWrite.All` permission can add credentials to any application or service principal, then authenticate as them to inherit their permissions.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: Application.ReadWrite.All] → Microsoft Graph
                  → [CAN_ESCALATE: GraphApplicationReadWrite] → All Apps & SPs
                  → Add credential → Authenticate as target → Inherit permissions
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `source = "Microsoft Graph"`
- `permission = "Application.ReadWrite.All"`
- `permissionType = "Application"`
- `consentType = "AllPrincipals"`

**Target:** All applications and service principals:
- `microsoft.directoryservices/applications`
- `microsoft.directoryservices/serviceprincipals`
- Excludes self (cannot add credential to itself via this path)

**Condition:** "Service Principal with Application.ReadWrite.All can add credentials to any application or service principal then authenticate as them"

## Attack Scenario

1. **Attacker compromises** SP with Application.ReadWrite.All
2. **Attacker enumerates** SPs with high privileges:
   ```cypher
   MATCH (sp:Resource)-[p:HAS_PERMISSION]->(:Resource)
   WHERE p.roleName = "Global Administrator"
      OR p.permission = "RoleManagement.ReadWrite.Directory"
   RETURN sp.displayName, sp.appId
   ```
3. **Attacker adds credential** to target SP via Graph API
4. **Attacker authenticates** as target SP using new credential
5. **Attacker inherits** target SP's permissions
6. **Result:** Privilege escalation to Global Admin (if target SP has it)

## Microsoft Graph API Calls

**Add Password (Secret):**
```http
POST https://graph.microsoft.com/v1.0/applications/{app-id}/addPassword
Content-Type: application/json

{
  "passwordCredential": {
    "displayName": "Backup Admin Key"
  }
}
```

**Add Certificate:**
```http
POST https://graph.microsoft.com/v1.0/applications/{app-id}/addKey
Content-Type: application/json

{
  "keyCredential": {
    "type": "AsymmetricX509Cert",
    "usage": "Verify",
    "key": "<base64-cert>"
  },
  "passwordCredential": null,
  "proof": "<proof-of-possession-token>"
}
```

**Add to Service Principal:**
```http
POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-id}/addPassword
```

## Edge Properties

```cypher
{
  method: "GraphApplicationReadWrite",
  category: "GraphPermission",
  condition: "Service Principal with Application.ReadWrite.All can add credentials to any application or service principal then authenticate as them",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SP with Application.ReadWrite.All and high-value targets
MATCH (attacker:Resource)-[esc:CAN_ESCALATE]->(target:Resource)
WHERE esc.method = "GraphApplicationReadWrite"
  AND EXISTS {
    MATCH (target)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
RETURN attacker.displayName as attacker_sp,
       attacker.appId as attacker_app_id,
       target.displayName as privileged_target,
       target.appId as target_app_id,
       collect(DISTINCT p.roleName) as target_roles
```

## Credential Types & Persistence

**Client Secrets:**
- ✅ Easy to add via API
- ✅ Work immediately
- ⚠️ Expire (max 2 years)
- ⚠️ Visible in portal

**Certificates:**
- ✅ Longer validity (custom)
- ✅ More difficult to detect
- ⚠️ Requires proof-of-possession token
- ⚠️ More complex to use

**Federated Credentials:**
- ✅ Workload identity federation
- ✅ No secrets stored
- ⚠️ Requires external IdP setup

## Why This Permission Is Dangerous

**Lateral Movement:**
- Jump from one SP to another
- Chain escalations across multiple SPs
- Eventually reach Global Admin SP

**Persistence:**
- Added credentials persist across password resets
- Difficult to revoke if not monitored
- Multiple credentials can be added

**Scope:**
- ALL applications and service principals
- Including Microsoft-owned SPs (Graph, Office, etc.)
- No exclusions or protective boundaries

## High-Value Targets

**Service Principals to Target:**
1. **Global Administrator SPs** - Direct tenant takeover
2. **Automation Accounts** - Often over-privileged
3. **Legacy Apps** - Rarely audited
4. **Third-Party Integrations** - Supply chain vector
5. **DevOps Pipelines** - Code execution + secrets

## Mitigation

- **Least Privilege:** Use `Application.ReadWrite.OwnedBy` instead
  - Limits scope to applications the SP owns
  - Much safer alternative
- **Monitoring:** Alert on credential additions to sensitive SPs
- **Application Protection:** Mark critical apps as "protected"
- **Regular Audit:** Review SPs with this permission
- **Credential Hygiene:** Audit all credentials on sensitive SPs
- **Break-Glass:** Exclude break-glass apps from this permission scope

## Comparison with Similar Permissions

| Permission | Can Add Credentials? | Scope |
|------------|---------------------|-------|
| `Application.ReadWrite.All` | ✅ All apps/SPs | Tenant-wide |
| `Application.ReadWrite.OwnedBy` | ✅ Owned apps only | Limited to ownership |
| `Directory.ReadWrite.All` | ✅ All apps/SPs + more | Entire directory |

## Related Documentation

- [Directory.ReadWrite.All](directory-readwrite-all.md) - Superset permission
- [Application Administrator](application-administrator.md) - Directory role equivalent
- [Service Principal Add Secret](service-principal-add-secret.md) - Ownership-based credential addition
- [../../Azure_IAM_Nodes/application.md](../../Azure_IAM_Nodes/application.md) - Application node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphApplicationReadWriteQuery()` - line 4182
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
