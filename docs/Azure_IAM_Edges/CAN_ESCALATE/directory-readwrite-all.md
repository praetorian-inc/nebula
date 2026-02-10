# Directory.ReadWrite.All Escalation

**Method:** `Directory.ReadWrite.All`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `Directory.ReadWrite.All` permission can modify any directory object including role assignments, enabling multiple escalation paths to tenant compromise.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: Directory.ReadWrite.All] → Microsoft Graph
                  → [CAN_ESCALATE: Directory.ReadWrite.All] → All Directory Objects
                  → Multiple escalation vectors → Tenant compromise
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `permission = "Directory.ReadWrite.All"`
- `source = "Microsoft Graph"` OR `source = "Graph API OAuth2 Grant"`
- `permissionType = "Application"` (or NULL for legacy)
- `consentType = "AllPrincipals"` (or NULL for legacy)

**Target:** All directory objects:
- All resource types starting with `microsoft.directoryservices/`
- Users, Groups, Service Principals, Applications, Devices, etc.

**Condition:** "Service Principal with Directory.ReadWrite.All can modify any directory object including role assignments"

## Attack Scenarios

### Scenario 1: Role Assignment
1. **Assign Global Administrator** role to attacker's account
2. Same as RoleManagement.ReadWrite.Directory

### Scenario 2: Password Reset
1. **Reset user password** via Graph API
2. **Log in as user** with new password
3. **Inherit user's permissions**

### Scenario 3: Group Membership Manipulation
1. **Add attacker to privileged group** (e.g., group with Global Admin role)
2. **Inherit group's permissions**

### Scenario 4: Application Credential Addition
1. **Add secret to privileged SP**
2. **Authenticate as SP**
3. **Inherit SP's permissions**

### Scenario 5: Service Principal Modification
1. **Modify SP properties** (e.g., reply URLs)
2. **OAuth flow manipulation**
3. **Token theft or impersonation**

## Edge Properties

```cypher
{
  method: "Directory.ReadWrite.All",
  category: "GraphPermission",
  condition: "Service Principal with Directory.ReadWrite.All can modify any directory object including role assignments",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SPs with Directory.ReadWrite.All
MATCH (sp:Resource)-[esc:CAN_ESCALATE]->(target:Resource)
WHERE esc.method = "Directory.ReadWrite.All"
WITH sp, count(DISTINCT target) as target_count
MATCH (sp)-[perm:HAS_PERMISSION]->(:Resource)
WHERE perm.permission = "Directory.ReadWrite.All"
RETURN sp.displayName as service_principal,
       sp.appId as app_id,
       target_count as directory_objects_can_modify,
       perm.consentType as consent_type
ORDER BY target_count DESC
```

## Microsoft Graph API Examples

**Assign Role:**
```http
POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
```

**Reset Password:**
```http
POST https://graph.microsoft.com/v1.0/users/{user-id}/changePassword
```

**Modify Group:**
```http
POST https://graph.microsoft.com/v1.0/groups/{group-id}/members/$ref
```

**Add App Credential:**
```http
POST https://graph.microsoft.com/v1.0/applications/{app-id}/addPassword
```

## Why This Permission Is Extremely Dangerous

**Broadest Scope:**
- Combines capabilities of multiple permissions:
  - RoleManagement.ReadWrite.Directory
  - User.ReadWrite.All
  - Group.ReadWrite.All
  - Application.ReadWrite.All
  - And more...

**No Restrictions:**
- No user tier restrictions (can target admins)
- No administrative unit boundaries
- No object type limitations

**Common Misconception:**
"We need it for sync/automation" - **Almost never true**

## Legitimate Alternatives

**Instead of Directory.ReadWrite.All, use:**

| Use Case | Better Permission |
|----------|-------------------|
| Read-only sync | `Directory.Read.All` |
| User provisioning | `User.ReadWrite.All` (still risky) |
| Group management | `Group.ReadWrite.All` |
| App registration | `Application.ReadWrite.OwnedBy` |
| Role assignment | Use PIM API with approval |

## Mitigation

- **Immediate Action:** Audit all SPs with this permission
- **Remove:** Revoke unless absolutely justified with business case
- **Alternative:** Use least-privilege permissions instead
- **Monitoring:** Alert on any Graph API calls by these SPs
- **Credential Protection:** Key Vault + Managed Identities
- **Break-Glass Review:** Ensure this permission isn't granted to break-glass SPs

## Related Documentation

- [RoleManagement.ReadWrite.Directory](rolemanagement-readwrite-directory.md) - Subset of this permission
- [User.ReadWrite.All](user-readwrite-all.md) - User-specific subset
- [Group.ReadWrite.All](group-readwrite-all.md) - Group-specific subset
- [Application.ReadWrite.All](application-readwrite-all.md) - Application-specific subset

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphDirectoryReadWriteQuery()` - line 4156
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
