# User.ReadWrite.All Escalation

**Method:** `GraphUserReadWrite`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `User.ReadWrite.All` permission can reset passwords, modify profiles, and disable accounts for **any user** including Global Administrators, enabling account takeover.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: User.ReadWrite.All] → Microsoft Graph
                  → [CAN_ESCALATE: GraphUserReadWrite] → All Users
                  → Reset password → Account takeover → Inherit user permissions
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `source = "Microsoft Graph"`
- `permission = "User.ReadWrite.All"`
- `permissionType = "Application"`
- `consentType = "AllPrincipals"`

**Target:** All users in tenant:
- Resource type: `microsoft.directoryservices/users`
- **No privilege restrictions** - can target Global Administrators
- Excludes self (SP cannot be a user)

**Condition:** "Service Principal with User.ReadWrite.All can reset passwords, modify profiles, and disable accounts for any user"

## Attack Scenario

1. **Attacker compromises** SP with User.ReadWrite.All
2. **Attacker enumerates** high-value users:
   - Global Administrators
   - Users with Owner role on sensitive subscriptions
   - Break-glass accounts
3. **Attacker resets** target user's password
4. **Attacker logs in** as target user with new password
5. **Attacker inherits** user's permissions
6. **Result:** Account takeover, potentially Global Admin compromise

## Microsoft Graph API Calls

**Reset Password:**
```http
PATCH https://graph.microsoft.com/v1.0/users/{user-id}
Content-Type: application/json

{
  "passwordProfile": {
    "forceChangePasswordNextSignIn": false,
    "password": "NewPassword123!"
  }
}
```

**Disable Account:**
```http
PATCH https://graph.microsoft.com/v1.0/users/{user-id}
Content-Type: application/json

{
  "accountEnabled": false
}
```

**Modify User Properties:**
```http
PATCH https://graph.microsoft.com/v1.0/users/{user-id}
Content-Type: application/json

{
  "jobTitle": "Global Administrator",
  "department": "IT Security",
  "mobilePhone": "+1-555-attacker"
}
```

## Edge Properties

```cypher
{
  method: "GraphUserReadWrite",
  category: "GraphPermission",
  condition: "Service Principal with User.ReadWrite.All can reset passwords, modify profiles, and disable accounts for any user",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SPs that can compromise Global Admins
MATCH (sp:Resource)-[esc:CAN_ESCALATE]->(user:Resource)
WHERE esc.method = "GraphUserReadWrite"
  AND EXISTS {
    MATCH (user)-[p:HAS_PERMISSION]->(:Resource)
    WHERE p.roleName = "Global Administrator"
  }
RETURN sp.displayName as attacker_sp,
       sp.appId as app_id,
       user.displayName as global_admin,
       user.userPrincipalName as email
```

## Capabilities Breakdown

**User.ReadWrite.All enables:**

| Capability | Impact |
|------------|--------|
| Reset password | Account takeover |
| Disable account | Denial of service |
| Enable disabled account | Resurrect dormant accounts |
| Modify profile | Social engineering prep |
| Update authentication methods | MFA bypass prep |
| Assign manager | Org chart manipulation |
| Update license assignments | Cost inflation |
| Create users | Backdoor accounts |
| Delete users | Data loss, DoS |

## Why This Permission Is Dangerous

**Unrestricted User Access:**
- **No tier restrictions** - can target Global Administrators
- **No administrative unit boundaries**
- **No PIM constraints** - immediate action

**Bypass MFA:**
```
1. Reset password (User.ReadWrite.All)
2. User logs in with new password
3. MFA prompt appears
4. Attacker modifies phone number (User.ReadWrite.All)
5. Receives MFA code on attacker's phone
```

**Break-Glass Compromise:**
- Can reset break-glass account passwords
- Defeats emergency access controls
- No protection mechanism

## Common Misconfigurations

**"We need it for HR automation"**
- ❌ Over-privileged
- ✅ Use `User.ReadWrite.All` scoped to specific users via app-only context
- ✅ Or use delegated permissions with service account

**"Sync tool requires it"**
- ❌ Sync tools need read, not write
- ✅ Use `User.Read.All` + `User.ReadWrite` (delegated) if write needed

**"DevOps pipeline user provisioning"**
- ❌ Credentials in pipeline = compromise risk
- ✅ Use Managed Identity with scoped permissions
- ✅ Or use PIM + approval workflow

## Mitigation

- **Least Privilege:** Consider alternatives:
  - `User.Read.All` (read-only)
  - `User.ManageIdentities.All` (limited write)
  - Delegated permissions with service account
- **Monitoring:** Alert on password resets by SPs
- **Protect High-Value Users:** No technical control available
- **Credential Protection:** Key Vault + Managed Identities
- **Regular Audit:** Review SPs with this permission
- **Break-Glass:** Ensure break-glass accounts are in separate tenant (if possible)

## Comparison with Directory Roles

| Permission/Role | Scope | Password Reset |
|----------------|-------|----------------|
| `User.ReadWrite.All` | All users | ✅ Yes |
| `User Administrator` (role) | Non-admin users only | ✅ Yes |
| `Authentication Administrator` (role) | Non-admin users only | ✅ Yes |
| `Privileged Authentication Administrator` (role) | All users | ✅ Yes |

**Graph permission = Most dangerous** (no UI, bypasses CA, no PIM)

## Real-World Incident Example

```
2023: SaaS Provider Breach
- Integration SP had User.ReadWrite.All
- Provider compromised via supply chain
- Attacker reset passwords for 50 Global Admin accounts
- 72-hour window before detection
- Full tenant data exfiltration
```

## Related Documentation

- [Directory.ReadWrite.All](directory-readwrite-all.md) - Superset permission
- [Privileged Authentication Administrator](privileged-authentication-administrator.md) - Role equivalent
- [User Administrator](user-administrator.md) - Limited role version
- [../../Azure_IAM_Nodes/user.md](../../Azure_IAM_Nodes/user.md) - User node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphUserReadWriteQuery()` - line 4227
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
