# Group.ReadWrite.All Escalation

**Method:** `GraphGroupReadWrite`
**Category:** Graph Permission Escalation

## Overview

Service Principal with `Group.ReadWrite.All` permission can modify group memberships to add users to privileged groups, enabling transitive privilege escalation.

## Escalation Path

```
Service Principal → [HAS_PERMISSION: Group.ReadWrite.All] → Microsoft Graph
                  → [CAN_ESCALATE: GraphGroupReadWrite] → All Groups
                  → Add user to privileged group → Inherit group's permissions
```

## Edge Creation Logic

**Source:** Service Principal with HAS_PERMISSION edge where:
- `source = "Microsoft Graph"`
- `permission = "Group.ReadWrite.All"`
- `permissionType = "Application"`
- `consentType = "AllPrincipals"`

**Target:** All groups in tenant:
- Resource type: `microsoft.directoryservices/groups`
- Excludes self (SP cannot be a group)

**Condition:** "Service Principal with Group.ReadWrite.All can modify group memberships to add users to privileged groups"

## Attack Scenario

1. **Attacker compromises** SP with Group.ReadWrite.All
2. **Attacker enumerates** privileged groups:
   ```cypher
   MATCH (group:Resource)-[p:HAS_PERMISSION]->(:Resource)
   WHERE p.roleName = "Global Administrator"
      OR p.permission = "Owner"
   RETURN group.displayName, group.id
   ```
3. **Attacker adds** their user account to privileged group
4. **User inherits** group's role assignments
5. **Result:** Privilege escalation via group membership

## Microsoft Graph API Calls

**Add Member to Group:**
```http
POST https://graph.microsoft.com/v1.0/groups/{group-id}/members/$ref
Content-Type: application/json

{
  "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/{user-or-sp-id}"
}
```

**Remove Member from Group:**
```http
DELETE https://graph.microsoft.com/v1.0/groups/{group-id}/members/{member-id}/$ref
```

**Create New Group:**
```http
POST https://graph.microsoft.com/v1.0/groups
Content-Type: application/json

{
  "displayName": "Backdoor Admins",
  "mailEnabled": false,
  "mailNickname": "backdoor",
  "securityEnabled": true
}
```

**Modify Group Properties:**
```http
PATCH https://graph.microsoft.com/v1.0/groups/{group-id}
Content-Type: application/json

{
  "description": "Modified by attacker"
}
```

## Edge Properties

```cypher
{
  method: "GraphGroupReadWrite",
  category: "GraphPermission",
  condition: "Service Principal with Group.ReadWrite.All can modify group memberships to add users to privileged groups",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <permission name>
}
```

## Detection Query

```cypher
// Find SPs with Group.ReadWrite.All and privileged groups they can modify
MATCH (sp:Resource)-[esc:CAN_ESCALATE]->(group:Resource)
WHERE esc.method = "GraphGroupReadWrite"
  AND EXISTS {
    MATCH (group)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["Owner", "Contributor", "User Access Administrator"]
  }
WITH sp, group, collect(DISTINCT p.roleName) as roles
RETURN sp.displayName as attacker_sp,
       sp.appId as app_id,
       count(group) as privileged_groups,
       collect(group.displayName)[0..5] as sample_groups,
       roles[0..3] as sample_roles
ORDER BY privileged_groups DESC
```

## Escalation Techniques

### Technique 1: Add to Existing Privileged Group
**Best for stealth** - modifies existing group

```
1. Find group with Global Administrator role
2. Add attacker account to group
3. Wait for token refresh (or force re-auth)
4. Inherit Global Administrator
```

### Technique 2: Create New Group + Assign Privileges
**Requires additional permissions** - needs role assignment capability

```
1. Create new group
2. Wait... can't assign role (needs RoleManagement.ReadWrite.Directory)
3. This technique fails without additional permission
```

### Technique 3: Modify Dynamic Group Rules
**Advanced** - for dynamic membership groups

```
1. Find dynamic group with privileges
2. Modify membershipRule to include attacker
3. Automatic membership via rule evaluation
4. Inherit privileges
```

### Technique 4: Nested Group Manipulation
**Complex** - multi-hop escalation

```
1. Group A has Global Admin
2. Group B is member of Group A
3. Add attacker to Group B
4. Inherit via transitive membership
```

## Why This Permission Is Dangerous

**Transitive Privilege Gain:**
- Adding to privileged group = instant privilege escalation
- No separate approval for role assignment
- Group membership is the privilege

**Role-Assignable Groups:**
- Azure AD role-assignable groups grant directory roles
- Modifying membership = role assignment
- Bypasses role assignment controls

**Azure RBAC Groups:**
- Groups assigned Azure RBAC roles (Owner, Contributor)
- Adding members = RBAC permission grant
- Subscription-level access gained

## High-Value Target Groups

**Directory Role Groups:**
```
- Groups assigned Global Administrator
- Groups assigned Privileged Role Administrator
- Groups assigned Application Administrator
```

**Azure RBAC Groups:**
```
- Groups with Owner on management groups
- Groups with Owner on subscriptions
- Groups with User Access Administrator
```

**Application Permission Groups:**
```
- Groups granted Graph API permissions
- Groups with consent to enterprise apps
```

## Mitigation

- **Least Privilege Alternatives:**
  - `Group.Read.All` (read-only)
  - `Group.ReadWrite` (delegated, limited scope)
  - `GroupMember.ReadWrite.All` (membership only, no create/delete)
- **Protected Groups:** Mark role-assignable groups as protected
- **Monitoring:** Alert on membership changes to privileged groups
- **Conditional Access:** N/A (application permissions bypass CA)
- **PIM for Groups:** Use PIM for group membership (eligible members)
- **Regular Audit:** Review SPs with this permission

## Comparison with Directory Roles

| Permission/Role | Can Modify | Scope |
|----------------|------------|-------|
| `Group.ReadWrite.All` | All groups | Tenant-wide |
| `Groups Administrator` (role) | All groups | Tenant-wide |
| `Group.ReadWrite` (delegated) | Groups user can access | Limited by user |
| `GroupMember.ReadWrite.All` | Membership only | Tenant-wide, no create/delete |

## Common Misconceptions

**"We need it for group provisioning"**
- ❌ Over-privileged for most use cases
- ✅ Use `GroupMember.ReadWrite.All` if only managing membership
- ✅ Use delegated permissions with service account

**"Sync tool requires it"**
- ❌ Sync tools rarely need full group write
- ✅ Use `Group.Read.All` + specific group modification via delegated

## Real-World Attack

```
Supply Chain Compromise
1. Third-party integration has Group.ReadWrite.All
2. Vendor credentials stolen
3. Attacker enumerates: "Global Admin Groups"
4. Adds backdoor user to "Global Administrators" group
5. Backdoor persists for 6 months
6. Discovered during security audit
```

## Related Documentation

- [Directory.ReadWrite.All](directory-readwrite-all.md) - Superset permission
- [Groups Administrator](groups-administrator.md) - Role equivalent
- [../CONTAINS/group-to-member.md](../CONTAINS/group-to-member.md) - Group membership edges
- [../../Azure_IAM_Nodes/group.md](../../Azure_IAM_Nodes/group.md) - Group node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGraphGroupReadWriteQuery()` - line 4251
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
