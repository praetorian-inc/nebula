# Groups Administrator Escalation

**Method:** `GroupsAdministrator`
**Category:** Directory Role Escalation

## Overview

Groups Administrator has full control over all groups, enabling escalation by adding themselves or others to privileged groups.

## Escalation Path

```
User → [HAS_PERMISSION: Groups Administrator] → Tenant
     → [CAN_ESCALATE: GroupsAdministrator] → All Groups
     → Add self to privileged group → Inherit group's role assignments
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Groups Administrator"` OR
- `templateId = "fdd7a751-b60b-444a-984c-02652fe8fa1c"`

**Target:** All groups in tenant:
- Resource type: `microsoft.directoryservices/groups`

**Condition:** "Groups Administrator can create, delete, and manage all aspects of groups including privileged group memberships"

## Attack Scenario

1. **Attacker compromises** user with Groups Administrator role
2. **Attacker enumerates** groups with high privileges:
   - Groups assigned Global Administrator role
   - Groups with Owner role on sensitive subscriptions
   - Groups with Graph API permissions
3. **Attacker adds** themselves to privileged group
4. **Attacker inherits** group's role assignments
5. **Result:** Privilege escalation via group membership

## Edge Properties

```cypher
{
  method: "GroupsAdministrator",
  category: "DirectoryRole",
  condition: "Groups Administrator can create, delete, and manage all aspects of groups including privileged group memberships",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
// Find Groups Admins and the privileged groups they can modify
MATCH (admin:Resource)-[esc:CAN_ESCALATE]->(group:Resource)
WHERE esc.method = "GroupsAdministrator"
  AND EXISTS {
    MATCH (group)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["Owner", "Contributor"]
  }
RETURN admin.displayName as groups_admin,
       group.displayName as privileged_group,
       collect(DISTINCT p.roleName) as group_roles
```

## Group-Based Escalation Techniques

**Add Self to Group:**
```powershell
Add-AzureADGroupMember -ObjectId <group-id> -RefObjectId <user-id>
```

**Create New Group with Privileges:**
1. Create new group
2. Assign privileged role to group
3. Add self as member

**Modify Group Properties:**
- Change dynamic membership rules
- Modify group owners
- Enable mail features

## Mitigation

- **PIM:** Require activation for Groups Administrator
- **Group Protection:** Mark privileged groups as "critical"
- **Monitoring:** Alert on membership changes to privileged groups
- **Conditional Access:** Require strong auth for group management
- **Administrative Units:** Scope group management to specific groups

## Related Documentation

- [Global Administrator](global-administrator.md) - Common target via group assignment
- [../../Azure_IAM_Nodes/group.md](../../Azure_IAM_Nodes/group.md) - Group node structure
- [../CONTAINS/group-to-member.md](../CONTAINS/group-to-member.md) - Group membership edges

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedGroupsAdminQuery()` - line 4063
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
