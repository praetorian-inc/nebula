# CAN_ESCALATE Edges

**Edge Relationship Type:** `CAN_ESCALATE`

---

## Purpose

CAN_ESCALATE edges represent **escalation potential** based on analytical logic. These edges interpret HAS_PERMISSION data to determine what can be abused through attack techniques and privilege escalation.

**Decision Rule:** If it requires escalation logic or abuse conditions → CAN_ESCALATE

---

## Available Documentation

### Directory Role Escalations
- [global-administrator.md](global-administrator.md) - Complete tenant control escalation

### RBAC Escalations
- [owner.md](owner.md) - Azure Owner role escalation

### Coming Soon
- Other directory roles (Privileged Role Admin, Application Admin, etc.)
- Graph permission escalations (RoleManagement, Directory.ReadWrite.All, etc.)
- Group-based escalations (Group Owner, Membership inheritance)
- Application escalations (SP credential abuse, app ownership)

---

## When to Use CAN_ESCALATE

- ✅ Privilege escalation potential (Global Admin CAN escalate to compromise any resource)
- ✅ Attack technique application (Owner CAN assign roles to compromise identities)
- ✅ Conditional abuse (RoleManagement permission CAN be used to assign Global Admin)
- ✅ Multi-step escalation paths (credential access → role assignment → resource compromise)

---

## Documentation Organization

### [directory-role-escalations/](directory-role-escalations/)
Escalation via Entra ID administrative roles (Global Admin, Privileged Role Admin, etc.)

### [rbac-escalations/](rbac-escalations/)
Escalation via Azure RBAC roles (Owner, User Access Administrator, etc.)

### [graph-permission-escalations/](graph-permission-escalations/)
Escalation via Microsoft Graph API permissions

### [group-based-escalations/](group-based-escalations/)
Escalation via group ownership and membership

### [application-escalations/](application-escalations/)
Escalation via application/service principal credential access

---

## Common Properties

All CAN_ESCALATE edges include:

- **method**: Attack technique name ("GlobalAdministrator", "AzureOwner", etc.)
- **condition**: Human-readable escalation condition
- **category**: Attack category ("DirectoryRole", "RBAC", "GraphPermission", etc.)

---

## Query Pattern

**Find what a principal can escalate to:**

```cypher
MATCH (principal:Resource {displayName: "Alice"})-[r:CAN_ESCALATE]->(target)
RETURN r.method,
       r.condition,
       count(DISTINCT target) as escalation_targets
ORDER BY escalation_targets DESC
```

---

## Implementation Pattern

CAN_ESCALATE edges are created in **Phase 5** by analyzing HAS_PERMISSION edges:

```cypher
-- Phase 5: Analyze escalation potential
MATCH (user)-[perm:HAS_PERMISSION]->(tenant)
WHERE perm.roleName = "Global Administrator"

-- Apply attack technique logic
WITH user
MATCH (escalate_target:Resource)
WHERE escalate_target <> user

-- Create escalation edges
CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "GlobalAdministrator",
    r.condition = "...",
    r.category = "DirectoryRole"
```

**Cardinality:** 1 HAS_PERMISSION edge → N CAN_ESCALATE edges (1:many relationship)

---

## Related Documentation

- **[HAS_PERMISSION Edges](../HAS_PERMISSION/)** - Current state data that CAN_ESCALATE analyzes
- **[Overview](../overview.md)** - Complete explanation of edge relationship types
- **[Analysis Examples](../analysis-examples.md)** - Attack path query examples
