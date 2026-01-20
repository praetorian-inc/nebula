# HAS_PERMISSION Edges

**Edge Relationship Type:** `HAS_PERMISSION`

---

## Purpose

HAS_PERMISSION edges represent the **current state** of permissions in the Azure/Entra ID environment. These are **factual data** directly mapped from Azure APIs without interpretation or analysis.

**Decision Rule:** If it describes current authorization state → HAS_PERMISSION

---

## When to Use HAS_PERMISSION

- ✅ Direct role assignments (user has Global Administrator role)
- ✅ RBAC assignments (principal has Owner on subscription)
- ✅ Graph API permissions (service principal has RoleManagement.ReadWrite.Directory)
- ✅ Group membership inheritance (member inherits group's permissions)
- ✅ Application management rights (app has Application Administrator managing it)

---

## Available Documentation

### Entra ID Directory Roles
- [global-administrator.md](global-administrator.md) - Global Administrator role assignment edges

### Azure RBAC
- [owner.md](owner.md) - Owner role assignment edges

### Application Management
- [application-credential-management.md](application-credential-management.md) - App credential management permissions
- [application-rbac-management.md](application-rbac-management.md) - App RBAC management permissions

### Coming Soon
- Other directory roles (Privileged Role Admin, Application Admin, etc.)
- Graph API permissions (RoleManagement.ReadWrite.Directory, etc.)
- Group membership inheritance edges

---

## Common Properties

All HAS_PERMISSION edges include:

- **permission**: Permission name
- **source**: Where permission comes from ("DirectoryRole", "AzureRBAC", "GraphPermission", etc.)
- **principalType**: "User", "ServicePrincipal", or "Group"
- **createdAt**: Edge creation timestamp

**Type-specific properties:**
- Entra ID: `roleName`, `templateId`, `roleTemplateId`
- Azure RBAC: `roleName`, `roleDefinitionId`, `scope`
- Graph Permissions: `permissionType`, `consentType`, `id`

---

## Query Pattern

**Find what permissions a principal has:**

```cypher
MATCH (principal:Resource {displayName: "Alice"})-[r:HAS_PERMISSION]->(target)
RETURN r.permission,
       r.roleName,
       r.source,
       target.displayName
ORDER BY r.permission
```

---

## Related Documentation

- **[CAN_ESCALATE Edges](../CAN_ESCALATE/)** - Escalation analysis derived from HAS_PERMISSION data
- **[Overview](../overview.md)** - Complete explanation of edge relationship types
