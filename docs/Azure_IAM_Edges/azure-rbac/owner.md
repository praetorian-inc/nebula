# Owner

## Description

The Owner role at any Azure scope provides full control over resources within that scope AND the ability to assign roles to other principals, enabling compromise of other identities.

## Edge Information

- **Attack Method**: AzureOwner
- **Edge Category**: RBAC
- **From**: Principal with Owner role assignment
- **To**: Any principal in the tenant

## Escalation Condition

Owner role at any scope provides full control AND can assign roles to compromise other identities.

## Technical Details

### Detection Query
```cypher
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.permission = "Owner"
WITH principal
MATCH (escalate_target:Resource)
WHERE escalate_target <> principal
CREATE (principal)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "AzureOwner",
    r.condition = "Owner role at any scope provides full control AND can assign roles to compromise other identities",
    r.category = "RBAC"
```

### Prerequisites
- Principal must have Owner role assignment at any Azure scope
- Scope can be Management Group, Subscription, Resource Group, or individual Resource

### Attack Scenarios

1. **Role Assignment Abuse**: Assign Owner role to attacker-controlled identities
2. **User Access Administrator Assignment**: Assign User Access Administrator to gain role assignment capabilities
3. **Resource Manipulation**: Modify resources to create backdoors or access paths
4. **Managed Identity Abuse**: Modify resources with managed identities to steal their tokens
5. **Cross-Subscription Escalation**: Use management group or root scope ownership

### Azure RBAC Scope Hierarchy

Owner permissions inherit down the Azure scope hierarchy:

```
Tenant Root Group (/)
├── Management Groups
│   ├── Subscriptions
│   │   ├── Resource Groups
│   │   │   └── Resources (VMs, Storage, etc.)
```

### Key Capabilities

Owner role provides:
- **Full resource control**: Create, modify, delete any resource within scope
- **Role assignment**: Assign any Azure role to any principal within scope
- **Policy management**: Create and modify Azure policies
- **Access control**: Modify resource access controls and permissions
- **Identity management**: Control managed identities and their assignments

### Attack Techniques

1. **Lateral Movement**: Assign roles to move across resource boundaries
2. **Privilege Persistence**: Create additional Owner assignments for persistence
3. **Identity Theft**: Attach managed identities to controlled resources → steal tokens
4. **Data Access**: Assign storage roles to access sensitive data
5. **Compute Compromise**: Assign VM roles to execute code on compute resources

### Mitigation Strategies

1. **Principle of Least Privilege**: Assign Owner only when necessary
2. **Time-Bound Access**: Use PIM for temporary Owner assignments
3. **Conditional Access**: Apply strict policies to Owner role assignments
4. **Regular Audits**: Review all Owner role assignments quarterly
5. **Segregation of Duties**: Separate Owner and User Access Administrator roles
6. **Monitoring**: Alert on Owner role assignments and usage
7. **Break-Glass Procedures**: Separate emergency access from regular operations

### Scope-Specific Risks

- **Tenant Root**: Can assign roles across entire Azure environment
- **Management Group**: Can affect multiple subscriptions
- **Subscription**: Can create resource groups and assign roles
- **Resource Group**: Can affect all resources within the group
- **Resource**: Limited to single resource but can modify its identity and access

### Detection Queries

Find all Owners in the environment:
```cypher
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.permission = "Owner"
RETURN principal.displayName, perm.scope, count(*) as owner_assignments
ORDER BY count(*) DESC
```

Find high-risk Owner assignments:
```cypher
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE perm.permission = "Owner" AND perm.scope IN ["/", "/providers/Microsoft.Management/managementGroups/"]
RETURN principal.displayName, principal.resourceType, perm.scope
```

### Related Edges

- [User Access Administrator](user-access-administrator.md) - Role assignment capability without full resource control
- [Global Administrator](../directory-roles/global-administrator.md) - Can elevate to Owner on any subscription

## References

- [Azure Built-in Roles - Owner](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner)
- [Azure RBAC Scope Hierarchy](https://docs.microsoft.com/en-us/azure/role-based-access-control/scope-overview)