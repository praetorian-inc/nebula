# Group Membership Inheritance

## Description

Members of groups with directory role assignments automatically inherit those roles, enabling privilege escalation through group membership manipulation.

## Edge Information

- **Attack Method**: GroupDirectoryRoleInheritance
- **Edge Category**: GroupMembership
- **From**: Group member (User, Service Principal, or nested Group)
- **To**: Directory role inherited from group

## Escalation Condition

Member of group with directory role assignment inherits that role automatically.

## Technical Details

### Detection Query
```cypher
MATCH (group:Resource)-[:CONTAINS]->(member:Resource),
      (group)-[group_perm:HAS_PERMISSION]->(role:Resource)
WHERE group.resourceType = "Microsoft.DirectoryServices/groups"
  AND group_perm.roleName IS NOT NULL
CREATE (member)-[r:CAN_ESCALATE]->(role)
SET r.method = "GroupDirectoryRoleInheritance",
    r.condition = "Member of group with directory role assignment inherits that role automatically",
    r.category = "GroupMembership"
```

### Prerequisites
- Group must have directory role assignment
- Principal must be a member of the group (direct or nested)
- Group must be role-assignable (for directory roles)

### Attack Scenarios

1. **Stealth Privilege Escalation**: Gain admin privileges through seemingly innocent group membership
2. **Nested Group Abuse**: Join groups that are members of privileged groups
3. **Dynamic Group Manipulation**: Modify attributes to meet dynamic group membership criteria
4. **Group Owner Abuse**: Group owners can add members to inherit privileges
5. **Bulk Privilege Assignment**: Add multiple accounts to privileged groups

### Group Types and Risks

#### **Role-Assignable Groups**
- Can be assigned directory roles (Global Admin, etc.)
- Higher privilege escalation risk
- Limited creation (requires special permissions)

#### **Dynamic Groups**
- Membership based on user/device attributes
- Risk: Manipulate attributes to gain membership
- Automatic privilege inheritance

#### **Nested Groups**
- Groups can be members of other groups
- Cascading privilege inheritance
- Complex attack paths through group hierarchies

### Attack Techniques

1. **Social Engineering**: Convince admins to add attacker to privileged groups
2. **Attribute Manipulation**: Modify user properties to meet dynamic group rules
3. **Group Owner Compromise**: Compromise group owners → add members
4. **Self-Service Group Abuse**: Use self-service group features to join groups
5. **Automation Abuse**: Use automated provisioning to add users to groups

### Mitigation Strategies

1. **Regular Group Audits**: Review privileged group memberships monthly
2. **Approval Workflows**: Require approval for privileged group membership changes
3. **Dynamic Group Validation**: Regularly review dynamic group membership rules
4. **Group Owner Protection**: Secure accounts that own privileged groups
5. **Nested Group Limits**: Limit nesting depth for role-assignable groups
6. **Monitoring**: Alert on privileged group membership changes
7. **Access Reviews**: Implement regular access reviews for privileged groups

### Detection Queries

Find privileged groups:
```cypher
MATCH (group:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE group.resourceType = "Microsoft.DirectoryServices/groups"
  AND perm.roleName CONTAINS "Administrator"
RETURN group.displayName, perm.roleName, count(*) as role_assignments
```

Find users with inherited admin roles:
```cypher
MATCH (group:Resource)-[:CONTAINS]->(user:Resource),
      (group)-[perm:HAS_PERMISSION]->(target:Resource)
WHERE group.resourceType = "Microsoft.DirectoryServices/groups"
  AND user.resourceType = "Microsoft.DirectoryServices/users"
  AND perm.roleName CONTAINS "Administrator"
RETURN user.displayName, group.displayName, perm.roleName
```

### Real-World Examples

In enterprise environments:
- **Exchange Administrators Group**: Members inherit Exchange admin privileges
- **Global Admins Group**: Members inherit Global Administrator role
- **Application Admins Group**: Members can manage all applications
- **Dynamic Admin Groups**: Membership based on department, location, etc.

### Compliance Considerations

- **SOX Compliance**: Group-based privilege assignment may violate segregation of duties
- **PCI DSS**: Privileged group access must be monitored and controlled
- **ISO 27001**: Access rights management includes group-based privileges
- **Zero Trust**: Group membership should be continuously validated

### Related Edges

- [Groups Administrator](../directory-roles/groups-administrator.md) - Can modify group memberships
- [Group Owner Add Member](group-owner-add-member.md) - Ownership-based membership control
- [User Administrator](../directory-roles/user-administrator.md) - Can modify user attributes for dynamic groups

## References

- [Entra ID Group-Based Role Assignment](https://docs.microsoft.com/en-us/azure/active-directory/roles/groups-concept)
- [Dynamic Group Membership Rules](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-dynamic-membership)