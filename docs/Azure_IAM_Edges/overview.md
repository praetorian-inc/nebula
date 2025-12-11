# Azure IAM Edges Overview

Azure IAM edges represent privilege escalation relationships within Azure and Entra ID environments. These edges model how compromise of one identity or resource can lead to compromise of another, enabling attack path analysis.

## Edge Types

Azure IAM edges are categorized into several types based on the escalation mechanism:

### Directory Role Escalations
- [Global Administrator](directory-roles/global-administrator.md)
- [Privileged Role Administrator](directory-roles/privileged-role-administrator.md)
- [Privileged Authentication Administrator](directory-roles/privileged-authentication-administrator.md)
- [Application Administrator](directory-roles/application-administrator.md)
- [Cloud Application Administrator](directory-roles/cloud-application-administrator.md)
- [Groups Administrator](directory-roles/groups-administrator.md)
- [User Administrator](directory-roles/user-administrator.md)
- [Authentication Administrator](directory-roles/authentication-administrator.md)

### Microsoft Graph API Permission Escalations
- [RoleManagement.ReadWrite.Directory](graph-permissions/rolemanagement-readwrite-directory.md)
- [Directory.ReadWrite.All](graph-permissions/directory-readwrite-all.md)
- [Application.ReadWrite.All](graph-permissions/application-readwrite-all.md)
- [AppRoleAssignment.ReadWrite.All](graph-permissions/approleassignment-readwrite-all.md)
- [User.ReadWrite.All](graph-permissions/user-readwrite-all.md)
- [Group.ReadWrite.All](graph-permissions/group-readwrite-all.md)

### Azure RBAC Escalations
- [Owner](azure-rbac/owner.md)
- [User Access Administrator](azure-rbac/user-access-administrator.md)

### Group-Based Escalations
- [Group Owner Add Member](group-based/group-owner-add-member.md)
- [Group Membership Inheritance](group-based/group-membership-inheritance.md)

### Application/Service Principal Escalations
- [Service Principal Owner Add Secret](application-sp/sp-owner-add-secret.md)
- [Application Owner Add Secret](application-sp/app-owner-add-secret.md)
- [Application To Service Principal](application-sp/application-to-service-principal.md)

## Edge Properties

All CAN_ESCALATE edges include the following properties:

- **method**: The attack technique name (e.g., "GlobalAdministrator")
- **condition**: Human-readable description of the escalation condition
- **category**: The attack category (e.g., "DirectoryRole", "GraphPermission", "RBAC")

## Multiple Attack Vectors

When the same principal can escalate to the same target through multiple methods, separate CAN_ESCALATE edges are created for each attack vector. For example, a user with both Global Administrator and Application Administrator roles will have two distinct edges to application targets, preserving all escalation paths for comprehensive analysis.

## Detection and Analysis

These edges enable several types of analysis:

### Attack Path Discovery
Find paths from compromised identities to high-value targets:
```cypher
MATCH path = (start:Resource)-[:CAN_ESCALATE*1..3]->(target:Resource)
WHERE start.displayName = "CompromisedUser"
  AND target.resourceType = "Microsoft.DirectoryServices/tenant"
RETURN path
```

### Privilege Escalation Analysis
Identify users who can escalate to tenant-level control:
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GlobalAdministrator"
RETURN source.displayName, count(target) as escalation_scope
```

### Critical Identity Protection
Find identities that can compromise the most resources:
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
RETURN source.displayName, source.resourceType, count(target) as compromise_potential
ORDER BY compromise_potential DESC
LIMIT 10
```

## Implementation Details

The Azure IAM edge system is implemented as part of the Nebula security framework:

- **Data Collection**: Azure IAM data collected via `iam-pull` module
- **Graph Creation**: Edges created during `iam-push` Phase 4
- **Schema**: Uses Neo4j CAN_ESCALATE relationship type
- **Performance**: Supports enterprise-scale Azure tenants


## Security Impact

Azure IAM edges enable security teams to:

1. **Visualize Attack Paths**: Understand how privilege escalation can occur
2. **Prioritize Protections**: Focus on identities with high compromise potential
3. **Validate Security**: Review critical account protections
4. **Incident Response**: Assess impact of compromised accounts

This documentation covers Azure and Entra ID privilege escalation vectors modeled by the Nebula framework.