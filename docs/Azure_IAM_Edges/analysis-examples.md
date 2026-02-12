# Azure IAM Edge Analysis Examples

## Analysis Queries

This document provides example queries for analyzing Azure IAM privilege escalation edges.

## Basic Edge Analysis

### Find Multiple Attack Vectors Between Same Nodes
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WITH source, target, collect(r.method) as attack_methods, count(r) as vector_count
WHERE vector_count > 1
RETURN source.displayName, target.displayName, attack_methods, vector_count
ORDER BY vector_count DESC
```

## Basic Edge Analysis

### Find All Attack Vectors
```cypher
MATCH ()-[r:CAN_ESCALATE]->()
RETURN DISTINCT r.method, r.category, r.condition
ORDER BY r.category, r.method
```

### Count Edges by Category
```cypher
MATCH ()-[r:CAN_ESCALATE]->()
RETURN r.category, count(r) as edge_count
ORDER BY edge_count DESC
```

### Find High-Impact Identities
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
RETURN source.displayName, source.resourceType, count(target) as escalation_potential
ORDER BY escalation_potential DESC
LIMIT 10
```

## Directory Role Analysis

### Global Administrator Paths
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GlobalAdministrator"
RETURN source.displayName, target.resourceType, count(target) as targets
ORDER BY targets DESC
```

### Privileged Authentication Administrator Impact
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "PrivilegedAuthenticationAdmin"
RETURN source.displayName, count(target) as password_reset_capability
```

## Graph Permission Analysis

### Find Service Principals with Dangerous Permissions
```cypher
MATCH (sp:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.category = "GraphPermission"
RETURN sp.displayName, r.method, count(target) as escalation_scope
ORDER BY escalation_scope DESC
```

### Role Management Permission Abuse
```cypher
MATCH (sp:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GraphRoleManagement"
RETURN sp.displayName, count(target) as can_assign_roles_to
```

## Azure RBAC Analysis

### Owner Role Escalation Paths
```cypher
MATCH (principal:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "AzureOwner"
RETURN principal.displayName, count(target) as owner_escalation_scope
ORDER BY owner_escalation_scope DESC
```

### User Access Administrator Analysis
```cypher
MATCH (principal:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "UserAccessAdmin"
RETURN principal.displayName, count(target) as role_assignment_capability
```

## Group-Based Analysis

### Group Ownership Risks
```cypher
MATCH (owner:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GroupOwnerAddMember"
RETURN owner.displayName, count(target) as can_add_to_groups
ORDER BY can_add_to_groups DESC
```

### Group Membership Privilege Inheritance
```cypher
MATCH (member:Resource)-[r:CAN_ESCALATE]->(role:Resource)
WHERE r.method = "GroupDirectoryRoleInheritance"
RETURN member.displayName, role.displayName, r.condition
```

## Application/Service Principal Analysis

### Application to Service Principal Escalation
```cypher
MATCH (app:Resource)-[r:CAN_ESCALATE]->(sp:Resource)
WHERE r.method = "ApplicationToServicePrincipal"
RETURN app.displayName, sp.displayName
```

### Service Principal Credential Addition
```cypher
MATCH (owner:Resource)-[r:CAN_ESCALATE]->(sp:Resource)
WHERE r.method = "ServicePrincipalAddSecret"
RETURN owner.displayName, sp.displayName
```

## Attack Path Discovery

### Multi-Hop Escalation Paths
```cypher
MATCH path = (start:Resource)-[:CAN_ESCALATE*1..3]->(end:Resource)
WHERE end.resourceType = "Microsoft.DirectoryServices/tenant"
   OR end.displayName CONTAINS "Global Administrator"
RETURN start.displayName, length(path) as hops, end.displayName
ORDER BY hops, start.displayName
LIMIT 20
```

### Shortest Path to Privilege
```cypher
MATCH (start:Resource), (end:Resource)
WHERE start.resourceType = "Microsoft.DirectoryServices/users"
  AND end.resourceType = "Microsoft.DirectoryServices/servicePrincipals"
MATCH path = shortestPath((start)-[:CAN_ESCALATE*1..5]->(end))
RETURN start.displayName, end.displayName, length(path) as escalation_distance
ORDER BY escalation_distance
LIMIT 10
```

## Risk Assessment Queries

### Critical Identity Protection Analysis
```cypher
MATCH (identity:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.category IN ["DirectoryRole", "GraphPermission"]
RETURN identity.displayName, identity.resourceType,
       collect(DISTINCT r.method) as escalation_methods,
       count(target) as compromise_potential
ORDER BY compromise_potential DESC
```

### Tenant-Level Compromise Vectors
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method IN ["GlobalAdministrator", "PrivilegedRoleAdmin", "GraphRoleManagement"]
RETURN source.displayName, source.resourceType, r.method, count(target) as tenant_risk
ORDER BY tenant_risk DESC
```

## Security Monitoring

### New Privilege Escalation Edges
```cypher
MATCH ()-[r:CAN_ESCALATE]->()
WHERE r.createdAt > datetime() - duration('P1D')
RETURN r.method, count(*) as new_edges_last_24h
ORDER BY new_edges_last_24h DESC
```

### High-Risk Edge Monitoring
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.category = "DirectoryRole" AND r.method IN ["GlobalAdministrator", "PrivilegedRoleAdmin"]
RETURN source.displayName, r.method, count(target) as risk_scope
```

These queries enable comprehensive analysis of Azure IAM privilege escalation relationships and attack surface assessment.