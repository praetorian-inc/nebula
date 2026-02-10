# Application to Service Principal Escalation

**Method:** `ApplicationToServicePrincipal`
**Category:** Application Identity Escalation

## Overview

Application compromise (credential addition) provides access to the corresponding Service Principal and all its permissions, representing the identity relationship between app registration and enterprise app.

## Escalation Path

```
Application → [CONTAINS] → Service Principal
            → [CAN_ESCALATE: ApplicationToServicePrincipal] → Service Principal
            → Add credential to app → Authenticate as SP → Inherit SP permissions
```

## Edge Creation Logic

**Source:** Application object

**Target:** Service Principal linked via CONTAINS edge

**Relationship:**
```cypher
(app:Resource)-[:CONTAINS]->(sp:Resource)
→ Creates: (app)-[:CAN_ESCALATE]->(sp)
```

**Condition:** "Application compromise (credential addition) provides access to corresponding Service Principal and all its permissions"

## Conceptual Model

**This edge represents:**
- The identity relationship between Application and Service Principal
- App credentials = SP authentication
- App compromise = SP compromise
- Structural privilege escalation (not attacker action)

**Purpose in Graph:**
- Show that Application objects are privilege escalation vectors
- Connect Application ownership/compromise to SP permissions
- Enable attack path queries through Application nodes

## Attack Scenarios

### Scenario 1: Via Application Administrator Role
```
1. Application Administrator can add credentials to any app
2. Add secret to Application
3. Authenticate as Service Principal using app credentials
4. Inherit SP's permissions (e.g., Global Administrator)
```

### Scenario 2: Via Application.ReadWrite.All Permission
```
1. SP with Application.ReadWrite.All
2. Add secret to Application
3. Authenticate as target SP
4. Chain escalation to SP with higher privileges
```

### Scenario 3: Via Application Ownership
```
1. User owns Application
2. Add secret to Application
3. Authenticate as Service Principal
4. Gain SP's permissions
```

## Edge Properties

```cypher
{
  method: "ApplicationToServicePrincipal",
  category: "ApplicationIdentity",
  condition: "Application compromise (credential addition) provides access to corresponding Service Principal and all its permissions"
}
```

## Detection Query

```cypher
// Find Applications that escalate to privileged SPs
MATCH (app:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "ApplicationToServicePrincipal"
  AND EXISTS {
    MATCH (sp)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
       OR p.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
  }
RETURN app.displayName as application,
       app.id as app_object_id,
       sp.displayName as service_principal,
       sp.appId as client_id,
       collect(DISTINCT p.roleName)[0..3] as sp_privileges
ORDER BY app.displayName
```

## Attack Path Analysis

**Complete Attack Chain:**
```cypher
// From user to Global Admin via app ownership
MATCH path = (user:Resource)-[:OWNS]->(app:Resource)
            -[:CAN_ESCALATE]->(sp:Resource)
            -[perm:HAS_PERMISSION]->(:Resource)
WHERE perm.roleName = "Global Administrator"
RETURN user.displayName as attacker_entry_point,
       app.displayName as compromised_app,
       sp.displayName as privileged_sp,
       length(path) as path_length
```

## Why This Edge Exists

**Graph Modeling:**
- Applications are not just containers of SPs
- Applications ARE privilege escalation vectors
- Need to model: "compromising app = gaining SP access"

**Attack Path Discovery:**
- Enables queries: "How can I reach Global Admin from this user?"
- Path: User → OWNS → App → CAN_ESCALATE → SP → HAS_PERMISSION → Tenant
- Without this edge, path analysis incomplete

**Risk Assessment:**
- Applications with many owners = high risk
- Applications with privileged SPs = high value targets
- This edge connects ownership risk to permission impact

## Application Compromise Methods

**How attackers compromise applications:**

1. **Credential Addition**
   - Via ownership
   - Via Application Administrator role
   - Via Application.ReadWrite.All permission

2. **Credential Theft**
   - Secrets in code repositories
   - Secrets in CI/CD pipelines
   - Secrets in configuration files

3. **Reply URL Manipulation**
   - OAuth flow hijacking
   - Token theft

## Difference from Other Escalation Edges

| Edge | Source | Represents |
|------|--------|------------|
| `ServicePrincipalAddSecret` | Owner | Owner's ability to add secret |
| `ApplicationAddSecret` | Owner | Owner's ability via app object |
| **`ApplicationToServicePrincipal`** | **Application** | **App identity = SP identity** |

**This edge models the object relationship, not attacker capability**

## Use in Attack Path Queries

**Query: All paths from user to Global Admin**
```cypher
MATCH path = (user:Resource {id: $userId})-[*1..5]->(target:Resource)
WHERE EXISTS {
  MATCH (target)-[p:HAS_PERMISSION]->(:Resource)
  WHERE p.roleName = "Global Administrator"
}
RETURN path
LIMIT 10
```

**ApplicationToServicePrincipal enables paths like:**
```
User → OWNS → App → CAN_ESCALATE → SP → HAS_PERMISSION → Tenant
```

## Multi-Tenant Implications

**Application in Tenant A:**
- Can have Service Principal in Tenant A (home tenant)
- Can have Service Principal in Tenant B (guest tenant)
- Can have Service Principal in Tenant C (guest tenant)

**Edge Creation:**
- One CAN_ESCALATE per app→SP pair
- Multiple SPs = multiple CAN_ESCALATE edges from same app
- Cross-tenant attack paths possible

## Mitigation

**Protect Applications:**
- Audit application ownership
- Monitor credential additions
- Limit who can create apps
- Review app→SP permission mappings

**Protect Service Principals:**
- Limit SP permissions
- Use least privilege
- Monitor SP authentication
- Rotate credentials regularly

**Monitor Attack Paths:**
- Query paths through Applications
- Identify high-risk applications
- Remediate excessive permissions

## Related Documentation

- [Service Principal Add Secret](service-principal-add-secret.md) - Direct SP ownership escalation
- [Application Add Secret](application-add-secret.md) - App ownership escalation
- [../CONTAINS/application-to-sp.md](../CONTAINS/application-to-sp.md) - Structural relationship
- [../../Azure_IAM_Nodes/application.md](../../Azure_IAM_Nodes/application.md) - Application node structure
- [../../Azure_IAM_Nodes/service-principal.md](../../Azure_IAM_Nodes/service-principal.md) - SP node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedApplicationToServicePrincipalQuery()` - line 4395
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Edge Creation:** Based on CONTAINS edges created in Phase 2a

**Note:** This edge creates a relationship from the Application object itself to the SP, not from an owner to the SP. It models the fundamental identity relationship.
