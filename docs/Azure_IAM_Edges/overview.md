# Azure IAM Edges Overview

Azure IAM edges represent privilege escalation relationships within Azure and Entra ID environments. These edges model how compromise of one identity or resource can lead to compromise of another, enabling attack path analysis.

## Edge Relationship Types: HAS_PERMISSION vs CAN_ESCALATE

The Nebula IAM module uses **two distinct relationship types** to separate current state from escalation analysis:

### HAS_PERMISSION - Current State Representation

**Purpose:** Represents **what permissions exist right now** in the environment

**When to use:**
- ✅ Direct role assignments (user has Global Administrator role)
- ✅ RBAC assignments (principal has Owner on subscription)
- ✅ Graph API permissions (service principal has RoleManagement.ReadWrite.Directory)
- ✅ Group membership inheritance (member inherits group's permissions)
- ✅ Application management rights (app has Application Administrator managing it)

**Key principle:** HAS_PERMISSION edges are **factual data** - they describe the current authorization state without interpretation or analysis.

**Example:**
```cypher
(Alice)-[HAS_PERMISSION {
    permission: "Global Administrator",
    roleName: "Global Administrator",
    source: "DirectoryRole",
    assignmentType: "PIM"
}]->(Tenant)
```

**Meaning:** Alice currently has Global Administrator role assignment (fact).

### CAN_ESCALATE - Escalation Logic & Analysis

**Purpose:** Represents **what can be abused** through escalation logic, conditions, or attack techniques

**When to use:**
- ✅ Privilege escalation potential (Global Admin CAN escalate to compromise any resource)
- ✅ Attack technique application (Owner CAN assign roles to compromise identities)
- ✅ Conditional abuse (RoleManagement permission CAN be used to assign Global Admin)
- ✅ Multi-step escalation paths (credential access → role assignment → resource compromise)

**Key principle:** CAN_ESCALATE edges require **analytical logic** - they interpret HAS_PERMISSION data to determine escalation possibilities.

**Example:**
```cypher
(Alice)-[CAN_ESCALATE {
    method: "GlobalAdministrator",
    condition: "Global Administrator role provides complete tenant control",
    category: "DirectoryRole"
}]->(Production-Subscription)
```

**Meaning:** Alice can abuse Global Admin role to escalate privileges on Production-Subscription (analysis).

### Implementation Pattern

**Two-phase process:**

1. **Phase 4 - Create HAS_PERMISSION edges** (factual data collection)
   - Query Azure/Entra ID for current role assignments
   - Create edges representing actual permissions
   - No analysis or interpretation

2. **Phase 5 - Create CAN_ESCALATE edges** (escalation analysis)
   - Query HAS_PERMISSION edges
   - Apply attack technique logic
   - Determine what principals can escalate to what resources

**Code Pattern:**
```cypher
-- Phase 4: Record current state
MERGE (principal)-[r:HAS_PERMISSION {roleName: ..., permission: ...}]->(target)
ON CREATE SET r.source = "DirectoryRole", ...

-- Phase 5: Analyze escalation potential
MATCH (user)-[perm:HAS_PERMISSION]->(tenant)
WHERE perm.roleName = "Global Administrator"
WITH user
MATCH (escalate_target:Resource)
CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "GlobalAdministrator", r.condition = "...", ...
```

### Why This Separation Matters

| Aspect | HAS_PERMISSION | CAN_ESCALATE |
|--------|---------------|--------------|
| **Nature** | Current state (facts) | Escalation potential (analysis) |
| **Query Use** | "What permissions does Alice have?" | "What can Alice escalate to?" |
| **Cardinality** | 1:1 with Azure data | 1:many (one permission → many targets) |
| **Updates** | Changes when Azure changes | Recomputed when HAS_PERMISSION changes |
| **Interpretation** | None (direct mapping) | Requires attack technique knowledge |

**Example Queries:**

```cypher
-- State query: What permissions does Alice have?
MATCH (alice:Resource {displayName: "Alice"})-[r:HAS_PERMISSION]->(target)
RETURN r.permission, r.roleName, target.displayName

-- Analysis query: What can Alice escalate to?
MATCH (alice:Resource {displayName: "Alice"})-[r:CAN_ESCALATE]->(target)
RETURN r.method, count(DISTINCT target) as escalation_targets
```

**Decision Rule:**

- If it describes **current authorization state** → HAS_PERMISSION
- If it requires **escalation logic or abuse conditions** → CAN_ESCALATE

## Edge Types (CAN_ESCALATE Escalations)

Azure IAM escalation vectors are categorized by privilege domain:

### Directory Role Escalations

**[View All CAN_ESCALATE](CAN_ESCALATE/)** | **[View HAS_PERMISSION](HAS_PERMISSION/)**

- [Global Administrator](CAN_ESCALATE/global-administrator.md) - Complete tenant control
- Privileged Role Administrator - Role assignment capabilities (to be documented)
- Privileged Authentication Administrator - Authentication control (to be documented)
- Application Administrator - Application management abuse (to be documented)
- Cloud Application Administrator - Cloud app management (to be documented)
- Groups Administrator - Group management abuse (to be documented)
- User Administrator - User management abuse (to be documented)
- Authentication Administrator - Auth method control (to be documented)

### Microsoft Graph API Permission Escalations

**[View All CAN_ESCALATE](CAN_ESCALATE/)** | **[View HAS_PERMISSION](HAS_PERMISSION/)**

- RoleManagement.ReadWrite.Directory - Direct role assignment (to be documented)
- Directory.ReadWrite.All - Directory object manipulation (to be documented)
- Application.ReadWrite.All - Application credential abuse (to be documented)
- AppRoleAssignment.ReadWrite.All - App role assignment (to be documented)
- User.ReadWrite.All - User manipulation (to be documented)
- Group.ReadWrite.All - Group manipulation (to be documented)

### Azure RBAC Escalations

**[View All CAN_ESCALATE](CAN_ESCALATE/)** | **[View HAS_PERMISSION](HAS_PERMISSION/)**

- [Owner](CAN_ESCALATE/owner.md) - Full resource control + role assignment
- User Access Administrator - Role assignment capabilities (to be documented)

### Group-Based Escalations

**[View All CAN_ESCALATE](CAN_ESCALATE/)** | **[View HAS_PERMISSION](HAS_PERMISSION/)**

- Group Owner Add Member - Add self to privileged groups (to be documented)
- Group Membership Inheritance - Transitive permission escalation (to be documented)

### Application/Service Principal Escalations

**[View All CAN_ESCALATE](CAN_ESCALATE/)** | **[View HAS_PERMISSION](HAS_PERMISSION/)**

- Service Principal Owner Add Secret - Credential abuse (to be documented)
- Application Owner Add Secret - App credential abuse (to be documented)
- Application To Service Principal - App-to-SP relationships (to be documented)

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
- **Graph Creation**: Multi-phase process during `iam-push`
- **Schema**: Uses Neo4j HAS_PERMISSION and CAN_ESCALATE relationship types
- **Performance**: Supports enterprise-scale Azure tenants

### iam-push Phase Architecture

**Phase 1-3: Resource Node Creation**
- Creates Resource nodes (users, groups, service principals, Azure resources)
- Uses MERGE to prevent duplicates
- Sets properties: displayName, resourceType, accountEnabled, etc.

**Phase 4: HAS_PERMISSION Edge Creation (6 Functions)**

All HAS_PERMISSION edges require both source and target Resource nodes to exist first.

| Function | Line | Purpose | Edges Created |
|----------|------|---------|---------------|
| `createEntraIDPermissionEdges()` | 1626 | Entra ID directory role assignments | Variable (~100s) |
| `createPIMEnrichedPermissionEdges()` | 1756 | PIM eligible assignment enrichment | Enriches existing |
| `createRBACPermissionEdges()` | 2016 | Azure RBAC role assignments | Variable (~100s) |
| `createGroupMemberPermissionEdges()` | 2164 | Transitive group member permissions | Variable (~100s) |
| `createApplicationCredentialPermissionEdges()` | 3747 | App Admin credential management | ~24 per tenant |
| `createApplicationRBACPermissionEdges()` | 3832 | RBAC-based app management | ~396 per tenant |

**Phase 5: CAN_ESCALATE Edge Creation**
- Analyzes HAS_PERMISSION edges to determine escalation relationships
- Creates CAN_ESCALATE edges based on ~19 attack vectors
- Examples: GlobalAdministrator, AzureOwner, GraphRoleManagement

### Resource Node Pre-requisites

**Critical:** All HAS_PERMISSION edges use MATCH to find existing nodes:

```cypher
MATCH (principal:Resource {id: $principalId})
MATCH (target:Resource {id: $targetResourceId})
MERGE (principal)-[r:HAS_PERMISSION {...}]->(target)
```

**If a principal or resource node doesn't exist:**
- The MATCH fails
- No edge is created
- **No error is logged** (silent failure)

**Prevention:** Ensure Phase 1-3 complete successfully before Phase 4 executes.

### PIM (Privileged Identity Management) Enrichment

**Function:** `createPIMEnrichedPermissionEdges()` (line 1756)

**Purpose:** Enrich existing HAS_PERMISSION edges with PIM metadata

**Process:**

1. **Match existing edges** created by `createEntraIDPermissionEdges()`:
```cypher
MATCH (principal:Resource {id: $principalId})-[r:HAS_PERMISSION]->(tenant:Resource)
WHERE r.templateId = $roleTemplateId
```

2. **Add PIM properties:**
```cypher
SET r.assignmentType = "PIM",
    r.pimProcessed = true
```

3. **Create eligible assignment edges** (if no active assignment exists):
```cypher
-- If PIM eligible exists but no active HAS_PERMISSION
CREATE (principal)-[r:HAS_PERMISSION]->(tenant)
SET r.assignmentType = "Eligible",
    r.pimProcessed = true,
    ...
```

4. **Mark non-PIM edges as Permanent:**
```cypher
MATCH (principal)-[r:HAS_PERMISSION]->(tenant)
WHERE r.pimProcessed IS NULL
SET r.assignmentType = "Permanent"
```

**Result:**
- Active assignments: `assignmentType = "PIM"` or `"Permanent"`
- Eligible-only assignments: `assignmentType = "Eligible"`

**Query Examples:**

```cypher
-- Find all PIM assignments (active)
MATCH ()-[r:HAS_PERMISSION]->()
WHERE r.assignmentType = "PIM"
RETURN count(r)

-- Find eligible-only assignments (not activated)
MATCH ()-[r:HAS_PERMISSION]->()
WHERE r.assignmentType = "Eligible"
RETURN count(r)
```

### MERGE Uniqueness Constraints

**All HAS_PERMISSION MERGE operations use uniqueness constraints to prevent duplicates:**

| Edge Type | Uniqueness Properties | Example |
|-----------|----------------------|---------|
| **Entra ID Roles** | `{templateId, permission}` | Each principal can have same role only once |
| **Azure RBAC** | `{roleDefinitionId, permission}` | Each principal-role-scope combo unique |
| **Group Membership** | `{permission}` | Member inherits group permission once |
| **Application Credential** | `{roleName, permission}` | Each principal-role combo unique |
| **Application RBAC** | `{roleName, permission}` | Each app-role combo unique |
| **Graph Permissions** | `{permission, permissionType, consentType, id}` | Complete grant context uniqueness |

**Why This Matters:**

Without proper uniqueness constraints, MERGE can:
- Create duplicate edges (same permission assigned twice)
- Overwrite data (last assignment wins, earlier assignments lost)
- Fail idempotency (re-running creates different results)

**Validation:**

```cypher
-- Detect duplicates (should return 0 rows)
MATCH (source)-[r:HAS_PERMISSION]->(target)
WITH source.id as sourceId, target.id as targetId, r.permission as permission, count(r) as edgeCount
WHERE edgeCount > 1
RETURN sourceId, targetId, permission, edgeCount
```


## Security Impact

Azure IAM edges enable security teams to:

1. **Visualize Attack Paths**: Understand how privilege escalation can occur
2. **Prioritize Protections**: Focus on identities with high compromise potential
3. **Validate Security**: Review critical account protections
4. **Incident Response**: Assess impact of compromised accounts

This documentation covers Azure and Entra ID privilege escalation vectors modeled by the Nebula framework.