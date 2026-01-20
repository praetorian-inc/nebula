# Azure IAM Edges Documentation

This documentation covers Azure and Entra ID privilege escalation vectors modeled as CAN_ESCALATE edges in the Nebula security framework.

## Overview

Azure IAM edges represent privilege escalation relationships that enable attack path analysis in Azure and Entra ID environments. These edges help security teams understand how compromise of one identity or resource can lead to compromise of others.

### Edge Relationship Types

The Nebula IAM module uses **two distinct relationship types**:

1. **HAS_PERMISSION** - Current state representation
   - Factual data: what permissions exist right now
   - Direct mapping from Azure/Entra ID data
   - Examples: role assignments, RBAC grants, API permissions

2. **CAN_ESCALATE** - Escalation logic & analysis
   - Analytical data: what can be abused through escalation
   - Requires attack technique logic and conditions
   - Examples: privilege escalation paths, attack vectors

**Decision Rule:**
- Current authorization state → HAS_PERMISSION
- Requires escalation logic or abuse conditions → CAN_ESCALATE

**See [Overview - Edge Relationship Types](overview.md#edge-relationship-types-has_permission-vs-can_escalate) for detailed explanation.**

## Quick Start

1. **[Overview](overview.md)** - Introduction to Azure IAM edge concepts and HAS_PERMISSION vs CAN_ESCALATE distinction
2. **[HAS_PERMISSION Edges](HAS_PERMISSION/)** - Current state representation (role assignments, permissions, grants)
3. **[CAN_ESCALATE Edges](CAN_ESCALATE/)** - Escalation analysis (attack vectors, privilege escalation paths)
4. **[Analysis Examples](analysis-examples.md)** - Query examples for attack path analysis

### Documentation by Edge Type

#### HAS_PERMISSION/ - Current State

**[Browse all HAS_PERMISSION edges](HAS_PERMISSION/)**

Factual data representing what permissions exist right now:

- [global-administrator.md](HAS_PERMISSION/global-administrator.md) - Global Admin role assignment edge creation
- [owner.md](HAS_PERMISSION/owner.md) - Owner RBAC assignment edge creation
- [application-credential-management.md](HAS_PERMISSION/application-credential-management.md) - App credential management permissions
- [application-rbac-management.md](HAS_PERMISSION/application-rbac-management.md) - App RBAC management permissions
- *More to be added as migration continues*

#### CAN_ESCALATE/ - Escalation Analysis

**[Browse all CAN_ESCALATE edges](CAN_ESCALATE/)**

Analytical data representing what can be abused through escalation:

- [global-administrator.md](CAN_ESCALATE/global-administrator.md) - Global Admin escalation attack scenarios
- [owner.md](CAN_ESCALATE/owner.md) - Owner role escalation attack scenarios
- *More to be added as migration continues*

## Key Features

- **Coverage**: 21 attack vectors across Azure/Entra ID privilege domains
- **Schema Compatibility**: Uses Neo4j relationship patterns
- **HAS_PERMISSION Functions**: 6 edge creation functions covering all permission types
- **Implementation**: Compatible with existing analysis tools

## Edge Creation Functions

The Nebula IAM module creates HAS_PERMISSION edges through 6 specialized functions:

| Function | Purpose | Documentation |
|----------|---------|---------------|
| **Entra ID Roles** | Directory role assignments | [HAS_PERMISSION/global-administrator.md](HAS_PERMISSION/global-administrator.md) (example) |
| **PIM Enrichment** | Eligible vs active classification | [Overview - PIM](overview.md#pim-privileged-identity-management-enrichment) |
| **Azure RBAC** | Subscription/resource role assignments | [HAS_PERMISSION/owner.md](HAS_PERMISSION/owner.md) (example) |
| **Group Membership** | Transitive permission inheritance | [HAS_PERMISSION/](HAS_PERMISSION/) (to be migrated) |
| **Application Credential** | App Admin credential management | [HAS_PERMISSION/application-credential-management.md](HAS_PERMISSION/application-credential-management.md) |
| **Application RBAC** | App management via RBAC roles | [HAS_PERMISSION/application-rbac-management.md](HAS_PERMISSION/application-rbac-management.md) |

**See [Overview - iam-push Phase Architecture](overview.md#iam-push-phase-architecture) for complete implementation details.**

## Implementation

The Azure IAM edge system is implemented in the Nebula framework:

- **Data Collection**: `nebula azure recon iam-pull`
- **Graph Creation**: `nebula azure recon iam-push --neo4j-url <url>`
- **Analysis**: Use Neo4j queries for attack path discovery

## Example Analysis

Find all paths to tenant compromise:
```cypher
MATCH (source:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method IN ["GlobalAdministrator", "PrivilegedAuthenticationAdmin"]
RETURN source.displayName, r.method, count(target) as compromise_scope
ORDER BY compromise_scope DESC
```

## Documentation Structure

Documentation is organized by **edge relationship type**:

### HAS_PERMISSION/ - Current State Documentation

Each HAS_PERMISSION file documents factual permission data:

- **Edge Creation Logic**: How edges are created from Azure data
- **Data Collection**: Collector queries and data format
- **Edge Properties**: Complete property reference with types
- **MERGE Uniqueness**: Uniqueness constraints preventing duplicates
- **Query Examples**: How to query current permission state
- **PIM Enrichment**: How PIM metadata is added (if applicable)

### CAN_ESCALATE/ - Escalation Analysis Documentation

Each CAN_ESCALATE file documents escalation logic and abuse scenarios:

- **Detection Queries**: How to find escalation paths
- **Escalation Logic**: Internal implementation (Phase 5)
- **Attack Scenarios**: Real-world exploitation methods
- **Mitigation Strategies**: Defense recommendations
- **Prerequisites**: Conditions required for escalation
- **Impact Analysis**: Scope and severity of compromise

## Documentation Status

**Initial documentation created for foundational edges:**

✅ **Completed:**
- Global Administrator (HAS_PERMISSION + CAN_ESCALATE)
- Owner (HAS_PERMISSION + CAN_ESCALATE)
- Application Credential Management (HAS_PERMISSION)
- Application RBAC Management (HAS_PERMISSION)

📝 **To be documented:**
- Remaining directory roles (7 roles)
- Graph API permissions (6 permissions)
- Group-based escalations (2 types)
- Application/SP escalations (3 types)

---

## Contributing

To add documentation for new edge types:

1. **For HAS_PERMISSION edges:**
   - Create file in `HAS_PERMISSION/{category}/{edge-name}.md`
   - Document edge creation logic, properties, MERGE patterns
   - Include query examples for current state

2. **For CAN_ESCALATE edges:**
   - Create file in `CAN_ESCALATE/{category}-escalations/{edge-name}.md`
   - Document detection queries, attack scenarios, mitigations
   - Include escalation logic and prerequisites

3. **Update both README files** (this file + category README)
4. **Cross-reference** between HAS_PERMISSION and CAN_ESCALATE versions

## Support

For questions about Azure IAM edges:

- Review the specific edge documentation
- Check the overview for general concepts
- Examine the technical implementation in the Nebula codebase
- Analyze real environments using the provided queries

This documentation represents production-validated Azure privilege escalation analysis capabilities.