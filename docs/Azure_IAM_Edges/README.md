# Azure IAM Edges Documentation

This documentation covers Azure and Entra ID privilege escalation vectors modeled as CAN_ESCALATE edges in the Nebula security framework.

## Overview

Azure IAM edges represent privilege escalation relationships that enable attack path analysis in Azure and Entra ID environments. These edges help security teams understand how compromise of one identity or resource can lead to compromise of others.

## Quick Start

1. **[Overview](overview.md)** - Introduction to Azure IAM edge concepts
2. **[Directory Roles](directory-roles/)** - Entra ID administrative role escalations
3. **[Graph Permissions](graph-permissions/)** - Microsoft Graph API permission escalations
4. **[Azure RBAC](azure-rbac/)** - Azure resource-based access control escalations
5. **[Group-Based](group-based/)** - Group membership and ownership escalations
6. **[Application/SP](application-sp/)** - Application and Service Principal escalations
7. **[Analysis Examples](analysis-examples.md)** - Query examples for attack path analysis

## Key Features

- **Coverage**: 21 attack vectors across Azure/Entra ID privilege domains
- **Schema Compatibility**: Uses Neo4j relationship patterns
- **Implementation**: Compatible with existing analysis tools

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

Each edge type includes:

- **Description**: What the edge represents
- **Technical Details**: Detection queries and prerequisites
- **Attack Scenarios**: Real-world exploitation methods
- **Mitigation Strategies**: Defense recommendations
- **Detection Queries**: Analysis and monitoring queries
- **Real-World Examples**: Validated findings from actual environments

## Contributing

To add documentation for new edge types:

1. Create markdown file in appropriate category folder
2. Follow the existing template structure
3. Include technical details, attack scenarios, and mitigations
4. Add real-world examples when available
5. Update the overview and category index files

## Support

For questions about Azure IAM edges:

- Review the specific edge documentation
- Check the overview for general concepts
- Examine the technical implementation in the Nebula codebase
- Analyze real environments using the provided queries

This documentation represents production-validated Azure privilege escalation analysis capabilities.