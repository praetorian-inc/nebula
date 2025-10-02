# Azure Graph API Reconnaissance Module Planning Document

## Executive Summary

This document outlines the design for Azure Entra ID reconnaissance and analysis modules using Microsoft Graph API. The system consists of three separate commands:
- **azcollect**: Collects Entra ID entities and stores them as nodes in Neo4j
- **azedge**: Creates all relationships (edges) between nodes
- **azpaths**: Analyzes the graph for privilege escalation paths

## Key Design Decisions & Clarifications

### Authentication Strategy
- **Existing Azure Module**: Uses `azidentity.NewDefaultAzureCredential()`
- **Our Approach**: Leverage the same authentication with added refresh token support
- **Token Management**: Automatic refresh before expiry to maintain long-running collections

### Built-in vs Custom Roles
- **Built-in Roles**: Have well-known `roleTemplateId` values (e.g., Global Admin = `62e90394-69f5-4237-9190-012177145e10`)
- **Custom Roles**: Have `isBuiltIn = false` property
- **Storage**: Store both but flag custom roles for easier analysis

### Privileged Identity Management (PIM) Handling
- **Eligible Assignments**: Collected via `/roleManagement/directory/roleEligibilitySchedules`
- **Active Assignments**: Collected via `/roleManagement/directory/roleAssignmentSchedules`
- **Graph Representation**: Different edge types: `AZHasRole` (permanent) vs `AZEligibleForRole` (PIM)

### Concurrency Recommendation
- **Worker Pools** over raw goroutines for:
  - Better rate limit control
  - Easier debugging and monitoring
  - Predictable resource usage
  - Circuit breaker implementation

### Batch API Strategy
- **Microsoft Graph Batch**: Supports up to 20 requests per batch
- **Implementation**: Engineers handle batching directly using Graph SDK
- **Flexibility**: Each collector can optimize batching for its specific needs

### Change Tracking Capabilities
- **Azure AD Audit Logs**: Historical changes via `/auditLogs/directoryAudits`
- **Delta Query**: Track changes since last sync using `$deltatoken`
- **Future Enhancement**: Real-time via webhooks/Event Grid (not in initial scope)

## 1. Azure Entity Types and Relationships

### Core Identity Entities

#### Users
- **Properties**: UPN, DisplayName, Mail, Department, JobTitle, Manager, CreatedDateTime
- **Relationships**: MemberOf (groups), Owns (applications/service principals), AssignedRoles
- **Graph API Endpoint**: `/users`

#### Groups
- **Properties**: DisplayName, Description, SecurityEnabled, MailEnabled, GroupTypes
- **Relationships**: Members, Owners, MemberOf (nested groups)
- **Graph API Endpoint**: `/groups`

#### Service Principals
- **Properties**: AppId, DisplayName, ServicePrincipalType, AppOwnerOrganizationId
- **Relationships**: Owners, AppRoleAssignments, OAuth2PermissionGrants
- **Graph API Endpoint**: `/servicePrincipals`

#### Applications (App Registrations)
- **Properties**: AppId, DisplayName, SignInAudience, RequiredResourceAccess
- **Relationships**: Owners, API Permissions, Certificates/Secrets
- **Graph API Endpoint**: `/applications`

#### Devices
- **Properties**: DisplayName, OperatingSystem, TrustType, IsCompliant, IsManaged
- **Relationships**: RegisteredOwners, RegisteredUsers
- **Graph API Endpoint**: `/devices`

### Administrative Entities

#### Directory Roles
- **Properties**: DisplayName, Description, RoleTemplateId
- **Relationships**: Members, ScopedMembers
- **Graph API Endpoint**: `/directoryRoles`

#### Role Assignments
- **Properties**: PrincipalId, RoleDefinitionId, Scope
- **Relationships**: Principal (user/group/SP), RoleDefinition
- **Graph API Endpoint**: `/roleManagement/directory/roleAssignments`

#### Administrative Units
- **Properties**: DisplayName, Description, Visibility
- **Relationships**: Members, ScopedRoleMembers
- **Graph API Endpoint**: `/administrativeUnits`

### Permission Entities

#### OAuth2 Permission Grants
- **Properties**: ClientId, ConsentType, PrincipalId, ResourceId, Scope
- **Relationships**: Client (service principal), Principal (user who consented), Resource (service principal)
- **Graph API Endpoint**: `/oauth2PermissionGrants`
- **Importance**: Tracks delegated permissions granted to applications

#### App Role Assignments
- **Properties**: AppRoleId, PrincipalId, PrincipalType, ResourceId
- **Relationships**: Principal (user/group/SP), Resource (service principal)
- **Graph API Endpoint**: `/servicePrincipals/{id}/appRoleAssignedTo`
- **Importance**: Tracks application permissions assigned to principals

### Future Scope (Not in Initial Implementation)

#### Azure Resource Management
- Subscriptions, Resource Groups, Management Groups
- ARM API integration for resource-level permissions
- Can be added as separate collectors in future phases

#### Conditional Access Policies
- Removed from initial scope
- Don't directly represent privilege escalation paths
- Can be added later as properties or separate analysis

## 2. Critical Attack Paths to Detect

Based on BloodHound's Azure edges research, the following privilege escalation paths must be detected:

### Primary Privilege Escalation Paths

1. **AZAddSecret** - Adding secrets to Service Principals/Applications
   - Required Roles: Cloud Application Administrator, Application Administrator
   - Abuse: Authenticate as the target service principal

2. **AZAddOwner** - Adding owners to Applications/Service Principals
   - Required Roles: Hybrid Identity Administrator, Partner Tier Support
   - Abuse: Gain full control over the target application

3. **AZAddMember** - Adding members to groups
   - Required Roles: Groups Administrator, User Administrator
   - Abuse: Inherit group permissions and roles

4. **AZResetPassword** - Reset user passwords
   - Required Roles: Password Administrator, Helpdesk Administrator
   - Abuse: Take over user accounts

5. **AZGrantRole** - Grant directory roles
   - Required Roles: Privileged Role Administrator
   - Abuse: Elevate privileges by granting admin roles

### MS Graph Specific Paths

6. **AZMGAddSecret** - Add secrets via MS Graph permissions
   - Required: Service Principal with Application.ReadWrite.All
   - Abuse: More stealthy than role-based secret addition

7. **AZMGAddMember** - Add members via MS Graph
   - Required: Directory.ReadWrite.All, Group.ReadWrite.All
   - Abuse: Hidden from Azure portal audit

8. **AZMGAddOwner** - Add owners via MS Graph
   - Required: Application.ReadWrite.All
   - Abuse: Not visible in standard permission audits

9. **AZMGGrantAppRoles** - Grant app roles via MS Graph
   - Required: RoleManagement.ReadWrite.Directory
   - Abuse: Grant Global Admin equivalent permissions

10. **AZMGGrantRole** - Grant directory roles via MS Graph
    - Required: RoleManagement.ReadWrite.Directory
    - Abuse: Direct path to Global Administrator

### High-Privilege Role Edges

11. **AZGlobalAdmin** - Global Administrator role
    - Highest privilege in tenant
    - Full control over all resources

12. **AZPrivilegedRoleAdmin** - Can manage all role assignments
    - Can grant Global Admin to any principal
    - Critical privilege escalation path

13. **AZPrivilegedAuthAdmin** - Reset any user's authentication
    - Can reset passwords/MFA for Global Admins
    - Backdoor access to any account

### PIM-Specific Edges

14. **AZRoleApprover** - Can approve PIM role activations
    - Bypass just-in-time access controls
    - Enable unauthorized privilege escalation

## 3. Module Structure

```
nebula/
├── cmd/
│   └── azure/
│       ├── recon/
│       │   └── azcollect.go           # Entry point for collection
│       └── analysis/
│           ├── azedge.go               # Entry point for edge creation
│           └── azpaths.go              # Entry point for path finding
└── pkg/
    └── links/
        └── azure/
            └── graph/
                ├── collectors/
                │   ├── registry.go                    # Collector registration
                │   ├── az_user_collector.go           # User collection
                │   ├── az_group_collector.go          # Group collection
                │   ├── az_service_principal_collector.go  # SP collection
                │   ├── az_application_collector.go    # App registration collection
                │   ├── az_device_collector.go         # Device collection
                │   ├── az_role_collector.go           # Role collection
                │   ├── az_admin_unit_collector.go     # Administrative unit collection
                │   ├── az_oauth2_grant_collector.go   # OAuth2 permission grants
                │   ├── az_app_role_assignment_collector.go # App role assignments
                │   └── az_pim_collector.go            # PIM eligibility collection
                ├── client/
                │   └── az_auth_manager.go             # Authentication handling
                ├── models/
                │   ├── az_entities.go                 # Node structures
                │   ├── az_edges.go                    # Edge structures
                │   └── az_permissions.go              # Permission constants
                ├── storage/
                │   └── az_neo4j_writer.go             # Neo4j operations
                ├── edges/
                │   ├── az_relationship_builder.go     # Basic relationships
                │   ├── az_edge_detector_registry.go   # Edge detector registration
                │   └── detectors/
                │       ├── az_add_secret.go           # AZAddSecret detector
                │       ├── az_add_owner.go            # AZAddOwner detector
                │       ├── az_add_member.go           # AZAddMember detector
                │       ├── az_grant_role.go           # AZGrantRole detector
                │       ├── az_reset_password.go       # AZResetPassword detector
                │       ├── az_mg_add_member.go        # MS Graph AddMember detector
                │       ├── az_mg_add_owner.go         # MS Graph AddOwner detector
                │       ├── az_mg_add_secret.go        # MS Graph AddSecret detector
                │       ├── az_mg_grant_app_roles.go   # MS Graph GrantAppRoles detector
                │       ├── az_mg_grant_role.go        # MS Graph GrantRole detector
                │       ├── az_global_admin.go         # Global Admin detector
                │       ├── az_privileged_role_admin.go # Privileged Role Admin detector
                │       ├── az_privileged_auth_admin.go # Privileged Auth Admin detector
                │       └── az_role_approver.go        # PIM Role Approver detector
                └── paths/
                    ├── az_path_calculator.go          # Path finding algorithms
                    ├── az_target_identifier.go        # Identify high-value targets
                    ├── az_risk_scorer.go              # Risk scoring logic
                    └── az_result_formatter.go         # JSON output generation
```

## 4. Collection Module (`azcollect`)

### CLI Interface
```bash
nebula azure recon azcollect \
  --tenant-id <tenant> \
  --client-id <client> \
  --client-secret <secret> \
  --neo4j-uri neo4j://localhost:7687 \
  --neo4j-username neo4j \
  --neo4j-password password \
  --neo4j-database neo4j \
  --collectors all  # Default: all collectors
  --batch-size 20 \
  --workers 5 \
  --output-json results.json
```

### Collection Architecture

```
┌──────────────────────────────────────────────────┐
│                 AZCollectCommand                  │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │            AZAuthManager                    │  │
│  │  - Token acquisition & refresh              │  │
│  │  - Credential management                    │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │        AZCollectorRegistry                  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │AZUserColl│ │AZGroupCol│ │AZAppColl │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │AZSPColl  │ │AZRoleColl│ │AZPIMColl │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘   │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │         AZNeo4jWriter                       │  │
│  │  - Cypher query generation                  │  │
│  │  - Transaction management                   │  │
│  │  - Node creation only (no edges)            │  │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Collector Interface
```go
type AZCollector interface {
    Name() string
    Collect(ctx context.Context) error  // Direct Neo4j writes
    Priority() int  // Collection order
}
```

### Collector Implementation Pattern
```go
type AZUserCollector struct {
    graphClient *msgraphsdk.GraphServiceClient  // Direct SDK usage
    neo4jWriter *AZNeo4jWriter
}

func (c *AZUserCollector) Collect(ctx context.Context) error {
    // Engineers handle batching and pagination directly
    batch := graphsdk.NewBatchRequestContent()

    // Add requests to batch (up to 20)
    batch.AddBatchRequestStep(graphsdk.BatchRequestStep{
        Id:      "1",
        Request: c.graphClient.Users().Request(),
    })

    // Execute batch
    response, err := c.graphClient.Batch().Request().Post(ctx, batch)

    // Handle pagination with PageIterator
    pageIterator, err := graphcore.NewPageIterator(response, ...)
    pageIterator.Iterate(ctx, func(item interface{}) bool {
        user := item.(models.User)

        // Store ALL relationship data in node properties
        node := AZUserNode{
            ID:                user.GetId(),
            UPN:               user.GetUserPrincipalName(),
            MemberOfGroups:    extractGroupIds(user),      // Store group IDs
            AssignedRoles:     extractRoleIds(user),        // Store role IDs
            EligibleRoles:     extractEligibleRoles(user),  // Store PIM roles
            // Store all data needed for edge creation
        }

        c.neo4jWriter.CreateNode(ctx, node)
        return true // continue iteration
    })

    return nil
}
```

### Storage Strategy
- **Memory-based approach** (Selected):
  - In-memory deduplication maps
  - Direct streaming to Neo4j
  - Sufficient for medium tenants (10k-50k users)
  - Simple implementation, easy to debug

## 5. Analysis Modules (Two Separate Commands)

### Edge Creation Module (`azedge`)
```bash
# Creates derived attack path edges based on permissions
nebula azure analysis azedge \
  --neo4j-uri neo4j://localhost:7687 \
  --neo4j-username neo4j \
  --neo4j-password password \
  --neo4j-database neo4j \
  --detectors all  # Default: all detectors
  --include-relationships  # Option to also create basic relationships
```

### Path Finding Module (`azpaths`)
```bash
# Queries for privilege escalation paths
nebula azure analysis azpaths \
  --neo4j-uri neo4j://localhost:7687 \
  --neo4j-username neo4j \
  --neo4j-password password \
  --neo4j-database neo4j \
  --max-depth 5 \
  --output-json paths.json

# Automatically finds all paths to high-privilege roles:
# Global Administrator, Privileged Role Administrator,
# Privileged Authentication Administrator, etc.
```

### Edge Creation Architecture (`azedge`)

```
┌──────────────────────────────────────────────────┐
│                AZEdgeCommand                      │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │         AZNeo4jReader                       │  │
│  │  - Query execution                          │  │
│  │  - Result parsing                           │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │       AZEdgeDetectorRegistry                │  │
│  │  ┌────────────┐ ┌────────────┐             │  │
│  │  │AZAddSecret │ │AZAddOwner  │             │  │
│  │  └────────────┘ └────────────┘             │  │
│  │  ┌────────────┐ ┌────────────┐             │  │
│  │  │AZAddMember │ │AZGrantRole │             │  │
│  │  └────────────┘ └────────────┘             │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │       AZRelationshipBuilder                  │  │
│  │  - Creates basic relationships from data     │  │
│  │  - AZMemberOf, AZHasRole, AZOwns            │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │         AZNeo4jWriter                       │  │
│  │  - Edge creation via Cypher                 │  │
│  │  - Batch processing for performance         │  │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Path Finding Architecture (`azpaths`)

```
┌──────────────────────────────────────────────────┐
│                AZPathsCommand                     │
├──────────────────────────────────────────────────┤
│                                                   │
│  ┌────────────────────────────────────────────┐  │
│  │         AZNeo4jReader                       │  │
│  │  - Query execution                          │  │
│  │  - Result parsing                           │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │         AZPathCalculator                    │  │
│  │  - Find paths to admin roles                │  │
│  │  - Shortest path algorithms                 │  │
│  │  - Attack chain identification              │  │
│  │  - Risk scoring                             │  │
│  └──────────────┬─────────────────────────────┘  │
│                  │                                │
│  ┌───────────────▼────────────────────────────┐  │
│  │         AZResultFormatter                   │  │
│  │  - JSON output generation                   │  │
│  │  - Path visualization                       │  │
│  │  - Risk summary                             │  │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Edge Detection Queries
```cypher
// Example: Detect AZAddSecret edges
MATCH (principal:AZServicePrincipal|AZUser|AZGroup)
WHERE principal.roles CONTAINS 'Cloud Application Administrator'
   OR principal.roles CONTAINS 'Application Administrator'
MATCH (target:AZApplication|AZServicePrincipal)
CREATE (principal)-[:AZAddSecret]->(target)
```

## 6. Neo4j Schema

### Node Types
```cypher
// Users
(:AZUser {
  id: string,           // Object ID
  userPrincipalName: string,
  displayName: string,
  mail: string,
  accountEnabled: boolean,
  userType: string,     // Member or Guest
  isBuiltIn: false,     // Always false for users
  invitedFrom: string,  // For B2B guests
  // Relationship data for edge creation
  memberOfGroups: string[],    // Group IDs this user belongs to
  assignedRoles: string[],     // Role IDs assigned directly
  eligibleRoles: string[],     // PIM eligible role IDs
  ownedApplications: string[], // App IDs this user owns
  // Permission arrays stored as JSON
  appRoleAssignments: json,    // Detailed app permissions
  oauth2PermissionGrants: json // Delegated permissions
})

// Groups
(:AZGroup {
  id: string,
  displayName: string,
  securityEnabled: boolean,
  mailEnabled: boolean,
  groupTypes: string[], // Unified, DynamicMembership
  isBuiltIn: boolean,   // True for default groups
  assignedRoles: string[],  // Roles assigned to this group
  owners: string[]         // User/SP IDs that own this group
})

// Service Principals
(:AZServicePrincipal {
  id: string,
  appId: string,
  displayName: string,
  servicePrincipalType: string, // Application, ManagedIdentity, Legacy
  isBuiltIn: boolean,
  // MS Graph permissions
  appRoles: string[],          // e.g., ["Directory.ReadWrite.All", "User.Read.All"]
  oauth2PermissionScopes: json, // Delegated permissions
  assignedRoles: string[],      // Directory roles
  owners: string[]              // User/SP IDs that own this SP
})

// Applications (App Registrations)
(:AZApplication {
  id: string,
  appId: string,
  displayName: string,
  signInAudience: string,
  isBuiltIn: boolean,
  requiredResourceAccess: json,  // API permissions configured
  appRoles: json,                // Application roles defined
  owners: string[],              // User/SP IDs that own this app
  passwordCredentials: integer,  // Count of passwords
  keyCredentials: integer        // Count of certificates
})

// Devices
(:AZDevice {
  id: string,
  displayName: string,
  accountEnabled: boolean,
  operatingSystem: string,
  operatingSystemVersion: string,
  trustType: string,     // AzureAd, ServerAd, Workplace
  isCompliant: boolean,
  isManaged: boolean,
  memberOfGroups: string[],      // Group memberships
  registeredOwners: string[],    // Owner user IDs
  registeredUsers: string[]      // Registered user IDs
})

// Directory Roles
(:AZRole {
  id: string,
  displayName: string,
  description: string,
  roleTemplateId: string, // For built-in roles
  isBuiltIn: boolean,
  permissions: string[]   // List of actions this role can perform
})

// Administrative Units
(:AZAdministrativeUnit {
  id: string,
  displayName: string,
  description: string,
  visibility: string,    // Public or HiddenMembership
  members: string[],     // Member IDs
  scopedRoleMembers: json  // Scoped role assignments
})

// OAuth2 Permission Grants (Delegated Permissions)
(:AZOAuth2PermissionGrant {
  id: string,
  clientId: string,      // Service principal that was granted consent
  consentType: string,   // AllPrincipals or Principal
  principalId: string,   // User who granted consent (if Principal)
  resourceId: string,    // Resource service principal
  scope: string          // Space-separated list of permissions
})

// App Role Assignments
(:AZAppRoleAssignment {
  id: string,
  appRoleId: string,     // The app role being assigned
  principalId: string,   // User/Group/SP receiving the role
  principalType: string, // User, Group, or ServicePrincipal
  resourceId: string     // The resource SP
})

// Tenants
(:AZTenant {
  id: string,
  displayName: string,
  verifiedDomains: string[],
  tenantType: string     // AAD, B2C, B2B
})
```

### Edge Types
```cypher
// Basic relationships (from API data stored in nodes)
(:AZUser)-[:AZMemberOf]->(:AZGroup)
(:AZGroup)-[:AZMemberOf]->(:AZGroup)  // Nested groups
(:AZUser|AZGroup|AZServicePrincipal)-[:AZHasRole]->(:AZRole)  // Permanent assignments
(:AZUser|AZGroup|AZServicePrincipal)-[:AZEligibleForRole]->(:AZRole)  // PIM eligible
(:AZUser|AZGroup|AZServicePrincipal)-[:AZOwns]->(:AZApplication|AZServicePrincipal)

// Derived attack path edges (from permission analysis)
// Primary privilege escalation paths
(:AZUser|AZGroup|AZServicePrincipal)-[:AZAddSecret]->(:AZApplication|AZServicePrincipal)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZAddOwner]->(:AZApplication|AZServicePrincipal)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZAddMember]->(:AZGroup)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZResetPassword]->(:AZUser)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZGrantRole]->(:AZRole)

// MS Graph specific privilege paths
(:AZServicePrincipal)-[:AZMGAddMember]->(:AZGroup)
(:AZServicePrincipal)-[:AZMGAddOwner]->(:AZApplication|AZServicePrincipal)
(:AZServicePrincipal)-[:AZMGAddSecret]->(:AZApplication|AZServicePrincipal)
(:AZServicePrincipal)-[:AZMGGrantAppRoles]->(:AZServicePrincipal)
(:AZServicePrincipal)-[:AZMGGrantRole]->(:AZRole)

// High-privilege role edges
(:AZUser|AZGroup|AZServicePrincipal)-[:AZGlobalAdmin]->(:AZTenant)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZPrivilegedRoleAdmin]->(:AZTenant)
(:AZUser|AZGroup|AZServicePrincipal)-[:AZPrivilegedAuthAdmin]->(:AZTenant)

// PIM-specific edges
(:AZUser|AZGroup|AZServicePrincipal)-[:AZRoleApprover]->(:AZRole)
```

## 7. Implementation Priorities

### Phase 1: Foundation (Week 1)
- [ ] AZAuthManager with refresh token support
- [ ] Neo4j writer for nodes
- [ ] CLI structure for collection module
- [ ] Direct Graph SDK integration in collectors

### Phase 2: Core Collectors (Week 2)
- [ ] AZUserCollector
- [ ] AZGroupCollector with membership
- [ ] AZRoleCollector (built-in vs custom)
- [ ] Collector registry pattern

### Phase 3: Advanced Collectors (Week 3)
- [ ] AZServicePrincipalCollector
- [ ] AZApplicationCollector
- [ ] AZDeviceCollector
- [ ] AZAdministrativeUnitCollector
- [ ] AZPIMCollector for eligible roles
- [ ] AZOAuth2GrantCollector for permission grants
- [ ] AZAppRoleAssignmentCollector for app role assignments

### Phase 4: Analysis Engine (Week 4)
- [ ] Edge detectors for main attack paths
- [ ] Path calculator using Neo4j queries
- [ ] JSON output formatter

## 8. Future Extensibility

### Azure Resources (Future)
- Design allows adding resource collectors later
- Separate `azresources` subcommand possible
- Node types: `AZVirtualMachine`, `AZStorageAccount`, etc.

### Streaming/Change Detection (Future)
- Delta query support for incremental updates
- Webhook integration for real-time changes
- Audit log processor for historical analysis

## 9. Key Technical Decisions

### Why Worker Pools?
- **Predictable resource usage**: Fixed number of workers
- **Better debugging**: Can track which worker processes what
- **Rate limit coordination**: Centralized through pool manager
- **Circuit breaker**: Easier to implement at pool level

### Why Separate Collection and Analysis?
- **Flexibility**: Can re-analyze without re-collecting
- **Performance**: Analysis queries optimized for Neo4j
- **Modularity**: Different teams can work on each module
- **Reusability**: Analysis works on any Neo4j with correct schema

### Why Batch API?
- **Rate limits**: 20 requests in one call vs 20 separate calls
- **Performance**: Significant reduction in round trips
- **Atomicity**: Batch succeeds or fails together

## 10. Technical Concerns and Considerations

### Neo4j Integration
- **Connection flags**: `--neo4j-uri`, `--neo4j-username`, `--neo4j-password`
- **Batch writes**: Use UNWIND for bulk inserts
- **Transaction management**: Group related writes in transactions
- **Index creation**: On `id` fields for all node types

### Authentication Handling
- **Leverage existing**: Azure module uses `azidentity.NewDefaultAzureCredential()`
- **Add refresh token**: Extend with refresh token support for long-running collections
- **Multiple methods**: Support CLI credentials, service principal, managed identity

### PIM (Privileged Identity Management)
- **Eligible vs Active**: Different API endpoints and edge types
- **Time-bound access**: Store activation requirements as properties
- **Just-in-time**: Track which roles require activation

### Built-in vs Custom Roles
- **Detection**: `isBuiltIn` property or check `roleTemplateId`
- **Well-known IDs**: Map common built-in roles (Global Admin, etc.)
- **Custom flagging**: Mark custom roles for security review

## 11. Design Clarifications

### Edge Creation Strategy

#### How azedge Builds Relationships
1. **Reads node properties**: Queries Neo4j for all nodes and their stored relationship data
2. **Creates basic edges**: Uses stored IDs (memberOfGroups, assignedRoles, etc.) to create edges
3. **Analyzes permissions**: Reads permission arrays to determine attack paths
4. **Creates derived edges**: Based on permission analysis

Example:
```cypher
// azedge reads nodes with relationship data
MATCH (u:AZUser)
WHERE u.memberOfGroups IS NOT NULL
UNWIND u.memberOfGroups AS groupId
MATCH (g:AZGroup {id: groupId})
MERGE (u)-[:AZMemberOf]->(g)
```

#### Preventing Edge Duplication

**How MERGE works**:
- MERGE matches on the entire pattern (nodes + relationship type)
- If exact pattern exists, it matches; otherwise creates
- Edge properties are NOT considered for matching

**Safe approach without timestamps**:
```cypher
// Simple MERGE without time properties
MERGE (u:AZUser {id: $userId})-[r:AZMemberOf]->(g:AZGroup {id: $groupId})
// No properties on edges to avoid duplicates
```

**If edge properties needed**:
```cypher
// Use static properties only
MERGE (u:AZUser {id: $userId})-[r:AZMemberOf]->(g:AZGroup {id: $groupId})
SET r.source = 'GraphAPI'  // Static properties only
```

### B2B Guest Users
- **What they are**: External users invited to access resources in your tenant
- **Security concern**: May have permissions but less visibility/governance

**Collection approach** - Guest users store same data as members:
```cypher
(:AZUser {
  userType: "Guest",
  invitedFrom: string,
  memberOfGroups: string[],    // Yes, stored
  assignedRoles: string[],     // Yes, stored
  eligibleRoles: string[],     // Yes, stored if they have PIM
  ownedApplications: string[]  // Yes, if they own apps
})
```

**Edge creation** - B2B guests get all standard edges:
- `AZMemberOf` - Groups they belong to
- `AZHasRole` - Direct role assignments
- `AZEligibleForRole` - PIM eligible roles
- All derived attack paths based on permissions

This enables full privilege escalation analysis for guest users.

### Conditional Access Policies
**Status**: Removed from initial scope
**Reason**: Don't directly represent privilege escalation paths
**Future Enhancement**: Can be added later as properties or separate analysis

### PIM Activation History
- **Current design**: Collects eligible roles (what users CAN activate)
- **Activation history**: Shows what users DID activate (audit trail)
- **Recommendation**: Not needed for initial privilege escalation analysis
  - Eligible roles already show potential access
  - Add activation history as future enhancement for forensics

### Performance Baselines
- **Small tenant**: < 1,000 users (development/testing)
- **Medium tenant**: 10,000 - 50,000 users (typical enterprise)
- **Large tenant**: 100,000+ users (Fortune 500)
- **Initial target**: Optimize for medium tenants

### Neo4j Indexing Strategy
- **Primary indexes** (for lookup performance):
  ```cypher
  CREATE INDEX ON :AZUser(id);
  CREATE INDEX ON :AZUser(userPrincipalName);
  CREATE INDEX ON :AZGroup(id);
  CREATE INDEX ON :AZServicePrincipal(id);
  CREATE INDEX ON :AZApplication(appId);
  CREATE INDEX ON :AZRole(roleTemplateId);
  ```
- **Composite indexes** (if needed later):
  ```cypher
  CREATE INDEX ON :AZUser(userType, accountEnabled);
  ```

## 12. Required Graph API Permissions

### Minimum Required Permissions (Read-Only)

For security audit purposes, these read-only permissions are sufficient:

#### Microsoft Graph API Permissions
```
User.Read.All                    - Read all users' profiles
Group.Read.All                   - Read all groups
Application.Read.All             - Read all applications
Directory.Read.All               - Read directory data (covers most needs)
RoleManagement.Read.Directory    - Read directory roles and assignments
AuditLog.Read.All               - Read audit logs (optional, for history)
Policy.Read.All                  - Read conditional access policies
PrivilegedAccess.Read.AzureAD   - Read PIM eligible roles
```

#### Permission Assignment Methods
1. **Application Permissions** (Recommended for automation):
   - Register an app in Azure AD
   - Grant permissions above as "Application" type
   - Use client credentials flow

2. **Delegated Permissions** (For interactive use):
   - User must have appropriate directory roles
   - Minimum role: Global Reader or Security Reader

#### Sample App Registration
```bash
# Using Azure CLI to create app with required permissions
az ad app create --display-name "Nebula-GraphRecon" \
  --required-resource-accesses @permissions.json

# permissions.json structure:
{
  "resourceAppId": "00000003-0000-0000-c000-000000000000", # Microsoft Graph
  "resourceAccess": [
    {
      "id": "df021288-bdef-4463-88db-98f22de89214", # User.Read.All
      "type": "Role"
    },
    {
      "id": "5b567255-7703-4780-807c-7be8301ae99b", # Group.Read.All
      "type": "Role"
    }
    # ... other permissions
  ]
}
```

#### Security Notes
- **No write permissions required** - This is a read-only reconnaissance tool
- **Principle of least privilege** - Only request what's needed
- **Use Directory.Read.All** - Covers most entity reads with single permission
- **Audit trail** - All API calls are logged in Azure AD audit logs

## 13. References and Resources

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [AzureHound Repository](https://github.com/SpecterOps/AzureHound)
- [BloodHound Azure Edges Documentation](https://bloodhound.specterops.io/resources/edges/overview)
- [Microsoft Graph SDK for Go](https://github.com/microsoftgraph/msgraph-sdk-go)
- [Azure AD Security Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-deployment-checklist-p2)

---

*This updated design focuses on Entra ID reconnaissance with clear separation between collection and analysis, direct Neo4j integration, and extensible architecture for future Azure resource support.*