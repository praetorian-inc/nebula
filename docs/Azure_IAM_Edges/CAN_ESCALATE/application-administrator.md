# Application Administrator Escalation

**Method:** `ApplicationAdmin`
**Category:** Directory Role Escalation

## Overview

Application Administrator can add credentials to applications and service principals, enabling identity assumption and permission inheritance.

## Escalation Path

```
User → [HAS_PERMISSION: Application Administrator] → Tenant
     → [CAN_ESCALATE: ApplicationAdmin] → All Applications & Service Principals
     → Assume SP identity → Inherit SP permissions
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Application Administrator"` OR
- `templateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"`

**Target:** All applications and service principals:
- `microsoft.directoryservices/applications`
- `microsoft.directoryservices/serviceprincipals`

**Condition:** "Application Administrator can add credentials to applications/service principals to assume their identity and inherit permissions"

## Attack Scenario

1. **Attacker compromises** user with Application Administrator role
2. **Attacker enumerates** service principals with high privileges (e.g., Global Admin SP)
3. **Attacker adds** secret/certificate to target SP
4. **Attacker authenticates** as SP using new credentials
5. **Attacker inherits** SP's permissions (potentially Global Administrator)

## Edge Properties

```cypher
{
  method: "ApplicationAdmin",
  category: "DirectoryRole",
  condition: "Application Administrator can add credentials to applications/service principals to assume their identity and inherit permissions",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
// Find Application Admins who can escalate to privileged SPs
MATCH (admin:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "ApplicationAdmin"
  AND EXISTS {
    MATCH (sp)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
  }
RETURN admin.displayName as attacker,
       sp.displayName as privileged_sp,
       collect(DISTINCT sp.appId) as app_ids
```

## Real-World Impact

**High-Value Targets:**
- Service principals with Global Administrator role
- SPs with RoleManagement.ReadWrite.Directory permission
- SPs with high Azure RBAC roles (Owner on subscriptions)

**Credential Addition Methods:**
- Client secrets (via Azure Portal or Graph API)
- Certificates (via PowerShell or API)

## Mitigation

- **PIM:** Require activation for Application Administrator role
- **Monitoring:** Alert on credential additions to sensitive SPs
- **Service Principal Protection:** Enable "Restrict non-admin users from creating service principals"
- **App-Level Protection:** Mark critical apps as protected
- **Audit:** Review Application Administrator assignments quarterly

## Related Documentation

- [Cloud Application Administrator](cloud-application-administrator.md) - Similar but excludes Application Proxy
- [Service Principal Owner Add Secret](service-principal-add-secret.md) - Ownership-based escalation
- [../../Azure_IAM_Nodes/service-principal.md](../../Azure_IAM_Nodes/service-principal.md) - SP node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedApplicationAdminQuery()` - line 4021
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
