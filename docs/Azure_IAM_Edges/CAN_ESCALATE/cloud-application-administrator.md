# Cloud Application Administrator Escalation

**Method:** `CloudApplicationAdmin`
**Category:** Directory Role Escalation

## Overview

Cloud Application Administrator can add credentials to applications and service principals (except Application Proxy apps), enabling identity assumption similar to Application Administrator.

## Escalation Path

```
User → [HAS_PERMISSION: Cloud Application Administrator] → Tenant
     → [CAN_ESCALATE: CloudApplicationAdmin] → Applications & SPs (non-Proxy)
     → Assume SP identity → Inherit SP permissions
```

## Edge Creation Logic

**Source:** User with HAS_PERMISSION edge where:
- `roleName = "Cloud Application Administrator"` OR
- `templateId = "158c047a-c907-4556-b7ef-446551a6b5f7"`

**Target:** Applications and service principals:
- `microsoft.directoryservices/applications`
- `microsoft.directoryservices/serviceprincipals`
- **Note:** Current implementation doesn't filter Application Proxy apps

**Condition:** "Cloud Application Administrator can add credentials to applications and service principals"

## Attack Scenario

Same as Application Administrator:

1. **Attacker compromises** user with Cloud Application Administrator role
2. **Attacker enumerates** service principals with high privileges
3. **Attacker adds** secret/certificate to target SP
4. **Attacker authenticates** as SP
5. **Attacker inherits** SP's permissions

## Difference from Application Administrator

**Cloud Application Administrator:**
- ✅ Manage cloud apps (SaaS, custom)
- ✅ Add credentials to SPs
- ❌ Cannot manage Application Proxy apps
- ❌ Cannot manage app registrations with secrets

**Application Administrator:**
- ✅ Everything Cloud Application Administrator can do
- ✅ Plus: Manage Application Proxy apps
- ✅ Plus: Full app registration management

**In Practice:** Both roles allow credential addition for escalation.

## Edge Properties

```cypher
{
  method: "CloudApplicationAdmin",
  category: "DirectoryRole",
  condition: "Cloud Application Administrator can add credentials to applications and service principals",
  sourcePermission: <HAS_PERMISSION.source>,
  viaGroup: <if inherited via group>,
  grantedByGroups: <array of granting groups>,
  targetRole: <role name or permission>
}
```

## Detection Query

```cypher
MATCH (admin:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "CloudApplicationAdmin"
RETURN admin.displayName as cloud_app_admin,
       count(sp) as manageable_sps
ORDER BY manageable_sps DESC
```

## Mitigation

Same as Application Administrator:
- PIM activation with approval
- Monitor credential additions
- Protect high-privilege service principals
- Audit role assignments

## Related Documentation

- [Application Administrator](application-administrator.md) - Broader permissions
- [Service Principal Add Secret](service-principal-add-secret.md) - Ownership-based credential addition
- [../../Azure_IAM_Nodes/application.md](../../Azure_IAM_Nodes/application.md) - Application node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedCloudApplicationAdminQuery()` - line 4042
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
