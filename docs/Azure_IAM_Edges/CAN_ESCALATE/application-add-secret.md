# Application Add Secret Escalation

**Method:** `ApplicationAddSecret`
**Category:** Application Ownership Escalation

## Overview

Owner of an Application can add secrets to the corresponding Service Principal, enabling identity assumption through the application object.

## Escalation Path

```
Owner → [OWNS] → Application
      → [CONTAINS] → Service Principal
      → [CAN_ESCALATE: ApplicationAddSecret] → Service Principal
      → Add secret to app → Credential propagates to SP → Authenticate as SP
```

## Edge Creation Logic

**Source:** Any principal with OWNS edge to Application

**Target:** Service Principal linked to owned Application via CONTAINS edge

**Relationship Chain:**
```cypher
(owner)-[:OWNS]->(app)-[:CONTAINS]->(sp)
→ Creates: (owner)-[:CAN_ESCALATE]->(sp)
```

**Condition:** "Application owner can add secrets to corresponding service principal"

## Attack Scenario

1. **Attacker compromises** user account that owns an application
2. **Attacker identifies** the application's service principal:
   ```powershell
   Get-AzureADApplication -Filter "displayName eq 'My App'"
   Get-AzureADServicePrincipal -Filter "appId eq '<app-client-id>'"
   ```
3. **Attacker adds** secret to **Application** (not SP directly):
   ```powershell
   New-AzureADApplicationPassword -ObjectId <app-object-id>
   ```
4. **Secret automatically available** to Service Principal
5. **Attacker authenticates** as SP using app credentials
6. **Attacker inherits** SP's permissions

## Microsoft Graph API Call

**Add Secret to Application:**
```http
POST https://graph.microsoft.com/v1.0/applications/{app-id}/addPassword
Content-Type: application/json

{
  "passwordCredential": {
    "displayName": "App Admin Key"
  }
}
```

**The secret works for SP authentication:**
```bash
curl -X POST https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token \
  -d "client_id={app-client-id}" \
  -d "client_secret={new-secret}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials"
```

## Edge Properties

```cypher
{
  method: "ApplicationAddSecret",
  category: "ApplicationOwnership",
  condition: "Application owner can add secrets to corresponding service principal"
}
```

## Detection Query

```cypher
// Find app owners who can escalate to privileged SPs
MATCH (owner:Resource)-[esc:CAN_ESCALATE]->(sp:Resource)
WHERE esc.method = "ApplicationAddSecret"
  AND EXISTS {
    MATCH (sp)-[p:HAS_PERMISSION]->(:Resource)
    WHERE toLower(p.roleName) CONTAINS "administrator"
  }
WITH owner, sp,
     [(owner)-[:OWNS]->(app:Resource)-[:CONTAINS]->(sp) | app.displayName][0] as app_name
RETURN owner.displayName as app_owner,
       app_name,
       sp.displayName as sp_name,
       sp.appId as client_id,
       collect(DISTINCT p.roleName)[0..3] as sp_roles
ORDER BY owner.displayName
```

## Application vs Service Principal Relationship

**Understanding the Objects:**
```
Application (App Registration)
  ├─ Lives in home tenant
  ├─ Definition/template of the app
  ├─ Can have credentials
  └─ CONTAINS relationship to...

Service Principal (Enterprise App)
  ├─ Lives in each tenant where app is installed
  ├─ Instance of the application
  ├─ Has permissions/role assignments
  └─ Uses credentials from Application
```

**Ownership Implications:**
- **Own Application** → Can add credentials → Affects SP
- **Own Service Principal** → Can add credentials → Direct to SP
- **Own Application** = More indirect but same result

## Why Application Ownership Is Dangerous

**Dual Control:**
- Application owners control the SP
- But may not be obvious from SP ownership audit
- Hidden escalation path

**Credential Inheritance:**
- Secrets added to App work for SP
- Certificates added to App work for SP
- Reply URLs on App affect SP OAuth flow

**Scope:**
- Application can have SPs in multiple tenants
- Owner in home tenant → Controls SPs in all tenants
- Cross-tenant privilege escalation

## Application Owner Capabilities

**Via Application:**
- Add client secrets → Works for SP
- Add certificates → Works for SP
- Modify reply URLs → OAuth flow manipulation
- Add owners → Grant app ownership
- Delete application → Cascades to SP deletion

**Resulting SP Access:**
- All SP permissions
- All SP role assignments
- All SP data access

## High-Value Owned Applications

**Target Applications:**
1. **Multi-Tenant Apps** - Credentials work across tenants
2. **Legacy Apps** - Rarely audited
3. **Automation Apps** - High privileges
4. **SaaS Connectors** - Supply chain vector
5. **DevOps Apps** - Pipeline access

## Mitigation

- **Ownership Audit:**
  - Review application ownership quarterly
  - Cross-reference with SP permissions
  - Remove unnecessary app owners
- **Application Protection:**
  - Limit ownership of apps with privileged SPs
  - Require approval for ownership changes
  - Separate development apps from production
- **Monitoring:**
  - Alert on credential additions to applications
  - Monitor `Add application credentials` activity
  - Link app credential activity to SP privilege
- **Access Review:**
  - Review app owners in context of SP permissions
  - App ownership = SP privilege escalation path
  - Audit app→SP CONTAINS relationships

## Application vs SP Credential Addition

| Target Object | API Endpoint | Effect on SP |
|---------------|-------------|--------------|
| Application | `/applications/{id}/addPassword` | ✅ SP can use credential |
| Service Principal | `/servicePrincipals/{id}/addPassword` | ✅ Direct SP credential |

**Both work for SP authentication!**

## Hidden Escalation Path

**Why this is often missed:**
```
Security Team: "Who owns the Global Admin SP?"
Audit Tool: "No direct owners"
✓ Approved

Reality:
- Application has 3 owners
- Application CONTAINS Service Principal
- Application owners can add secrets
- Missed escalation path!
```

**Lesson:** Audit application ownership, not just SP ownership

## Real-World Example

```
2024: Cloud Security Incident
- Developer owned application
- Application had SP with RoleManagement.ReadWrite.Directory
- Developer's account compromised
- Attacker added secret to application (not SP)
- Used secret to authenticate as SP
- Assigned Global Administrator to attacker account
- Tenant compromise
```

## Related Documentation

- [Service Principal Add Secret](service-principal-add-secret.md) - Direct SP ownership
- [Application Administrator](application-administrator.md) - Via directory role
- [Application.ReadWrite.All](application-readwrite-all.md) - Via Graph permission
- [../OWNS/application-ownership.md](../OWNS/application-ownership.md) - Application ownership edge
- [../CONTAINS/application-to-sp.md](../CONTAINS/application-to-sp.md) - App→SP relationship
- [../../Azure_IAM_Nodes/application.md](../../Azure_IAM_Nodes/application.md) - Application node structure

## Implementation

**File:** `pkg/links/azure/iam/neo4j_importer.go`
**Function:** `getValidatedAppOwnerAddSecretQuery()` - line 4378
**Phase:** Phase 4 (CAN_ESCALATE edge creation)
**Edge Creation:** Traverses OWNS→Application→CONTAINS→SP relationships
