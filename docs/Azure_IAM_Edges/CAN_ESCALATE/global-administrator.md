# Global Administrator - CAN_ESCALATE Escalation

**Edge Type:** `CAN_ESCALATE`
**Method:** `GlobalAdministrator`
**Category:** `DirectoryRole`
**From:** User or Service Principal with Global Administrator role
**To:** Any resource in the tenant

---

## Overview

Global Administrator role provides complete control over the Entra ID tenant and can elevate to Owner on any Azure subscription. Principals with this role can escalate to compromise any resource in the entire tenant.

---

## Escalation Condition

Global Administrator role provides complete tenant control and can elevate to Owner on any Azure subscription.

---

## Detection Queries

### Find Global Administrator Escalation Paths

```cypher
MATCH (user:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GlobalAdministrator"
  AND r.category = "DirectoryRole"
RETURN user.displayName, target.displayName, r.condition
ORDER BY user.displayName
```

**Expected Results:**
- Shows which principals have Global Administrator role
- Shows all resources they can escalate to (entire tenant)

### Find Global Administrators with High Escalation Scope

```cypher
MATCH (user:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "GlobalAdministrator"
WITH user, count(DISTINCT target) as escalation_targets
ORDER BY escalation_targets DESC
RETURN user.displayName,
       user.resourceType,
       escalation_targets
```

**Expected:** Typically thousands of targets per Global Admin (entire tenant scope)

---

## Escalation Logic (Internal Implementation)

**Phase 5 CAN_ESCALATE edge creation** (neo4j_importer.go:~4012):

```cypher
-- Find principals with Global Administrator HAS_PERMISSION
MATCH (user:Resource)-[perm:HAS_PERMISSION]->(tenant:Resource)
WHERE perm.roleName = "Global Administrator"
   OR perm.templateId = "62e90394-69f5-4237-9190-012177145e10"

-- Create CAN_ESCALATE edges to all tenant resources
WITH user
MATCH (escalate_target:Resource)
WHERE escalate_target <> user
CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "GlobalAdministrator",
    r.condition = "Global Administrator role provides complete tenant control and can elevate to Owner on any Azure subscription",
    r.category = "DirectoryRole"
```

**Cardinality:** 1 HAS_PERMISSION edge → N CAN_ESCALATE edges (N = all tenant resources)

---

## Attack Scenarios

### 1. Complete Tenant Takeover

Global Admin can modify any directory object, assign any role, access any resource:

**Attack Steps:**
1. Authenticate as Global Administrator
2. Assign additional admin roles for persistence
3. Access Microsoft 365 services (Exchange, SharePoint, Teams)
4. Modify security policies and conditional access

**Impact:** Complete compromise of tenant identity and access management

### 2. Azure Subscription Elevation

Global Admin can elevate to Owner role on any Azure subscription:

**Attack Steps:**
1. Use Global Admin to access Azure portal
2. Elevate access to become Owner of subscription
3. Access all Azure resources in subscription
4. Modify RBAC assignments for persistence

**Impact:** Full control over Azure infrastructure and data

### 3. Cross-Service Access

Global Admin provides access to all Microsoft 365 services:

**Services Accessible:**
- Exchange Online (all mailboxes)
- SharePoint Online (all sites)
- Teams (all conversations)
- OneDrive (all user files)
- Power Platform (all apps and data)

### 4. Identity Management Abuse

Global Admin can create, modify, or delete any user, group, or application:

**Attack Steps:**
1. Create backdoor admin accounts
2. Add attacker principals to privileged groups
3. Register malicious applications with dangerous permissions
4. Modify existing identities to gain access

### 5. Security Bypass

Global Admin can disable security features and modify policies:

**Attack Steps:**
1. Disable conditional access policies
2. Modify MFA requirements
3. Disable security defaults
4. Modify identity protection settings
5. Disable audit logging

---

## Mitigation Strategies

### 1. Minimize Global Admins

**Recommendation:** Limit to 2-5 Global Administrators maximum

**Rationale:** Each Global Admin is a critical compromise risk

### 2. Use Break-Glass Accounts

**Pattern:** Separate emergency access accounts with:
- Strong, rotated passwords stored in physical vault
- Excluded from conditional access policies
- Dedicated monitoring and alerting
- Regular verification of access

### 3. Enable PIM (Privileged Identity Management)

**Benefits:**
- Just-in-time access (activate when needed)
- Time-bound assignments (auto-expire)
- Approval workflows for activation
- Audit trail of privileged access

### 4. Monitor Global Admin Activity

**Alert On:**
- Any Global Administrator authentication
- Directory role assignments by Global Admins
- Security policy modifications
- Bulk operations (mass user creation, etc.)
- Subscription elevation activities

### 5. Protect Global Admin Owners

**If Global Admin is a Service Principal:**
- Secure application owners (they can add credentials)
- Use certificate auth (not client secrets)
- Restrict owner assignments
- Monitor owner changes

### 6. Multi-Admin Authorization

**Pattern:** Require 2+ Global Admins to approve critical changes:
- New Global Admin assignments
- Security policy changes
- Conditional access modifications
- Break-glass account access

---

## Prerequisites

- Principal must have Global Administrator directory role assignment
- Role must be active (not just eligible through PIM)
- Principal must be able to authenticate

---

## Related Escalations

- **Privileged Role Administrator** - Can assign Global Administrator role (legacy docs: directory-roles/)
- **Application Administrator** - Can potentially escalate to Global Admin via application manipulation (legacy docs: directory-roles/)
- **HAS_PERMISSION Data:** [HAS_PERMISSION/global-administrator.md](../HAS_PERMISSION/global-administrator.md) - Edge creation and properties

---

## References

- [Microsoft Entra ID Global Administrator Role](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator)
- [Azure Global Administrator Elevation](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin)
- [MITRE ATT&CK: Valid Accounts - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
