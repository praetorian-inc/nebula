# Owner - CAN_ESCALATE Escalation

**Edge Type:** `CAN_ESCALATE`
**Method:** `AzureOwner`
**Category:** `RBAC`
**From:** Principal with Owner role assignment
**To:** Any principal in the tenant

---

## Overview

The Owner role at any Azure scope provides full control over resources within that scope AND the ability to assign roles to other principals, enabling compromise of other identities.

---

## Escalation Condition

Owner role at any scope provides full control AND can assign roles to compromise other identities.

---

## Detection Queries

### Find Owner Escalation Paths

```cypher
MATCH (principal:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "AzureOwner"
  AND r.category = "RBAC"
RETURN principal.displayName,
       principal.resourceType,
       count(DISTINCT target) as escalation_targets,
       r.condition
ORDER BY escalation_targets DESC
```

**Expected Results:**
- Shows principals with Owner role assignments
- Shows count of resources they can escalate to
- Typically high counts (subscription/management group Owners affect many resources)

### Find High-Risk Owners

```cypher
-- Owners with ability to compromise many identities
MATCH (principal:Resource)-[r:CAN_ESCALATE]->(target:Resource)
WHERE r.method = "AzureOwner"
WITH principal, count(DISTINCT target) as targets
WHERE targets > 100
RETURN principal.displayName, principal.resourceType, targets
ORDER BY targets DESC
```

---

## Escalation Logic (Internal Implementation)

**Phase 5 CAN_ESCALATE edge creation** (neo4j_importer.go:~4100):

```cypher
-- Find principals with Owner HAS_PERMISSION
MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(scope:Resource)
WHERE perm.permission = "Owner"

-- Create CAN_ESCALATE edges to all principals (can assign them roles)
WITH principal
MATCH (escalate_target:Resource)
WHERE escalate_target <> principal
CREATE (principal)-[r:CAN_ESCALATE]->(escalate_target)
SET r.method = "AzureOwner",
    r.condition = "Owner role at any scope provides full control AND can assign roles to compromise other identities",
    r.category = "RBAC"
```

**Cardinality:** 1 HAS_PERMISSION edge → N CAN_ESCALATE edges (N = all identities in tenant)

---

## Attack Scenarios

### 1. Role Assignment Abuse

Owner can assign roles to attacker-controlled identities:

**Attack Steps:**
1. Authenticate with Owner credentials
2. Assign Owner role to attacker principal
3. Attacker now has persistent Owner access
4. Repeat for additional persistence

**Impact:** Lateral movement and privilege persistence

### 2. User Access Administrator Assignment

Owner can assign User Access Administrator to gain role assignment capabilities:

**Attack Steps:**
1. Assign User Access Administrator to attacker
2. Attacker can now assign roles without full Owner permissions
3. Lower profile than direct Owner assignment
4. Can still compromise identities via role assignments

### 3. Resource Manipulation

Owner can modify resources to create backdoors:

**Examples:**
- Attach malicious managed identity to VM
- Modify storage account access policies
- Deploy backdoor Azure Functions
- Modify Key Vault access policies

### 4. Managed Identity Abuse

Owner can modify resources with managed identities to steal tokens:

**Attack Steps:**
1. Identify resource with high-privilege managed identity
2. Modify resource to execute attacker code
3. Steal managed identity token from IMDS endpoint
4. Use stolen token to access other resources

### 5. Cross-Subscription Escalation

Owner at management group or root scope:

**Impact:**
- Can affect multiple subscriptions
- Can assign roles across entire Azure environment
- Critical compromise point for multi-subscription tenants

---

## Mitigation Strategies

### 1. Principle of Least Privilege

**Recommendation:** Assign Owner only when necessary

**Alternatives:**
- Contributor (resource control without role assignment)
- Reader (visibility without control)
- Custom roles (specific permissions needed)

### 2. Time-Bound Access (PIM)

**Benefits:**
- Temporary Owner assignments
- Activation approval workflows
- Audit trail of elevated access
- Auto-expiration after time limit

### 3. Conditional Access Policies

**Apply to Owner assignments:**
- Require MFA
- Restrict to trusted networks/devices
- Block legacy authentication
- Require compliant devices

### 4. Regular Audits

**Quarterly Review:**
- All Owner role assignments
- Assignment justifications
- Scope appropriateness (subscription vs resource group)
- Service Principal Owners (high risk)

### 5. Segregation of Duties

**Pattern:** Separate Owner and User Access Administrator roles:
- Prevents single identity from having both capabilities
- Requires collusion for role assignment abuse
- Limits blast radius of compromise

### 6. Monitoring & Alerting

**Alert On:**
- New Owner role assignments
- Owner authentication from unexpected locations
- Role assignments performed by Owners
- Managed identity modifications by Owners
- Resource policy changes by Owners

### 7. Break-Glass Procedures

**Pattern:** Separate emergency access from regular operations:
- Dedicated break-glass Owner accounts
- Physical credential storage
- Emergency activation procedures
- Post-use review and rotation

---

## Scope-Specific Risks

| Scope | Risk Level | Impact | Recommendations |
|-------|------------|--------|-----------------|
| **Tenant Root (/)** | Critical | Can assign roles across entire Azure environment | Never assign, use PIM only |
| **Management Group** | High | Can affect multiple subscriptions | Strict approval, quarterly review |
| **Subscription** | Medium-High | Can create resource groups and assign roles | Time-bound via PIM |
| **Resource Group** | Medium | Can affect all resources within group | Appropriate for operational teams |
| **Resource** | Low-Medium | Limited to single resource but can modify identity | Least-privilege alternative to higher scopes |

---

## Prerequisites

- Principal must have Owner role assignment at any Azure scope
- Scope can be Management Group, Subscription, Resource Group, or individual Resource
- Principal must be able to authenticate to Azure

---

## Related Escalations

- **User Access Administrator** - Role assignment capability without full resource control (legacy docs: azure-rbac/)
- **[Global Administrator](global-administrator.md)** - Can elevate to Owner on any subscription
- **HAS_PERMISSION Data:** [HAS_PERMISSION/owner.md](../HAS_PERMISSION/owner.md) - Edge creation and properties

---

## References

- [Azure Built-in Roles - Owner](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner)
- [Azure RBAC Scope Hierarchy](https://docs.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
- [MITRE ATT&CK: Valid Accounts - Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
