# Azure IAM Privilege Escalation Research System

**Date**: 2025-01-17
**Status**: Design Approved
**Goal**: Build a repeatable research pipeline to systematically discover Azure privilege escalation techniques from authoritative sources and output structured markdown documentation

---

## Problem Statement

The Nebula IAM-push module's CAN_ESCALATE detection currently has gaps - we're missing privilege escalation paths that exist in production Azure/Entra ID environments. To increase tool efficacy, we need comprehensive intelligence about all known privilege escalation techniques across:
- Entra ID directory roles
- Microsoft Graph API permissions
- Azure RBAC roles
- Cross-domain interactions between these systems

**Success Criteria**: Discover 50-100+ documented privilege escalation techniques through automated, repeatable research.

---

## Design Overview

### Architecture

**Research Pipeline Components:**

1. **Research Orchestrator** (`scripts/orchestrate.sh`)
   - Coordinates multi-phase data collection
   - Tracks progress and logs findings
   - Supports full and incremental update modes

2. **Source Collectors** (modular Python scripts):
   - `collectors/microsoft-docs.py` - Scrapes Microsoft Entra ID role permissions, Azure RBAC documentation
   - `collectors/security-research.py` - Aggregates conference talks, blog posts, research papers
   - `collectors/mitre-attack.py` - Pulls Azure techniques from MITRE ATT&CK framework
   - `collectors/competitor-tools.py` - Analyzes BloodHound/ROADtools detection logic (future)

3. **Synthesis Engine**:
   - Deduplicates findings across sources
   - Identifies privilege escalation patterns
   - Generates technique markdown files with consistent structure

4. **Output**: Structured techniques in `docs/azure-iam-research/techniques/` organized by category

---

## Technique Documentation Schema

Each privilege escalation technique is documented in markdown with YAML frontmatter:

```markdown
---
id: TECH-001
name: Application Administrator Add Credentials to High-Privilege App
category: directory-roles
subcategory: application-management
severity: critical
mitre_attack: T1098.001 (Account Manipulation: Additional Cloud Credentials)
discovered_date: 2025-01-17
last_validated: 2025-01-17
sources:
  - Microsoft Entra ID Role Permissions Reference
  - SpecterOps "Azure Privilege Escalation via Service Principals" (2024)
---

# Application Administrator Add Credentials to High-Privilege App

## Summary
Application Administrators can add client secrets to any application, including those with high-privilege Microsoft Graph permissions, allowing them to assume the application's identity and inherit its elevated permissions.

## Required Starting Permissions
- Entra ID Role: Application Administrator (or Cloud Application Administrator)
- OR Graph API Permission: Application.ReadWrite.All

## Attack Path
1. Identify target application with high-privilege Graph permissions (e.g., Directory.ReadWrite.All)
2. Add new client secret to the application via Azure Portal or Graph API
3. Authenticate as the application using the new credentials
4. Execute actions with the application's elevated permissions

## Target Privilege Gained
- Variable: Depends on target application's Graph API permissions
- Common high-value targets: Applications with RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All

## Real-World Examples
[Space for documented incidents, pen test findings, or lab validations]

## References
- [Microsoft: Application Administrator Role](https://learn.microsoft.com...)
- [SpecterOps Blog: Azure Priv Esc](https://posts.specterops.io...)

## Validation Status
- [ ] Tested in lab environment
- [ ] Confirmed in production-like tenant
```

**Key Design Decision**: Focus on intelligence gathering only - no detection queries in initial research phase. Detection implementation comes later after validation.

---

## Directory Structure

```
docs/azure-iam-research/
├── README.md                          # Overview, how to use, update process
├── techniques/
│   ├── directory-roles/               # Entra ID directory role escalations
│   │   ├── TECH-001-app-admin-credential-add.md
│   │   ├── TECH-002-privileged-role-admin-role-assignment.md
│   │   ├── TECH-003-user-admin-password-reset.md
│   │   └── ...
│   ├── graph-permissions/             # Microsoft Graph API permission escalations
│   │   ├── TECH-101-directory-readwrite-all.md
│   │   ├── TECH-102-rolemanagement-readwrite.md
│   │   └── ...
│   ├── rbac/                          # Azure RBAC role escalations
│   │   ├── TECH-201-owner-role-assignment.md
│   │   ├── TECH-202-user-access-admin.md
│   │   └── ...
│   ├── cross-domain/                  # Techniques spanning multiple domains
│   │   ├── TECH-301-pim-to-rbac.md
│   │   ├── TECH-302-managed-identity-exploitation.md
│   │   └── ...
│   └── INDEX.md                       # Auto-generated index of all techniques
│
├── scripts/
│   ├── orchestrate.sh                 # Main research pipeline
│   ├── collectors/
│   │   ├── microsoft-docs.py
│   │   ├── security-research.py
│   │   ├── mitre-attack.py
│   │   └── requirements.txt
│   └── synthesis/
│       ├── deduplicate.py
│       ├── generate-markdown.py
│       └── generate-index.py
│
└── raw-data/                          # Scraped data (gitignored, regenerated)
    ├── microsoft-roles.json
    ├── security-research.json
    └── mitre-attack.json
```

**ID Numbering Scheme:**
- `TECH-001-099`: Directory Roles
- `TECH-100-199`: Graph Permissions
- `TECH-200-299`: Azure RBAC
- `TECH-300-399`: Cross-Domain
- `TECH-400+`: Reserved for future categories

---

## Research Workflow

### Phase 1: Microsoft Official Documentation Mining

**Target Sources:**
- Entra ID built-in roles permissions reference (~90 roles)
- Azure RBAC built-in roles (~300+ roles)
- Microsoft Graph API permissions reference
- Azure Resource Manager permissions documentation

**Extraction Logic:**
- For each role: extract permissions granted, modifiable resources, documented risks
- Parse permission hierarchies (e.g., "can modify all directory objects")
- Identify cross-references between roles

**Output**: `raw-data/microsoft-roles.json`

---

### Phase 2: Security Research Aggregation

**Sources:**
- Blog aggregation: SpecterOps, NetSPI, NCC Group, Datadog Security Labs
- Conference talks: YouTube/SlideShare for "Azure privilege escalation", "Entra ID attack"
- Research papers: arXiv, academic databases
- MITRE ATT&CK API: Pull all Azure/M365 techniques

**Extraction Logic:**
- Use LLM to parse blog posts and extract:
  - Technique name
  - Starting permission required
  - Attack steps
  - Target privilege gained
- Cross-reference with Microsoft docs to validate

**Output**: `raw-data/security-research.json`

---

### Phase 3: Synthesis & Deduplication

**Process:**
1. Merge findings from all sources
2. Deduplicate by technique signature (starting permission + target privilege)
3. Rank by source authority (Microsoft docs > multiple research sources > single source)
4. Generate unique TECH-XXX IDs
5. Create markdown files in appropriate category folders
6. Generate INDEX.md with filterable table

**Output**: `docs/azure-iam-research/techniques/{category}/TECH-XXX-{name}.md`

---

## Update Workflow & Repeatability

### Initial Research Run

```bash
# One-time setup
cd docs/azure-iam-research/scripts
pip install -r collectors/requirements.txt

# Execute full research pipeline (2-4 hours)
./orchestrate.sh --mode full
```

**Expected Output:**
- 50-100 technique markdown files
- Coverage across all 4 categories
- Auto-generated INDEX.md

---

### Periodic Updates (Monthly/Quarterly)

```bash
# Incremental update mode
./orchestrate.sh --mode incremental --since 2025-01-01
```

**Process:**
1. Scrape only new content since last run
2. Identify new techniques or updates to existing ones
3. Add new TECH-XXX files or update existing ones
4. Flag deprecated techniques

---

### Version Control

- Commit all generated markdown files to git
- Track changes over time (new techniques discovered, old ones updated)
- `raw-data/` is gitignored (regenerated each run)

---

## Validation Process (Post-Generation)

1. **Manual Review**: Security team reviews top 20 critical/high severity techniques
2. **Lab Testing**: Priority techniques tested in Azure test tenant
3. **Checkbox Updates**: Mark validation status in each technique file
4. **Implementation Planning**: Feed validated techniques into neo4j_importer.go development

---

## Success Metrics

After initial run:
- ✅ 50-100 documented privilege escalation techniques
- ✅ Coverage across all 4 categories (directory-roles, graph-permissions, rbac, cross-domain)
- ✅ Each technique with authoritative sources cited
- ✅ Repeatable pipeline that can discover new techniques automatically

---

## Integration with Existing Workflow

This research system **enhances** the existing `iam-push` workflow:
- Research generates intelligence about escalation techniques
- Validated techniques inform new detection queries in `neo4j_importer.go`
- Pipeline can be re-run to keep detections current as Azure evolves

**Future**: After validation, techniques will be translated into Neo4j Cypher queries following the existing pattern (e.g., `getValidatedApplicationAdminQuery()`)

---

## Non-Goals (Out of Scope)

- Detection query implementation (comes after research validation)
- Real-time monitoring or alerting
- Automated remediation
- Performance optimization (focus is on maximum intelligence coverage)
