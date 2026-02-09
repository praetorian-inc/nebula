# Azure IAM Privilege Escalation Research System

Automated intelligence gathering pipeline for discovering Azure/Entra ID privilege escalation techniques.

## Overview

This system collects privilege escalation techniques from multiple authoritative sources, deduplicates them, and generates structured documentation for integration into Nebula's IAM-push module.

## Architecture

```
azure-iam-research/
├── scripts/
│   ├── orchestrate.sh           # Main pipeline orchestrator
│   ├── collectors/              # Phase 1: Data collection
│   │   ├── microsoft-docs.py    # Official Microsoft documentation
│   │   ├── security-research.py # Security blogs and conference talks
│   │   ├── mitre-attack.py      # MITRE ATT&CK framework
│   │   └── requirements.txt     # Python dependencies
│   └── synthesis/               # Phase 2: Data processing
│       ├── deduplicate.py       # Merge and deduplicate techniques
│       ├── generate-markdown.py # Create structured markdown files
│       └── generate-index.py    # Generate searchable index
├── techniques/                  # Output: Structured documentation
│   ├── directory-roles/         # TECH-001 to TECH-099
│   ├── graph-permissions/       # TECH-100 to TECH-199
│   ├── rbac/                    # TECH-200 to TECH-299
│   ├── cross-domain/            # TECH-300 to TECH-399
│   └── INDEX.md                 # Searchable table of all techniques
├── raw-data/                    # Intermediate: Raw collector output
└── intermediate/                # Intermediate: Deduplicated JSON
```

## Quick Start

### 1. Install Dependencies

```bash
cd docs/azure-iam-research
pip3 install -r scripts/collectors/requirements.txt
```

### 2. Run Full Pipeline

```bash
./scripts/orchestrate.sh
```

This will:
- Collect data from Microsoft docs, security research, and MITRE ATT&CK
- Deduplicate and merge techniques
- Generate structured markdown files in `techniques/`
- Create searchable index at `techniques/INDEX.md`

### 3. View Results

```bash
# Browse the index
cat techniques/INDEX.md

# View a specific technique
cat techniques/directory-roles/TECH-001-global-administrator-role-assignment.md
```

## Pipeline Modes

### Full Pipeline (Default)
```bash
./scripts/orchestrate.sh --full
```

### Collectors Only
Run just the data collection phase:
```bash
./scripts/orchestrate.sh --collectors-only
```

### Synthesis Only
Run just the processing phase (requires existing `raw-data/`):
```bash
./scripts/orchestrate.sh --synthesis-only
```

### Clean Output
Remove all generated data:
```bash
./scripts/orchestrate.sh --clean
```

## Technique Structure

Each technique is documented with:

### Frontmatter (YAML)
```yaml
---
id: TECH-001
name: Global Administrator Role Assignment
category: directory-roles
subcategory: administrative-roles
severity: critical
mitre_attack: T1098.003
discovered_date: 2024-01-15
last_validated: 2025-01-17
sources:
  - Microsoft Official Documentation
  - MITRE ATT&CK Framework
---
```

### Content Sections
1. **Summary** - Brief description of the technique
2. **Required Starting Permissions** - Initial access level needed
3. **Attack Path** - Step-by-step escalation process
4. **Target Privilege Gained** - Final privilege level achieved
5. **Real-World Examples** - Documented incidents or findings
6. **References** - Source URLs and documentation
7. **Validation Status** - Testing checkboxes

## ID Numbering Scheme

| Range | Category | Examples |
|-------|----------|----------|
| TECH-001 to TECH-099 | Directory Roles | Global Admin, Privileged Role Admin |
| TECH-100 to TECH-199 | Graph Permissions | RoleManagement.ReadWrite.Directory |
| TECH-200 to TECH-299 | RBAC | Owner at subscription/management group |
| TECH-300 to TECH-399 | Cross-Domain | Power Platform → Entra ID, Azure → Entra ID |

## Data Sources

### 1. Microsoft Official Documentation
- **Source**: Microsoft Learn (learn.microsoft.com)
- **Authority**: Primary source (weight: 100)
- **Coverage**: Entra ID roles, Azure RBAC roles, Graph API permissions
- **Script**: `collectors/microsoft-docs.py`

### 2. Security Research
- **Sources**: SpecterOps, NetSPI, NCC Group, Datadog Security Labs
- **Authority**: Secondary source (weight: 50)
- **Coverage**: Novel techniques, real-world attacks, conference talks
- **Script**: `collectors/security-research.py`

### 3. MITRE ATT&CK
- **Source**: MITRE ATT&CK Enterprise (via STIX API)
- **Authority**: High authority (weight: 90)
- **Coverage**: Azure/Office 365 techniques with privilege escalation tactic
- **Script**: `collectors/mitre-attack.py`

## Deduplication Logic

Techniques are deduplicated by **signature**: `starting_permission + target_privilege`

When duplicates are found:
1. Select highest authority source as primary
2. Merge all source citations
3. Preserve best description and attack steps
4. Track all sources in frontmatter

## Update Workflow

### Monthly Updates
```bash
# 1. Run the full pipeline
./scripts/orchestrate.sh

# 2. Review new/updated techniques
git diff techniques/

# 3. Commit updates
git add techniques/ intermediate/ raw-data/
git commit -m "feat(azure-iam): update privilege escalation research ($(date +%Y-%m))"
```

### Adding New Sources

1. Create new collector script in `scripts/collectors/`
2. Follow the pattern from existing collectors:
   - Accept output directory as CLI argument
   - Output JSON to `raw-data/{source-name}.json`
   - Include collection metadata (date, source URL)
3. Update `scripts/orchestrate.sh` to call new collector
4. Update deduplication source authority weights in `deduplicate.py`

## Integration with IAM-Push

Once techniques are documented:

1. **Review Technique Files** - Validate attack paths and requirements
2. **Identify Missing Coverage** - Compare with existing CAN_ESCALATE queries in `pkg/links/azure/iam/neo4j_importer.go`
3. **Implement Detection** - Add new Cypher queries for uncovered techniques
4. **Test in Lab** - Validate detection in simulated Azure tenant
5. **Deploy to Production** - Merge to main branch

## Success Metrics

### Coverage Targets
- **50-100+ documented techniques** across all categories
- **20+ validated techniques** (tested in lab environment)
- **100% of Microsoft built-in roles** documented

### Quality Metrics
- **100% source attribution** - Every technique cites authoritative sources
- **Complete attack paths** - No "[To be documented]" placeholders
- **Real-world examples** - At least 1 example per high/critical severity technique

## Troubleshooting

### Missing Dependencies
```bash
pip3 install -r scripts/collectors/requirements.txt
```

### Collector Failures
Check logs in terminal output. Common issues:
- Network timeouts (retry with `--collectors-only`)
- Rate limiting (add delays in collector scripts)
- API changes (update collector URL patterns)

### Empty Output
If `techniques/` is empty:
1. Check `raw-data/` has JSON files with data
2. Run synthesis manually: `./scripts/orchestrate.sh --synthesis-only`
3. Check for errors in `deduplicate.py` or `generate-markdown.py`

## Contributing

### Adding Techniques Manually

1. Create markdown file in appropriate category folder
2. Follow the frontmatter structure (see existing files)
3. Assign next available ID in category range
4. Run `scripts/synthesis/generate-index.py techniques/` to update index

### Improving Collectors

The collector scripts are currently scaffolding with TODO sections:
- `microsoft-docs.py` - Needs HTML parsing for Microsoft Learn pages
- `security-research.py` - Needs blog scraping and LLM-assisted extraction

Contributions to implement these sections are welcome.

## License

Part of the Praetorian Chariot platform.

## Contact

For questions or issues, see the main Chariot documentation or file an issue in the repository.
