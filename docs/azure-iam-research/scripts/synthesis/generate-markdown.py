#!/usr/bin/env python3
"""
Markdown Generator

Generates structured markdown files for each privilege escalation technique.

Input: intermediate/deduplicated-techniques.json
Output: techniques/{category}/TECH-XXX-{name}.md
"""

import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MarkdownGenerator:
    """Generates markdown documentation for techniques."""

    # ID ranges by category
    ID_RANGES = {
        "directory-roles": (1, 99),
        "graph-permissions": (100, 199),
        "rbac": (200, 299),
        "cross-domain": (300, 399)
    }

    def __init__(self, input_file: str, techniques_dir: str):
        self.input_file = Path(input_file)
        self.techniques_dir = Path(techniques_dir)

    def load_techniques(self) -> List[Dict]:
        """Load deduplicated techniques."""
        logger.info(f"Loading techniques from {self.input_file}...")

        with open(self.input_file) as f:
            data = json.load(f)
            techniques = data.get('techniques', [])

        logger.info(f"Loaded {len(techniques)} techniques")
        return techniques

    def assign_ids(self, techniques: List[Dict]) -> List[Dict]:
        """
        Assign unique TECH-XXX IDs to techniques based on category.

        Args:
            techniques: List of technique dictionaries

        Returns:
            Techniques with assigned IDs
        """
        logger.info("Assigning technique IDs...")

        # Group by category
        by_category = {}
        for tech in techniques:
            category = tech.get('category', 'unknown')
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(tech)

        # Assign IDs within each category's range
        for category, tech_list in by_category.items():
            if category not in self.ID_RANGES:
                logger.warning(f"Unknown category: {category}, skipping ID assignment")
                continue

            start_id, end_id = self.ID_RANGES[category]
            for idx, tech in enumerate(tech_list, start=start_id):
                tech['id'] = f"TECH-{idx:03d}"

        return techniques

    def slugify(self, text: str) -> str:
        """Convert text to URL-friendly slug."""
        text = text.lower()
        text = re.sub(r'[^\w\s-]', '', text)
        text = re.sub(r'[-\s]+', '-', text)
        return text.strip('-')

    def generate_filename(self, technique: Dict) -> str:
        """Generate filename for technique."""
        tech_id = technique.get('id', 'TECH-000')
        name = technique.get('name', 'unnamed')
        slug = self.slugify(name)
        return f"{tech_id}-{slug}.md"

    def generate_frontmatter(self, technique: Dict) -> str:
        """Generate YAML frontmatter for technique."""
        sources = technique.get('sources', [])
        source_names = [s['name'] for s in sources]

        frontmatter = f"""---
id: {technique.get('id', 'TECH-000')}
name: {technique.get('name', 'Unnamed Technique')}
category: {technique.get('category', 'unknown')}
subcategory: {technique.get('subcategory', 'general')}
severity: {technique.get('severity', 'medium')}
mitre_attack: {technique.get('mitre_id', 'N/A')}
discovered_date: {technique.get('created', datetime.utcnow().strftime('%Y-%m-%d'))}
last_validated: {technique.get('modified', datetime.utcnow().strftime('%Y-%m-%d'))}
sources:
"""
        for source in source_names:
            frontmatter += f"  - {source}\n"

        frontmatter += "---\n"
        return frontmatter

    def generate_content(self, technique: Dict) -> str:
        """Generate markdown content for technique."""
        name = technique.get('name', 'Unnamed Technique')
        description = technique.get('description', 'No description available.')

        content = f"\n# {name}\n\n"
        content += f"## Summary\n{description}\n\n"

        # Required Starting Permissions
        content += "## Required Starting Permissions\n"
        starting_perms = technique.get('starting_permissions', [])
        if starting_perms:
            for perm in starting_perms:
                content += f"- {perm}\n"
        else:
            content += "- [To be documented]\n"
        content += "\n"

        # Attack Path
        content += "## Attack Path\n"
        attack_steps = technique.get('attack_steps', [])
        if attack_steps:
            for idx, step in enumerate(attack_steps, 1):
                content += f"{idx}. {step}\n"
        else:
            content += "[To be documented]\n"
        content += "\n"

        # Target Privilege Gained
        content += "## Target Privilege Gained\n"
        target_priv = technique.get('target_privilege', 'Unknown')
        content += f"- {target_priv}\n\n"

        # Real-World Examples
        content += "## Real-World Examples\n"
        examples = technique.get('examples', [])
        if examples:
            for example in examples:
                content += f"- {example}\n"
        else:
            content += "[Space for documented incidents, pen test findings, or lab validations]\n"
        content += "\n"

        # References
        content += "## References\n"
        refs = technique.get('references', [])
        if refs:
            for ref in refs:
                content += f"- [{ref.get('title', 'Reference')}]({ref.get('url', '#')})\n"
        else:
            content += "- [To be added]\n"
        content += "\n"

        # Validation Status
        content += "## Validation Status\n"
        content += "- [ ] Tested in lab environment\n"
        content += "- [ ] Confirmed in production-like tenant\n"

        return content

    def write_markdown_file(self, technique: Dict) -> Path:
        """Write technique to markdown file."""
        category = technique.get('category', 'unknown')
        category_dir = self.techniques_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)

        filename = self.generate_filename(technique)
        file_path = category_dir / filename

        frontmatter = self.generate_frontmatter(technique)
        content = self.generate_content(technique)

        with open(file_path, 'w') as f:
            f.write(frontmatter)
            f.write(content)

        return file_path

    def run(self) -> None:
        """Execute markdown generation workflow."""
        logger.info("Starting markdown generation...")

        techniques = self.load_techniques()
        techniques = self.assign_ids(techniques)

        files_created = []
        for tech in techniques:
            file_path = self.write_markdown_file(tech)
            files_created.append(file_path)

        logger.info(f"Generated {len(files_created)} markdown files")
        logger.info("Markdown generation complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_json_file> <techniques_directory>")
        sys.exit(1)

    input_file = sys.argv[1]
    techniques_dir = sys.argv[2]

    generator = MarkdownGenerator(input_file, techniques_dir)
    generator.run()


if __name__ == "__main__":
    main()
