#!/usr/bin/env python3
"""
Index Generator

Generates INDEX.md with filterable table of all privilege escalation techniques.

Input: techniques/**/*.md
Output: techniques/INDEX.md
"""

import logging
import re
import sys
from pathlib import Path
from typing import Dict, List
import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IndexGenerator:
    """Generates searchable index of all techniques."""

    def __init__(self, techniques_dir: str):
        self.techniques_dir = Path(techniques_dir)

    def find_all_techniques(self) -> List[Path]:
        """Find all technique markdown files."""
        logger.info("Searching for technique files...")

        technique_files = list(self.techniques_dir.glob("**/*.md"))
        # Exclude INDEX.md itself
        technique_files = [f for f in technique_files if f.name != "INDEX.md"]

        logger.info(f"Found {len(technique_files)} technique files")
        return technique_files

    def parse_frontmatter(self, file_path: Path) -> Dict:
        """Extract YAML frontmatter from markdown file."""
        with open(file_path) as f:
            content = f.read()

        # Extract frontmatter between --- markers
        match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
        if not match:
            logger.warning(f"No frontmatter found in {file_path}")
            return {}

        frontmatter_text = match.group(1)
        try:
            metadata = yaml.safe_load(frontmatter_text)
            return metadata
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse frontmatter in {file_path}: {e}")
            return {}

    def generate_index_table(self, techniques: List[Dict]) -> str:
        """Generate markdown table for index."""
        # Sort by ID
        techniques = sorted(techniques, key=lambda t: t.get('id', ''))

        table = "| ID | Name | Category | Severity | MITRE ATT&CK | Last Updated |\n"
        table += "|---|---|---|---|---|---|\n"

        for tech in techniques:
            tech_id = tech.get('id', 'N/A')
            name = tech.get('name', 'Unknown')
            category = tech.get('category', 'unknown')
            severity = tech.get('severity', 'medium')
            mitre = tech.get('mitre_attack', 'N/A')
            updated = tech.get('last_validated', 'N/A')

            # Create link to technique file
            file_name = tech.get('_file_name', '')
            name_link = f"[{name}](./{category}/{file_name})" if file_name else name

            table += f"| {tech_id} | {name_link} | {category} | {severity} | {mitre} | {updated} |\n"

        return table

    def generate_category_breakdown(self, techniques: List[Dict]) -> str:
        """Generate category breakdown section."""
        # Count by category
        category_counts = {}
        for tech in techniques:
            category = tech.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

        breakdown = "## Category Breakdown\n\n"
        for category, count in sorted(category_counts.items()):
            breakdown += f"- **{category}**: {count} techniques\n"
        breakdown += "\n"

        return breakdown

    def generate_severity_breakdown(self, techniques: List[Dict]) -> str:
        """Generate severity breakdown section."""
        # Count by severity
        severity_counts = {}
        for tech in techniques:
            severity = tech.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        breakdown = "## Severity Breakdown\n\n"
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            breakdown += f"- **{severity.upper()}**: {count} techniques\n"
        breakdown += "\n"

        return breakdown

    def generate_index(self, techniques: List[Dict]) -> str:
        """Generate complete INDEX.md content."""
        index = "# Azure IAM Privilege Escalation Techniques - Index\n\n"
        index += f"**Total Techniques**: {len(techniques)}\n\n"
        index += f"**Last Generated**: {self.get_timestamp()}\n\n"

        index += "---\n\n"

        index += self.generate_category_breakdown(techniques)
        index += self.generate_severity_breakdown(techniques)

        index += "---\n\n"

        index += "## All Techniques\n\n"
        index += self.generate_index_table(techniques)

        return index

    def get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    def write_index(self, index_content: str) -> None:
        """Write INDEX.md file."""
        index_file = self.techniques_dir / "INDEX.md"

        with open(index_file, 'w') as f:
            f.write(index_content)

        logger.info(f"Generated index at {index_file}")

    def run(self) -> None:
        """Execute index generation workflow."""
        logger.info("Starting index generation...")

        technique_files = self.find_all_techniques()

        # Parse all techniques
        techniques = []
        for file_path in technique_files:
            metadata = self.parse_frontmatter(file_path)
            if metadata:
                metadata['_file_name'] = file_path.name
                techniques.append(metadata)

        # Generate index
        index_content = self.generate_index(techniques)
        self.write_index(index_content)

        logger.info("Index generation complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <techniques_directory>")
        sys.exit(1)

    techniques_dir = sys.argv[1]

    generator = IndexGenerator(techniques_dir)
    generator.run()


if __name__ == "__main__":
    main()
