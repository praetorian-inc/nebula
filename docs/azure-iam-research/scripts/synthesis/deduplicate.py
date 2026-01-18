#!/usr/bin/env python3
"""
Technique Deduplication

Merges privilege escalation techniques from multiple sources, deduplicates
based on technique signature, and ranks by source authority.

Input: raw-data/*.json
Output: intermediate/deduplicated-techniques.json
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TechniqueDeduplicator:
    """Deduplicates and merges privilege escalation techniques."""

    # Source authority ranking (higher = more authoritative)
    SOURCE_AUTHORITY = {
        "Microsoft Official Documentation": 100,
        "MITRE ATT&CK Framework": 90,
        "Security Research Aggregation": 50
    }

    def __init__(self, raw_data_dir: str, output_dir: str):
        self.raw_data_dir = Path(raw_data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def load_all_sources(self) -> List[Dict]:
        """Load data from all collector outputs."""
        logger.info("Loading data from all sources...")

        all_techniques = []

        # Load Microsoft docs
        ms_file = self.raw_data_dir / "microsoft-roles.json"
        if ms_file.exists():
            with open(ms_file) as f:
                ms_data = json.load(f)
                techniques = ms_data.get('techniques', [])
                for tech in techniques:
                    tech['source'] = "Microsoft Official Documentation"
                all_techniques.extend(techniques)
                logger.info(f"Loaded {len(techniques)} techniques from Microsoft documentation")

        # Load security research
        research_file = self.raw_data_dir / "security-research.json"
        if research_file.exists():
            with open(research_file) as f:
                research_data = json.load(f)
                techniques = research_data.get('techniques', [])
                for tech in techniques:
                    tech['source'] = "Security Research Aggregation"
                all_techniques.extend(techniques)
                logger.info(f"Loaded {len(techniques)} techniques from security research")

        # Load MITRE ATT&CK
        mitre_file = self.raw_data_dir / "mitre-attack.json"
        if mitre_file.exists():
            with open(mitre_file) as f:
                mitre_data = json.load(f)
                techniques = mitre_data.get('techniques', [])
                for tech in techniques:
                    tech['source'] = "MITRE ATT&CK Framework"
                all_techniques.extend(techniques)
                logger.info(f"Loaded {len(techniques)} techniques from MITRE ATT&CK")

        logger.info(f"Total raw techniques loaded: {len(all_techniques)}")
        return all_techniques

    def compute_signature(self, technique: Dict) -> str:
        """
        Compute a signature for technique deduplication.

        Signature based on: starting permission + target privilege gained

        Args:
            technique: Technique dictionary

        Returns:
            Normalized signature string
        """
        # TODO: Implement signature computation
        # For now, use technique name as proxy
        name = technique.get('name', '').lower().strip()
        return name

    def deduplicate_techniques(self, techniques: List[Dict]) -> List[Dict]:
        """
        Deduplicate techniques by signature, keeping highest authority version.

        Args:
            techniques: List of all collected techniques

        Returns:
            Deduplicated list of techniques
        """
        logger.info("Deduplicating techniques...")

        signature_map: Dict[str, List[Dict]] = {}

        # Group by signature
        for tech in techniques:
            sig = self.compute_signature(tech)
            if sig not in signature_map:
                signature_map[sig] = []
            signature_map[sig].append(tech)

        # For each signature, select best version
        deduplicated = []
        for sig, tech_list in signature_map.items():
            if len(tech_list) == 1:
                deduplicated.append(tech_list[0])
            else:
                # Merge multiple sources into one technique
                merged = self.merge_techniques(tech_list)
                deduplicated.append(merged)

        logger.info(f"Deduplicated: {len(techniques)} → {len(deduplicated)} techniques")
        return deduplicated

    def merge_techniques(self, techniques: List[Dict]) -> Dict:
        """
        Merge multiple versions of same technique from different sources.

        Args:
            techniques: List of technique dictionaries with same signature

        Returns:
            Merged technique with all sources cited
        """
        # Select primary version (highest authority)
        primary = max(
            techniques,
            key=lambda t: self.SOURCE_AUTHORITY.get(t.get('source', ''), 0)
        )

        # Collect all sources
        all_sources = []
        for tech in techniques:
            source = tech.get('source', 'Unknown')
            if source not in [s['name'] for s in all_sources]:
                all_sources.append({
                    "name": source,
                    "authority": self.SOURCE_AUTHORITY.get(source, 0)
                })

        primary['sources'] = sorted(all_sources, key=lambda s: s['authority'], reverse=True)
        primary['source_count'] = len(all_sources)

        return primary

    def categorize_techniques(self, techniques: List[Dict]) -> List[Dict]:
        """
        Assign category and subcategory to each technique.

        Categories:
        - directory-roles
        - graph-permissions
        - rbac
        - cross-domain

        Args:
            techniques: Deduplicated techniques

        Returns:
            Techniques with category assignments
        """
        logger.info("Categorizing techniques...")

        for tech in techniques:
            # TODO: Implement categorization logic
            # For now, assign "unknown"
            if 'category' not in tech:
                tech['category'] = 'unknown'
            if 'subcategory' not in tech:
                tech['subcategory'] = 'general'

        return techniques

    def save_results(self, techniques: List[Dict]) -> None:
        """Save deduplicated techniques."""
        output_file = self.output_dir / "deduplicated-techniques.json"

        data = {
            "deduplication_complete": True,
            "total_techniques": len(techniques),
            "techniques": techniques
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved deduplicated techniques to {output_file}")

    def run(self) -> None:
        """Execute deduplication workflow."""
        logger.info("Starting technique deduplication...")

        techniques = self.load_all_sources()
        deduplicated = self.deduplicate_techniques(techniques)
        categorized = self.categorize_techniques(deduplicated)
        self.save_results(categorized)

        logger.info("Deduplication complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <raw_data_directory> <output_directory>")
        sys.exit(1)

    raw_data_dir = sys.argv[1]
    output_dir = sys.argv[2]

    deduplicator = TechniqueDeduplicator(raw_data_dir, output_dir)
    deduplicator.run()


if __name__ == "__main__":
    main()
