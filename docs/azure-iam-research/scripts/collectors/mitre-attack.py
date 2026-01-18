#!/usr/bin/env python3
"""
MITRE ATT&CK Collector

Pulls Azure/Office 365 privilege escalation techniques from the MITRE ATT&CK framework.

Output: raw-data/mitre-attack.json
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MitreAttackCollector:
    """Collects Azure privilege escalation techniques from MITRE ATT&CK."""

    # MITRE ATT&CK STIX API endpoint
    STIX_API_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

    def fetch_attack_data(self) -> Dict:
        """
        Fetch MITRE ATT&CK Enterprise data from GitHub.

        Returns:
            STIX bundle as dictionary
        """
        logger.info("Fetching MITRE ATT&CK data...")

        try:
            response = self.session.get(self.STIX_API_URL, timeout=60)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Fetched {len(data.get('objects', []))} STIX objects")
            return data
        except Exception as e:
            logger.error(f"Failed to fetch ATT&CK data: {e}")
            return {}

    def filter_azure_techniques(self, stix_data: Dict) -> List[Dict]:
        """
        Filter techniques relevant to Azure/Office 365/Entra ID.

        Args:
            stix_data: MITRE ATT&CK STIX bundle

        Returns:
            List of Azure-relevant technique dictionaries
        """
        logger.info("Filtering Azure/Office 365 techniques...")

        techniques = []

        for obj in stix_data.get('objects', []):
            # Look for attack-pattern objects (techniques)
            if obj.get('type') != 'attack-pattern':
                continue

            # Check if technique applies to Azure/Office 365
            platforms = obj.get('x_mitre_platforms', [])
            azure_relevant = any(
                platform in platforms
                for platform in ['Azure', 'Office 365', 'Azure AD', 'SaaS']
            )

            if not azure_relevant:
                continue

            # Check if technique is privilege escalation
            tactics = [ref.get('phase_name', '') for ref in obj.get('kill_chain_phases', [])]
            is_priv_esc = 'privilege-escalation' in tactics

            technique = {
                "mitre_id": obj.get('external_references', [{}])[0].get('external_id', ''),
                "name": obj.get('name', ''),
                "description": obj.get('description', ''),
                "tactics": tactics,
                "is_privilege_escalation": is_priv_esc,
                "platforms": platforms,
                "url": obj.get('external_references', [{}])[0].get('url', ''),
                "data_sources": obj.get('x_mitre_data_sources', []),
                "detection": obj.get('x_mitre_detection', ''),
                "created": obj.get('created', ''),
                "modified": obj.get('modified', '')
            }

            techniques.append(technique)

        logger.info(f"Filtered {len(techniques)} Azure-relevant techniques")
        priv_esc_count = sum(1 for t in techniques if t['is_privilege_escalation'])
        logger.info(f"  - {priv_esc_count} are privilege escalation techniques")

        return techniques

    def save_results(self, techniques: List[Dict]) -> None:
        """Save collected data to JSON file."""

        output_file = self.output_dir / "mitre-attack.json"

        data = {
            "collection_date": datetime.utcnow().isoformat() + "Z",
            "source": "MITRE ATT&CK Framework",
            "source_url": self.STIX_API_URL,
            "techniques": techniques,
            "summary": {
                "total_techniques": len(techniques),
                "privilege_escalation_techniques": sum(
                    1 for t in techniques if t['is_privilege_escalation']
                )
            }
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved results to {output_file}")

    def run(self) -> None:
        """Execute full collection workflow."""
        logger.info("Starting MITRE ATT&CK collection...")

        stix_data = self.fetch_attack_data()

        if not stix_data:
            logger.error("Failed to fetch ATT&CK data, aborting")
            return

        techniques = self.filter_azure_techniques(stix_data)

        self.save_results(techniques)

        logger.info("MITRE ATT&CK collection complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_directory>")
        sys.exit(1)

    output_dir = sys.argv[1]

    collector = MitreAttackCollector(output_dir)
    collector.run()


if __name__ == "__main__":
    main()
