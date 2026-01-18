#!/usr/bin/env python3
"""
Microsoft Official Documentation Collector

Scrapes Microsoft Entra ID role permissions, Azure RBAC roles, and Graph API
permissions from official Microsoft documentation.

Output: raw-data/microsoft-roles.json
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import requests
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MicrosoftDocsCollector:
    """Collects privilege escalation intelligence from Microsoft documentation."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                         'AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/91.0.4472.124 Safari/537.36'
        })

    def collect_entra_roles(self) -> List[Dict]:
        """
        Scrape Entra ID built-in roles from Microsoft Learn.

        Target: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference

        Returns:
            List of role dictionaries with permissions and escalation notes
        """
        logger.info("Collecting Entra ID role permissions...")

        url = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            roles = []

            # TODO: Implement HTML parsing logic to extract:
            # - Role name
            # - Role template ID
            # - Permissions granted
            # - Description
            # - Documented escalation notes

            logger.info(f"Collected {len(roles)} Entra ID roles")
            return roles

        except Exception as e:
            logger.error(f"Failed to collect Entra ID roles: {e}")
            return []

    def collect_azure_rbac_roles(self) -> List[Dict]:
        """
        Scrape Azure RBAC built-in roles from Microsoft Learn.

        Target: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles

        Returns:
            List of RBAC role dictionaries
        """
        logger.info("Collecting Azure RBAC roles...")

        url = "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            roles = []

            # TODO: Implement HTML parsing logic to extract:
            # - Role name
            # - Role ID
            # - Actions and NotActions
            # - DataActions and NotDataActions
            # - Assignable scopes

            logger.info(f"Collected {len(roles)} Azure RBAC roles")
            return roles

        except Exception as e:
            logger.error(f"Failed to collect Azure RBAC roles: {e}")
            return []

    def collect_graph_permissions(self) -> List[Dict]:
        """
        Scrape Microsoft Graph API permissions reference.

        Target: https://learn.microsoft.com/en-us/graph/permissions-reference

        Returns:
            List of Graph permission dictionaries
        """
        logger.info("Collecting Microsoft Graph API permissions...")

        url = "https://learn.microsoft.com/en-us/graph/permissions-reference"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            permissions = []

            # TODO: Implement HTML parsing logic to extract:
            # - Permission name
            # - Permission type (Application/Delegated)
            # - Admin consent required
            # - Description
            # - Escalation implications

            logger.info(f"Collected {len(permissions)} Graph API permissions")
            return permissions

        except Exception as e:
            logger.error(f"Failed to collect Graph API permissions: {e}")
            return []

    def save_results(self, entra_roles: List[Dict], rbac_roles: List[Dict],
                    graph_perms: List[Dict]) -> None:
        """Save collected data to JSON file."""

        output_file = self.output_dir / "microsoft-roles.json"

        data = {
            "collection_date": datetime.utcnow().isoformat() + "Z",
            "source": "Microsoft Official Documentation",
            "entra_roles": entra_roles,
            "azure_rbac_roles": rbac_roles,
            "graph_permissions": graph_perms,
            "summary": {
                "total_entra_roles": len(entra_roles),
                "total_rbac_roles": len(rbac_roles),
                "total_graph_permissions": len(graph_perms)
            }
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved results to {output_file}")

    def run(self) -> None:
        """Execute full collection workflow."""
        logger.info("Starting Microsoft documentation collection...")

        entra_roles = self.collect_entra_roles()
        rbac_roles = self.collect_azure_rbac_roles()
        graph_perms = self.collect_graph_permissions()

        self.save_results(entra_roles, rbac_roles, graph_perms)

        logger.info("Microsoft documentation collection complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_directory>")
        sys.exit(1)

    output_dir = sys.argv[1]

    collector = MicrosoftDocsCollector(output_dir)
    collector.run()


if __name__ == "__main__":
    main()
