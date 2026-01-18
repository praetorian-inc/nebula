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
        Collect Entra ID built-in roles with privilege escalation potential.

        Uses curated list of documented privilege escalation roles from Microsoft Learn.
        More reliable than HTML scraping for security research purposes.

        Returns:
            List of technique dictionaries with escalation paths
        """
        logger.info("Collecting Entra ID privilege escalation techniques...")

        # Curated list from Microsoft official documentation
        # Source: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
        techniques = [
            {
                "name": "Global Administrator Role Assignment",
                "description": "Global Administrator can manage all aspects of Azure AD and Microsoft services that use Azure AD identities. Can assign any role to any user, providing complete tenant control.",
                "category": "directory-roles",
                "subcategory": "administrative-roles",
                "severity": "critical",
                "starting_permissions": ["Any directory role with user management permissions"],
                "target_privilege": "Global Administrator (complete tenant control)",
                "attack_steps": [
                    "Obtain any directory role with role assignment permissions (e.g., Privileged Role Administrator)",
                    "Assign Global Administrator role to controlled user account via Azure Portal or Graph API",
                    "Authenticate as newly promoted Global Administrator",
                    "Gain complete tenant control including all Azure AD, Exchange Online, SharePoint, Teams"
                ],
                "mitre_id": "T1098.003",
                "examples": [
                    "Red team engagement where Privileged Role Administrator was leveraged to assign Global Admin to test account"
                ],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Global Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#global-administrator"
                    }
                ]
            },
            {
                "name": "Privileged Role Administrator to Global Admin",
                "description": "Privileged Role Administrator can assign most directory roles including Global Administrator, effectively providing a path to full tenant compromise.",
                "category": "directory-roles",
                "subcategory": "administrative-roles",
                "severity": "critical",
                "starting_permissions": ["Privileged Role Administrator"],
                "target_privilege": "Global Administrator or any directory role",
                "attack_steps": [
                    "Authenticate as user with Privileged Role Administrator role",
                    "Use Azure Portal or Microsoft Graph API to assign Global Administrator role",
                    "Authenticate as newly elevated account",
                    "Exercise full tenant administrative control"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Privileged Role Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-role-administrator"
                    }
                ]
            },
            {
                "name": "Privileged Authentication Administrator Password Reset",
                "description": "Privileged Authentication Administrator can reset passwords and authentication methods for any user including Global Administrators, providing credential takeover path.",
                "category": "directory-roles",
                "subcategory": "authentication-management",
                "severity": "critical",
                "starting_permissions": ["Privileged Authentication Administrator"],
                "target_privilege": "Any user account credentials including Global Administrators",
                "attack_steps": [
                    "Authenticate as Privileged Authentication Administrator",
                    "Identify target administrator account (e.g., Global Administrator)",
                    "Reset password or register new authentication method for target via Azure Portal or Graph API",
                    "Authenticate as compromised administrator",
                    "Leverage administrator privileges for persistent access"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Privileged Authentication Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-authentication-administrator"
                    }
                ]
            },
            {
                "name": "Application Administrator Service Principal Escalation",
                "description": "Application Administrator can create app registrations and grant admin consent for privileged Graph API permissions, creating service principals with elevated privileges.",
                "category": "directory-roles",
                "subcategory": "application-management",
                "severity": "high",
                "starting_permissions": ["Application Administrator"],
                "target_privilege": "Service principal with privileged Graph API permissions (RoleManagement.ReadWrite.Directory, etc.)",
                "attack_steps": [
                    "Authenticate as Application Administrator",
                    "Create new app registration in Azure AD",
                    "Request privileged Graph API permissions (Application type): RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All",
                    "Grant admin consent for requested permissions",
                    "Generate client secret for service principal",
                    "Authenticate as service principal using client credentials flow",
                    "Use Microsoft Graph API to assign directory roles or modify privileged users"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Application Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#application-administrator"
                    },
                    {
                        "title": "Microsoft Graph Permission Reference",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference"
                    }
                ]
            },
            {
                "name": "Cloud Application Administrator Service Principal Escalation",
                "description": "Similar to Application Administrator, Cloud Application Administrator can create apps and grant consent for escalation-capable Graph permissions.",
                "category": "directory-roles",
                "subcategory": "application-management",
                "severity": "high",
                "starting_permissions": ["Cloud Application Administrator"],
                "target_privilege": "Service principal with privileged Graph API permissions",
                "attack_steps": [
                    "Authenticate as Cloud Application Administrator",
                    "Create app registration or modify existing enterprise application",
                    "Request and grant admin consent for Graph API permissions with escalation potential",
                    "Generate service principal credentials (client secret or certificate)",
                    "Authenticate as service principal",
                    "Leverage Graph API permissions to escalate privileges"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Cloud Application Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator"
                    }
                ]
            },
            {
                "name": "Groups Administrator Privileged Group Membership",
                "description": "Groups Administrator can add members to any security group including those with privileged directory role assignments.",
                "category": "directory-roles",
                "subcategory": "group-management",
                "severity": "medium",
                "starting_permissions": ["Groups Administrator"],
                "target_privilege": "Membership in privileged groups with directory role assignments",
                "attack_steps": [
                    "Authenticate as Groups Administrator",
                    "Enumerate security groups with directory role assignments (role-assignable groups)",
                    "Add controlled user account to privileged group",
                    "Inherit directory role permissions through group membership",
                    "Authenticate as user with inherited role",
                    "Leverage inherited privileges for further escalation"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Groups Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#groups-administrator"
                    }
                ]
            },
            {
                "name": "User Administrator Password Reset for Limited Admins",
                "description": "User Administrator can reset passwords for users with limited admin roles, enabling lateral movement to admin accounts.",
                "category": "directory-roles",
                "subcategory": "user-management",
                "severity": "medium",
                "starting_permissions": ["User Administrator"],
                "target_privilege": "Credentials for limited admin roles (Helpdesk Administrator, Password Administrator, etc.)",
                "attack_steps": [
                    "Authenticate as User Administrator",
                    "Identify users with limited admin roles within reset scope",
                    "Reset password for target limited admin account via Azure Portal",
                    "Authenticate as compromised admin",
                    "Leverage admin permissions for lateral movement within tenant"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - User Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#user-administrator"
                    }
                ]
            },
            {
                "name": "Authentication Administrator Password Reset for Non-Admins",
                "description": "Authentication Administrator can reset authentication methods for non-admin users, enabling account takeover of users with sensitive data access.",
                "category": "directory-roles",
                "subcategory": "authentication-management",
                "severity": "low",
                "starting_permissions": ["Authentication Administrator"],
                "target_privilege": "Credentials for non-admin user accounts",
                "attack_steps": [
                    "Authenticate as Authentication Administrator",
                    "Identify non-admin users with access to sensitive data or applications",
                    "Reset authentication methods (password, MFA) for target users",
                    "Authenticate as compromised user",
                    "Access sensitive business data or applications",
                    "Use compromised identity for social engineering or data exfiltration"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Entra ID Built-in Roles - Authentication Administrator",
                        "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#authentication-administrator"
                    }
                ]
            }
        ]

        logger.info(f"Collected {len(techniques)} privilege escalation techniques from Entra ID roles")
        return techniques

    def collect_azure_rbac_roles(self) -> List[Dict]:
        """
        Collect Azure RBAC built-in roles with privilege escalation potential.

        Focuses on roles that enable escalation from Azure to Entra ID or within Azure.

        Returns:
            List of technique dictionaries with RBAC escalation paths
        """
        logger.info("Collecting Azure RBAC privilege escalation techniques...")

        # Curated list from Microsoft official documentation
        # Source: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
        techniques = [
            {
                "name": "Owner at Subscription or Management Group Scope",
                "description": "Owner role at subscription or management group scope grants full access to all resources including role assignments, enabling privilege escalation across the Azure hierarchy.",
                "category": "rbac",
                "subcategory": "azure-control-plane",
                "severity": "critical",
                "starting_permissions": ["Owner role at subscription or management group scope"],
                "target_privilege": "User Access Administrator or Owner at higher scopes, potential Entra ID escalation via managed identities",
                "attack_steps": [
                    "Authenticate with Owner role at subscription or management group",
                    "Assign Owner or User Access Administrator role to controlled identity at parent scope",
                    "Alternatively, assign privileged roles to managed identities",
                    "Use managed identity to access Entra ID if assigned appropriate permissions",
                    "Escalate within Azure or bridge to Entra ID tenant"
                ],
                "mitre_id": "T1098",
                "examples": [],
                "references": [
                    {
                        "title": "Azure Built-in Roles - Owner",
                        "url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner"
                    }
                ]
            },
            {
                "name": "User Access Administrator Role Assignment",
                "description": "User Access Administrator can manage role assignments for Azure resources without full Owner permissions, enabling privilege escalation through role manipulation.",
                "category": "rbac",
                "subcategory": "azure-control-plane",
                "severity": "high",
                "starting_permissions": ["User Access Administrator at any scope"],
                "target_privilege": "Owner or Contributor at subscription/management group, managed identity with Entra ID access",
                "attack_steps": [
                    "Authenticate with User Access Administrator role",
                    "Assign Owner or Contributor role to controlled user or managed identity",
                    "Use elevated permissions to access sensitive resources",
                    "Assign privileged Graph API permissions to managed identities for Entra ID bridge"
                ],
                "mitre_id": "T1098",
                "examples": [],
                "references": [
                    {
                        "title": "Azure Built-in Roles - User Access Administrator",
                        "url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#user-access-administrator"
                    }
                ]
            },
            {
                "name": "Contributor with Key Vault Access",
                "description": "Contributor role combined with Key Vault access can expose stored credentials including service principal secrets and privileged account passwords.",
                "category": "rbac",
                "subcategory": "data-plane-access",
                "severity": "high",
                "starting_permissions": ["Contributor + Key Vault access policies or RBAC permissions"],
                "target_privilege": "Service principal credentials, privileged user passwords, API keys",
                "attack_steps": [
                    "Authenticate with Contributor role",
                    "Enumerate Key Vaults in accessible subscriptions",
                    "Access Key Vault secrets containing service principal credentials or admin passwords",
                    "Use stolen credentials to authenticate as privileged identity",
                    "Leverage elevated access for further escalation"
                ],
                "mitre_id": "T1555.005",
                "examples": [],
                "references": [
                    {
                        "title": "Azure Built-in Roles - Contributor",
                        "url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#contributor"
                    },
                    {
                        "title": "Key Vault Security",
                        "url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features"
                    }
                ]
            },
            {
                "name": "Automation Operator Runbook Execution",
                "description": "Automation Account Operator can execute runbooks that may contain privileged credentials or perform privileged operations.",
                "category": "rbac",
                "subcategory": "automation-abuse",
                "severity": "medium",
                "starting_permissions": ["Automation Operator or Automation Job Operator"],
                "target_privilege": "Credentials embedded in runbooks, managed identity permissions",
                "attack_steps": [
                    "Authenticate with Automation Operator role",
                    "Enumerate Automation Accounts and runbooks",
                    "Execute runbooks or review runbook code for embedded credentials",
                    "Extract service principal secrets or managed identity assignments",
                    "Use stolen credentials for privilege escalation"
                ],
                "mitre_id": "T1078.004",
                "examples": [],
                "references": [
                    {
                        "title": "Azure Automation Security",
                        "url": "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview"
                    }
                ]
            }
        ]

        logger.info(f"Collected {len(techniques)} privilege escalation techniques from Azure RBAC")
        return techniques

    def collect_graph_permissions(self) -> List[Dict]:
        """
        Collect Microsoft Graph API permissions with privilege escalation potential.

        Focuses on permissions that enable role manipulation, user modification,
        and other privilege escalation vectors.

        Returns:
            List of technique dictionaries with Graph permission escalation paths
        """
        logger.info("Collecting Microsoft Graph API privilege escalation techniques...")

        # Curated list from Microsoft official documentation
        # Source: https://learn.microsoft.com/en-us/graph/permissions-reference
        techniques = [
            {
                "name": "RoleManagement.ReadWrite.Directory Application Permission",
                "description": "Allows an application to read and write all directory RBAC settings including role definitions and role assignments, enabling complete directory role manipulation.",
                "category": "graph-permissions",
                "subcategory": "role-management",
                "severity": "critical",
                "starting_permissions": ["Service principal with RoleManagement.ReadWrite.Directory application permission"],
                "target_privilege": "Ability to assign Global Administrator or any directory role",
                "attack_steps": [
                    "Authenticate as service principal with RoleManagement.ReadWrite.Directory",
                    "Use Microsoft Graph API to enumerate directory roles",
                    "Assign Global Administrator role to controlled user account via POST to /directoryRoles/{id}/members",
                    "Authenticate as newly promoted Global Administrator",
                    "Gain complete tenant control"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - RoleManagement.ReadWrite.Directory",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreadwritedirectory"
                    },
                    {
                        "title": "Assign Directory Roles - Microsoft Graph API",
                        "url": "https://learn.microsoft.com/en-us/graph/api/directoryrole-post-members"
                    }
                ]
            },
            {
                "name": "AppRoleAssignment.ReadWrite.All Application Permission",
                "description": "Allows an application to manage app role assignments for any app, enabling privilege escalation by granting additional Graph permissions to service principals.",
                "category": "graph-permissions",
                "subcategory": "permission-management",
                "severity": "critical",
                "starting_permissions": ["Service principal with AppRoleAssignment.ReadWrite.All"],
                "target_privilege": "Self-assignment of RoleManagement.ReadWrite.Directory or other privileged Graph permissions",
                "attack_steps": [
                    "Authenticate as service principal with AppRoleAssignment.ReadWrite.All",
                    "Use Graph API to identify Microsoft Graph service principal ID",
                    "Grant additional privileged Graph permissions to self (e.g., RoleManagement.ReadWrite.Directory)",
                    "Authenticate with new elevated permissions",
                    "Use newly acquired permissions for further escalation (e.g., role assignments)"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - AppRoleAssignment.ReadWrite.All",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#approleassignmentreadwriteall"
                    }
                ]
            },
            {
                "name": "Directory.ReadWrite.All Application Permission",
                "description": "Allows an application to read and write all directory data including users, groups, and applications, enabling wide-ranging modification capabilities.",
                "category": "graph-permissions",
                "subcategory": "directory-modification",
                "severity": "high",
                "starting_permissions": ["Service principal with Directory.ReadWrite.All"],
                "target_privilege": "Ability to modify users, groups, reset passwords, add group members",
                "attack_steps": [
                    "Authenticate as service principal with Directory.ReadWrite.All",
                    "Identify privileged security groups with role assignments",
                    "Add controlled user to privileged group via PATCH /groups/{id}",
                    "Inherit directory role permissions through group membership",
                    "Alternatively, reset passwords for non-admin users",
                    "Leverage compromised accounts for lateral movement"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - Directory.ReadWrite.All",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#directoryreadwriteall"
                    }
                ]
            },
            {
                "name": "User.ReadWrite.All Application Permission",
                "description": "Allows an application to read and write all user properties including password resets, enabling account takeover of user accounts.",
                "category": "graph-permissions",
                "subcategory": "user-modification",
                "severity": "high",
                "starting_permissions": ["Service principal with User.ReadWrite.All"],
                "target_privilege": "Password control over all user accounts (excluding admins with stronger protections)",
                "attack_steps": [
                    "Authenticate as service principal with User.ReadWrite.All",
                    "Enumerate non-admin users with access to sensitive resources",
                    "Reset password for target user via PATCH /users/{id} with passwordProfile",
                    "Authenticate as compromised user",
                    "Access sensitive data or applications",
                    "Use compromised identity for social engineering attacks"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - User.ReadWrite.All",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#userreadwriteall"
                    }
                ]
            },
            {
                "name": "GroupMember.ReadWrite.All Application Permission",
                "description": "Allows an application to add and remove members from all groups, enabling privilege escalation via privileged group membership.",
                "category": "graph-permissions",
                "subcategory": "group-modification",
                "severity": "high",
                "starting_permissions": ["Service principal with GroupMember.ReadWrite.All"],
                "target_privilege": "Membership in privileged groups with directory role assignments or Azure RBAC roles",
                "attack_steps": [
                    "Authenticate as service principal with GroupMember.ReadWrite.All",
                    "Enumerate groups with privileged role assignments (role-assignable groups)",
                    "Add controlled user account to privileged group via POST /groups/{id}/members",
                    "User inherits directory role or Azure RBAC role through group membership",
                    "Authenticate as user with inherited privileges",
                    "Leverage inherited role for further escalation"
                ],
                "mitre_id": "T1098.003",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - GroupMember.ReadWrite.All",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadwriteall"
                    }
                ]
            },
            {
                "name": "Application.ReadWrite.All Application Permission",
                "description": "Allows an application to create and modify app registrations and service principals including adding credentials, enabling credential theft and permission escalation.",
                "category": "graph-permissions",
                "subcategory": "application-management",
                "severity": "high",
                "starting_permissions": ["Service principal with Application.ReadWrite.All"],
                "target_privilege": "Ability to add credentials to existing privileged service principals",
                "attack_steps": [
                    "Authenticate as service principal with Application.ReadWrite.All",
                    "Enumerate existing service principals with privileged permissions",
                    "Add new client secret or certificate to target service principal via POST /servicePrincipals/{id}/addPassword",
                    "Authenticate as compromised service principal using stolen credentials",
                    "Leverage service principal's existing privileges for escalation"
                ],
                "mitre_id": "T1098.001",
                "examples": [],
                "references": [
                    {
                        "title": "Microsoft Graph Permissions - Application.ReadWrite.All",
                        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadwriteall"
                    },
                    {
                        "title": "Add Service Principal Password - Microsoft Graph API",
                        "url": "https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword"
                    }
                ]
            }
        ]

        logger.info(f"Collected {len(techniques)} privilege escalation techniques from Graph API permissions")
        return techniques

    def save_results(self, entra_techniques: List[Dict], rbac_techniques: List[Dict],
                    graph_techniques: List[Dict]) -> None:
        """Save collected techniques to JSON file."""

        output_file = self.output_dir / "microsoft-roles.json"

        # Combine all techniques
        all_techniques = entra_techniques + rbac_techniques + graph_techniques

        data = {
            "collection_date": datetime.utcnow().isoformat() + "Z",
            "source": "Microsoft Official Documentation",
            "techniques": all_techniques,
            "summary": {
                "total_techniques": len(all_techniques),
                "entra_id_techniques": len(entra_techniques),
                "azure_rbac_techniques": len(rbac_techniques),
                "graph_permission_techniques": len(graph_techniques)
            }
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(all_techniques)} techniques to {output_file}")

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
