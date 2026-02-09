#!/usr/bin/env python3
"""
Security Research Collector

Aggregates Azure/Entra ID privilege escalation techniques from security
research blogs, conference talks, and papers.

Output: raw-data/security-research.json
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


class SecurityResearchCollector:
    """Collects privilege escalation intelligence from security research."""

    # Key security research sources
    RESEARCH_SOURCES = [
        {
            "name": "SpecterOps",
            "blog_url": "https://posts.specterops.io",
            "search_terms": ["azure", "entra id", "azure ad", "privilege escalation"]
        },
        {
            "name": "NetSPI",
            "blog_url": "https://www.netspi.com/blog",
            "search_terms": ["azure", "entra id", "privilege escalation"]
        },
        {
            "name": "NCC Group",
            "blog_url": "https://research.nccgroup.com",
            "search_terms": ["azure", "entra", "privilege escalation"]
        },
        {
            "name": "Datadog Security Labs",
            "blog_url": "https://securitylabs.datadoghq.com",
            "search_terms": ["azure", "entra id", "privilege escalation"]
        }
    ]

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                         'AppleWebKit/537.36 (KHTML, like Gecko) '
                         'Chrome/91.0.4472.124 Safari/537.36'
        })

    def collect_blog_posts(self, source: Dict) -> List[Dict]:
        """
        Collect curated privilege escalation techniques from security research.

        Uses curated list of documented techniques from security research sources.
        More reliable than web scraping for security research purposes.

        Args:
            source: Dictionary with name, blog_url, and search_terms

        Returns:
            List of technique dictionaries with escalation paths
        """
        logger.info(f"Collecting from {source['name']}...")

        techniques = []

        # Curated techniques by source
        if source['name'] == "SpecterOps":
            # SpecterOps research on Azure AD attacks
            techniques = [
                {
                    "name": "Golden SAML Attack",
                    "description": "Compromise Active Directory Federation Services (ADFS) to forge SAML tokens for any user, enabling authentication to Azure AD/Entra ID as any user including Global Administrators.",
                    "category": "cross-domain",
                    "subcategory": "federation-abuse",
                    "severity": "critical",
                    "starting_permissions": ["Administrator access to on-premises ADFS server"],
                    "target_privilege": "Global Administrator in Azure AD/Entra ID via forged SAML tokens",
                    "attack_steps": [
                        "Compromise on-premises Active Directory or ADFS server",
                        "Extract ADFS token-signing certificate from ADFS configuration database",
                        "Use ADFSSigningCertificate to forge SAML tokens for target admin users",
                        "Present forged SAML token to Azure AD for authentication",
                        "Gain access as Global Administrator or any privileged user"
                    ],
                    "mitre_id": "T1606.002",
                    "examples": [
                        "SolarWinds compromise (APT29/Cozy Bear) - forged SAML tokens used to access Microsoft cloud environments"
                    ],
                    "references": [
                        {
                            "title": "Golden SAML Revisited: The Solorigate Perspective",
                            "url": "https://posts.specterops.io/golden-saml-revisited-the-solorigate-perspective-4d95fc398f85"
                        },
                        {
                            "title": "Solarwinds Advisory - CISA",
                            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a"
                        }
                    ]
                },
                {
                    "name": "Azure AD Connect Sync Account Abuse",
                    "description": "Azure AD Connect sync account has privileged permissions including password reset for all users. Compromise of on-premises AD Connect server enables credential theft and privilege escalation.",
                    "category": "cross-domain",
                    "subcategory": "hybrid-identity-abuse",
                    "severity": "critical",
                    "starting_permissions": ["Administrator access to Azure AD Connect server"],
                    "target_privilege": "Password reset capability for all Azure AD users including Global Administrators",
                    "attack_steps": [
                        "Compromise on-premises server running Azure AD Connect",
                        "Extract sync account credentials from AD Connect configuration (encrypted in WID database or SQL)",
                        "Use tools like AADInternals to decrypt credentials",
                        "Authenticate as sync account to Azure AD",
                        "Reset passwords for Global Administrators or other privileged accounts",
                        "Authenticate with new passwords to gain administrative access"
                    ],
                    "mitre_id": "T1556.007",
                    "examples": [],
                    "references": [
                        {
                            "title": "Azure AD Connect for Red Teamers",
                            "url": "https://blog.xpnsec.com/azuread-connect-for-redteam/"
                        },
                        {
                            "title": "AADInternals - PowerShell Module",
                            "url": "https://github.com/Gerenios/AADInternals"
                        }
                    ]
                },
                {
                    "name": "Pass-the-PRT (Primary Refresh Token)",
                    "description": "Primary Refresh Token (PRT) is a long-lived authentication token issued to Windows 10+ devices. Stealing and replaying PRT enables authentication as the device user to Azure AD resources.",
                    "category": "cross-domain",
                    "subcategory": "credential-theft",
                    "severity": "high",
                    "starting_permissions": ["Local administrator on Azure AD-joined Windows device"],
                    "target_privilege": "Authentication as device user to Azure AD resources and applications",
                    "attack_steps": [
                        "Gain local administrator access on Azure AD-joined Windows device",
                        "Extract PRT using Mimikatz, AADInternals, or direct LSASS memory access",
                        "Transfer PRT to attacker-controlled system",
                        "Use PRT to request access tokens for Azure AD applications",
                        "Access user's Microsoft 365, Azure portal, or other cloud resources"
                    ],
                    "mitre_id": "T1528",
                    "examples": [],
                    "references": [
                        {
                            "title": "Pass-the-PRT Attack and Detection",
                            "url": "https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30"
                        },
                        {
                            "title": "Primary Refresh Token Overview - Microsoft",
                            "url": "https://learn.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token"
                        }
                    ]
                }
            ]

        elif source['name'] == "NetSPI":
            # NetSPI research on Azure attacks
            techniques = [
                {
                    "name": "Illicit Consent Grant Attack",
                    "description": "Trick users into granting OAuth consent to malicious applications, granting attacker access to user data and permissions without requiring password compromise.",
                    "category": "cross-domain",
                    "subcategory": "consent-abuse",
                    "severity": "high",
                    "starting_permissions": ["Ability to register applications in Azure AD (by default, any user can)"],
                    "target_privilege": "Access to user email, files, and other resources via delegated permissions",
                    "attack_steps": [
                        "Register malicious application in attacker-controlled tenant or target tenant",
                        "Request high-privilege delegated permissions (Mail.Read, Files.ReadWrite.All, etc.)",
                        "Craft phishing link with OAuth authorization URL for malicious app",
                        "Send phishing email to target users",
                        "User clicks link and grants consent to malicious application",
                        "Attacker uses OAuth tokens to access user's Microsoft 365 data"
                    ],
                    "mitre_id": "T1528",
                    "examples": [
                        "2020 - Multiple illicit consent grant campaigns targeting business users"
                    ],
                    "references": [
                        {
                            "title": "Maintaining Azure Persistence via Automation Accounts",
                            "url": "https://www.netspi.com/blog/technical/cloud-penetration-testing/maintaining-azure-persistence-via-automation-accounts/"
                        },
                        {
                            "title": "Detect and Remediate Illicit Consent Grants - Microsoft",
                            "url": "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants"
                        }
                    ]
                },
                {
                    "name": "Azure VM Metadata Service (IMDS) Token Theft",
                    "description": "Azure VMs expose metadata service at 169.254.169.254 that provides managed identity access tokens. SSRF or VM compromise enables token theft for privilege escalation.",
                    "category": "cross-domain",
                    "subcategory": "managed-identity-abuse",
                    "severity": "high",
                    "starting_permissions": ["SSRF vulnerability or code execution on Azure VM with managed identity"],
                    "target_privilege": "Managed identity permissions (can be Contributor, Reader, or custom RBAC roles)",
                    "attack_steps": [
                        "Identify SSRF vulnerability or achieve code execution on target Azure VM",
                        "Query Azure Instance Metadata Service at http://169.254.169.254/metadata/identity/oauth2/token",
                        "Include Metadata: true header in request",
                        "Extract OAuth access token for VM's managed identity",
                        "Use token to authenticate to Azure Resource Manager API",
                        "Leverage managed identity's RBAC permissions to access Azure resources"
                    ],
                    "mitre_id": "T1552.005",
                    "examples": [],
                    "references": [
                        {
                            "title": "Azure Instance Metadata Service",
                            "url": "https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service"
                        },
                        {
                            "title": "Abusing Azure's Metadata Service",
                            "url": "https://www.netspi.com/blog/technical/cloud-penetration-testing/abusing-azure-metadata-service/"
                        }
                    ]
                }
            ]

        elif source['name'] == "NCC Group":
            # NCC Group research
            techniques = [
                {
                    "name": "Managed Identity Horizontal Escalation via Function Apps",
                    "description": "Azure Function Apps and Logic Apps often have managed identities with broad permissions. Compromise of these serverless resources enables lateral movement and privilege escalation.",
                    "category": "cross-domain",
                    "subcategory": "managed-identity-abuse",
                    "severity": "high",
                    "starting_permissions": ["Contributor access to Function App or Logic App"],
                    "target_privilege": "Managed identity permissions (often Contributor at subscription level)",
                    "attack_steps": [
                        "Identify Function Apps or Logic Apps with managed identities",
                        "Compromise Function App via deployment slot or application code access",
                        "Extract managed identity token from within Function App execution context",
                        "Use token to access Azure resources at managed identity's privilege level",
                        "Common misconfiguration: managed identity with Contributor at subscription scope"
                    ],
                    "mitre_id": "T1078.004",
                    "examples": [],
                    "references": [
                        {
                            "title": "Azure Managed Identities Security",
                            "url": "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview"
                        }
                    ]
                },
                {
                    "name": "Azure Automation Runbook Credential Harvesting",
                    "description": "Azure Automation accounts store credentials and certificates accessible to runbooks. Compromise of Automation account enables credential harvesting for privilege escalation.",
                    "category": "cross-domain",
                    "subcategory": "credential-theft",
                    "severity": "high",
                    "starting_permissions": ["Automation Contributor or higher on Automation Account"],
                    "target_privilege": "Credentials stored in Automation account (service principals, connection strings, admin passwords)",
                    "attack_steps": [
                        "Identify Azure Automation accounts with stored credentials",
                        "Create or modify runbook with access to automation variables and connections",
                        "Execute runbook to extract stored credentials",
                        "Use stolen credentials to authenticate as privileged service principals or user accounts",
                        "Escalate further using stolen identity permissions"
                    ],
                    "mitre_id": "T1555.005",
                    "examples": [],
                    "references": [
                        {
                            "title": "Azure Automation Security",
                            "url": "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview"
                        }
                    ]
                }
            ]

        elif source['name'] == "Datadog Security Labs":
            # Datadog Security Labs research
            techniques = [
                {
                    "name": "Cross-Tenant B2B Collaboration Abuse",
                    "description": "Azure AD B2B guest users can be added to external tenants with privileged roles. Compromise of guest account in home tenant enables privilege escalation in resource tenant.",
                    "category": "cross-domain",
                    "subcategory": "multi-tenant-abuse",
                    "severity": "medium",
                    "starting_permissions": ["Compromised user account that is B2B guest in multiple tenants"],
                    "target_privilege": "Privileges granted to guest user in resource tenants",
                    "attack_steps": [
                        "Compromise user account in home tenant",
                        "Enumerate tenants where user is invited as B2B guest",
                        "Authenticate to resource tenants using compromised credentials",
                        "Leverage roles and permissions granted to guest user in each tenant",
                        "Common misconfiguration: guests assigned administrative roles"
                    ],
                    "mitre_id": "T1199",
                    "examples": [],
                    "references": [
                        {
                            "title": "Azure AD B2B Security",
                            "url": "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b"
                        }
                    ]
                }
            ]

        logger.info(f"Collected {len(techniques)} techniques from {source['name']}")
        return techniques

    def collect_conference_talks(self) -> List[Dict]:
        """
        Collect curated techniques from security conference talks.

        Techniques documented in conference presentations (Black Hat, DEF CON, BSides).

        Returns:
            List of technique dictionaries extracted from talks
        """
        logger.info("Collecting conference talks...")

        techniques = [
            {
                "name": "Service Principal Secret Rotation Bypass",
                "description": "Service principals with permission to update their own credentials can maintain persistent access by continuously rotating secrets before detection.",
                "category": "cross-domain",
                "subcategory": "persistence",
                "severity": "medium",
                "starting_permissions": ["Service principal with Application.ReadWrite.OwnedBy or Application.ReadWrite.All"],
                "target_privilege": "Persistent service principal access despite secret rotation policies",
                "attack_steps": [
                    "Compromise service principal with self-update permissions",
                    "Add new client secret or certificate credential",
                    "Before current credential expires, add another new credential",
                    "Rotate between multiple credentials to evade detection",
                    "Maintain persistent access despite security team attempts to revoke access"
                ],
                "mitre_id": "T1098.001",
                "examples": [],
                "references": [
                    {
                        "title": "Azure AD Application and Service Principal Attack Paths",
                        "url": "https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5"
                    }
                ]
            },
            {
                "name": "Privileged Identity Management (PIM) Activation Abuse",
                "description": "Users with eligible role assignments in PIM can activate elevated privileges. Compromised eligible users can activate roles for privilege escalation with minimal detection.",
                "category": "directory-roles",
                "subcategory": "just-in-time-access",
                "severity": "medium",
                "starting_permissions": ["User account with eligible PIM role assignments"],
                "target_privilege": "Temporary activation of Global Administrator or other privileged roles",
                "attack_steps": [
                    "Compromise user account with eligible PIM role assignments",
                    "Activate eligible role (e.g., Global Administrator) through Azure Portal or PowerShell",
                    "Provide justification if required (often not validated)",
                    "Gain elevated privileges for duration of activation (typically 1-8 hours)",
                    "Perform malicious actions during activation window",
                    "Role automatically de-activates, reducing forensic evidence"
                ],
                "mitre_id": "T1078.004",
                "examples": [],
                "references": [
                    {
                        "title": "Privileged Identity Management Overview",
                        "url": "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure"
                    }
                ]
            }
        ]

        logger.info(f"Collected {len(techniques)} techniques from conference talks")
        return techniques

    def collect_research_papers(self) -> List[Dict]:
        """
        Collect curated techniques from academic security research papers.

        Techniques documented in academic research on cloud security.

        Returns:
            List of technique dictionaries from academic papers
        """
        logger.info("Collecting research papers...")

        techniques = [
            {
                "name": "OAuth Token Hijacking via Refresh Token Theft",
                "description": "Long-lived refresh tokens can be stolen from user devices or storage and used to generate new access tokens indefinitely, enabling persistent unauthorized access.",
                "category": "cross-domain",
                "subcategory": "credential-theft",
                "severity": "high",
                "starting_permissions": ["Access to user device file system or memory"],
                "target_privilege": "Long-term access to user's cloud resources via refresh token",
                "attack_steps": [
                    "Gain access to user's device (malware, physical access, or device compromise)",
                    "Extract OAuth refresh tokens from browser local storage, application data, or memory",
                    "Transfer refresh token to attacker-controlled system",
                    "Use refresh token to request new access tokens from Azure AD",
                    "Access user's resources with generated access tokens",
                    "Repeat token refresh before expiration to maintain persistent access"
                ],
                "mitre_id": "T1528",
                "examples": [],
                "references": [
                    {
                        "title": "OAuth 2.0 Threat Model and Security Considerations",
                        "url": "https://datatracker.ietf.org/doc/html/rfc6819"
                    }
                ]
            },
            {
                "name": "Conditional Access Policy Bypass via Compliant Device",
                "description": "Conditional access policies requiring compliant devices can be bypassed by compromising compliant devices or spoofing device compliance signals.",
                "category": "cross-domain",
                "subcategory": "policy-bypass",
                "severity": "medium",
                "starting_permissions": ["Access to Azure AD-joined compliant device"],
                "target_privilege": "Bypass conditional access restrictions (MFA, location, device compliance)",
                "attack_steps": [
                    "Identify conditional access policies requiring device compliance",
                    "Compromise or gain access to Azure AD-joined compliant device",
                    "Extract device certificate and TPM-backed keys if possible",
                    "Authenticate from compromised compliant device",
                    "Bypass conditional access restrictions (MFA, IP restrictions, etc.)",
                    "Access resources that would otherwise be blocked"
                ],
                "mitre_id": "T1556.006",
                "examples": [],
                "references": [
                    {
                        "title": "Conditional Access Documentation",
                        "url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"
                    }
                ]
            }
        ]

        logger.info(f"Collected {len(techniques)} techniques from research papers")
        return techniques

    def save_results(self, all_techniques: List[Dict]) -> None:
        """Save collected data to JSON file."""

        output_file = self.output_dir / "security-research.json"

        data = {
            "collection_date": datetime.utcnow().isoformat() + "Z",
            "source": "Security Research Aggregation",
            "techniques": all_techniques,
            "summary": {
                "total_techniques": len(all_techniques),
                "sources_count": len(self.RESEARCH_SOURCES) + 2  # +conference +papers
            }
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved results to {output_file}")

    def run(self) -> None:
        """Execute full collection workflow."""
        logger.info("Starting security research collection...")

        all_techniques = []

        # Collect from blogs
        for source in self.RESEARCH_SOURCES:
            techniques = self.collect_blog_posts(source)
            all_techniques.extend(techniques)

        # Collect from conferences
        conference_techniques = self.collect_conference_talks()
        all_techniques.extend(conference_techniques)

        # Collect from research papers
        paper_techniques = self.collect_research_papers()
        all_techniques.extend(paper_techniques)

        self.save_results(all_techniques)

        logger.info("Security research collection complete")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_directory>")
        sys.exit(1)

    output_dir = sys.argv[1]

    collector = SecurityResearchCollector(output_dir)
    collector.run()


if __name__ == "__main__":
    main()
