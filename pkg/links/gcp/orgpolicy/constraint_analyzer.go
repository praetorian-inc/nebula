package orgpolicy

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

type ConstraintConfig struct {
	ExpectedEnforced  bool
	AllowlistRequired bool
	Description       string
	Rationale         string
	Severity          string
}

var secureConstraintConfigs = map[string]ConstraintConfig{
	"constraints/iam.automaticIamGrantsForDefaultServiceAccounts": {
		ExpectedEnforced: true,
		Description:      "Disable Automatic IAM Grants for Default Service Accounts",
		Rationale:        "Default service accounts are automatically granted the Editor role, which violates least privilege principles",
		Severity:         "HIGH",
	},
	"constraints/compute.skipDefaultNetworkCreation": {
		ExpectedEnforced: true,
		Description:      "Skip Default Network Creation",
		Rationale:        "Default VPC includes permissive firewall rules allowing SSH/RDP from internet",
		Severity:         "HIGH",
	},
	"constraints/sql.restrictPublicIp": {
		ExpectedEnforced: true,
		Description:      "Restrict Public IP access on Cloud SQL instances",
		Rationale:        "Public IP access exposes databases to internet-based attacks",
		Severity:         "CRITICAL",
	},
	"constraints/cloudbuild.useBuildServiceAccount": {
		ExpectedEnforced: false,
		Description:      "Disable Default Cloud Build Service Account",
		Rationale:        "Legacy Cloud Build service account has excessive privileges including arbitrary Storage operations",
		Severity:         "HIGH",
	},
	"constraints/cloudbuild.useComputeServiceAccount": {
		ExpectedEnforced: false,
		Description:      "Disable Compute Engine Service Account by Default (Cloud Build)",
		Rationale:        "Prevents privilege escalation via Cloud Build using overprivileged Compute Engine default SA",
		Severity:         "HIGH",
	},
	"constraints/iam.disableServiceAccountKeyCreation": {
		ExpectedEnforced: true,
		Description:      "Disable Service Account Key Creation",
		Rationale:        "Service account keys provide long-term access and are difficult to rotate, creating security risks",
		Severity:         "MEDIUM",
	},
	"constraints/storage.publicAccessPrevention": {
		ExpectedEnforced: true,
		Description:      "Enforce Public Access Prevention",
		Rationale:        "Prevents data exposure by blocking ACLs and IAM permissions granting access to allUsers/allAuthenticatedUsers",
		Severity:         "CRITICAL",
	},
	"constraints/iam.allowedPolicyMemberDomains": {
		AllowlistRequired: true,
		Description:       "Domain Restricted Sharing",
		Rationale:         "Restricts IAM policy members to approved domains, preventing unauthorized external access",
		Severity:          "MEDIUM",
	},
}

type GcpConstraintAnalyzerLink struct {
	*base.GcpBaseLink
}

func NewGcpConstraintAnalyzerLink(configs ...cfg.Config) chain.Link {
	g := &GcpConstraintAnalyzerLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpConstraintAnalyzerLink) Initialize() error {
	return g.GcpBaseLink.Initialize()
}

func (g *GcpConstraintAnalyzerLink) Process(resource tab.GCPResource) error {
	if !isPolicyResource(resource.ResourceType) {
		return nil
	}

	constraintID, ok := resource.Properties["constraintId"].(string)
	if !ok {
		return nil
	}

	config, exists := secureConstraintConfigs[constraintID]
	if !exists {
		return nil
	}

	isCompliant, expectedConfig, actualConfig := evaluateCompliance(resource.Properties, config)

	resource.Properties["isCompliant"] = isCompliant
	resource.Properties["expectedConfig"] = expectedConfig
	resource.Properties["actualConfig"] = actualConfig
	resource.Properties["severity"] = config.Severity
	resource.Properties["description"] = config.Description
	resource.Properties["rationale"] = config.Rationale

	g.Send(resource)
	return nil
}

func isPolicyResource(resourceType tab.CloudResourceType) bool {
	return resourceType == tab.GCPResourceOrganizationPolicy ||
		resourceType == tab.GCPResourceFolderPolicy ||
		resourceType == tab.GCPResourceProjectPolicy
}

func evaluateCompliance(properties map[string]any, config ConstraintConfig) (bool, string, string) {
	if config.AllowlistRequired {
		return evaluateAllowlistCompliance(properties, config)
	}
	return evaluateBooleanCompliance(properties, config)
}

func evaluateBooleanCompliance(properties map[string]any, config ConstraintConfig) (bool, string, string) {
	enforced, ok := properties["enforced"].(bool)
	if !ok {
		enforced = false
	}

	expectedConfig := fmt.Sprintf("enforced=%t", config.ExpectedEnforced)
	actualConfig := fmt.Sprintf("enforced=%t", enforced)

	isCompliant := enforced == config.ExpectedEnforced

	return isCompliant, expectedConfig, actualConfig
}

func evaluateAllowlistCompliance(properties map[string]any, config ConstraintConfig) (bool, string, string) {
	allowedValues, hasAllowed := properties["allowedValues"].([]string)
	deniedValues, hasDenied := properties["deniedValues"].([]string)

	expectedConfig := "allowedValues configured with domain restrictions"

	if !hasAllowed && !hasDenied {
		actualConfig := "no domain restrictions configured"
		return false, expectedConfig, actualConfig
	}

	if hasAllowed && len(allowedValues) > 0 {
		actualConfig := fmt.Sprintf("allowedValues=%v", allowedValues)
		return true, expectedConfig, actualConfig
	}

	if hasDenied && len(deniedValues) > 0 {
		actualConfig := fmt.Sprintf("deniedValues=%v", deniedValues)
		return true, expectedConfig, actualConfig
	}

	actualConfig := "no effective domain restrictions"
	return false, expectedConfig, actualConfig
}
