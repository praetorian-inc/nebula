package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureIAMPull = chain.NewModule(
	cfg.NewMetadata(
		"Azure IAM Pull - Comprehensive Identity & Access Management Enumeration",
		"Collects Azure AD, PIM, and Azure Resource Manager data in AzureHunter format. Requires refresh token authentication.",
	).WithProperties(map[string]any{
		"id":          "iam-pull",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{
			"https://github.com/praetorian-inc/AzureHunter",
			"https://learn.microsoft.com/en-us/graph/api/overview",
			"https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest",
		},
	}),
).WithLinks(
	// Collect ALL Azure data (Graph, PIM, AzureRM) in one comprehensive link
	// Subscription discovery is handled internally by this link
	azure.NewIAMComprehensiveCollectorLink,
).WithInputParam(
	options.AzureSubscription(),
).WithParams(
	options.AzureRefreshToken(),
	options.AzureTenantID(),
	options.AzureProxy(),
).WithOutputters(
	// Use standard Nebula JSON outputter for single consolidated file
	outputters.NewRuntimeJSONOutputter,
).WithConfigs(
	// Set default output directory if not specified
	cfg.WithArg("output", "./nebula-output"),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "iam-pull", *AzureIAMPull)
}