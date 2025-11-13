package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure/iam"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureIAMPullSDK = chain.NewModule(
	cfg.NewMetadata(
		"Azure IAM Pull SDK - Comprehensive Identity & Access Management Enumeration",
		"Collects Azure AD, PIM, and Azure Resource Manager data using Azure SDKs with standard authentication via az login.",
	).WithProperties(map[string]any{
		"id":          "iam-pull-sdk",
		"platform":    "azure",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{
			"https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/",
			"https://learn.microsoft.com/en-us/graph/api/overview",
			"https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-rest",
		},
	}),
).WithLinks(
	// Single comprehensive SDK-based collector link
	// Uses standard Azure authentication (az login) instead of refresh token
	iam.NewSDKComprehensiveCollectorLink,
).WithInputParam(
	options.AzureSubscription(),
).WithOutputters(
	// Use standard Nebula JSON outputter for single consolidated file
	outputters.NewRuntimeJSONOutputter,
).WithConfigs(
	// Set default output directory if not specified
	cfg.WithArg("output", "./nebula-output"),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "iam-pull-sdk", *AzureIAMPullSDK)
}