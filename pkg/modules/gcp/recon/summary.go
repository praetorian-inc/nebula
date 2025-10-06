package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpSummary.Metadata().Properties()["id"].(string), *GcpSummary)
}

var GcpSummary = chain.NewModule(
	cfg.NewMetadata(
		"GCP Summary",
		"Summarize resources within an organization, folder, or project scope (requires Asset API)",
	).WithProperties(map[string]any{
		"id":          "summary",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://cloud.google.com/asset-inventory/docs/overview",
			"https://cloud.google.com/asset-inventory/docs/search-resources",
		},
	}),
).WithLinks(
	hierarchy.NewGcpAssetSearchRouterLink,
	hierarchy.NewGcpSummaryOutputFormatterLink,
).WithOutputters(
	outputters.NewMarkdownTableConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
).WithConfigs(
	cfg.WithArg("module-name", "summary"),
).WithAutoRun()
