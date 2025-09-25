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
	registry.Register("gcp", "recon", GcpOrgAllScan.Metadata().Properties()["id"].(string), *GcpOrgAllScan)
}

var GcpOrgAllScan = chain.NewModule(
	cfg.NewMetadata(
		"GCP Organization-Wide All Resources Scan",
		"Scan all available resource types across all projects in a GCP organization.",
	).WithProperties(map[string]any{
		"id":          "all-recon-org-scan",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithLinks(
	hierarchy.NewGcpOrgInfoLink,              // Get organization info
	hierarchy.NewGcpOrgProjectListLink,       // List all projects (with recursive folder traversal)
	hierarchy.NewGcpOrgAllResourcesFanOut,    // Fan out to all resource types for each project
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[bool]("filter-sys-projects", "filter out system projects").WithDefault(true),
).WithConfigs(
	cfg.WithArg("module-name", "all-recon-org-scan"),
	cfg.WithArg("filter-sys-projects", true),
).WithStrictness(chain.Lax)