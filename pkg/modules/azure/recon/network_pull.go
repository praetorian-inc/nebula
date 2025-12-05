package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure/network"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureNetworkPull = chain.NewModule(
	cfg.NewMetadata(
		"Azure Network Pull - Streamlined Network Topology Collection",
		"Collects network topology focusing on security-relevant resources with service tag expansion",
	).WithProperties(map[string]any{
		"id":          "network-pull",
		"platform":    "azure",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.microsoft.com/azure/virtual-network/",
			"https://docs.microsoft.com/azure/network-watcher/",
			"https://www.microsoft.com/en-us/download/details.aspx?id=56519",
		},
	}),
).WithLinks(
	// Use the new topology collector with service tag expansion
	network.NewNetworkTopologyCollectorLink,
).WithOutputters(
	// Output to JSON file for persistence
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	// Expose subscription parameter from the link
	cfg.NewParam[string]("subscription", "Target subscription ID or 'all' for all subscriptions").
		WithDefault("all").
		WithShortcode("s"),
	cfg.NewParam[bool]("expand-service-tags", "Expand Azure service tags to IP ranges").
		WithDefault(true),
).WithConfigs(
	// Output directory for collected data
	cfg.WithArg("output", "./nebula-output"),
	// Output file name
	cfg.WithArg("outfile", "network-topology.jsonl"),
	// Default subscription to all
	cfg.WithArg("subscription", "all"),
	// Enable service tag expansion (default: true)
	cfg.WithArg("expand-service-tags", true),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "network-pull", *AzureNetworkPull)
}