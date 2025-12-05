package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure/network"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureNetworkPush = chain.NewModule(
	cfg.NewMetadata(
		"Azure Network Push - Neo4j Network Topology Import",
		"Imports network topology with pre-processed security rules for query-time analysis",
	).WithProperties(map[string]any{
		"id":          "network-push",
		"platform":    "azure",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://neo4j.com/developer/graph-database/",
			"https://docs.microsoft.com/azure/network-watcher/network-watcher-topology-overview/",
		},
	}),
).WithParams(
	// Declare parameters that can be provided via command line
	cfg.NewParam[string]("neo4j-url", "Neo4j connection URL"),
	cfg.NewParam[string]("neo4j-user", "Neo4j username"),
	cfg.NewParam[string]("neo4j-password", "Neo4j password"),
	cfg.NewParam[string]("data-file", "Input data file path"),
	cfg.NewParam[bool]("clear-db", "Clear database before import"),
).WithConfigs(
	// Neo4j connection parameters (default Neo4j port)
	cfg.WithArg("neo4j-url", "bolt://localhost:7687"),
	cfg.WithArg("neo4j-user", "neo4j"),
	cfg.WithArg("neo4j-password", ""),  // No default password for security
	// Input data file (from network-pull)
	cfg.WithArg("data-file", "./nebula-output/network-topology-all-subscriptions.json"),
	// Clear database before import
	cfg.WithArg("clear-db", false),
	// Set default output directory for import summary
	cfg.WithArg("output", "./nebula-output"),
).WithLinks(
	// Read the JSONL file first
	network.NewJSONLReaderLink,
	// Then import to Neo4j
	network.NewNetworkTopologyImporterLink,
).WithOutputters(
	// Runtime JSON outputter for import summary
	outputters.NewRuntimeJSONOutputter,
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "network-push", *AzureNetworkPush)
}