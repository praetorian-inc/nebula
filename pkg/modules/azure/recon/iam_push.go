package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/azure/iam"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var AzureIAMPush = chain.NewModule(
	cfg.NewMetadata(
		"Azure IAM Push - Neo4j Import for BloodHound Analysis",
		"Imports consolidated Azure IAM data into Neo4j for Entra ID attack path analysis using simplified graph model.",
	).WithProperties(map[string]any{
		"id":          "iam-push",
		"platform":    "azure",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references":  []string{
			"https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
			"https://neo4j.com/developer/graph-database/",
			"https://bloodhound.readthedocs.io/en/latest/",
		},
	}),
).WithLinks(
	// Single comprehensive Neo4j importer with simplified graph model
	iam.NewNeo4jImporterLink,
).WithOutputters(
	// Standard Nebula JSON outputter for import summary
	outputters.NewRuntimeJSONOutputter,
).WithConfigs(
	// Neo4j connection parameters
	cfg.WithArg("neo4j-url", "bolt://localhost:7687"),
	cfg.WithArg("neo4j-user", "neo4j"),
	cfg.WithArg("neo4j-password", ""),
	cfg.WithArg("data-file", ""),
	cfg.WithArg("clear-db", false),
).WithAutoRun()

func init() {
	registry.Register("azure", "recon", "iam-push", *AzureIAMPush)
}