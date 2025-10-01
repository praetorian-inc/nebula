package analysis

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	azgraph "github.com/praetorian-inc/nebula/pkg/links/azure/graph"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "analysis", "azedge", *AzureGraphEdge)
}

// AzureGraphEdge creates edges between Entra ID entities in Neo4j
var AzureGraphEdge = chain.NewModule(
	cfg.NewMetadata(
		"Azure Graph Edge Creation",
		"Create relationships and attack path edges between Entra ID entities in Neo4j",
	).WithProperties(map[string]any{
		"id":          "azedge",
		"platform":    "azure",
		"category":    "analysis",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://bloodhound.specterops.io/resources/edges/overview",
			"https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48",
		},
	}),
).WithLinks(
	azgraph.NewAzureNeo4jReaderLink,
	azgraph.NewAzureRelationshipBuilderLink,
	azgraph.NewAzureEdgeDetectorRegistryLink,
	azgraph.NewAzureNeo4jWriterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
)