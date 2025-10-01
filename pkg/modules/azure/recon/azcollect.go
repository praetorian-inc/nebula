package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	azgraph "github.com/praetorian-inc/nebula/pkg/links/azure/graph"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("azure", "recon", "azcollect", *AzureGraphCollect)
}

// AzureGraphCollect collects Entra ID entities using Microsoft Graph API
var AzureGraphCollect = chain.NewModule(
	cfg.NewMetadata(
		"Azure Graph Collect",
		"Collect Entra ID entities from Microsoft Graph API and store in Neo4j",
	).WithProperties(map[string]any{
		"id":          "azcollect",
		"platform":    "azure",
		"category":    "recon",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://learn.microsoft.com/en-us/graph/overview",
			"https://learn.microsoft.com/en-us/graph/permissions-reference",
		},
	}),
).WithLinks(
	azgraph.NewAzureAuthManagerLink,
	azgraph.NewAzureCollectorRegistryLink,
	azgraph.NewAzureNeo4jWriterLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
)