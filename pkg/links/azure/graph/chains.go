package graph

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/client"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/collectors"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/edges"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// NewAzureGraphCollectionChain creates a chain for collecting Azure Graph data
func NewAzureGraphCollectionChain(config cfg.Config) chain.Chain {
	return chain.NewChain(
		client.NewAzureAuthManagerLink(),
		collectors.NewAzureCollectorRegistryLink(),
		storage.NewAZNeo4jWriterLink(),
	).WithConfigs(config)
}

// NewAzureGraphEdgeChain creates a chain for creating edges between Azure Graph entities
func NewAzureGraphEdgeChain(config cfg.Config) chain.Chain {
	return chain.NewChain(
		storage.NewAZNeo4jReaderLink(),
		edges.NewAzureRelationshipBuilderLink(),
		edges.NewAzureEdgeDetectorRegistryLink(),
		storage.NewAZNeo4jWriterLink(),
	).WithConfigs(config)
}

// Export link constructors for module usage
var (
	NewAzureAuthManagerLink        = client.NewAzureAuthManagerLink
	NewAzureCollectorRegistryLink  = collectors.NewAzureCollectorRegistryLink
	NewAzureNeo4jWriterLink        = storage.NewAZNeo4jWriterLink
	NewAzureNeo4jReaderLink        = storage.NewAZNeo4jReaderLink
	NewAzureRelationshipBuilderLink = edges.NewAzureRelationshipBuilderLink
	NewAzureEdgeDetectorRegistryLink = edges.NewAzureEdgeDetectorRegistryLink
)