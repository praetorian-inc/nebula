package hierarchy

import (
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/compute"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/containers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/storage"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

type GcpOrgAllResourcesFanOut struct {
	*base.GcpBaseLink
}

// creates a link to fan out to all resource discovery links for each project
func NewGcpOrgAllResourcesFanOut(configs ...cfg.Config) chain.Link {
	g := &GcpOrgAllResourcesFanOut{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgAllResourcesFanOut) Process(resource tab.GCPResource) error {
	// Only process projects - don't forward non-project resources to prevent infinite loop
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}

	// Forward the project itself
	g.Send(&resource)

	// Create multi-chain for all resource types
	multi := chain.NewMulti(
		// Storage resources
		chain.NewChain(storage.NewGcpStorageBucketListLink()),
		chain.NewChain(storage.NewGcpSQLInstanceListLink()),

		// Compute resources
		chain.NewChain(compute.NewGcpInstanceListLink()),

		// Networking resources (already has its own fanout)
		chain.NewChain(compute.NewGCPNetworkingFanOut()),

		// Application resources
		chain.NewChain(applications.NewGcpFunctionListLink()),
		chain.NewChain(applications.NewGcpCloudRunServiceListLink()),
		chain.NewChain(applications.NewGcpAppEngineApplicationListLink()),

		// Container resources - chained together
		chain.NewChain(
			containers.NewGcpRepositoryListLink(),
			containers.NewGcpContainerImageListLink(),
		),
	)

	multi.WithConfigs(cfg.WithArgs(g.Args()))
	multi.WithStrictness(chain.Lax)
	multi.Send(resource)
	multi.Close()

	// Collect and forward all results
	for result, ok := chain.RecvAs[*tab.GCPResource](multi); ok; result, ok = chain.RecvAs[*tab.GCPResource](multi) {
		g.Send(result)
	}

	if err := multi.Error(); err != nil {
		slog.Warn("Some resources failed for project (continuing with others)", "project", resource.Name, "error", err)

		resourceErrors := common.ParseAggregatedListError(resource.Name, err.Error())
		for _, resourceError := range resourceErrors {
			g.Send(resourceError)
		}
	}
	return nil
}
