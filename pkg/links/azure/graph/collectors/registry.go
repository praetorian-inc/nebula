package collectors

import (
	"context"
	"fmt"
	"sort"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZCollector interface for all Azure Graph collectors
type AZCollector interface {
	Name() string
	Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error
	Priority() int // Lower number = higher priority
}

// AzureCollectorRegistryLink manages and runs all collectors
type AzureCollectorRegistryLink struct {
	*chain.Base
	collectors []AZCollector
}

func NewAzureCollectorRegistryLink(configs ...cfg.Config) chain.Link {
	l := &AzureCollectorRegistryLink{}
	l.Base = chain.NewBase(l, configs...)

	// Register all collectors
	l.collectors = []AZCollector{
		&AZUserCollector{},
		&AZGroupCollector{},
		&AZRoleCollector{},
		&AZServicePrincipalCollector{},
		&AZApplicationCollector{},
		&AZDeviceCollector{},
	}

	// Sort by priority
	sort.Slice(l.collectors, func(i, j int) bool {
		return l.collectors[i].Priority() < l.collectors[j].Priority()
	})

	return l
}

func (l *AzureCollectorRegistryLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[[]string]("collectors", "List of collectors to run (default: all)"),
	}
}

func (l *AzureCollectorRegistryLink) Process(data any) error {
	clientCtx, ok := data.(*GraphClientContext)
	if !ok {
		return fmt.Errorf("expected GraphClientContext, got %T", data)
	}

	// Get Neo4j writer from context
	writer := l.Context().Value("neo4j_writer").(*storage.AZNeo4jWriter)

	// Get collectors to run
	collectorsToRun, _ := cfg.As[[]string](l.Arg("collectors"))
	if len(collectorsToRun) == 0 {
		collectorsToRun = []string{"all"}
	}
	runAll := false
	for _, c := range collectorsToRun {
		if c == "all" {
			runAll = true
			break
		}
	}

	// Run collectors
	for _, collector := range l.collectors {
		if !runAll {
			// Check if this collector should run
			shouldRun := false
			for _, name := range collectorsToRun {
				if collector.Name() == name {
					shouldRun = true
					break
				}
			}
			if !shouldRun {
				continue
			}
		}

		l.Logger.Info("Running collector", "name", collector.Name())

		if err := collector.Collect(l.Context(), clientCtx.Client, writer); err != nil {
			l.Logger.Error("Collector failed", "name", collector.Name(), "error", err)
			// Continue with other collectors
		}
	}

	// Send completion signal
	l.Send(&CollectionComplete{
		NodeCount: writer.GetNodeCount(),
	})

	return nil
}

// GraphClientContext holds the authenticated Graph client
type GraphClientContext struct {
	Client     *msgraphsdk.GraphServiceClient
	Credential any
}

// CollectionComplete signals collection is done
type CollectionComplete struct {
	NodeCount int
}