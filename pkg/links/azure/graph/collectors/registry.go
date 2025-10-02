package collectors

import (
	"context"
	"fmt"
	"sort"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/client"
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
	writer     *storage.AZNeo4jWriter
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
		cfg.NewParam[string]("neo4j_uri", "Neo4j connection URI").WithDefault("neo4j://localhost:7687"),
		cfg.NewParam[string]("neo4j_username", "Neo4j username").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_password", "Neo4j password").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_database", "Neo4j database").WithDefault("neo4j"),
	}
}

func (l *AzureCollectorRegistryLink) Process(data any) error {
	clientCtx, ok := data.(*client.GraphClientContext)
	if !ok {
		return fmt.Errorf("expected GraphClientContext, got %T", data)
	}

	// Initialize Neo4j connection
	uri, _ := cfg.As[string](l.Arg("neo4j_uri"))
	username, _ := cfg.As[string](l.Arg("neo4j_username"))
	password, _ := cfg.As[string](l.Arg("neo4j_password"))
	database, _ := cfg.As[string](l.Arg("neo4j_database"))

	l.Logger.Info("Connecting to Neo4j", "uri", uri, "database", database)

	// Create Neo4j driver
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}
	defer driver.Close(l.Context())

	// Verify connection
	err = driver.VerifyConnectivity(l.Context())
	if err != nil {
		return fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	// Create writer
	l.writer = &storage.AZNeo4jWriter{
		Driver:   driver,
		Database: database,
	}

	// Create indexes for performance
	if err := l.writer.CreateIndexes(l.Context()); err != nil {
		l.Logger.Warn("Failed to create indexes", "error", err)
	}

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

		if err := collector.Collect(l.Context(), clientCtx.Client, l.writer); err != nil {
			l.Logger.Error("Collector failed", "name", collector.Name(), "error", err)
			// Continue with other collectors
		}
	}

	// Send completion signal
	l.Send(&CollectionComplete{
		NodeCount: l.writer.GetNodeCount(),
	})

	return nil
}

// CollectionComplete signals collection is done
type CollectionComplete struct {
	NodeCount int
}
