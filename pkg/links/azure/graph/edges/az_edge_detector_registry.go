package edges

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AzureEdgeDetectorRegistryLink runs edge detectors to create privilege escalation edges
type AzureEdgeDetectorRegistryLink struct {
	*chain.Base
	writer *storage.AZNeo4jWriter
}

func NewAzureEdgeDetectorRegistryLink(configs ...cfg.Config) chain.Link {
	l := &AzureEdgeDetectorRegistryLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureEdgeDetectorRegistryLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[[]string]("detectors", "List of edge detectors to run").WithDefault([]string{"all"}),
		cfg.NewParam[string]("neo4j_uri", "Neo4j connection URI").WithDefault("neo4j://localhost:7687"),
		cfg.NewParam[string]("neo4j_username", "Neo4j username").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_password", "Neo4j password").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_database", "Neo4j database").WithDefault("neo4j"),
	}
}

func (l *AzureEdgeDetectorRegistryLink) Process(data any) error {
	nodeData, ok := data.(*storage.NodeData)
	if !ok {
		return fmt.Errorf("expected NodeData, got %T", data)
	}

	// Initialize Neo4j writer if not already done
	if l.writer == nil {
		if err := l.initWriter(); err != nil {
			return err
		}
	}

	// Get detectors to run
	detectorsToRun, _ := cfg.As[[]string](l.Arg("detectors"))
	if len(detectorsToRun) == 0 {
		detectorsToRun = []string{"all"}
	}

	runAll := false
	for _, d := range detectorsToRun {
		if d == "all" {
			runAll = true
			break
		}
	}

	// For now, we'll create some basic privilege escalation edges based on roles
	// In a full implementation, each detector would be a separate struct with its own logic

	if runAll || contains(detectorsToRun, "role-based") {
		l.detectRoleBasedEscalation(nodeData, l.writer)
	}

	if runAll || contains(detectorsToRun, "ownership") {
		l.detectOwnershipEscalation(nodeData, l.writer)
	}

	l.Logger.Info("Edge detection complete")
	l.Send(nodeData)

	return nil
}

func (l *AzureEdgeDetectorRegistryLink) detectRoleBasedEscalation(nodeData *storage.NodeData, writer *storage.AZNeo4jWriter) {
	// Detect users/groups/SPs with Cloud Application Administrator role (can add secrets)
	cloudAppAdminRoleID := "158c047a-c907-4556-b7ef-446551a6b5f7"
	appAdminRoleID := "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

	// Check users with these roles
	for userID, userData := range nodeData.Users {
		if roles, ok := userData["assignedRoles"].([]string); ok {
			for _, roleID := range roles {
				if roleID == cloudAppAdminRoleID || roleID == appAdminRoleID {
					// This user can add secrets to apps
					for appID := range nodeData.Applications {
						if err := writer.CreateEdge(l.Context(), userID, appID, "AZAddSecret", "AZUser", "AZApplication"); err != nil {
							l.Logger.Error("Failed to create AZAddSecret edge", "user", userID, "app", appID, "error", err)
						}
					}
				}
			}
		}
	}

	// Similar logic for groups and service principals...
}

func (l *AzureEdgeDetectorRegistryLink) detectOwnershipEscalation(nodeData *storage.NodeData, writer *storage.AZNeo4jWriter) {
	// Owners can add secrets to their applications
	for appID, appData := range nodeData.Applications {
		if owners, ok := appData["owners"].([]string); ok {
			for _, ownerID := range owners {
				// Determine owner type
				ownerLabel := "AZUser"
				if _, exists := nodeData.ServicePrincipals[ownerID]; exists {
					ownerLabel = "AZServicePrincipal"
				}

				// Owner can add secret
				if err := writer.CreateEdge(l.Context(), ownerID, appID, "AZAddSecret", ownerLabel, "AZApplication"); err != nil {
					l.Logger.Error("Failed to create AZAddSecret edge for owner", "owner", ownerID, "app", appID, "error", err)
				}

				// Owner can add other owners
				if err := writer.CreateEdge(l.Context(), ownerID, appID, "AZAddOwner", ownerLabel, "AZApplication"); err != nil {
					l.Logger.Error("Failed to create AZAddOwner edge", "owner", ownerID, "app", appID, "error", err)
				}
			}
		}
	}
}

func (l *AzureEdgeDetectorRegistryLink) initWriter() error {
	uri, _ := cfg.As[string](l.Arg("neo4j_uri"))
	username, _ := cfg.As[string](l.Arg("neo4j_username"))
	password, _ := cfg.As[string](l.Arg("neo4j_password"))
	database, _ := cfg.As[string](l.Arg("neo4j_database"))

	l.Logger.Info("Connecting to Neo4j for edge detection", "uri", uri, "database", database)

	// Create Neo4j driver
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	// Verify connection
	err = driver.VerifyConnectivity(l.Context())
	if err != nil {
		return fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	l.writer = &storage.AZNeo4jWriter{
		Driver:   driver,
		Database: database,
	}

	return nil
}

func (l *AzureEdgeDetectorRegistryLink) Close() {
	if l.writer != nil && l.writer.Driver != nil {
		l.writer.Driver.Close(context.Background())
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
