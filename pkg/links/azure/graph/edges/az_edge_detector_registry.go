package edges

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AzureEdgeDetectorRegistryLink runs edge detectors to create privilege escalation edges
type AzureEdgeDetectorRegistryLink struct {
	*chain.Base
}

func NewAzureEdgeDetectorRegistryLink(configs ...cfg.Config) chain.Link {
	l := &AzureEdgeDetectorRegistryLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureEdgeDetectorRegistryLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[[]string]("detectors", "List of edge detectors to run").WithDefault([]string{"all"}),
	}
}

func (l *AzureEdgeDetectorRegistryLink) Process(data any) error {
	nodeData, ok := data.(*storage.NodeData)
	if !ok {
		return fmt.Errorf("expected NodeData, got %T", data)
	}

	// Get Neo4j writer from context
	writer := l.Context().Value("neo4j_writer").(*storage.AZNeo4jWriter)

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
		l.detectRoleBasedEscalation(nodeData, writer)
	}

	if runAll || contains(detectorsToRun, "ownership") {
		l.detectOwnershipEscalation(nodeData, writer)
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}