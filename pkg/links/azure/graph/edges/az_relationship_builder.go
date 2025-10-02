package edges

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AzureRelationshipBuilderLink builds basic relationships from node data
type AzureRelationshipBuilderLink struct {
	*chain.Base
	writer *storage.AZNeo4jWriter
}

func NewAzureRelationshipBuilderLink(configs ...cfg.Config) chain.Link {
	l := &AzureRelationshipBuilderLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureRelationshipBuilderLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("neo4j_uri", "Neo4j connection URI").WithDefault("neo4j://localhost:7687"),
		cfg.NewParam[string]("neo4j_username", "Neo4j username").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_password", "Neo4j password").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_database", "Neo4j database").WithDefault("neo4j"),
	}
}

func (l *AzureRelationshipBuilderLink) Process(data any) error {
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

	l.Logger.Info("Starting relationship building",
		"users", len(nodeData.Users),
		"groups", len(nodeData.Groups),
		"servicePrincipals", len(nodeData.ServicePrincipals),
		"applications", len(nodeData.Applications),
		"roles", len(nodeData.Roles))

	edgeCount := 0

	// Build user relationships
	for userID, userData := range nodeData.Users {
		// Member of groups
		groups := l.extractStringArray(userData["memberOfGroups"])
		l.Logger.Debug("Processing user groups", "userID", userID, "groupCount", len(groups), "rawData", userData["memberOfGroups"])
		for _, groupID := range groups {
			if err := l.writer.CreateEdge(l.Context(), userID, groupID, "AZMemberOf", "AZUser", "AZGroup"); err != nil {
				l.Logger.Error("Failed to create membership edge", "user", userID, "group", groupID, "error", err)
			} else {
				edgeCount++
			}
		}

		// Role assignments
		roles := l.extractStringArray(userData["assignedRoles"])
		for _, roleID := range roles {
			if err := l.writer.CreateEdge(l.Context(), userID, roleID, "AZHasRole", "AZUser", "AZRole"); err != nil {
				l.Logger.Error("Failed to create role edge", "user", userID, "role", roleID, "error", err)
			} else {
				edgeCount++
			}
		}

		// Eligible roles (PIM)
		eligibleRoles := l.extractStringArray(userData["eligibleRoles"])
		for _, roleID := range eligibleRoles {
			if err := l.writer.CreateEdge(l.Context(), userID, roleID, "AZEligibleForRole", "AZUser", "AZRole"); err != nil {
				l.Logger.Error("Failed to create eligible role edge", "user", userID, "role", roleID, "error", err)
			} else {
				edgeCount++
			}
		}

		// Owned applications
		apps := l.extractStringArray(userData["ownedApplications"])
		for _, appID := range apps {
			if err := l.writer.CreateEdge(l.Context(), userID, appID, "AZOwns", "AZUser", "AZApplication"); err != nil {
				l.Logger.Error("Failed to create ownership edge", "user", userID, "app", appID, "error", err)
			} else {
				edgeCount++
			}
		}
	}

	// Build group relationships
	for groupID, groupData := range nodeData.Groups {
		// Owners
		owners := l.extractStringArray(groupData["owners"])
		for _, ownerID := range owners {
			// Determine owner type (user or service principal)
			ownerLabel := "AZUser"
			if _, exists := nodeData.ServicePrincipals[ownerID]; exists {
				ownerLabel = "AZServicePrincipal"
			}
			if err := l.writer.CreateEdge(l.Context(), ownerID, groupID, "AZOwns", ownerLabel, "AZGroup"); err != nil {
				l.Logger.Error("Failed to create group ownership edge", "owner", ownerID, "group", groupID, "error", err)
			}
		}

		// Group role assignments
		roles := l.extractStringArray(groupData["assignedRoles"])
		for _, roleID := range roles {
			if err := l.writer.CreateEdge(l.Context(), groupID, roleID, "AZHasRole", "AZGroup", "AZRole"); err != nil {
				l.Logger.Error("Failed to create group role edge", "group", groupID, "role", roleID, "error", err)
			}
		}
	}

	// Pass data to next link
	l.Send(nodeData)

	return nil
}

func (l *AzureRelationshipBuilderLink) initWriter() error {
	uri, _ := cfg.As[string](l.Arg("neo4j_uri"))
	username, _ := cfg.As[string](l.Arg("neo4j_username"))
	password, _ := cfg.As[string](l.Arg("neo4j_password"))
	database, _ := cfg.As[string](l.Arg("neo4j_database"))

	l.Logger.Info("Connecting to Neo4j for edge creation", "uri", uri, "database", database)

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

// extractStringArray extracts a string array from various formats
func (l *AzureRelationshipBuilderLink) extractStringArray(data any) []string {
	if data == nil {
		return []string{}
	}

	// Try direct type assertion first
	if arr, ok := data.([]string); ok {
		return arr
	}

	// Try []interface{} (common for JSON unmarshaling)
	if arr, ok := data.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	// Try JSON string
	if jsonStr, ok := data.(string); ok && jsonStr != "" {
		var result []string
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			return result
		}
	}

	return []string{}
}

func (l *AzureRelationshipBuilderLink) Close() {
	if l.writer != nil && l.writer.Driver != nil {
		l.writer.Driver.Close(context.Background())
	}
}
