package edges

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AzureRelationshipBuilderLink builds basic relationships from node data
type AzureRelationshipBuilderLink struct {
	*chain.Base
}

func NewAzureRelationshipBuilderLink(configs ...cfg.Config) chain.Link {
	l := &AzureRelationshipBuilderLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureRelationshipBuilderLink) Process(data any) error {
	nodeData, ok := data.(*storage.NodeData)
	if !ok {
		return fmt.Errorf("expected NodeData, got %T", data)
	}

	// Get Neo4j writer from context
	writer := l.Context().Value("neo4j_writer").(*storage.AZNeo4jWriter)

	// Build user relationships
	for userID, userData := range nodeData.Users {
		// Member of groups
		if groups, ok := userData["memberOfGroups"].([]string); ok {
			for _, groupID := range groups {
				if err := writer.CreateEdge(l.Context(), userID, groupID, "AZMemberOf", "AZUser", "AZGroup"); err != nil {
					l.Logger.Error("Failed to create membership edge", "user", userID, "group", groupID, "error", err)
				}
			}
		}

		// Role assignments
		if roles, ok := userData["assignedRoles"].([]string); ok {
			for _, roleID := range roles {
				if err := writer.CreateEdge(l.Context(), userID, roleID, "AZHasRole", "AZUser", "AZRole"); err != nil {
					l.Logger.Error("Failed to create role edge", "user", userID, "role", roleID, "error", err)
				}
			}
		}

		// Eligible roles (PIM)
		if eligibleRoles, ok := userData["eligibleRoles"].([]string); ok {
			for _, roleID := range eligibleRoles {
				if err := writer.CreateEdge(l.Context(), userID, roleID, "AZEligibleForRole", "AZUser", "AZRole"); err != nil {
					l.Logger.Error("Failed to create eligible role edge", "user", userID, "role", roleID, "error", err)
				}
			}
		}

		// Owned applications
		if apps, ok := userData["ownedApplications"].([]string); ok {
			for _, appID := range apps {
				if err := writer.CreateEdge(l.Context(), userID, appID, "AZOwns", "AZUser", "AZApplication"); err != nil {
					l.Logger.Error("Failed to create ownership edge", "user", userID, "app", appID, "error", err)
				}
			}
		}
	}

	// Build group relationships
	for groupID, groupData := range nodeData.Groups {
		// Owners
		if owners, ok := groupData["owners"].([]string); ok {
			for _, ownerID := range owners {
				// Determine owner type (user or service principal)
				ownerLabel := "AZUser"
				if _, exists := nodeData.ServicePrincipals[ownerID]; exists {
					ownerLabel = "AZServicePrincipal"
				}
				if err := writer.CreateEdge(l.Context(), ownerID, groupID, "AZOwns", ownerLabel, "AZGroup"); err != nil {
					l.Logger.Error("Failed to create group ownership edge", "owner", ownerID, "group", groupID, "error", err)
				}
			}
		}

		// Group role assignments
		if roles, ok := groupData["assignedRoles"].([]string); ok {
			for _, roleID := range roles {
				if err := writer.CreateEdge(l.Context(), groupID, roleID, "AZHasRole", "AZGroup", "AZRole"); err != nil {
					l.Logger.Error("Failed to create group role edge", "group", groupID, "role", roleID, "error", err)
				}
			}
		}
	}

	// Pass data to next link
	l.Send(nodeData)

	return nil
}