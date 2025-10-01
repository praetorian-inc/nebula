package collectors

import (
	"context"
	"fmt"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryroles"
	graphmodels "github.com/praetorian-inc/nebula/pkg/links/azure/graph/models"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZRoleCollector collects Azure AD directory roles
type AZRoleCollector struct{}

func (c *AZRoleCollector) Name() string {
	return "roles"
}

func (c *AZRoleCollector) Priority() int {
	return 3 // Collect roles after users and groups
}

func (c *AZRoleCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// Get all directory roles
	requestConfig := &directoryroles.DirectoryRolesRequestBuilderGetRequestConfiguration{
		QueryParameters: &directoryroles.DirectoryRolesRequestBuilderGetQueryParameters{
			Select: []string{"id", "displayName", "description", "roleTemplateId"},
			Expand: []string{"members"},
		},
	}

	result, err := client.DirectoryRoles().Get(ctx, requestConfig)
	if err != nil {
		return fmt.Errorf("failed to get directory roles: %w", err)
	}

	// Process roles
	for _, role := range result.GetValue() {
		if err := c.processRole(ctx, role, writer); err != nil {
			// Log but continue
			continue
		}
	}

	return nil
}

func (c *AZRoleCollector) processRole(ctx context.Context, role models.DirectoryRoleable, writer *storage.AZNeo4jWriter) error {
	// Extract members
	var members []string
	if role.GetMembers() != nil {
		for _, member := range role.GetMembers() {
			if dirObj, ok := member.(models.DirectoryObjectable); ok {
				if dirObj.GetId() != nil {
					members = append(members, *dirObj.GetId())
				}
			}
		}
	}

	// Determine if it's a built-in role based on roleTemplateId
	isBuiltIn := true // Directory roles are typically built-in
	permissions := getRolePermissions(stringValue(role.GetRoleTemplateId()))

	// Create role node
	node := &graphmodels.AZRole{
		ID:             stringValue(role.GetId()),
		DisplayName:    stringValue(role.GetDisplayName()),
		Description:    stringValue(role.GetDescription()),
		RoleTemplateID: stringValue(role.GetRoleTemplateId()),
		IsBuiltIn:      isBuiltIn,
		Permissions:    permissions,
		Members:        members,
	}

	return writer.CreateNode(ctx, node)
}

// getRolePermissions returns permissions for well-known role templates
func getRolePermissions(roleTemplateId string) []string {
	// Map of well-known role template IDs to their key permissions
	rolePermissions := map[string][]string{
		"62e90394-69f5-4237-9190-012177145e10": { // Global Administrator
			"*", // Full control
		},
		"29232cdf-9323-42fd-ade2-1d097af3e4de": { // Exchange Administrator
			"Exchange.*",
		},
		"b0f54661-2d74-4c50-afa3-1ec803f12efe": { // Billing Administrator
			"Billing.*",
			"Purchase.*",
		},
		"fe930be7-5e62-47db-91af-98c3a49a38b1": { // User Administrator
			"User.ReadWrite.All",
			"User.ManageIdentities.All",
			"User.EnableDisableAccount.All",
		},
		"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": { // Application Administrator
			"Application.ReadWrite.All",
			"AppRoleAssignment.ReadWrite.All",
		},
		"158c047a-c907-4556-b7ef-446551a6b5f7": { // Cloud Application Administrator
			"Application.ReadWrite.OwnedBy",
			"AppRoleAssignment.ReadWrite.All",
		},
		"966707d0-3269-4727-9be2-8c3a10f19b9d": { // Password Administrator
			"User.ResetPassword",
		},
		"e8611ab8-c189-46e8-94e1-60213ab1f814": { // Privileged Role Administrator
			"RoleManagement.ReadWrite.Directory",
			"PIM.ReadWrite",
		},
		"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": { // Privileged Authentication Administrator
			"User.ResetPassword.All",
			"User.InvalidateAllRefreshTokens",
		},
		"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": { // Conditional Access Administrator
			"Policy.ReadWrite.ConditionalAccess",
			"Policy.ReadWrite.AuthenticationMethod",
		},
		"f2ef992c-3afb-46b9-b7cf-a126ee74c451": { // Global Reader
			"*.Read.All",
		},
	}

	if perms, exists := rolePermissions[roleTemplateId]; exists {
		return perms
	}

	// Default permissions for unknown roles
	return []string{"Directory.Read.All"}
}