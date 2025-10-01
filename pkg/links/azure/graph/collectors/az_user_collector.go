package collectors

import (
	"context"
	"fmt"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	graphmodels "github.com/praetorian-inc/nebula/pkg/links/azure/graph/models"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZUserCollector collects Azure AD users
type AZUserCollector struct{}

func (c *AZUserCollector) Name() string {
	return "users"
}

func (c *AZUserCollector) Priority() int {
	return 1 // Collect users first
}

func (c *AZUserCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// Request specific properties and expand memberOf
	requestConfig := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: []string{
				"id", "userPrincipalName", "displayName", "mail",
				"accountEnabled", "userType", "department", "jobTitle",
			},
			Expand: []string{"memberOf"},
			Top:    int32Ptr(999), // Max page size
		},
	}

	result, err := client.Users().Get(ctx, requestConfig)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	// Process initial page
	if err := c.processUserPage(ctx, result, writer, client); err != nil {
		return err
	}

	// Handle pagination
	pageIterator, err := msgraphcore.NewPageIterator[models.Userable](result, client.GetAdapter(), models.CreateUserCollectionResponseFromDiscriminatorValue)

	if err != nil {
		return fmt.Errorf("failed to create page iterator: %w", err)
	}

	err = pageIterator.Iterate(ctx, func(user models.Userable) bool {
		if err := c.processUser(ctx, user, writer, client); err != nil {
			// Log error but continue processing
			return true
		}
		return true // Continue iteration
	})

	if err != nil {
		return fmt.Errorf("failed to iterate users: %w", err)
	}

	return nil
}

func (c *AZUserCollector) processUserPage(ctx context.Context, result models.UserCollectionResponseable, writer *storage.AZNeo4jWriter, client *msgraphsdk.GraphServiceClient) error {
	for _, user := range result.GetValue() {
		if err := c.processUser(ctx, user, writer, client); err != nil {
			// Log but continue
			continue
		}
	}
	return nil
}

func (c *AZUserCollector) processUser(ctx context.Context, user models.Userable, writer *storage.AZNeo4jWriter, client *msgraphsdk.GraphServiceClient) error {
	// Extract group memberships
	var memberOfGroups []string
	if user.GetMemberOf() != nil {
		for _, member := range user.GetMemberOf() {
			if group, ok := member.(models.Groupable); ok {
				if group.GetId() != nil {
					memberOfGroups = append(memberOfGroups, *group.GetId())
				}
			}
		}
	}

	// Get role assignments (separate API call)
	roleAssignments, _ := c.getUserRoleAssignments(ctx, client, *user.GetId())

	// Create user node
	node := &graphmodels.AZUser{
		ID:                stringValue(user.GetId()),
		UserPrincipalName: stringValue(user.GetUserPrincipalName()),
		DisplayName:       stringValue(user.GetDisplayName()),
		Mail:              stringValue(user.GetMail()),
		AccountEnabled:    boolValue(user.GetAccountEnabled()),
		UserType:          stringValue(user.GetUserType()),
		Department:        stringValue(user.GetDepartment()),
		JobTitle:          stringValue(user.GetJobTitle()),
		MemberOfGroups:    memberOfGroups,
		AssignedRoles:     roleAssignments,
	}

	return writer.CreateNode(ctx, node)
}

func (c *AZUserCollector) getUserRoleAssignments(ctx context.Context, client *msgraphsdk.GraphServiceClient, userId string) ([]string, error) {
	// Get direct role assignments
	roles, err := client.Users().ByUserId(userId).TransitiveMemberOf().GraphDirectoryRole().Get(ctx, nil)
	if err != nil {
		return nil, err
	}

	var roleIds []string
	for _, role := range roles.GetValue() {
		if role.GetId() != nil {
			roleIds = append(roleIds, *role.GetId())
		}
	}

	return roleIds, nil
}

// Helper functions
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func boolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func int32Ptr(i int32) *int32 {
	return &i
}