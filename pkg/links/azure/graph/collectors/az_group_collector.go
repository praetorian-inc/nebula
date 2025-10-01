package collectors

import (
	"context"
	"fmt"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	graphmodels "github.com/praetorian-inc/nebula/pkg/links/azure/graph/models"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZGroupCollector collects Azure AD groups
type AZGroupCollector struct{}

func (c *AZGroupCollector) Name() string {
	return "groups"
}

func (c *AZGroupCollector) Priority() int {
	return 2 // Collect groups after users
}

func (c *AZGroupCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// Request specific properties and expand owners/members
	requestConfig := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
			Select: []string{
				"id", "displayName", "description", "securityEnabled",
				"mailEnabled", "groupTypes",
			},
			Expand: []string{"owners", "members"},
			Top:    int32Ptr(999), // Max page size
		},
	}

	result, err := client.Groups().Get(ctx, requestConfig)
	if err != nil {
		return fmt.Errorf("failed to get groups: %w", err)
	}

	// Process groups
	for _, group := range result.GetValue() {
		if err := c.processGroup(ctx, group, writer); err != nil {
			// Log but continue
			continue
		}
	}

	// Handle pagination if needed
	if result.GetOdataNextLink() != nil {
		// TODO: Implement pagination
	}

	return nil
}

func (c *AZGroupCollector) processGroup(ctx context.Context, group models.Groupable, writer *storage.AZNeo4jWriter) error {
	// Extract owners
	var owners []string
	if group.GetOwners() != nil {
		for _, owner := range group.GetOwners() {
			if user, ok := owner.(models.Userable); ok {
				if user.GetId() != nil {
					owners = append(owners, *user.GetId())
				}
			}
			if sp, ok := owner.(models.ServicePrincipalable); ok {
				if sp.GetId() != nil {
					owners = append(owners, *sp.GetId())
				}
			}
		}
	}

	// Extract members
	var members []string
	if group.GetMembers() != nil {
		for _, member := range group.GetMembers() {
			// Members can be users, groups, service principals, etc.
			if dirObj, ok := member.(models.DirectoryObjectable); ok {
				if dirObj.GetId() != nil {
					members = append(members, *dirObj.GetId())
				}
			}
		}
	}

	// Check if it's a built-in group (well-known SIDs or specific display names)
	isBuiltIn := isBuiltInGroup(stringValue(group.GetDisplayName()))

	// Create group node
	node := &graphmodels.AZGroup{
		ID:              stringValue(group.GetId()),
		DisplayName:     stringValue(group.GetDisplayName()),
		Description:     stringValue(group.GetDescription()),
		SecurityEnabled: boolValue(group.GetSecurityEnabled()),
		MailEnabled:     boolValue(group.GetMailEnabled()),
		GroupTypes:      stringSliceValue(group.GetGroupTypes()),
		IsBuiltIn:       isBuiltIn,
		Owners:          owners,
		Members:         members,
	}

	return writer.CreateNode(ctx, node)
}

func isBuiltInGroup(displayName string) bool {
	builtInGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
		"Account Operators",
		"Backup Operators",
		"Print Operators",
		"Server Operators",
		"Domain Controllers",
		"Read-only Domain Controllers",
		"Group Policy Creator Owners",
		"Cryptographic Operators",
	}

	for _, builtin := range builtInGroups {
		if displayName == builtin {
			return true
		}
	}
	return false
}

func stringSliceValue(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}