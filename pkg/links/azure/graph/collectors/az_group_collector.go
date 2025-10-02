package collectors

import (
	"context"
	"fmt"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
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
	// Request specific properties without expanding (will fetch members/owners separately)
	requestConfig := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
			Select: []string{
				"id", "displayName", "description", "securityEnabled",
				"mailEnabled", "groupTypes",
			},
			Top: int32Ptr(999), // Max page size
		},
	}

	result, err := client.Groups().Get(ctx, requestConfig)
	if err != nil {
		return fmt.Errorf("failed to get groups: %w", err)
	}

	// Process groups
	for _, group := range result.GetValue() {
		if err := c.processGroup(ctx, group, writer, client); err != nil {
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

func (c *AZGroupCollector) processGroup(ctx context.Context, group models.Groupable, writer *storage.AZNeo4jWriter, client *msgraphsdk.GraphServiceClient) error {
	// Get group ID
	groupId := stringValue(group.GetId())
	if groupId == "" {
		return fmt.Errorf("group has no ID")
	}

	// Fetch owners separately
	var owners []string
	ownersResult, err := client.Groups().ByGroupId(groupId).Owners().Get(ctx, nil)
	if err == nil && ownersResult != nil {
		for _, owner := range ownersResult.GetValue() {
			if owner.GetId() != nil {
				owners = append(owners, *owner.GetId())
			}
		}
	}

	// Fetch members separately
	var members []string
	membersResult, err := client.Groups().ByGroupId(groupId).Members().Get(ctx, nil)
	if err == nil && membersResult != nil {
		for _, member := range membersResult.GetValue() {
			if member.GetId() != nil {
				members = append(members, *member.GetId())
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
