package collectors_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/collectors"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/models"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// MockNeo4jWriter for testing
type MockNeo4jWriter struct {
	Nodes []any
	Edges []Edge
}

type Edge struct {
	From      string
	To        string
	Type      string
	FromLabel string
	ToLabel   string
}

func (m *MockNeo4jWriter) CreateNode(ctx context.Context, node any) error {
	m.Nodes = append(m.Nodes, node)
	return nil
}

func (m *MockNeo4jWriter) CreateEdge(ctx context.Context, fromID, toID, edgeType string, fromLabel, toLabel string) error {
	m.Edges = append(m.Edges, Edge{
		From:      fromID,
		To:        toID,
		Type:      edgeType,
		FromLabel: fromLabel,
		ToLabel:   toLabel,
	})
	return nil
}

func (m *MockNeo4jWriter) GetNodeCount() int {
	return len(m.Nodes)
}

func (m *MockNeo4jWriter) CreateIndexes(ctx context.Context) error {
	return nil
}

func TestCollectorPriorities(t *testing.T) {
	tests := []struct {
		name     string
		collector collectors.AZCollector
		expected int
	}{
		{"Users", &collectors.AZUserCollector{}, 1},
		{"Groups", &collectors.AZGroupCollector{}, 2},
		{"Roles", &collectors.AZRoleCollector{}, 3},
		{"ServicePrincipals", &collectors.AZServicePrincipalCollector{}, 4},
		{"Applications", &collectors.AZApplicationCollector{}, 5},
		{"Devices", &collectors.AZDeviceCollector{}, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.collector.Priority())
		})
	}
}

func TestCollectorNames(t *testing.T) {
	tests := []struct {
		collector collectors.AZCollector
		expected  string
	}{
		{&collectors.AZUserCollector{}, "users"},
		{&collectors.AZGroupCollector{}, "groups"},
		{&collectors.AZRoleCollector{}, "roles"},
		{&collectors.AZServicePrincipalCollector{}, "serviceprincipals"},
		{&collectors.AZApplicationCollector{}, "applications"},
		{&collectors.AZDeviceCollector{}, "devices"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.collector.Name())
		})
	}
}

func TestNodeCreation(t *testing.T) {
	ctx := context.Background()
	writer := &MockNeo4jWriter{}

	// Test user node creation
	user := &models.AZUser{
		ID:                "user-123",
		UserPrincipalName: "test@example.com",
		DisplayName:       "Test User",
		AccountEnabled:    true,
		UserType:          "Member",
		MemberOfGroups:    []string{"group-1", "group-2"},
		AssignedRoles:     []string{"role-1"},
	}

	err := writer.CreateNode(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, 1, writer.GetNodeCount())

	// Verify the node was stored correctly
	storedNode := writer.Nodes[0].(*models.AZUser)
	assert.Equal(t, "user-123", storedNode.ID)
	assert.Equal(t, "test@example.com", storedNode.UserPrincipalName)
	assert.Equal(t, 2, len(storedNode.MemberOfGroups))

	// Test group node creation
	group := &models.AZGroup{
		ID:              "group-123",
		DisplayName:     "Test Group",
		SecurityEnabled: true,
		Members:         []string{"user-1", "user-2"},
		Owners:          []string{"admin-1"},
	}

	err = writer.CreateNode(ctx, group)
	require.NoError(t, err)
	assert.Equal(t, 2, writer.GetNodeCount())
}

func TestEdgeCreation(t *testing.T) {
	ctx := context.Background()
	writer := &MockNeo4jWriter{}

	// Test membership edge
	err := writer.CreateEdge(ctx, "user-1", "group-1", "AZMemberOf", "AZUser", "AZGroup")
	require.NoError(t, err)
	assert.Equal(t, 1, len(writer.Edges))

	edge := writer.Edges[0]
	assert.Equal(t, "user-1", edge.From)
	assert.Equal(t, "group-1", edge.To)
	assert.Equal(t, "AZMemberOf", edge.Type)

	// Test role assignment edge
	err = writer.CreateEdge(ctx, "user-1", "role-1", "AZHasRole", "AZUser", "AZRole")
	require.NoError(t, err)
	assert.Equal(t, 2, len(writer.Edges))

	// Test ownership edge
	err = writer.CreateEdge(ctx, "sp-1", "app-1", "AZOwns", "AZServicePrincipal", "AZApplication")
	require.NoError(t, err)
	assert.Equal(t, 3, len(writer.Edges))
}

func TestPrivilegeEscalationEdges(t *testing.T) {
	ctx := context.Background()
	writer := &MockNeo4jWriter{}

	privEscEdges := []struct {
		from      string
		to        string
		edgeType  string
		fromLabel string
		toLabel   string
	}{
		{"user-1", "app-1", "AZAddSecret", "AZUser", "AZApplication"},
		{"user-2", "app-2", "AZAddOwner", "AZUser", "AZApplication"},
		{"user-3", "group-1", "AZAddMember", "AZUser", "AZGroup"},
		{"user-4", "user-5", "AZResetPassword", "AZUser", "AZUser"},
		{"sp-1", "role-1", "AZGrantRole", "AZServicePrincipal", "AZRole"},
	}

	for _, edge := range privEscEdges {
		err := writer.CreateEdge(ctx, edge.from, edge.to, edge.edgeType, edge.fromLabel, edge.toLabel)
		require.NoError(t, err)
	}

	assert.Equal(t, len(privEscEdges), len(writer.Edges))

	// Verify all privilege escalation edges were created
	edgeTypes := make(map[string]bool)
	for _, edge := range writer.Edges {
		edgeTypes[edge.Type] = true
	}

	assert.True(t, edgeTypes["AZAddSecret"])
	assert.True(t, edgeTypes["AZAddOwner"])
	assert.True(t, edgeTypes["AZAddMember"])
	assert.True(t, edgeTypes["AZResetPassword"])
	assert.True(t, edgeTypes["AZGrantRole"])
}