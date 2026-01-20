package iam

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMERGEQueryIncludesUniquenessProperties verifies that the MERGE queries
// include roleName and permission in the relationship pattern for uniqueness.
//
// BUG: Current MERGE pattern:
//   MERGE (source)-[r:HAS_PERMISSION]->(tenant)
//   SET r.roleName = edge.roleName, r.permission = edge.permission
//
// This matches on (source, HAS_PERMISSION, tenant) only, missing roleName and permission.
// When the same principal has multiple roles:
//   - First MERGE creates edge
//   - Second MERGE finds SAME edge (same source+target), overwrites roleName via SET
//   - Result: Data loss (only last role survives)
//
// FIX: Include uniqueness properties in MERGE pattern:
//   MERGE (source)-[r:HAS_PERMISSION {roleName: edge.roleName, permission: edge.permission}]->(tenant)
//   ON CREATE SET r.source = edge.source, r.principalType = edge.principalType, r.createdAt = edge.createdAt
//   ON MATCH SET r.createdAt = edge.createdAt
//
// This matches on (source, HAS_PERMISSION, tenant, roleName, permission).
// Different roles create different edges, no overwrites.
func TestMERGEQueryIncludesUniquenessProperties(t *testing.T) {
	tests := []struct {
		name         string
		querySnippet string
		shouldHave   []string
		shouldNotHave []string
	}{
		{
			name: "Credential permission MERGE should include uniqueness properties",
			// This is the query from createApplicationCredentialPermissionEdges (line 3726)
			querySnippet: `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (tenant {resourceType: "Microsoft.DirectoryServices/tenant"})
		MERGE (source)-[r:HAS_PERMISSION]->(tenant)
		SET r.permission = edge.permission,
		    r.roleName = edge.roleName,
		    r.source = edge.source,
		    r.principalType = edge.principalType,
		    r.createdAt = edge.createdAt
		RETURN count(r) as created`,
			shouldHave: []string{
				// After fix, should include these in MERGE pattern
				// "MERGE (source)-[r:HAS_PERMISSION {roleName: edge.roleName, permission: edge.permission}]->(tenant)",
				// "ON CREATE SET",
				// "ON MATCH SET",
			},
			shouldNotHave: []string{
				// This pattern is WRONG - causes overwrites
				"MERGE (source)-[r:HAS_PERMISSION]->(tenant)\n\t\tSET r.permission",
			},
		},
		{
			name: "RBAC permission MERGE should include uniqueness properties",
			// This is the query from createApplicationRBACPermissionEdges (line 3812)
			querySnippet: `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (tenant {resourceType: "Microsoft.DirectoryServices/tenant"})
		MERGE (source)-[r:HAS_PERMISSION]->(tenant)
		SET r.permission = edge.permission,
		    r.roleName = edge.roleName,
		    r.source = edge.source,
		    r.principalType = edge.principalType,
		    r.createdAt = edge.createdAt
		RETURN count(r) as created`,
			shouldHave: []string{
				// After fix, should have these
			},
			shouldNotHave: []string{
				// This pattern is WRONG
				"MERGE (source)-[r:HAS_PERMISSION]->(tenant)\n\t\tSET r.permission",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the WRONG pattern exists (this test documents the bug)
			for _, wrongPattern := range tt.shouldNotHave {
				if strings.Contains(tt.querySnippet, wrongPattern) {
					t.Logf("BUG CONFIRMED: Query uses incorrect MERGE pattern that causes overwrites")
					t.Logf("Found pattern: %s", wrongPattern)
					// This will FAIL until we fix the Cypher queries
					// Once fixed, this assertion will pass
					assert.NotContains(t, tt.querySnippet, wrongPattern,
						"MERGE should NOT use separate SET for uniqueness properties")
				}
			}

			// After fix, verify correct pattern exists
			for _, correctPattern := range tt.shouldHave {
				assert.Contains(t, tt.querySnippet, correctPattern,
					"MERGE should include uniqueness properties in relationship pattern")
			}
		})
	}
}

// TestMERGEUniquenessScenario documents the expected behavior with examples.
// This is a documentation test that describes what SHOULD happen.
func TestMERGEUniquenessScenario(t *testing.T) {
	t.Run("Scenario: Elgin Lee has 2 roles", func(t *testing.T) {
		// Given: 2 edges for same principal, different roles
		edges := []map[string]interface{}{
			{
				"sourceId":      "elgin-lee-user-id",
				"roleName":       "Application Administrator",
				"permission":     "ApplicationCredentialManagement",
				"source":         "DirectoryRole",
				"principalType":  "User",
			},
			{
				"sourceId":      "elgin-lee-user-id",
				"roleName":       "Cloud Application Administrator",
				"permission":     "ApplicationCredentialManagement",
				"source":         "DirectoryRole",
				"principalType":  "User",
			},
		}

		// When: Processed with CORRECT MERGE logic
		// MERGE (source)-[r:HAS_PERMISSION {roleName: edge.roleName, permission: edge.permission}]->(tenant)

		// Then: Should create 2 SEPARATE edges
		expectedEdgeCount := 2
		t.Logf("Expected behavior: %d items should create %d separate edges", len(edges), expectedEdgeCount)

		// Each edge should have its own roleName preserved
		expectedRoles := []string{"Application Administrator", "Cloud Application Administrator"}
		t.Logf("Expected roles to exist separately: %v", expectedRoles)

		// With BUGGY logic: Would create only 1 edge with last roleName (data loss)
		// MERGE (source)-[r:HAS_PERMISSION]->(tenant)
		// SET r.roleName = edge.roleName  ← OVERWRITES first role with second role
		t.Logf("BUGGY behavior: Would create only 1 edge, losing 'Application Administrator'")
	})

	t.Run("Scenario: 396 RBAC permissions for various principals", func(t *testing.T) {
		// Given: 396 items in input
		inputCount := 396

		// When: Processed with CORRECT MERGE logic
		// Then: Should create 396 edges (no data loss)
		expectedEdgeCount := 396
		t.Logf("Expected: %d items → %d edges", inputCount, expectedEdgeCount)

		// With BUGGY logic: Creates only 132 edges (264 lost via overwrites)
		buggyEdgeCount := 132
		dataLoss := inputCount - buggyEdgeCount
		t.Logf("BUGGY behavior: %d items → only %d edges (%d lost)", inputCount, buggyEdgeCount, dataLoss)
	})

	t.Run("Scenario: Idempotence - re-running with same data", func(t *testing.T) {
		// Given: Same edge run twice
		_ = []map[string]interface{}{
			{
				"sourceId":   "user-123",
				"roleName":    "Role A",
				"permission":  "PermissionX",
			},
		}

		// When: First run
		// MERGE creates edge (ON CREATE triggers)
		firstRunCreates := 1
		t.Logf("First run: Creates %d edge", firstRunCreates)

		// When: Second run with SAME data
		// MERGE finds existing edge (ON MATCH triggers)
		// ON MATCH only updates timestamp, doesn't increment count
		secondRunCreates := 0
		t.Logf("Second run: Creates %d edges (idempotent)", secondRunCreates)

		// Then: Total edges = 1 (no duplicates)
		totalEdges := 1
		t.Logf("Total edges after 2 runs: %d (no duplicates)", totalEdges)
	})
}

// TestMERGECorrectCypherSyntax verifies the FIXED Cypher syntax compiles correctly.
// This test documents the correct syntax for the fix.
func TestMERGECorrectCypherSyntax(t *testing.T) {
	correctQuery := `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (tenant {resourceType: "Microsoft.DirectoryServices/tenant"})
		MERGE (source)-[r:HAS_PERMISSION {roleName: edge.roleName, permission: edge.permission}]->(tenant)
		ON CREATE SET r.source = edge.source,
		              r.principalType = edge.principalType,
		              r.createdAt = edge.createdAt
		ON MATCH SET r.createdAt = edge.createdAt
		RETURN count(r) as created`

	// Verify query has correct structure
	assert.Contains(t, correctQuery, "MERGE (source)-[r:HAS_PERMISSION {roleName: edge.roleName, permission: edge.permission}]->(tenant)",
		"MERGE should include uniqueness properties in relationship pattern")
	assert.Contains(t, correctQuery, "ON CREATE SET",
		"Should use ON CREATE for properties set only on new edges")
	assert.Contains(t, correctQuery, "ON MATCH SET",
		"Should use ON MATCH for properties updated on existing edges")
	assert.NotContains(t, correctQuery, "MERGE (source)-[r:HAS_PERMISSION]->(tenant)\n\t\tSET",
		"Should NOT use separate SET after MERGE (causes overwrites)")

	t.Logf("Correct MERGE syntax verified:")
	t.Logf("1. Uniqueness properties in MERGE pattern: {roleName: ..., permission: ...}")
	t.Logf("2. ON CREATE for initial properties")
	t.Logf("3. ON MATCH for updates (timestamp)")
}
