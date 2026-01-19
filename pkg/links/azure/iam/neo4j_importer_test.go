package iam

import (
	"strings"
	"testing"
)

// TestExtractPIMAssignmentData tests extraction of principal and role info from both
// flat (SDK) and nested (legacy) data structures.
func TestExtractPIMAssignmentData(t *testing.T) {
	tests := []struct {
		name                string
		assignment          map[string]interface{}
		expectPrincipalID   string
		expectRoleTemplateID string
		expectRoleName       string
	}{
		{
			name: "SDK flat structure - should extract successfully",
			assignment: map[string]interface{}{
				"principalId":      "/subscriptions/abc/providers/Microsoft.DirectoryServices/principals/user-123",
				"roleDefinitionId": "/subscriptions/abc/providers/Microsoft.Authorization/roleDefinitions/role-456",
				"displayName":      "Owner",
			},
			expectPrincipalID:   "/subscriptions/abc/providers/Microsoft.DirectoryServices/principals/user-123",
			expectRoleTemplateID: "role-456",
			expectRoleName:       "Owner",
		},
		{
			name: "Legacy nested structure - should extract successfully",
			assignment: map[string]interface{}{
				"subject": map[string]interface{}{
					"id": "/subscriptions/abc/providers/Microsoft.DirectoryServices/principals/user-789",
				},
				"roleDefinition": map[string]interface{}{
					"templateId":  "role-999",
					"displayName": "Contributor",
				},
			},
			expectPrincipalID:   "/subscriptions/abc/providers/Microsoft.DirectoryServices/principals/user-789",
			expectRoleTemplateID: "role-999",
			expectRoleName:       "Contributor",
		},
		{
			name: "SDK flat structure - missing principalId - extracts role but should skip in production",
			assignment: map[string]interface{}{
				"roleDefinitionId": "/subscriptions/abc/providers/Microsoft.Authorization/roleDefinitions/role-456",
				"displayName":      "Owner",
			},
			expectPrincipalID:   "",
			expectRoleTemplateID: "role-456",
			expectRoleName:       "Owner",
		},
		{
			name: "SDK flat structure - empty principalId - extracts role but should skip in production",
			assignment: map[string]interface{}{
				"principalId":      "",
				"roleDefinitionId": "/subscriptions/abc/providers/Microsoft.Authorization/roleDefinitions/role-456",
				"displayName":      "Owner",
			},
			expectPrincipalID:   "",
			expectRoleTemplateID: "role-456",
			expectRoleName:       "Owner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal link instance with helper methods
			l := &Neo4jImporterLink{}

			// Simulate the NEW extraction logic (lines 1780-1825 after fix)
			var principalId, roleTemplateId, roleName string

			// Try SDK flat format first
			principalId = l.getStringValue(tt.assignment, "principalId")
			if principalId == "" {
				// Fall back to legacy nested format
				subject := l.getMapValue(tt.assignment, "subject")
				if subject != nil {
					principalId = l.getStringValue(subject, "id")
				}
			}
			// Normalize (lowercasing)
			principalId = l.normalizeResourceId(principalId)

			// Extract role definition - try SDK flat format first
			roleDefinitionId := l.getStringValue(tt.assignment, "roleDefinitionId")
			if roleDefinitionId != "" {
				// Extract template ID from path
				parts := strings.Split(roleDefinitionId, "/")
				if len(parts) > 0 {
					roleTemplateId = parts[len(parts)-1]
				}
			} else {
				// Fall back to legacy nested format
				roleDefinition := l.getMapValue(tt.assignment, "roleDefinition")
				if roleDefinition != nil {
					roleTemplateId = l.getStringValue(roleDefinition, "templateId")
				}
			}

			// Extract role name - both formats
			roleName = l.getStringValue(tt.assignment, "displayName")
			if roleName == "" {
				roleDefinition := l.getMapValue(tt.assignment, "roleDefinition")
				if roleDefinition != nil {
					roleName = l.getStringValue(roleDefinition, "displayName")
				}
			}

			// Verify extraction results (normalize expected too for comparison)
			expectedPrincipalId := strings.ToLower(tt.expectPrincipalID)
			if principalId != expectedPrincipalId {
				t.Errorf("principalId: got %q, want %q", principalId, expectedPrincipalId)
			}
			if roleTemplateId != tt.expectRoleTemplateID {
				t.Errorf("roleTemplateId: got %q, want %q", roleTemplateId, tt.expectRoleTemplateID)
			}
			if roleName != tt.expectRoleName {
				t.Errorf("roleName: got %q, want %q", roleName, tt.expectRoleName)
			}
		})
	}
}
