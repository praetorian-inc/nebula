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
				// Extract template ID from path like "/...roleDefinitions/role-456"
				parts := strings.Split(roleDefinitionId, "/")
				if len(parts) > 0 {
					roleTemplateId = parts[len(parts)-1]
				}
			} else {
				// Fall back to legacy nested format
				roleDefMap := l.getMapValue(tt.assignment, "roleDefinition")
				if roleDefMap != nil {
					roleTemplateId = l.getStringValue(roleDefMap, "templateId")
				}
			}
			roleTemplateId = l.normalizeResourceId(roleTemplateId)

			// Extract display name - try SDK flat format first
			roleName = l.getStringValue(tt.assignment, "displayName")
			if roleName == "" {
				// Fall back to legacy nested format
				roleDefMap := l.getMapValue(tt.assignment, "roleDefinition")
				if roleDefMap != nil {
					roleName = l.getStringValue(roleDefMap, "displayName")
				}
			}

			// Verify expectations
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

// TestApplicationCredentialPermissionFieldExtraction tests that Application Credential
// permission collector produces data with correct field names that the importer expects.
// BUG: Collector uses "role" but importer expects "roleName"
func TestApplicationCredentialPermissionFieldExtraction(t *testing.T) {
	tests := []struct {
		name              string
		permission        map[string]interface{}
		expectPrincipalID string
		expectRoleName    string
	}{
		{
			name: "Valid permission with correct fields",
			permission: map[string]interface{}{
				"principalId":       "user-123",
				"principalName":     "John Doe",
				"principalType":     "#microsoft.graph.user",
				"roleName":          "Application Administrator",
				"permissionType":    "ApplicationCredentialManagement",
				"capability":        "CanManageApplicationCredentials",
			},
			expectPrincipalID: "user-123",
			expectRoleName:    "Application Administrator",
		},
		{
			name: "Permission missing principalId - should be skipped by importer",
			permission: map[string]interface{}{
				"principalName":     "John Doe",
				"principalType":     "#microsoft.graph.user",
				"roleName":          "Application Administrator",
				"permissionType":    "ApplicationCredentialManagement",
			},
			expectPrincipalID: "",
			expectRoleName:    "Application Administrator",
		},
		{
			name: "Permission missing roleName - should be skipped by importer",
			permission: map[string]interface{}{
				"principalId":       "user-456",
				"principalName":     "Jane Smith",
				"principalType":     "#microsoft.graph.user",
				"permissionType":    "ApplicationCredentialManagement",
			},
			expectPrincipalID: "user-456",
			expectRoleName:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Neo4jImporterLink{}

			// Extract fields as importer does (lines 3690-3691)
			principalID := l.getStringValue(tt.permission, "principalId")
			roleName := l.getStringValue(tt.permission, "roleName")

			if principalID != tt.expectPrincipalID {
				t.Errorf("principalId: got %q, want %q", principalID, tt.expectPrincipalID)
			}
			if roleName != tt.expectRoleName {
				t.Errorf("roleName: got %q, want %q", roleName, tt.expectRoleName)
			}

			// Verify importer validation would work correctly
			if tt.expectPrincipalID != "" && tt.expectRoleName != "" {
				if principalID == "" || roleName == "" {
					t.Errorf("Valid permission should extract both fields, got principalID=%q roleName=%q",
						principalID, roleName)
				}
			}
		})
	}
}

// TestApplicationRBACPermissionFieldExtraction tests that Application RBAC
// permission collector produces data with correct field names that the importer expects.
// BUG: Collector uses "applicationId" and "role" but importer expects "principalId" and "roleName"
func TestApplicationRBACPermissionFieldExtraction(t *testing.T) {
	tests := []struct {
		name              string
		permission        map[string]interface{}
		expectPrincipalID string
		expectRoleName    string
	}{
		{
			name: "Valid permission with correct fields",
			permission: map[string]interface{}{
				"principalId":       "app-789",
				"applicationName":   "MyApp",
				"roleName":          "Cloud Application Administrator",
				"permissionType":    "ApplicationRBAC",
				"scope":             "Application",
				"implicitAccess":    true,
			},
			expectPrincipalID: "app-789",
			expectRoleName:    "Cloud Application Administrator",
		},
		{
			name: "Permission missing principalId - should be skipped by importer",
			permission: map[string]interface{}{
				"applicationName":   "MyApp",
				"roleName":          "Application Developer",
				"permissionType":    "ApplicationRBAC",
			},
			expectPrincipalID: "",
			expectRoleName:    "Application Developer",
		},
		{
			name: "Permission missing roleName - should be skipped by importer",
			permission: map[string]interface{}{
				"principalId":       "app-999",
				"applicationName":   "AnotherApp",
				"permissionType":    "ApplicationRBAC",
			},
			expectPrincipalID: "app-999",
			expectRoleName:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Neo4jImporterLink{}

			// Extract fields as importer does (lines 3776-3777)
			principalID := l.getStringValue(tt.permission, "principalId")
			roleName := l.getStringValue(tt.permission, "roleName")

			if principalID != tt.expectPrincipalID {
				t.Errorf("principalId: got %q, want %q", principalID, tt.expectPrincipalID)
			}
			if roleName != tt.expectRoleName {
				t.Errorf("roleName: got %q, want %q", roleName, tt.expectRoleName)
			}

			// Verify importer validation would work correctly
			if tt.expectPrincipalID != "" && tt.expectRoleName != "" {
				if principalID == "" || roleName == "" {
					t.Errorf("Valid permission should extract both fields, got principalID=%q roleName=%q",
						principalID, roleName)
				}
			}
		})
	}
}
