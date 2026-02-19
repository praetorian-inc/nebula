package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFunctionAppsAdminManagedIdentityTemplate is a test helper that loads the function_apps_admin_managed_identity template
func loadFunctionAppsAdminManagedIdentityTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "function_apps_admin_managed_identity" {
			return tmpl
		}
	}
	t.Fatal("Should find function_apps_admin_managed_identity template")
	return nil
}

// TestFunctionAppsAdminManagedIdentityTemplateYAMLParsing verifies the YAML template parses correctly
func TestFunctionAppsAdminManagedIdentityTemplateYAMLParsing(t *testing.T) {
	tmpl := loadFunctionAppsAdminManagedIdentityTemplate(t)

	assert.Equal(t, "function_apps_admin_managed_identity", tmpl.ID)
	assert.Equal(t, "Function Apps with Admin Managed Identity", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "Low", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestFunctionAppsAdminManagedIdentityTemplateCategory verifies template has correct category
func TestFunctionAppsAdminManagedIdentityTemplateCategory(t *testing.T) {
	tmpl := loadFunctionAppsAdminManagedIdentityTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Privilege Escalation", "Should have Privilege Escalation category")
}

// TestFunctionAppsAdminManagedIdentityTemplateQueryStructure verifies KQL query has required components
func TestFunctionAppsAdminManagedIdentityTemplateQueryStructure(t *testing.T) {
	tmpl := loadFunctionAppsAdminManagedIdentityTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.web/sites'", "Should filter for microsoft.web/sites")
	assert.Contains(t, query, "where kind contains 'functionapp'", "Should filter for functionapp kind")

	// Verify managed identity checks
	assert.Contains(t, query, "isnotnull(identity)", "Should check for non-null identity")
	assert.Contains(t, query, "identity.type =~ 'SystemAssigned'", "Should filter for SystemAssigned identity")

	// Verify role GUID filters with comments
	assert.Contains(t, query, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Should include Owner role GUID")
	assert.Contains(t, query, "// Owner", "Should have comment documenting Owner role GUID")
	assert.Contains(t, query, "b24988ac-6180-42a0-ab88-20f7382dd24c", "Should include Contributor role GUID")
	assert.Contains(t, query, "// Contributor", "Should have comment documenting Contributor role GUID")
	assert.Contains(t, query, "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", "Should include User Access Administrator role GUID")
	assert.Contains(t, query, "// User Access Administrator", "Should have comment documenting User Access Administrator role GUID")

	// Verify join and project clause
	assert.Contains(t, query, "join kind=inner", "Should use inner join for role assignments")
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "subscriptionId", "resourceGroup,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}
}

// TestFunctionAppsAdminManagedIdentityTemplateReferences verifies documentation references exist
func TestFunctionAppsAdminManagedIdentityTemplateReferences(t *testing.T) {
	tmpl := loadFunctionAppsAdminManagedIdentityTemplate(t)

	require.NotEmpty(t, tmpl.References, "Should have documentation references")

	foundMicrosoftDocs := false
	for _, ref := range tmpl.References {
		if strings.Contains(ref, "microsoft.com") {
			foundMicrosoftDocs = true
			break
		}
	}
	assert.True(t, foundMicrosoftDocs, "Should have at least one Microsoft documentation reference")
}

// TestFunctionAppsAdminManagedIdentityTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestFunctionAppsAdminManagedIdentityTemplateTriageNotes(t *testing.T) {
	tmpl := loadFunctionAppsAdminManagedIdentityTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := tmpl.TriageNotes
	assert.Contains(t, notes, "Function App", "Triage notes should mention Function App")
	assert.Contains(t, notes, "managed identity", "Triage notes should mention managed identity")
	assert.Contains(t, notes, "IMDS", "Triage notes should mention IMDS")
	assert.Contains(t, notes, "Owner", "Triage notes should mention Owner role")
	assert.Contains(t, notes, "Contributor", "Triage notes should mention Contributor role")
	assert.Contains(t, notes, "User Access Administrator", "Triage notes should mention User Access Administrator role")
}

// TestFunctionAppsAdminManagedIdentityTemplateCount verifies new template increases total count
func TestFunctionAppsAdminManagedIdentityTemplateCount(t *testing.T) {
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err)

	templates := loader.GetTemplates()

	argScanCount := 0
	foundOurs := false
	for _, tmpl := range templates {
		for _, category := range tmpl.Category {
			if category == "arg-scan" {
				argScanCount++
				break
			}
		}
		if tmpl.ID == "function_apps_admin_managed_identity" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "function_apps_admin_managed_identity template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
