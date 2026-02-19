package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFunctionAppHTTPAnonymousAccessTemplate is a test helper that loads the function_app_http_anonymous_access template
func loadFunctionAppHTTPAnonymousAccessTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "function_app_http_anonymous_access" {
			return tmpl
		}
	}
	t.Fatal("Should find function_app_http_anonymous_access template")
	return nil
}

// TestFunctionAppHTTPAnonymousAccessTemplateYAMLParsing verifies the YAML template parses correctly
func TestFunctionAppHTTPAnonymousAccessTemplateYAMLParsing(t *testing.T) {
	tmpl := loadFunctionAppHTTPAnonymousAccessTemplate(t)

	assert.Equal(t, "function_app_http_anonymous_access", tmpl.ID)
	assert.Equal(t, "Function App HTTP Triggers Without Access Keys", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "High", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestFunctionAppHTTPAnonymousAccessTemplateCategory verifies template has correct category
func TestFunctionAppHTTPAnonymousAccessTemplateCategory(t *testing.T) {
	tmpl := loadFunctionAppHTTPAnonymousAccessTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Access Control", "Should have Access Control category")
}

// TestFunctionAppHTTPAnonymousAccessTemplateQueryStructure verifies KQL query has required components
func TestFunctionAppHTTPAnonymousAccessTemplateQueryStructure(t *testing.T) {
	tmpl := loadFunctionAppHTTPAnonymousAccessTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.web/sites'", "Should filter for microsoft.web/sites")
	assert.Contains(t, query, "where kind contains 'functionapp'", "Should filter for functionapp kind")

	// Verify project clause with key fields
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "kind,", "subscriptionId", "resourceGroup,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}
}

// TestFunctionAppHTTPAnonymousAccessTemplateReferences verifies documentation references exist
func TestFunctionAppHTTPAnonymousAccessTemplateReferences(t *testing.T) {
	tmpl := loadFunctionAppHTTPAnonymousAccessTemplate(t)

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

// TestFunctionAppHTTPAnonymousAccessTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestFunctionAppHTTPAnonymousAccessTemplateTriageNotes(t *testing.T) {
	tmpl := loadFunctionAppHTTPAnonymousAccessTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := tmpl.TriageNotes
	assert.Contains(t, notes, "anonymous", "Triage notes should mention anonymous access")
	assert.Contains(t, notes, "authLevel", "Triage notes should mention authLevel")
	assert.Contains(t, notes, "function key", "Triage notes should mention function key")
	assert.Contains(t, notes, "authentication", "Triage notes should mention authentication")
}

// TestFunctionAppHTTPAnonymousAccessTemplateCount verifies at least one arg-scan template is present
func TestFunctionAppHTTPAnonymousAccessTemplateCount(t *testing.T) {
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
		if tmpl.ID == "function_app_http_anonymous_access" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "function_app_http_anonymous_access template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
