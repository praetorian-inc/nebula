package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadAppServiceAuthDisabledTemplate is a test helper that loads the app_service_auth_disabled template
func loadAppServiceAuthDisabledTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "app_service_auth_disabled" {
			return tmpl
		}
	}
	t.Fatal("Should find app_service_auth_disabled template")
	return nil
}

// TestAppServiceAuthDisabledTemplateYAMLParsing verifies the YAML template parses correctly
func TestAppServiceAuthDisabledTemplateYAMLParsing(t *testing.T) {
	tmpl := loadAppServiceAuthDisabledTemplate(t)

	assert.Equal(t, "app_service_auth_disabled", tmpl.ID)
	assert.Equal(t, "App Service Authentication Disabled", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "Medium", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestAppServiceAuthDisabledTemplateCategory verifies template has correct category
func TestAppServiceAuthDisabledTemplateCategory(t *testing.T) {
	tmpl := loadAppServiceAuthDisabledTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Access Control", "Should have Access Control category")
}

// TestAppServiceAuthDisabledTemplateQueryStructure verifies KQL query has required components
func TestAppServiceAuthDisabledTemplateQueryStructure(t *testing.T) {
	tmpl := loadAppServiceAuthDisabledTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.web/sites'", "Should filter for microsoft.web/sites")
	assert.Contains(t, query, "where kind !contains 'functionapp'", "Should exclude functionapp kind")

	// Verify enrichment comment for enricher-based detection
	assert.Contains(t, query, "authsettingsV2", "Should mention authsettingsV2 enricher in comment")

	// Verify enrichment fields using proper null-safe patterns
	assert.Contains(t, query, "tolower(coalesce(properties.publicNetworkAccess", "Should use coalesce for publicNetworkAccess")
	assert.Contains(t, query, "coalesce(tobool(properties.httpsOnly), false)", "Should use coalesce for httpsOnly")

	// Verify project clause with key fields
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "kind,", "subscriptionId", "resourceGroup,", "publicNetworkAccess,", "httpsOnly,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}
}

// TestAppServiceAuthDisabledTemplateReferences verifies documentation references exist
func TestAppServiceAuthDisabledTemplateReferences(t *testing.T) {
	tmpl := loadAppServiceAuthDisabledTemplate(t)

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

// TestAppServiceAuthDisabledTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestAppServiceAuthDisabledTemplateTriageNotes(t *testing.T) {
	tmpl := loadAppServiceAuthDisabledTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := tmpl.TriageNotes
	assert.Contains(t, notes, "Easy Auth", "Triage notes should mention Easy Auth")
	assert.Contains(t, notes, "authsettingsV2", "Triage notes should mention authsettingsV2")
	assert.Contains(t, notes, "authentication", "Triage notes should mention authentication")
	assert.Contains(t, notes, "platform", "Triage notes should mention platform")
}

// TestAppServiceAuthDisabledTemplateCount verifies at least one arg-scan template is present
func TestAppServiceAuthDisabledTemplateCount(t *testing.T) {
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
		if tmpl.ID == "app_service_auth_disabled" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "app_service_auth_disabled template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
