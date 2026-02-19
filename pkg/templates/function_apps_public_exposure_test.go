package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFunctionAppsPublicExposureTemplate is a test helper that loads the function_apps_public_exposure template
func loadFunctionAppsPublicExposureTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "function_apps_public_exposure" {
			return tmpl
		}
	}
	t.Fatal("Should find function_apps_public_exposure template")
	return nil
}

// TestFunctionAppsPublicExposureTemplateYAMLParsing verifies the YAML template parses correctly
func TestFunctionAppsPublicExposureTemplateYAMLParsing(t *testing.T) {
	tmpl := loadFunctionAppsPublicExposureTemplate(t)

	assert.Equal(t, "function_apps_public_exposure", tmpl.ID)
	assert.Equal(t, "Function Apps Publicly Exposed", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "Medium", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestFunctionAppsPublicExposureTemplateCategory verifies template has correct category
func TestFunctionAppsPublicExposureTemplateCategory(t *testing.T) {
	tmpl := loadFunctionAppsPublicExposureTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Public Access", "Should have Public Access category")
}

// TestFunctionAppsPublicExposureTemplateQueryStructure verifies KQL query has required components
func TestFunctionAppsPublicExposureTemplateQueryStructure(t *testing.T) {
	tmpl := loadFunctionAppsPublicExposureTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.web/sites'", "Should filter for microsoft.web/sites")
	assert.Contains(t, query, "where kind contains 'functionapp'", "Should filter for functionapp kind")

	// Verify null-safe coalesce patterns
	assert.Contains(t, query, "coalesce(properties.publicNetworkAccess,", "Should use coalesce for publicNetworkAccess")
	assert.Contains(t, query, "coalesce(array_length(properties.privateEndpointConnections", "Should use Pattern C coalesce for PE array_length")

	// Verify detection logic
	assert.Contains(t, query, "where publicNetworkAccess != 'disabled'", "Should filter for non-disabled public access")
	assert.Contains(t, query, "where hasPrivateEndpoint == false", "Should filter for no private endpoints")

	// Verify project clause with key fields
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "kind,", "subscriptionId", "resourceGroup,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}

	// Verify enrichment fields
	assert.Contains(t, query, "hasIpRestrictions", "Should include hasIpRestrictions enrichment field")
	assert.Contains(t, query, "hostingPlan", "Should include hostingPlan enrichment field")
	assert.Contains(t, query, "httpsOnly", "Should include httpsOnly enrichment field")
}

// TestFunctionAppsPublicExposureTemplateReferences verifies documentation references exist
func TestFunctionAppsPublicExposureTemplateReferences(t *testing.T) {
	tmpl := loadFunctionAppsPublicExposureTemplate(t)

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

// TestFunctionAppsPublicExposureTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestFunctionAppsPublicExposureTemplateTriageNotes(t *testing.T) {
	tmpl := loadFunctionAppsPublicExposureTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := tmpl.TriageNotes
	assert.Contains(t, notes, "Function App", "Triage notes should mention Function App")
	assert.Contains(t, notes, "private endpoint", "Triage notes should mention private endpoint")
	assert.Contains(t, notes, "Consumption plan", "Triage notes should mention Consumption plan limitations")
	assert.Contains(t, notes, "Compensating Controls", "Triage notes should mention compensating controls")
	assert.Contains(t, notes, "CANNOT use private endpoints", "Triage notes should mention Consumption plan PE limitation")
	assert.Contains(t, notes, "Pending", "Triage notes should document PE connection state limitation")
}

// TestFunctionAppsPublicExposureTemplateCount verifies new template increases total count
func TestFunctionAppsPublicExposureTemplateCount(t *testing.T) {
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
		if tmpl.ID == "function_apps_public_exposure" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "function_apps_public_exposure template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
