package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadAKSRBACTemplate is a test helper that loads the aks_rbac_disabled template
func loadAKSRBACTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "aks_rbac_disabled" {
			return tmpl
		}
	}
	t.Fatal("Should find aks_rbac_disabled template")
	return nil
}

// TestAKSRBACDisabledTemplateYAMLParsing verifies the YAML template parses correctly
func TestAKSRBACDisabledTemplateYAMLParsing(t *testing.T) {
	aksRBACTemplate := loadAKSRBACTemplate(t)

	// Verify basic template structure
	assert.Equal(t, "aks_rbac_disabled", aksRBACTemplate.ID)
	assert.Equal(t, "AKS Clusters with RBAC Disabled", aksRBACTemplate.Name)
	assert.NotEmpty(t, aksRBACTemplate.Description)
	assert.Equal(t, "High", aksRBACTemplate.Severity)
	assert.NotEmpty(t, aksRBACTemplate.Query)
}

// TestAKSRBACDisabledTemplateCategory verifies template has correct category
func TestAKSRBACDisabledTemplateCategory(t *testing.T) {
	aksRBACTemplate := loadAKSRBACTemplate(t)

	require.NotNil(t, aksRBACTemplate.Category, "Template should have a category")
	require.NotEmpty(t, aksRBACTemplate.Category, "Category should not be empty")

	// Verify it contains "arg-scan" category
	assert.Contains(t, aksRBACTemplate.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, aksRBACTemplate.Category, "Privilege Escalation", "Should have Privilege Escalation category")
}

// TestAKSRBACDisabledTemplateQueryStructure verifies KQL query has required components
func TestAKSRBACDisabledTemplateQueryStructure(t *testing.T) {
	aksRBACTemplate := loadAKSRBACTemplate(t)

	query := aksRBACTemplate.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'Microsoft.ContainerService/managedClusters'", "Should filter for AKS clusters")
	assert.Contains(t, query, "extend enableRbac", "Should extract enableRBAC property")
	assert.Contains(t, query, "where enableRbac == false", "Should filter for RBAC disabled")
	assert.Contains(t, query, "project", "Should have project clause")

	// Verify projected fields
	assert.Contains(t, query, "id,", "Should project id field")
	assert.Contains(t, query, "name,", "Should project name field")
	assert.Contains(t, query, "subscriptionId,", "Should project subscriptionId")
	assert.Contains(t, query, "resourceGroup,", "Should project resourceGroup")
	assert.Contains(t, query, "enableRbac,", "Should project enableRbac field")
	assert.Contains(t, query, "enableAzureRbac,", "Should project enableAzureRbac for context")
}

// TestAKSRBACDisabledTemplateReferences verifies documentation references exist
func TestAKSRBACDisabledTemplateReferences(t *testing.T) {
	aksRBACTemplate := loadAKSRBACTemplate(t)

	require.NotEmpty(t, aksRBACTemplate.References, "Should have documentation references")

	// Verify references point to Microsoft documentation
	foundMicrosoftDocs := false
	for _, ref := range aksRBACTemplate.References {
		if strings.Contains(ref, "microsoft.com") {
			foundMicrosoftDocs = true
			break
		}
	}
	assert.True(t, foundMicrosoftDocs, "Should have at least one Microsoft documentation reference")
}

// TestAKSRBACDisabledTemplateTriageNotes verifies triage guidance exists
func TestAKSRBACDisabledTemplateTriageNotes(t *testing.T) {
	aksRBACTemplate := loadAKSRBACTemplate(t)

	assert.NotEmpty(t, aksRBACTemplate.TriageNotes, "Should have triage notes for security context")

	// Verify triage notes mention key security concerns
	notes := aksRBACTemplate.TriageNotes
	assert.Contains(t, notes, "RBAC", "Triage notes should explain RBAC")
	assert.Contains(t, notes, "risk", "Should explain security risks")
	assert.Contains(t, notes, "cannot be changed after cluster creation", "Should document that enableRBAC is immutable post-creation")
}

// TestTemplateCountIncreased verifies new template increases total count
func TestTemplateCountIncreased(t *testing.T) {
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err)

	templates := loader.GetTemplates()

	// Count ARG scan templates
	argScanCount := 0
	for _, tmpl := range templates {
		for _, category := range tmpl.Category {
			if category == "arg-scan" {
				argScanCount++
				break
			}
		}
	}

	// Should have at least one arg-scan template (our new one)
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")

	// Verify aks_rbac_disabled is one of them using helper
	aksRBACTemplate := loadAKSRBACTemplate(t)
	assert.NotNil(t, aksRBACTemplate, "aks_rbac_disabled template should be loaded")
}
