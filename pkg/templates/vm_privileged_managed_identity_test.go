package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadVMPrivilegedManagedIdentityTemplate is a test helper that loads the vm_privileged_managed_identity template
func loadVMPrivilegedManagedIdentityTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "vm_privileged_managed_identity" {
			return tmpl
		}
	}
	t.Fatal("Should find vm_privileged_managed_identity template")
	return nil
}

// TestVMPrivilegedManagedIdentityTemplateYAMLParsing verifies the YAML template parses correctly
func TestVMPrivilegedManagedIdentityTemplateYAMLParsing(t *testing.T) {
	tmpl := loadVMPrivilegedManagedIdentityTemplate(t)

	assert.Equal(t, "vm_privileged_managed_identity", tmpl.ID)
	assert.Equal(t, "VMs with Privileged Managed Identities", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "Low", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestVMPrivilegedManagedIdentityTemplateCategory verifies template has correct category
func TestVMPrivilegedManagedIdentityTemplateCategory(t *testing.T) {
	tmpl := loadVMPrivilegedManagedIdentityTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Access Control", "Should have Access Control category")
}

// TestVMPrivilegedManagedIdentityTemplateQueryStructure verifies KQL query has required components
func TestVMPrivilegedManagedIdentityTemplateQueryStructure(t *testing.T) {
	tmpl := loadVMPrivilegedManagedIdentityTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.compute/virtualmachines'", "Should filter for microsoft.compute/virtualmachines")
	assert.Contains(t, query, "where isnotnull(identity)", "Should filter for VMs with managed identities")

	// Verify project clause with key fields
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "subscriptionId", "resourceGroup,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}

	// Verify enricher design comment is present
	assert.Contains(t, query, "enricher", "Query should have KQL comment explaining enricher-based design")
}

// TestVMPrivilegedManagedIdentityTemplateReferences verifies documentation references exist
func TestVMPrivilegedManagedIdentityTemplateReferences(t *testing.T) {
	tmpl := loadVMPrivilegedManagedIdentityTemplate(t)

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

// TestVMPrivilegedManagedIdentityTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestVMPrivilegedManagedIdentityTemplateTriageNotes(t *testing.T) {
	tmpl := loadVMPrivilegedManagedIdentityTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := strings.ToLower(tmpl.TriageNotes)
	assert.Contains(t, notes, "managed identity", "Triage notes should mention managed identity")
	assert.Contains(t, notes, "imds", "Triage notes should mention IMDS")
	assert.Contains(t, notes, "privilege", "Triage notes should mention privilege")

	// Should mention lateral movement or escalation
	mentionsLateralOrEscalation := strings.Contains(notes, "lateral movement") || strings.Contains(notes, "escalation")
	assert.True(t, mentionsLateralOrEscalation, "Triage notes should mention lateral movement or escalation")
}

// TestVMPrivilegedManagedIdentityTemplateCount verifies at least one arg-scan template is present
func TestVMPrivilegedManagedIdentityTemplateCount(t *testing.T) {
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
		if tmpl.ID == "vm_privileged_managed_identity" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "vm_privileged_managed_identity template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
