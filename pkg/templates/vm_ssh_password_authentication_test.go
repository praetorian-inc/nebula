package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadVMSSHPasswordAuthTemplate is a test helper that loads the vm_ssh_password_authentication template
func loadVMSSHPasswordAuthTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "Template loader should initialize successfully")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "Should have loaded at least one template")

	for _, tmpl := range templates {
		if tmpl.ID == "vm_ssh_password_authentication" {
			return tmpl
		}
	}
	t.Fatal("Should find vm_ssh_password_authentication template")
	return nil
}

// TestVMSSHPasswordAuthTemplateYAMLParsing verifies the YAML template parses correctly
func TestVMSSHPasswordAuthTemplateYAMLParsing(t *testing.T) {
	tmpl := loadVMSSHPasswordAuthTemplate(t)

	assert.Equal(t, "vm_ssh_password_authentication", tmpl.ID)
	assert.Equal(t, "VM SSH Password Authentication Enabled", tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.Equal(t, "High", tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

// TestVMSSHPasswordAuthTemplateCategory verifies template has correct category
func TestVMSSHPasswordAuthTemplateCategory(t *testing.T) {
	tmpl := loadVMSSHPasswordAuthTemplate(t)

	require.NotNil(t, tmpl.Category, "Template should have a category")
	require.NotEmpty(t, tmpl.Category, "Category should not be empty")

	assert.Contains(t, tmpl.Category, "arg-scan", "Should have arg-scan category")
	assert.Contains(t, tmpl.Category, "Access Control", "Should have Access Control category")
}

// TestVMSSHPasswordAuthTemplateQueryStructure verifies KQL query has required components
func TestVMSSHPasswordAuthTemplateQueryStructure(t *testing.T) {
	tmpl := loadVMSSHPasswordAuthTemplate(t)

	query := tmpl.Query

	// Verify KQL query structure
	assert.Contains(t, query, "resources", "Query should start with resources table")
	assert.Contains(t, query, "where type =~ 'microsoft.compute/virtualmachines'", "Should filter for microsoft.compute/virtualmachines")
	assert.Contains(t, query, "osType =~ 'Linux'", "Should filter for Linux VMs only")

	// Verify Pattern C coalesce usage for null-safe boolean check
	assert.Contains(t, query, "coalesce(tobool(", "Should use coalesce(tobool(...)) pattern")
	assert.Contains(t, query, "disablePasswordAuthentication), false)", "Should default missing values to false")
	assert.Contains(t, query, "where disablePasswordAuth == false", "Should filter for password auth enabled VMs")

	// Verify project clause with key fields
	assert.Contains(t, query, "project", "Should have project clause")
	for _, field := range []string{"id,", "name,", "type,", "subscriptionId", "resourceGroup,"} {
		assert.Contains(t, query, field, "Query project clause should include "+field)
	}
}

// TestVMSSHPasswordAuthTemplateReferences verifies documentation references exist
func TestVMSSHPasswordAuthTemplateReferences(t *testing.T) {
	tmpl := loadVMSSHPasswordAuthTemplate(t)

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

// TestVMSSHPasswordAuthTemplateTriageNotes verifies triage guidance exists and covers key topics
func TestVMSSHPasswordAuthTemplateTriageNotes(t *testing.T) {
	tmpl := loadVMSSHPasswordAuthTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "Should have triage notes for security context")

	notes := tmpl.TriageNotes
	assert.Contains(t, notes, "password", "Triage notes should mention password authentication")
	assert.Contains(t, notes, "SSH", "Triage notes should mention SSH")
	assert.Contains(t, notes, "brute", "Triage notes should mention brute-force attacks")
	assert.Contains(t, notes, "key", "Triage notes should mention SSH key authentication")
}

// TestVMSSHPasswordAuthTemplateCount verifies at least one arg-scan template is present
func TestVMSSHPasswordAuthTemplateCount(t *testing.T) {
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
		if tmpl.ID == "vm_ssh_password_authentication" {
			foundOurs = true
		}
	}

	assert.True(t, foundOurs, "vm_ssh_password_authentication template should be loaded")
	assert.GreaterOrEqual(t, argScanCount, 1, "Should have at least one arg-scan template")
}
