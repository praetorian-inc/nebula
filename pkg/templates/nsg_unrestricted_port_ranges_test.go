package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadNSGUnrestrictedPortRangesTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err)
	require.NotNil(t, loader)

	for _, tmpl := range loader.GetTemplates() {
		if tmpl.ID == "nsg_unrestricted_port_ranges" {
			return tmpl
		}
	}
	t.Fatal("template nsg_unrestricted_port_ranges not found")
	return nil
}

func TestNSGUnrestrictedPortRanges_YAMLParsing(t *testing.T) {
	tmpl := loadNSGUnrestrictedPortRangesTemplate(t)

	assert.Equal(t, "nsg_unrestricted_port_ranges", tmpl.ID)
	assert.NotEmpty(t, tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.NotEmpty(t, tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

func TestNSGUnrestrictedPortRanges_Category(t *testing.T) {
	tmpl := loadNSGUnrestrictedPortRangesTemplate(t)

	assert.Contains(t, tmpl.Category, "Access Control")
	assert.Contains(t, tmpl.Category, "arg-scan")
}

func TestNSGUnrestrictedPortRanges_QueryStructure(t *testing.T) {
	tmpl := loadNSGUnrestrictedPortRangesTemplate(t)
	query := tmpl.Query

	// Verify case-insensitive operators are used for direction and access
	assert.True(t, strings.Contains(query, "=~ 'Inbound'"), "query should use =~ for direction filter")
	assert.True(t, strings.Contains(query, "=~ 'Allow'"), "query should use =~ for access filter")

	// Verify case-sensitive == is NOT used for direction/access
	assert.False(t, strings.Contains(query, "== 'Inbound'"), "query must not use == for direction filter")
	assert.False(t, strings.Contains(query, "== 'Allow'"), "query must not use == for access filter")

	// Verify key structural elements
	assert.Contains(t, query, "microsoft.network/networksecuritygroups")
	assert.Contains(t, query, "mv-expand rule = properties.securityRules")
	assert.Contains(t, query, "totalPortSpan > 1000")
}

func TestNSGUnrestrictedPortRanges_References(t *testing.T) {
	tmpl := loadNSGUnrestrictedPortRangesTemplate(t)

	assert.NotEmpty(t, tmpl.References)
	for _, ref := range tmpl.References {
		assert.NotEmpty(t, ref)
		assert.True(t, strings.HasPrefix(ref, "http"), "reference should be a URL: %s", ref)
	}
}

func TestNSGUnrestrictedPortRanges_TriageNotes(t *testing.T) {
	tmpl := loadNSGUnrestrictedPortRangesTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes)
	assert.Contains(t, tmpl.TriageNotes, "totalPortSpan")
}

func TestNSGUnrestrictedPortRanges_TemplateCount(t *testing.T) {
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err)

	templates := loader.GetTemplates()
	assert.NotEmpty(t, templates)

	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "nsg_unrestricted_port_ranges" {
			found = true
			break
		}
	}
	assert.True(t, found, "nsg_unrestricted_port_ranges template should be present in the embedded template set")
}
