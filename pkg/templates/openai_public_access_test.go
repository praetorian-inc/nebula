package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadOpenAIPublicAccessTemplate is a helper that loads all embedded templates and
// returns the one with ID "openai_public_access".
func loadOpenAIPublicAccessTemplate(t *testing.T) *ARGQueryTemplate {
	t.Helper()

	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "failed to create template loader")

	for _, tmpl := range loader.GetTemplates() {
		if tmpl.ID == "openai_public_access" {
			return tmpl
		}
	}

	t.Fatal("template 'openai_public_access' not found in embedded templates")
	return nil
}

func TestOpenAIPublicAccess_YAMLParsing(t *testing.T) {
	tmpl := loadOpenAIPublicAccessTemplate(t)

	assert.Equal(t, "openai_public_access", tmpl.ID)
	assert.NotEmpty(t, tmpl.Name)
	assert.NotEmpty(t, tmpl.Description)
	assert.NotEmpty(t, tmpl.Severity)
	assert.NotEmpty(t, tmpl.Query)
}

func TestOpenAIPublicAccess_Category(t *testing.T) {
	tmpl := loadOpenAIPublicAccessTemplate(t)

	assert.Contains(t, tmpl.Category, "Public Access")
	assert.Contains(t, tmpl.Category, "arg-scan")
}

func TestOpenAIPublicAccess_QueryStructure(t *testing.T) {
	tmpl := loadOpenAIPublicAccessTemplate(t)

	query := tmpl.Query

	// Verify resource type filter uses case-insensitive operator
	assert.Contains(t, query, "type =~ 'microsoft.cognitiveservices/accounts'")

	// Verify OpenAI kind filter
	assert.Contains(t, query, "kind =~ 'OpenAI'")

	// Verify Pattern C: null-safe array length via coalesce
	assert.Contains(t, query, "coalesce(array_length(properties.privateEndpointConnections), 0)")

	// Verify public network access uses coalesce with safe default
	assert.True(t,
		strings.Contains(query, "coalesce(properties.publicNetworkAccess"),
		"query should use coalesce for publicNetworkAccess null safety",
	)

	// Verify the query filters for enabled public access and no private endpoint
	assert.Contains(t, query, "publicNetworkAccess == 'enabled'")
	assert.Contains(t, query, "hasPrivateEndpoint == false")
}

func TestOpenAIPublicAccess_References(t *testing.T) {
	tmpl := loadOpenAIPublicAccessTemplate(t)

	require.NotEmpty(t, tmpl.References, "template should have at least one reference")

	for _, ref := range tmpl.References {
		assert.NotEmpty(t, ref, "reference URL should not be empty")
	}

	// Verify at least one Microsoft docs reference
	hasMicrosoftRef := false
	for _, ref := range tmpl.References {
		if strings.Contains(ref, "learn.microsoft.com") {
			hasMicrosoftRef = true
			break
		}
	}
	assert.True(t, hasMicrosoftRef, "template should reference Microsoft documentation")
}

func TestOpenAIPublicAccess_TriageNotes(t *testing.T) {
	tmpl := loadOpenAIPublicAccessTemplate(t)

	assert.NotEmpty(t, tmpl.TriageNotes, "template should have triage notes")

	// Triage notes should contain remediation guidance
	assert.True(t,
		strings.Contains(tmpl.TriageNotes, "private endpoint") ||
			strings.Contains(tmpl.TriageNotes, "Private endpoint"),
		"triage notes should mention private endpoint guidance",
	)
}

func TestOpenAIPublicAccess_TemplateCount(t *testing.T) {
	loader, err := NewTemplateLoader(LoadEmbedded)
	require.NoError(t, err, "failed to create template loader")

	templates := loader.GetTemplates()
	require.NotEmpty(t, templates, "embedded templates should not be empty")

	// Verify exactly one template with this ID is registered
	count := 0
	for _, tmpl := range templates {
		if tmpl.ID == "openai_public_access" {
			count++
		}
	}
	assert.Equal(t, 1, count, "expected exactly one 'openai_public_access' template")
}
