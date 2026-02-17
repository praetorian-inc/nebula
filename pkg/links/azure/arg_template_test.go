package azure

import (
	"slices"
	"testing"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewARGTemplateLoaderLink(t *testing.T) {
	tests := []struct {
		name      string
		sub       string
		directory string
		category  string
	}{
		{
			name:      "No filters",
			sub:       "sub1",
			directory: "",
			category:  "",
		},
		{
			name:      "With category filter",
			sub:       "sub1",
			directory: "",
			category:  "arg-scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Dynamically determine expected results
			loader, err := templates.NewTemplateLoader(templates.LoadEmbedded)
			require.NoError(t, err, "Template loader should initialize")
			if tt.directory != "" {
				_ = loader.LoadUserTemplates(tt.directory)
			}
			templatesList := loader.GetTemplates()
			expected := 0
			for _, t := range templatesList {
				if tt.category == "" || slices.Contains(t.Category, tt.category) {
					expected += 1
				}
			}

			link := NewARGTemplateLoaderLink(
				cfg.WithArg("template-dir", tt.directory),
				cfg.WithArg("category", tt.category),
				cfg.WithArg("subscription", tt.sub),
			)

			c := chain.NewChain(link)
			c.Send(tt.sub)
			c.Close()

			results := 0
			for v, ok := chain.RecvAs[ARGTemplateQueryInput](c); ok; v, ok = chain.RecvAs[ARGTemplateQueryInput](c) {
				if tt.category != "" && !slices.Contains(v.Template.Category, tt.category) {
					continue // Only count/assert those matching the filter
				}
				results++
				assert.NotNil(t, v.Template)
				assert.Equal(t, tt.sub, v.Subscription)
				if tt.category != "" {
					assert.Contains(t, v.Template.Category, tt.category)
				}
			}
			assert.NoError(t, c.Error())
			assert.Equal(t, expected, results)
		})
	}
}
