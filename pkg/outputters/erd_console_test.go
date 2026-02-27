package outputters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLambdaExtractor_SingleURLNoQualifier tests a single Lambda function URL without qualifier
func TestLambdaExtractor_SingleURLNoQualifier(t *testing.T) {
	// Create the outputter to access the Lambda extractor
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Single URL with no qualifier (base function URL only)
	props := map[string]any{
		"FunctionUrls": []any{
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "",
				"FunctionUrl":  "https://abc123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
		},
	}

	// Act: Extract the function URL
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should return success with formatted URL in actions slice
	assert.True(t, success, "Extractor should succeed")
	assert.Empty(t, extractedValue, "Extracted value should be empty (URLs go in actions)")
	assert.Len(t, actions, 1, "Should have exactly one action")
	assert.Equal(t, "Function URL: https://abc123.lambda-url.us-east-1.on.aws/ (auth: NONE)", actions[0])
}

// TestLambdaExtractor_SingleURLWithQualifier tests a single Lambda function URL with qualifier
func TestLambdaExtractor_SingleURLWithQualifier(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Single URL with prod alias
	props := map[string]any{
		"FunctionUrls": []any{
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "prod",
				"FunctionUrl":  "https://prod123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
		},
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert
	assert.True(t, success)
	assert.Empty(t, extractedValue)
	assert.Len(t, actions, 1)
	assert.Equal(t, "Function URL: https://prod123.lambda-url.us-east-1.on.aws/ (alias: prod, auth: NONE)", actions[0])
}

// TestLambdaExtractor_MultipleURLsBaseAndAliases tests multiple function URLs (base + aliases)
func TestLambdaExtractor_MultipleURLsBaseAndAliases(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Base URL (empty qualifier) + prod and staging aliases
	props := map[string]any{
		"FunctionUrls": []any{
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "",
				"FunctionUrl":  "https://base123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "prod",
				"FunctionUrl":  "https://prod123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "staging",
				"FunctionUrl":  "https://staging123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "AWS_IAM",
			},
		},
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert
	assert.True(t, success)
	assert.Empty(t, extractedValue)
	assert.Len(t, actions, 3, "Should have three URLs (base + 2 aliases)")
	assert.Equal(t, "Function URL: https://base123.lambda-url.us-east-1.on.aws/ (base, auth: NONE)", actions[0])
	assert.Equal(t, "Function URL: https://prod123.lambda-url.us-east-1.on.aws/ (alias: prod, auth: NONE)", actions[1])
	assert.Equal(t, "Function URL: https://staging123.lambda-url.us-east-1.on.aws/ (alias: staging, auth: AWS_IAM)", actions[2])
}

// TestLambdaExtractor_MultipleURLsDifferentAuthTypes tests multiple URLs with mixed auth types
func TestLambdaExtractor_MultipleURLsDifferentAuthTypes(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Public NONE auth and private AWS_IAM auth
	props := map[string]any{
		"FunctionUrls": []any{
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "public",
				"FunctionUrl":  "https://public123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "private",
				"FunctionUrl":  "https://private123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "AWS_IAM",
			},
		},
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert
	assert.True(t, success)
	assert.Empty(t, extractedValue)
	assert.Len(t, actions, 2)
	assert.Equal(t, "Function URL: https://public123.lambda-url.us-east-1.on.aws/ (alias: public, auth: NONE)", actions[0])
	assert.Equal(t, "Function URL: https://private123.lambda-url.us-east-1.on.aws/ (alias: private, auth: AWS_IAM)", actions[1])
}

// TestLambdaExtractor_EmptyFunctionUrlsArray tests empty FunctionUrls array fallback
func TestLambdaExtractor_EmptyFunctionUrlsArray(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Empty FunctionUrls array with singular FunctionUrl fallback
	props := map[string]any{
		"FunctionUrls": []any{},
		"FunctionUrl":  "https://fallback123.lambda-url.us-east-1.on.aws/",
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should fall back to FunctionUrl (singular)
	assert.True(t, success, "Should fall back to singular FunctionUrl")
	assert.Equal(t, "https://fallback123.lambda-url.us-east-1.on.aws/", extractedValue, "Should return singular URL")
	assert.Nil(t, actions, "Actions should be nil when using fallback")
}

// TestLambdaExtractor_InvalidFunctionUrlsEntries tests handling of invalid entries in FunctionUrls
func TestLambdaExtractor_InvalidFunctionUrlsEntries(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Mix of valid and invalid entries
	props := map[string]any{
		"FunctionUrls": []any{
			"not-a-map", // Invalid: string instead of map
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "valid",
				"FunctionUrl":  "https://valid123.lambda-url.us-east-1.on.aws/",
				"AuthType":     "NONE",
			},
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "invalid",
				"FunctionUrl":  "", // Invalid: empty URL
				"AuthType":     "NONE",
			},
		},
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should skip invalid entries and only return valid one
	assert.True(t, success, "Should succeed with at least one valid entry")
	assert.Empty(t, extractedValue)
	assert.Len(t, actions, 1, "Should only include valid URL")
	assert.Equal(t, "Function URL: https://valid123.lambda-url.us-east-1.on.aws/ (alias: valid, auth: NONE)", actions[0])
}

// TestLambdaExtractor_OnlyFunctionUrlSingular tests backward compatibility with singular FunctionUrl
func TestLambdaExtractor_OnlyFunctionUrlSingular(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Only singular FunctionUrl (no FunctionUrls array)
	props := map[string]any{
		"FunctionUrl": "https://legacy123.lambda-url.us-east-1.on.aws/",
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should use backward compatibility path
	assert.True(t, success, "Should support backward compatibility")
	assert.Equal(t, "https://legacy123.lambda-url.us-east-1.on.aws/", extractedValue)
	assert.Nil(t, actions)
}

// TestLambdaExtractor_NeitherFunctionUrlsNorFunctionUrl tests no URLs present
func TestLambdaExtractor_NeitherFunctionUrlsNorFunctionUrl(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: Lambda function with no function URLs at all
	props := map[string]any{
		"FunctionName": "my-function",
		"Runtime":      "nodejs18.x",
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should return false (no URLs to extract)
	assert.False(t, success, "Should return false when no URLs present")
	assert.Empty(t, extractedValue)
	assert.Nil(t, actions)
}

// TestLambdaExtractor_DefaultAuthType tests that missing AuthType defaults to NONE
func TestLambdaExtractor_DefaultAuthType(t *testing.T) {
	o := &ERDConsoleOutputter{
		extractors: make(map[string]PropertyExtractor),
	}
	o.registerDefaultExtractors()

	// Arrange: URL without AuthType specified
	props := map[string]any{
		"FunctionUrls": []any{
			map[string]any{
				"FunctionName": "my-function",
				"Qualifier":    "prod",
				"FunctionUrl":  "https://noauth123.lambda-url.us-east-1.on.aws/",
				// AuthType is missing - should default to NONE
			},
		},
	}

	// Act
	extractedValue, actions, success := o.extractors["AWS::Lambda::Function"](props)

	// Assert: Should default AuthType to NONE
	assert.True(t, success)
	assert.Empty(t, extractedValue)
	assert.Len(t, actions, 1)
	assert.Equal(t, "Function URL: https://noauth123.lambda-url.us-east-1.on.aws/ (alias: prod, auth: NONE)", actions[0])
}
