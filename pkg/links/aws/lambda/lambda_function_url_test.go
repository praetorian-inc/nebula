package lambda

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFunctionURLInfo_JSONRoundTrip tests JSON serialization with struct tags
func TestFunctionURLInfo_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		info         FunctionURLInfo
		expectedJSON string
	}{
		{
			name: "base function URL omits empty Qualifier",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "",
				FunctionURL:  "https://abc123.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
			expectedJSON: `{"FunctionName":"my-function","FunctionUrl":"https://abc123.lambda-url.us-east-1.on.aws/","AuthType":"NONE"}`,
		},
		{
			name: "alias function URL includes Qualifier",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "prod",
				FunctionURL:  "https://def456.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
			expectedJSON: `{"FunctionName":"my-function","Qualifier":"prod","FunctionUrl":"https://def456.lambda-url.us-east-1.on.aws/","AuthType":"NONE"}`,
		},
		{
			name: "AWS_IAM auth type",
			info: FunctionURLInfo{
				FunctionName: "secure-function",
				Qualifier:    "staging",
				FunctionURL:  "https://ghi789.lambda-url.us-west-2.on.aws/",
				AuthType:     "AWS_IAM",
			},
			expectedJSON: `{"FunctionName":"secure-function","Qualifier":"staging","FunctionUrl":"https://ghi789.lambda-url.us-west-2.on.aws/","AuthType":"AWS_IAM"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonBytes, err := json.Marshal(tt.info)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.expectedJSON, string(jsonBytes))

			// Test unmarshaling round-trip
			var unmarshaled FunctionURLInfo
			err = json.Unmarshal(jsonBytes, &unmarshaled)
			assert.NoError(t, err)
			assert.Equal(t, tt.info, unmarshaled)
		})
	}
}

// TestFunctionURLInfo_IsAlias tests the IsAlias helper method
func TestFunctionURLInfo_IsAlias(t *testing.T) {
	tests := []struct {
		name     string
		info     FunctionURLInfo
		expected bool
	}{
		{
			name: "base function (empty qualifier)",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "",
				FunctionURL:  "https://abc123.lambda-url.us-east-1.on.aws/",
			},
			expected: false,
		},
		{
			name: "alias function",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "prod",
				FunctionURL:  "https://def456.lambda-url.us-east-1.on.aws/",
			},
			expected: true,
		},
		{
			name: "$LATEST qualifier is not an alias",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "$LATEST",
				FunctionURL:  "https://abc123.lambda-url.us-east-1.on.aws/",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.info.IsAlias())
		})
	}
}

// TestFunctionURLInfo_QualifiedName tests the qualified name generation
func TestFunctionURLInfo_QualifiedName(t *testing.T) {
	tests := []struct {
		name     string
		info     FunctionURLInfo
		expected string
	}{
		{
			name: "base function returns just function name",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "",
			},
			expected: "my-function",
		},
		{
			name: "alias returns function:alias format",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "prod",
			},
			expected: "my-function:prod",
		},
		{
			name: "$LATEST returns just function name",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "$LATEST",
			},
			expected: "my-function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.info.QualifiedName())
		})
	}
}

// TestParseQualifierFromArn tests ARN qualifier extraction
func TestParseQualifierFromArn(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "base function ARN (7 parts) returns empty",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			expected: "",
		},
		{
			name:     "alias ARN (8 parts) returns alias name",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:my-function:prod",
			expected: "prod",
		},
		{
			name:     "$LATEST ARN returns $LATEST",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:my-function:$LATEST",
			expected: "$LATEST",
		},
		{
			name:     "numeric version ARN returns version number",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:my-function:42",
			expected: "42",
		},
		{
			name:     "malformed ARN (too few parts) returns empty",
			arn:      "arn:aws:lambda:us-east-1",
			expected: "",
		},
		{
			name:     "empty string returns empty",
			arn:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := parseQualifierFromArn(tt.arn)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
