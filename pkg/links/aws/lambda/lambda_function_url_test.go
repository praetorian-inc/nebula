package lambda

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFunctionURLInfo_Structure tests the FunctionURLInfo struct holds alias information
func TestFunctionURLInfo_Structure(t *testing.T) {
	tests := []struct {
		name     string
		info     FunctionURLInfo
		expected FunctionURLInfo
	}{
		{
			name: "base function URL (no qualifier)",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "",
				FunctionURL:  "https://abc123.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
			expected: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "",
				FunctionURL:  "https://abc123.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
		},
		{
			name: "alias function URL",
			info: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "prod",
				FunctionURL:  "https://def456.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
			expected: FunctionURLInfo{
				FunctionName: "my-function",
				Qualifier:    "prod",
				FunctionURL:  "https://def456.lambda-url.us-east-1.on.aws/",
				AuthType:     "NONE",
			},
		},
		{
			name: "alias with IAM auth",
			info: FunctionURLInfo{
				FunctionName: "secure-function",
				Qualifier:    "staging",
				FunctionURL:  "https://ghi789.lambda-url.us-west-2.on.aws/",
				AuthType:     "AWS_IAM",
			},
			expected: FunctionURLInfo{
				FunctionName: "secure-function",
				Qualifier:    "staging",
				FunctionURL:  "https://ghi789.lambda-url.us-west-2.on.aws/",
				AuthType:     "AWS_IAM",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.FunctionName, tt.info.FunctionName)
			assert.Equal(t, tt.expected.Qualifier, tt.info.Qualifier)
			assert.Equal(t, tt.expected.FunctionURL, tt.info.FunctionURL)
			assert.Equal(t, tt.expected.AuthType, tt.info.AuthType)
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
