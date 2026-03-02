package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeKeyPolicyForCreateGrant(t *testing.T) {
	accountID := "123456789012"

	tests := []struct {
		name           string
		policy         string
		expectedCount  int
		expectedSeverity string
	}{
		{
			name: "Secure key policy - root only",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowRootAccount",
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "kms:*",
					"Resource": "*"
				}]
			}`,
			expectedCount: 0,
		},
		{
			name: "Vulnerable - role with CreateGrant no conditions",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "kms:*",
						"Resource": "*"
					},
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:role/VulnerableRole"},
						"Action": ["kms:CreateGrant", "kms:ListGrants"],
						"Resource": "*"
					}
				]
			}`,
			expectedCount:    1,
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Vulnerable - wildcard principal with account condition",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "kms:*",
						"Resource": "*"
					},
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "kms:CreateGrant",
						"Resource": "*",
						"Condition": {
							"StringEquals": {
								"aws:PrincipalAccount": "123456789012"
							}
						}
					}
				]
			}`,
			expectedCount:    1,
			expectedSeverity: "HIGH",
		},
		{
			name: "Vulnerable - wildcard principal no conditions",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "kms:*",
						"Resource": "*"
					},
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "kms:CreateGrant",
						"Resource": "*"
					}
				]
			}`,
			expectedCount:    1,
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Safe - service principal",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "kms:*",
						"Resource": "*"
					},
					{
						"Effect": "Allow",
						"Principal": {"Service": "logs.amazonaws.com"},
						"Action": ["kms:CreateGrant", "kms:Encrypt", "kms:Decrypt"],
						"Resource": "*"
					}
				]
			}`,
			expectedCount:    1,
			expectedSeverity: "LOW",
		},
		{
			name: "Role with conditions - medium risk",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "kms:*",
						"Resource": "*"
					},
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:role/SomeRole"},
						"Action": "kms:CreateGrant",
						"Resource": "*",
						"Condition": {
							"StringEquals": {
								"kms:GranteePrincipal": "arn:aws:iam::123456789012:role/TargetRole"
							}
						}
					}
				]
			}`,
			expectedCount:    1,
			expectedSeverity: "MEDIUM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeKeyPolicyForCreateGrant(tt.policy, accountID)
			assert.Equal(t, tt.expectedCount, len(findings), "Expected %d findings, got %d", tt.expectedCount, len(findings))

			if tt.expectedCount > 0 && tt.expectedSeverity != "" {
				assert.Equal(t, tt.expectedSeverity, findings[0].Severity, "Expected severity %s, got %s", tt.expectedSeverity, findings[0].Severity)
			}
		})
	}
}

func TestAnalyzeGrants(t *testing.T) {
	accountID := "123456789012"

	tests := []struct {
		name             string
		grants           []map[string]interface{}
		expectedCount    int
		expectedSeverity string
	}{
		{
			name:          "No grants",
			grants:        []map[string]interface{}{},
			expectedCount: 0,
		},
		{
			name: "Grant with only DescribeKey - safe",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-123",
					"GranteePrincipal": "arn:aws:iam::123456789012:role/SafeRole",
					"Operations":       []string{"DescribeKey"},
				},
			},
			expectedCount: 0,
		},
		{
			name: "Grant with Decrypt - medium risk",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-123",
					"GranteePrincipal": "arn:aws:iam::123456789012:role/DecryptRole",
					"Operations":       []string{"Decrypt", "DescribeKey"},
				},
			},
			expectedCount:    1,
			expectedSeverity: "MEDIUM",
		},
		{
			name: "Grant with broad operations - high risk",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-123",
					"GranteePrincipal": "arn:aws:iam::123456789012:role/BroadRole",
					"Operations":       []string{"Decrypt", "Encrypt", "GenerateDataKey", "ReEncryptFrom"},
				},
			},
			expectedCount:    1,
			expectedSeverity: "HIGH",
		},
		{
			name: "Cross-account grant - high risk",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-cross",
					"GranteePrincipal": "arn:aws:iam::999888777666:role/ExternalRole",
					"Operations":       []string{"Decrypt"},
				},
			},
			expectedCount:    1,
			expectedSeverity: "HIGH",
		},
		{
			name: "Grant with constraints - lower risk",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-constrained",
					"GranteePrincipal": "arn:aws:iam::123456789012:role/ConstrainedRole",
					"Operations":       []string{"Decrypt", "Encrypt"},
					"Constraints": map[string]interface{}{
						"EncryptionContextEquals": map[string]string{
							"Department": "Finance",
						},
					},
				},
			},
			expectedCount:    1,
			expectedSeverity: "MEDIUM",
		},
		{
			name: "Multiple grants with mixed risk",
			grants: []map[string]interface{}{
				{
					"GrantId":          "grant-1",
					"GranteePrincipal": "arn:aws:iam::123456789012:role/Role1",
					"Operations":       []string{"Decrypt"},
				},
				{
					"GrantId":          "grant-2",
					"GranteePrincipal": "arn:aws:iam::999888777666:role/ExternalRole",
					"Operations":       []string{"Decrypt", "GenerateDataKey"},
				},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeGrants(tt.grants, accountID)
			assert.Equal(t, tt.expectedCount, len(findings), "Expected %d findings, got %d", tt.expectedCount, len(findings))

			if tt.expectedCount > 0 && tt.expectedSeverity != "" {
				assert.Equal(t, tt.expectedSeverity, findings[0].Severity, "Expected severity %s, got %s", tt.expectedSeverity, findings[0].Severity)
			}
		})
	}
}

func TestClassifyOverallRisk(t *testing.T) {
	tests := []struct {
		name            string
		policyFindings  []PolicyFinding
		grantFindings   []GrantFinding
		expectedRisk    string
		expectedReasons int
	}{
		{
			name:           "No findings",
			policyFindings: []PolicyFinding{},
			grantFindings:  []GrantFinding{},
			expectedRisk:   "NONE",
		},
		{
			name: "Only policy findings",
			policyFindings: []PolicyFinding{
				{Severity: "HIGH", Description: "Policy issue"},
			},
			grantFindings:   []GrantFinding{},
			expectedRisk:    "HIGH",
			expectedReasons: 1,
		},
		{
			name:           "Only grant findings",
			policyFindings: []PolicyFinding{},
			grantFindings: []GrantFinding{
				{Severity: "MEDIUM", Description: "Grant issue"},
			},
			expectedRisk:    "MEDIUM",
			expectedReasons: 1,
		},
		{
			name: "Mixed findings - highest wins",
			policyFindings: []PolicyFinding{
				{Severity: "CRITICAL", Description: "Critical policy issue"},
			},
			grantFindings: []GrantFinding{
				{Severity: "HIGH", Description: "High grant issue"},
				{Severity: "MEDIUM", Description: "Medium grant issue"},
			},
			expectedRisk:    "CRITICAL",
			expectedReasons: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk, reasons := classifyOverallRisk(tt.policyFindings, tt.grantFindings)
			assert.Equal(t, tt.expectedRisk, risk)
			if tt.expectedReasons > 0 {
				assert.Equal(t, tt.expectedReasons, len(reasons))
			}
		})
	}
}

func TestNormalizeToStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "Single string",
			input:    "kms:CreateGrant",
			expected: []string{"kms:CreateGrant"},
		},
		{
			name:     "String slice",
			input:    []string{"kms:CreateGrant", "kms:Decrypt"},
			expected: []string{"kms:CreateGrant", "kms:Decrypt"},
		},
		{
			name:     "Interface slice",
			input:    []interface{}{"kms:CreateGrant", "kms:Decrypt"},
			expected: []string{"kms:CreateGrant", "kms:Decrypt"},
		},
		{
			name:     "Nil",
			input:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeToStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractPrincipals(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "Wildcard string",
			input:    "*",
			expected: []string{"*"},
		},
		{
			name: "AWS principal map with single ARN",
			input: map[string]interface{}{
				"AWS": "arn:aws:iam::123456789012:root",
			},
			expected: []string{"arn:aws:iam::123456789012:root"},
		},
		{
			name: "AWS principal map with multiple ARNs",
			input: map[string]interface{}{
				"AWS": []interface{}{
					"arn:aws:iam::123456789012:root",
					"arn:aws:iam::123456789012:role/SomeRole",
				},
			},
			expected: []string{
				"arn:aws:iam::123456789012:root",
				"arn:aws:iam::123456789012:role/SomeRole",
			},
		},
		{
			name: "Service principal",
			input: map[string]interface{}{
				"Service": "logs.amazonaws.com",
			},
			expected: []string{"logs.amazonaws.com"},
		},
		{
			name: "Mixed principals",
			input: map[string]interface{}{
				"AWS":     "arn:aws:iam::123456789012:root",
				"Service": "kms.amazonaws.com",
			},
			expected: []string{
				"arn:aws:iam::123456789012:root",
				"kms.amazonaws.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPrincipals(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestClassifyPrincipalRisk(t *testing.T) {
	accountID := "123456789012"

	tests := []struct {
		name          string
		principal     string
		hasConditions bool
		actions       []string
		expected      string
	}{
		{
			name:          "Root account - no finding",
			principal:     "arn:aws:iam::123456789012:root",
			hasConditions: false,
			actions:       []string{"kms:CreateGrant"},
			expected:      "NONE",
		},
		{
			name:          "Wildcard no conditions - critical",
			principal:     "*",
			hasConditions: false,
			actions:       []string{"kms:CreateGrant"},
			expected:      "CRITICAL",
		},
		{
			name:          "Wildcard with conditions - high",
			principal:     "*",
			hasConditions: true,
			actions:       []string{"kms:CreateGrant"},
			expected:      "HIGH",
		},
		{
			name:          "Role no conditions - critical (self-escalate)",
			principal:     "arn:aws:iam::123456789012:role/SomeRole",
			hasConditions: false,
			actions:       []string{"kms:CreateGrant"},
			expected:      "CRITICAL",
		},
		{
			name:          "Role with conditions - medium",
			principal:     "arn:aws:iam::123456789012:role/SomeRole",
			hasConditions: true,
			actions:       []string{"kms:CreateGrant"},
			expected:      "MEDIUM",
		},
		{
			name:          "Service principal - low",
			principal:     "logs.amazonaws.com",
			hasConditions: false,
			actions:       []string{"kms:CreateGrant"},
			expected:      "LOW",
		},
		{
			name:          "kms:* action - high when no conditions",
			principal:     "arn:aws:iam::123456789012:role/AdminRole",
			hasConditions: false,
			actions:       []string{"kms:*"},
			expected:      "HIGH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyPrincipalRisk(tt.principal, accountID, tt.hasConditions, tt.actions)
			assert.Equal(t, tt.expected, result)
		})
	}
}
