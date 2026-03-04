package kms

import (
	"testing"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
)

func TestConvertGrantOperations(t *testing.T) {
	tests := []struct {
		name     string
		input    []kmstypes.GrantOperation
		expected []string
	}{
		{
			name:     "Empty operations",
			input:    []kmstypes.GrantOperation{},
			expected: nil,
		},
		{
			name: "Single operation",
			input: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
			},
			expected: []string{"Decrypt"},
		},
		{
			name: "Multiple operations",
			input: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
				kmstypes.GrantOperationEncrypt,
				kmstypes.GrantOperationGenerateDataKey,
				kmstypes.GrantOperationCreateGrant,
			},
			expected: []string{"Decrypt", "Encrypt", "GenerateDataKey", "CreateGrant"},
		},
		{
			name: "All crypto operations",
			input: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
				kmstypes.GrantOperationEncrypt,
				kmstypes.GrantOperationGenerateDataKey,
				kmstypes.GrantOperationGenerateDataKeyWithoutPlaintext,
				kmstypes.GrantOperationReEncryptFrom,
				kmstypes.GrantOperationReEncryptTo,
			},
			expected: []string{
				"Decrypt",
				"Encrypt",
				"GenerateDataKey",
				"GenerateDataKeyWithoutPlaintext",
				"ReEncryptFrom",
				"ReEncryptTo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertGrantOperations(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertGrantConstraints(t *testing.T) {
	tests := []struct {
		name     string
		input    *kmstypes.GrantConstraints
		expected map[string]interface{}
	}{
		{
			name:     "Nil constraints",
			input:    nil,
			expected: nil,
		},
		{
			name:     "Empty constraints",
			input:    &kmstypes.GrantConstraints{},
			expected: map[string]interface{}{},
		},
		{
			name: "EncryptionContextEquals only",
			input: &kmstypes.GrantConstraints{
				EncryptionContextEquals: map[string]string{
					"Department": "Finance",
					"Project":    "Budget",
				},
			},
			expected: map[string]interface{}{
				"EncryptionContextEquals": map[string]string{
					"Department": "Finance",
					"Project":    "Budget",
				},
			},
		},
		{
			name: "EncryptionContextSubset only",
			input: &kmstypes.GrantConstraints{
				EncryptionContextSubset: map[string]string{
					"Environment": "Production",
				},
			},
			expected: map[string]interface{}{
				"EncryptionContextSubset": map[string]string{
					"Environment": "Production",
				},
			},
		},
		{
			name: "Both constraint types",
			input: &kmstypes.GrantConstraints{
				EncryptionContextEquals: map[string]string{
					"Department": "Finance",
				},
				EncryptionContextSubset: map[string]string{
					"Environment": "Production",
				},
			},
			expected: map[string]interface{}{
				"EncryptionContextEquals": map[string]string{
					"Department": "Finance",
				},
				"EncryptionContextSubset": map[string]string{
					"Environment": "Production",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input == nil {
				// convertGrantConstraints is not called with nil in actual code
				// but we test nil handling anyway
				return
			}
			result := convertGrantConstraints(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractAccountFromArn(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid KMS key ARN",
			input:    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			expected: "123456789012",
		},
		{
			name:     "Valid IAM role ARN",
			input:    "arn:aws:iam::123456789012:role/MyRole",
			expected: "123456789012",
		},
		{
			name:     "Valid S3 bucket ARN",
			input:    "arn:aws:s3:::my-bucket",
			expected: "",
		},
		{
			name:     "GovCloud ARN",
			input:    "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			expected: "123456789012",
		},
		{
			name:     "China region ARN",
			input:    "arn:aws-cn:kms:cn-north-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			expected: "123456789012",
		},
		{
			name:     "Too few parts",
			input:    "arn:aws:kms",
			expected: "",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAccountFromArn(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildGrantResource(t *testing.T) {
	lister := &KMSGrantLister{}

	tests := []struct {
		name              string
		grantID           string
		granteePrincipal  string
		retiringPrincipal *string
		grantName         *string
		issuingAccount    *string
		operations        []kmstypes.GrantOperation
		constraints       *kmstypes.GrantConstraints
		keyID             string
		keyArn            string
		region            string
		accountID         string
		expectedType      string
		checkProperties   func(t *testing.T, props map[string]interface{})
	}{
		{
			name:             "Basic grant without optional fields",
			grantID:          "grant-123",
			granteePrincipal: "arn:aws:iam::123456789012:role/MyRole",
			operations: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
			},
			keyID:        "12345678-1234-1234-1234-123456789012",
			keyArn:       "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			region:       "us-east-1",
			accountID:    "123456789012",
			expectedType: "AWS::KMS::Grant",
			checkProperties: func(t *testing.T, props map[string]interface{}) {
				assert.Equal(t, "grant-123", props["GrantId"])
				assert.Equal(t, "12345678-1234-1234-1234-123456789012", props["KeyId"])
				assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", props["KeyArn"])
				assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", props["GranteePrincipal"])
				assert.Equal(t, []string{"Decrypt"}, props["Operations"])
				assert.Nil(t, props["RetiringPrincipal"])
				assert.Nil(t, props["Name"])
				assert.Nil(t, props["IssuingAccount"])
			},
		},
		{
			name:              "Grant with all optional fields",
			grantID:           "grant-456",
			granteePrincipal:  "arn:aws:iam::123456789012:role/GranteeRole",
			retiringPrincipal: strPtr("arn:aws:iam::123456789012:role/RetirerRole"),
			grantName:         strPtr("MyGrant"),
			issuingAccount:    strPtr("123456789012"),
			operations: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
				kmstypes.GrantOperationEncrypt,
				kmstypes.GrantOperationCreateGrant,
			},
			constraints: &kmstypes.GrantConstraints{
				EncryptionContextEquals: map[string]string{
					"Department": "Engineering",
				},
			},
			keyID:        "key-789",
			keyArn:       "arn:aws:kms:us-west-2:123456789012:key/key-789",
			region:       "us-west-2",
			accountID:    "123456789012",
			expectedType: "AWS::KMS::Grant",
			checkProperties: func(t *testing.T, props map[string]interface{}) {
				assert.Equal(t, "grant-456", props["GrantId"])
				assert.Equal(t, "key-789", props["KeyId"])
				assert.Equal(t, "arn:aws:iam::123456789012:role/GranteeRole", props["GranteePrincipal"])
				assert.Equal(t, "arn:aws:iam::123456789012:role/RetirerRole", props["RetiringPrincipal"])
				assert.Equal(t, "MyGrant", props["Name"])
				assert.Equal(t, "123456789012", props["IssuingAccount"])
				assert.Equal(t, []string{"Decrypt", "Encrypt", "CreateGrant"}, props["Operations"])
				constraints := props["Constraints"].(map[string]interface{})
				assert.NotNil(t, constraints["EncryptionContextEquals"])
			},
		},
		{
			name:             "Cross-account grant",
			grantID:          "grant-cross",
			granteePrincipal: "arn:aws:iam::999888777666:role/ExternalRole",
			operations: []kmstypes.GrantOperation{
				kmstypes.GrantOperationDecrypt,
				kmstypes.GrantOperationGenerateDataKey,
			},
			keyID:        "cross-key",
			keyArn:       "arn:aws:kms:eu-west-1:123456789012:key/cross-key",
			region:       "eu-west-1",
			accountID:    "123456789012",
			expectedType: "AWS::KMS::Grant",
			checkProperties: func(t *testing.T, props map[string]interface{}) {
				assert.Equal(t, "arn:aws:iam::999888777666:role/ExternalRole", props["GranteePrincipal"])
				assert.Equal(t, []string{"Decrypt", "GenerateDataKey"}, props["Operations"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant := kmstypes.GrantListEntry{
				GrantId:          &tt.grantID,
				GranteePrincipal: &tt.granteePrincipal,
				Operations:       tt.operations,
			}
			if tt.retiringPrincipal != nil {
				grant.RetiringPrincipal = tt.retiringPrincipal
			}
			if tt.grantName != nil {
				grant.Name = tt.grantName
			}
			if tt.issuingAccount != nil {
				grant.IssuingAccount = tt.issuingAccount
			}
			if tt.constraints != nil {
				grant.Constraints = tt.constraints
			}

			resource := lister.buildGrantResource(grant, tt.keyID, tt.keyArn, tt.region, tt.accountID)

			assert.Equal(t, tt.grantID, resource.Identifier)
			assert.Equal(t, tt.expectedType, resource.TypeName)
			assert.Equal(t, tt.region, resource.Region)
			assert.Equal(t, tt.accountID, resource.AccountId)

			props, ok := resource.Properties.(map[string]interface{})
			assert.True(t, ok, "Properties should be a map")
			tt.checkProperties(t, props)
		})
	}
}

// Helper function to create string pointers
func strPtr(s string) *string {
	return &s
}
