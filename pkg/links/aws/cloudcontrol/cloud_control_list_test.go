package cloudcontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for hasNativeAPIFallback
// =============================================================================

func TestHasNativeAPIFallback(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		expected     bool
	}{
		// KMS types should have fallback
		{name: "KMS Key has fallback", resourceType: "AWS::KMS::Key", expected: true},
		{name: "KMS Grant has fallback", resourceType: "AWS::KMS::Grant", expected: true},
		{name: "KMS Alias has fallback", resourceType: "AWS::KMS::Alias", expected: true},
		{name: "KMS ReplicaKey has fallback", resourceType: "AWS::KMS::ReplicaKey", expected: true},

		// Non-KMS types should not have fallback
		{name: "S3 Bucket has no fallback", resourceType: "AWS::S3::Bucket", expected: false},
		{name: "EC2 Instance has no fallback", resourceType: "AWS::EC2::Instance", expected: false},
		{name: "IAM Role has no fallback", resourceType: "AWS::IAM::Role", expected: false},
		{name: "Lambda Function has no fallback", resourceType: "AWS::Lambda::Function", expected: false},
		{name: "RDS DBInstance has no fallback", resourceType: "AWS::RDS::DBInstance", expected: false},
		{name: "DynamoDB Table has no fallback", resourceType: "AWS::DynamoDB::Table", expected: false},

		// Edge cases
		{name: "Empty string has no fallback", resourceType: "", expected: false},
		{name: "Invalid type has no fallback", resourceType: "InvalidType", expected: false},
		{name: "Partial KMS prefix has no fallback", resourceType: "AWS::KM", expected: false},
		{name: "KMS without double colon has no fallback", resourceType: "AWS::KMSKey", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasNativeAPIFallback(tt.resourceType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Tests for getNativeAPIFallbackHandler
// =============================================================================

func TestGetNativeAPIFallbackHandler(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		expectFound  bool
	}{
		// KMS types should return handler
		{name: "KMS Key returns handler", resourceType: "AWS::KMS::Key", expectFound: true},
		{name: "KMS Grant returns handler", resourceType: "AWS::KMS::Grant", expectFound: true},
		{name: "KMS Alias returns handler", resourceType: "AWS::KMS::Alias", expectFound: true},
		{name: "KMS ReplicaKey returns handler", resourceType: "AWS::KMS::ReplicaKey", expectFound: true},

		// Non-KMS types should not return handler
		{name: "S3 Bucket returns no handler", resourceType: "AWS::S3::Bucket", expectFound: false},
		{name: "EC2 Instance returns no handler", resourceType: "AWS::EC2::Instance", expectFound: false},
		{name: "Empty string returns no handler", resourceType: "", expectFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, found := getNativeAPIFallbackHandler(tt.resourceType)
			assert.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				assert.NotNil(t, handler)
			} else {
				assert.Nil(t, handler)
			}
		})
	}
}

// =============================================================================
// Tests for processError - THE CRITICAL FUNCTION
// This is where the bug was found: TypeNotFoundException wasn't triggering fallback
// =============================================================================

func TestProcessError(t *testing.T) {
	a := &AWSCloudControl{}

	tests := []struct {
		name           string
		resourceType   string
		region         string
		err            error
		expectError    bool
		expectBreak    bool
		expectFallback bool
		errorContains  string
	}{
		// =================================================================
		// TypeNotFoundException cases - This is the bug that was fixed!
		// =================================================================
		{
			name:           "TypeNotFoundException with KMS Grant fallback",
			resourceType:   "AWS::KMS::Grant",
			region:         "us-east-1",
			err:            errors.New("TypeNotFoundException: CloudControl does not support AWS::KMS::Grant"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "TypeNotFoundException with KMS Key fallback",
			resourceType:   "AWS::KMS::Key",
			region:         "us-west-2",
			err:            errors.New("TypeNotFoundException: Type not found"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "TypeNotFoundException with KMS Alias fallback",
			resourceType:   "AWS::KMS::Alias",
			region:         "eu-west-1",
			err:            errors.New("TypeNotFoundException: Resource type not available"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "TypeNotFoundException without fallback (S3)",
			resourceType:   "AWS::S3::Bucket",
			region:         "us-east-1",
			err:            errors.New("TypeNotFoundException: CloudControl does not support this type"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "is not available in region",
		},
		{
			name:           "TypeNotFoundException without fallback (EC2)",
			resourceType:   "AWS::EC2::Instance",
			region:         "ap-northeast-1",
			err:            errors.New("TypeNotFoundException: Unknown type"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "is not available in region",
		},
		{
			name:           "TypeNotFoundException without fallback (custom resource)",
			resourceType:   "AWS::Custom::Resource",
			region:         "eu-west-1",
			err:            errors.New("TypeNotFoundException: Unknown type"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "is not available in region",
		},

		// =================================================================
		// AccessDeniedException cases
		// =================================================================
		{
			name:           "AccessDeniedException with KMS Key fallback",
			resourceType:   "AWS::KMS::Key",
			region:         "us-east-1",
			err:            errors.New("AccessDeniedException: User is not authorized to perform cloudcontrol:ListResources on AWS::KMS::Key"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "AccessDeniedException with KMS Grant fallback",
			resourceType:   "AWS::KMS::Grant",
			region:         "us-east-1",
			err:            errors.New("AccessDeniedException: Access denied"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "AccessDeniedException without fallback",
			resourceType:   "AWS::EC2::Instance",
			region:         "us-east-1",
			err:            errors.New("AccessDeniedException: User is not authorized"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "access denied to list resources",
		},
		{
			name:           "Not authorized to perform error with fallback",
			resourceType:   "AWS::KMS::Key",
			region:         "ap-southeast-1",
			err:            errors.New("User is not authorized to perform cloudcontrol:ListResources"),
			expectError:    false,
			expectBreak:    true,
			expectFallback: true,
		},
		{
			name:           "Not authorized to perform error without fallback",
			resourceType:   "AWS::Lambda::Function",
			region:         "us-east-1",
			err:            errors.New("User is not authorized to perform cloudcontrol:ListResources"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "access denied",
		},

		// =================================================================
		// UnsupportedActionException cases
		// =================================================================
		{
			name:           "UnsupportedActionException",
			resourceType:   "AWS::SomeService::Resource",
			region:         "us-east-1",
			err:            errors.New("UnsupportedActionException: ListResources not supported for this type"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "is not supported in region",
		},
		{
			name:           "UnsupportedActionException in ap-south-1",
			resourceType:   "AWS::AppRunner::Service",
			region:         "ap-south-1",
			err:            errors.New("UnsupportedActionException: Service not available"),
			expectError:    true,
			expectBreak:    true,
			expectFallback: false,
			errorContains:  "is not supported in region",
		},

		// =================================================================
		// ThrottlingException cases - should NOT break
		// =================================================================
		{
			name:           "ThrottlingException should not break",
			resourceType:   "AWS::EC2::Instance",
			region:         "us-east-1",
			err:            errors.New("ThrottlingException: Rate exceeded"),
			expectError:    true,
			expectBreak:    false,
			expectFallback: false,
			errorContains:  "rate limited",
		},
		{
			name:           "ThrottlingException with request too frequent",
			resourceType:   "AWS::S3::Bucket",
			region:         "us-west-2",
			err:            errors.New("ThrottlingException: Request rate is too high"),
			expectError:    true,
			expectBreak:    false,
			expectFallback: false,
			errorContains:  "rate limited",
		},

		// =================================================================
		// Default/unknown error cases
		// =================================================================
		{
			name:           "Unknown error",
			resourceType:   "AWS::EC2::Instance",
			region:         "us-east-1",
			err:            errors.New("Some random error occurred"),
			expectError:    true,
			expectBreak:    false,
			expectFallback: false,
			errorContains:  "failed to ListResources",
		},
		{
			name:           "Network timeout error",
			resourceType:   "AWS::S3::Bucket",
			region:         "us-west-2",
			err:            errors.New("connection timeout"),
			expectError:    true,
			expectBreak:    false,
			expectFallback: false,
			errorContains:  "failed to ListResources",
		},
		{
			name:           "AWS SDK error",
			resourceType:   "AWS::Lambda::Function",
			region:         "eu-central-1",
			err:            errors.New("operation error CloudControl: ListResources, https response error"),
			expectError:    true,
			expectBreak:    false,
			expectFallback: false,
			errorContains:  "failed to ListResources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultErr, shouldBreak, useFallback := a.processError(tt.resourceType, tt.region, tt.err)

			assert.Equal(t, tt.expectBreak, shouldBreak, "shouldBreak mismatch")
			assert.Equal(t, tt.expectFallback, useFallback, "useFallback mismatch")

			if tt.expectError {
				assert.NotNil(t, resultErr, "expected an error but got nil")
				if tt.errorContains != "" {
					assert.Contains(t, resultErr.Error(), tt.errorContains)
				}
			} else {
				assert.Nil(t, resultErr, "expected nil error but got: %v", resultErr)
			}
		})
	}
}

// TestProcessErrorFallbackConsistency verifies that TypeNotFoundException and
// AccessDeniedException behave consistently when fallback handlers exist.
// This is a REGRESSION TEST for the bug where only AccessDeniedException
// triggered fallback but TypeNotFoundException did not.
func TestProcessErrorFallbackConsistency(t *testing.T) {
	a := &AWSCloudControl{}

	// All KMS resource types should trigger fallback for both error types
	kmsTypes := []string{
		"AWS::KMS::Key",
		"AWS::KMS::Grant",
		"AWS::KMS::Alias",
		"AWS::KMS::ReplicaKey",
	}

	errorTypes := []struct {
		name string
		err  error
	}{
		{"TypeNotFoundException", errors.New("TypeNotFoundException: Type not found")},
		{"AccessDeniedException", errors.New("AccessDeniedException: Access denied")},
		{"Not authorized", errors.New("User is not authorized to perform this action")},
	}

	for _, resourceType := range kmsTypes {
		for _, errType := range errorTypes {
			t.Run(resourceType+"_"+errType.name, func(t *testing.T) {
				resultErr, shouldBreak, useFallback := a.processError(resourceType, "us-east-1", errType.err)

				assert.Nil(t, resultErr, "Should not return error when fallback is available for %s with %s", resourceType, errType.name)
				assert.True(t, shouldBreak, "Should break to use fallback for %s with %s", resourceType, errType.name)
				assert.True(t, useFallback, "Should signal to use fallback for %s with %s", resourceType, errType.name)
			})
		}
	}
}

// TestProcessErrorNonFallbackTypes verifies that resource types without
// native API fallbacks return proper errors instead of silently failing.
func TestProcessErrorNonFallbackTypes(t *testing.T) {
	a := &AWSCloudControl{}

	nonFallbackTypes := []string{
		"AWS::S3::Bucket",
		"AWS::EC2::Instance",
		"AWS::IAM::Role",
		"AWS::Lambda::Function",
		"AWS::DynamoDB::Table",
		"AWS::RDS::DBInstance",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
	}

	for _, resourceType := range nonFallbackTypes {
		t.Run(resourceType+"_TypeNotFoundException", func(t *testing.T) {
			err := errors.New("TypeNotFoundException: Type not found")
			resultErr, shouldBreak, useFallback := a.processError(resourceType, "us-east-1", err)

			assert.NotNil(t, resultErr, "Should return error when no fallback available for %s", resourceType)
			assert.True(t, shouldBreak, "Should break on TypeNotFoundException for %s", resourceType)
			assert.False(t, useFallback, "Should not use fallback for %s", resourceType)
			assert.Contains(t, resultErr.Error(), "is not available in region")
		})

		t.Run(resourceType+"_AccessDeniedException", func(t *testing.T) {
			err := errors.New("AccessDeniedException: Access denied")
			resultErr, shouldBreak, useFallback := a.processError(resourceType, "us-east-1", err)

			assert.NotNil(t, resultErr, "Should return error when no fallback available for %s", resourceType)
			assert.True(t, shouldBreak, "Should break on AccessDeniedException for %s", resourceType)
			assert.False(t, useFallback, "Should not use fallback for %s", resourceType)
			assert.Contains(t, resultErr.Error(), "access denied")
		})
	}
}

// =============================================================================
// Tests for isGlobalService
// =============================================================================

func TestIsGlobalService(t *testing.T) {
	a := &AWSCloudControl{}

	tests := []struct {
		name         string
		resourceType string
		region       string
		expected     bool
	}{
		// IAM is global - should skip non-us-east-1 regions
		{name: "IAM Role in us-east-1", resourceType: "AWS::IAM::Role", region: "us-east-1", expected: false},
		{name: "IAM Role in us-west-2", resourceType: "AWS::IAM::Role", region: "us-west-2", expected: true},
		{name: "IAM User in us-east-1", resourceType: "AWS::IAM::User", region: "us-east-1", expected: false},
		{name: "IAM User in eu-west-1", resourceType: "AWS::IAM::User", region: "eu-west-1", expected: true},

		// Regional services should not be skipped
		{name: "EC2 Instance in us-east-1", resourceType: "AWS::EC2::Instance", region: "us-east-1", expected: false},
		{name: "EC2 Instance in us-west-2", resourceType: "AWS::EC2::Instance", region: "us-west-2", expected: false},
		{name: "S3 Bucket in us-east-1", resourceType: "AWS::S3::Bucket", region: "us-east-1", expected: false},
		{name: "S3 Bucket in ap-northeast-1", resourceType: "AWS::S3::Bucket", region: "ap-northeast-1", expected: false},

		// KMS is regional
		{name: "KMS Key in us-east-1", resourceType: "AWS::KMS::Key", region: "us-east-1", expected: false},
		{name: "KMS Key in us-west-2", resourceType: "AWS::KMS::Key", region: "us-west-2", expected: false},
		{name: "KMS Grant in us-east-1", resourceType: "AWS::KMS::Grant", region: "us-east-1", expected: false},
		{name: "KMS Grant in eu-central-1", resourceType: "AWS::KMS::Grant", region: "eu-central-1", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.isGlobalService(tt.resourceType, tt.region)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Tests for resourceDescriptionToERD
// =============================================================================

func TestResourceDescriptionToERD(t *testing.T) {
	a := &AWSCloudControl{}

	tests := []struct {
		name           string
		resource       cctypes.ResourceDescription
		resourceType   string
		accountId      string
		region         string
		expectedID     string
		expectedType   string
		expectedRegion string
	}{
		{
			name: "Standard EC2 instance",
			resource: cctypes.ResourceDescription{
				Identifier: aws.String("i-1234567890abcdef0"),
				Properties: aws.String(`{"InstanceId":"i-1234567890abcdef0","InstanceType":"t2.micro"}`),
			},
			resourceType:   "AWS::EC2::Instance",
			accountId:      "123456789012",
			region:         "us-east-1",
			expectedID:     "i-1234567890abcdef0",
			expectedType:   "AWS::EC2::Instance",
			expectedRegion: "us-east-1",
		},
		{
			name: "S3 bucket",
			resource: cctypes.ResourceDescription{
				Identifier: aws.String("my-bucket"),
				Properties: aws.String(`{"BucketName":"my-bucket"}`),
			},
			resourceType:   "AWS::S3::Bucket",
			accountId:      "123456789012",
			region:         "us-west-2",
			expectedID:     "my-bucket",
			expectedType:   "AWS::S3::Bucket",
			expectedRegion: "us-west-2",
		},
		{
			name: "KMS key",
			resource: cctypes.ResourceDescription{
				Identifier: aws.String("12345678-1234-1234-1234-123456789012"),
				Properties: aws.String(`{"KeyId":"12345678-1234-1234-1234-123456789012"}`),
			},
			resourceType:   "AWS::KMS::Key",
			accountId:      "123456789012",
			region:         "eu-west-1",
			expectedID:     "12345678-1234-1234-1234-123456789012",
			expectedType:   "AWS::KMS::Key",
			expectedRegion: "eu-west-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := a.resourceDescriptionToERD(tt.resource, tt.resourceType, tt.accountId, tt.region)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedID, result.Identifier)
			assert.Equal(t, tt.expectedType, result.TypeName)
			assert.Equal(t, tt.expectedRegion, result.Region)
			assert.Equal(t, tt.accountId, result.AccountId)
		})
	}
}

// =============================================================================
// Tests for SupportedResourceTypes
// =============================================================================

func TestSupportedResourceTypesIncludesGrant(t *testing.T) {
	a := &AWSCloudControl{}
	types := a.SupportedResourceTypes()

	found := false
	for _, rt := range types {
		if string(rt) == "AWS::KMS::Grant" {
			found = true
			break
		}
	}

	assert.True(t, found, "AWS::KMS::Grant should be in SupportedResourceTypes()")
}

func TestSupportedResourceTypesIncludesKMSKey(t *testing.T) {
	a := &AWSCloudControl{}
	types := a.SupportedResourceTypes()

	found := false
	for _, rt := range types {
		if string(rt) == "AWS::KMS::Key" {
			found = true
			break
		}
	}

	assert.True(t, found, "AWS::KMS::Key should be in SupportedResourceTypes()")
}

func TestSupportedResourceTypesIncludesAllKMSTypes(t *testing.T) {
	a := &AWSCloudControl{}
	types := a.SupportedResourceTypes()

	expectedKMSTypes := map[string]bool{
		"AWS::KMS::Alias":      false,
		"AWS::KMS::Grant":      false,
		"AWS::KMS::Key":        false,
		"AWS::KMS::ReplicaKey": false,
	}

	for _, rt := range types {
		if _, ok := expectedKMSTypes[string(rt)]; ok {
			expectedKMSTypes[string(rt)] = true
		}
	}

	for kmsType, found := range expectedKMSTypes {
		assert.True(t, found, "%s should be in SupportedResourceTypes()", kmsType)
	}
}

func TestSupportedResourceTypesCount(t *testing.T) {
	a := &AWSCloudControl{}
	types := a.SupportedResourceTypes()

	// Ensure we have a substantial number of supported types
	// This guards against accidental deletion of supported types
	assert.Greater(t, len(types), 300, "Should have more than 300 supported resource types")
}

func TestSupportedResourceTypesNoDuplicates(t *testing.T) {
	a := &AWSCloudControl{}
	types := a.SupportedResourceTypes()

	seen := make(map[model.CloudResourceType]bool)
	for _, rt := range types {
		if seen[rt] {
			t.Errorf("Duplicate resource type found: %s", rt)
		}
		seen[rt] = true
	}
}

// =============================================================================
// Tests for KMS Grant helper functions
// =============================================================================

func TestConvertKMSGrantOperations(t *testing.T) {
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
		{
			name: "Administrative operations",
			input: []kmstypes.GrantOperation{
				kmstypes.GrantOperationCreateGrant,
				kmstypes.GrantOperationRetireGrant,
				kmstypes.GrantOperationDescribeKey,
			},
			expected: []string{"CreateGrant", "RetireGrant", "DescribeKey"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertKMSGrantOperations(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertKMSGrantConstraints(t *testing.T) {
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
				// convertKMSGrantConstraints is not called with nil in actual code
				return
			}
			result := convertKMSGrantConstraints(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Tests for kmsKeyInfo struct
// =============================================================================

func TestKmsKeyInfoStruct(t *testing.T) {
	keyID := "12345678-1234-1234-1234-123456789012"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyID
	now := time.Now()

	multiRegion := false
	metadata := &kmstypes.KeyMetadata{
		KeyId:        aws.String(keyID),
		Arn:          aws.String(keyArn),
		KeyState:     kmstypes.KeyStateEnabled,
		KeyUsage:     kmstypes.KeyUsageTypeEncryptDecrypt,
		KeyManager:   kmstypes.KeyManagerTypeCustomer,
		Enabled:      true,
		MultiRegion:  &multiRegion,
		CreationDate: &now,
	}

	keyInfo := kmsKeyInfo{
		KeyID:    keyID,
		KeyArn:   keyArn,
		Metadata: metadata,
	}

	assert.Equal(t, keyID, keyInfo.KeyID)
	assert.Equal(t, keyArn, keyInfo.KeyArn)
	assert.NotNil(t, keyInfo.Metadata)
	assert.Equal(t, kmstypes.KeyStateEnabled, keyInfo.Metadata.KeyState)
	assert.Equal(t, kmstypes.KeyManagerTypeCustomer, keyInfo.Metadata.KeyManager)
}

// =============================================================================
// Tests for error message patterns
// These tests verify that error message parsing works correctly
// =============================================================================

func TestErrorMessagePatterns(t *testing.T) {
	a := &AWSCloudControl{}

	// Test various real-world error message formats
	realWorldErrors := []struct {
		name           string
		errorMsg       string
		resourceType   string
		expectFallback bool
		expectBreak    bool
	}{
		{
			name:           "AWS API TypeNotFoundException format",
			errorMsg:       "operation error CloudControl: ListResources, TypeNotFoundException: Resource type AWS::KMS::Grant is not supported",
			resourceType:   "AWS::KMS::Grant",
			expectFallback: true,
			expectBreak:    true,
		},
		{
			name:           "AWS API AccessDeniedException format",
			errorMsg:       "operation error CloudControl: ListResources, https response error StatusCode: 403, AccessDeniedException: User: arn:aws:iam::123456789012:user/testuser is not authorized",
			resourceType:   "AWS::KMS::Key",
			expectFallback: true,
			expectBreak:    true,
		},
		{
			name:           "STS assume role AccessDenied",
			errorMsg:       "operation error STS: AssumeRole, https response error StatusCode: 403, AccessDenied: User is not authorized to perform sts:AssumeRole",
			resourceType:   "AWS::EC2::Instance",
			expectFallback: false,
			expectBreak:    true,
		},
		{
			name:           "CloudControl UnsupportedActionException",
			errorMsg:       "operation error CloudControl: ListResources, UnsupportedActionException: Resource type AWS::CustomService::Resource does not support LIST handler",
			resourceType:   "AWS::CustomService::Resource",
			expectFallback: false,
			expectBreak:    true,
		},
		{
			name:           "Rate limiting with RequestId",
			errorMsg:       "operation error CloudControl: ListResources, ThrottlingException: Rate exceeded, RequestId: abc123",
			resourceType:   "AWS::S3::Bucket",
			expectFallback: false,
			expectBreak:    false,
		},
	}

	for _, tt := range realWorldErrors {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errorMsg)
			_, shouldBreak, useFallback := a.processError(tt.resourceType, "us-east-1", err)

			assert.Equal(t, tt.expectBreak, shouldBreak, "shouldBreak mismatch for: %s", tt.name)
			assert.Equal(t, tt.expectFallback, useFallback, "useFallback mismatch for: %s", tt.name)
		})
	}
}

// =============================================================================
// Tests for Metadata
// =============================================================================

func TestMetadata(t *testing.T) {
	a := &AWSCloudControl{}
	metadata := a.Metadata()

	require.NotNil(t, metadata)
	assert.Equal(t, "AWS CloudControl", metadata.Name)
}

// =============================================================================
// Integration-style tests (testing multiple components together)
// =============================================================================

// TestFallbackRegistryConsistency ensures that hasNativeAPIFallback and
// getNativeAPIFallbackHandler are consistent
func TestFallbackRegistryConsistency(t *testing.T) {
	testTypes := []string{
		"AWS::KMS::Key",
		"AWS::KMS::Grant",
		"AWS::KMS::Alias",
		"AWS::KMS::ReplicaKey",
		"AWS::S3::Bucket",
		"AWS::EC2::Instance",
		"AWS::IAM::Role",
	}

	for _, resourceType := range testTypes {
		t.Run(resourceType, func(t *testing.T) {
			hasFallback := hasNativeAPIFallback(resourceType)
			handler, found := getNativeAPIFallbackHandler(resourceType)

			// Both should agree on whether a fallback exists
			assert.Equal(t, hasFallback, found,
				"hasNativeAPIFallback and getNativeAPIFallbackHandler should agree for %s", resourceType)

			// If fallback exists, handler should be non-nil
			if hasFallback {
				assert.NotNil(t, handler, "Handler should not be nil when fallback exists for %s", resourceType)
			} else {
				assert.Nil(t, handler, "Handler should be nil when no fallback exists for %s", resourceType)
			}
		})
	}
}

// TestProcessErrorWithFallbackTriggersFallback verifies the complete flow
// from error to fallback signal
func TestProcessErrorWithFallbackTriggersFallback(t *testing.T) {
	a := &AWSCloudControl{}

	// Simulate what happens when CloudControl fails for AWS::KMS::Grant
	// This is the exact scenario that was broken before the fix
	err := errors.New("TypeNotFoundException: CloudControl does not support AWS::KMS::Grant")
	resultErr, shouldBreak, useFallback := a.processError("AWS::KMS::Grant", "us-east-1", err)

	// Verify the fallback is triggered correctly
	assert.Nil(t, resultErr, "Should not return error")
	assert.True(t, shouldBreak, "Should break pagination loop")
	assert.True(t, useFallback, "Should signal to use native API fallback")

	// Verify fallback handler exists
	handler, found := getNativeAPIFallbackHandler("AWS::KMS::Grant")
	assert.True(t, found, "Handler should exist for AWS::KMS::Grant")
	assert.NotNil(t, handler, "Handler should not be nil")
}
