package aws

import (
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestERDToAWSResourceTransformer_Creation(t *testing.T) {
	// Verify the transformer can be created
	transformer := NewERDToAWSResourceTransformer()
	if transformer == nil {
		t.Fatal("NewERDToAWSResourceTransformer returned nil")
	}
}

func TestTransformERDToAWSResource(t *testing.T) {
	tests := []struct {
		name        string
		erd         *types.EnrichedResourceDescription
		expectError bool
	}{
		{
			name: "Valid S3 Bucket ERD",
			erd: &types.EnrichedResourceDescription{
				TypeName:   "AWS::S3::Bucket",
				Identifier: "test-bucket",
				Region:     "us-east-1",
				AccountId:  "123456789012",
			},
			expectError: false,
		},
		{
			name: "Valid EC2 Instance ERD",
			erd: &types.EnrichedResourceDescription{
				TypeName:   "AWS::EC2::Instance",
				Identifier: "i-1234567890abcdef0",
				Region:     "us-west-2",
				AccountId:  "123456789012",
			},
			expectError: false,
		},
		{
			name: "ERD with empty TypeName",
			erd: &types.EnrichedResourceDescription{
				Identifier: "test-resource",
				Region:     "us-east-1",
				AccountId:  "123456789012",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awsResource, err := TransformERDToAWSResource(tt.erd)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if awsResource == nil {
					t.Errorf("Expected AWSResource but got nil")
				} else {
					// Verify basic fields are preserved
					if awsResource.ResourceType.String() != tt.erd.TypeName {
						t.Errorf("ResourceType mismatch: got %s, want %s",
							awsResource.ResourceType, tt.erd.TypeName)
					}
					if awsResource.Region != tt.erd.Region {
						t.Errorf("Region mismatch: got %s, want %s",
							awsResource.Region, tt.erd.Region)
					}
					if awsResource.AccountRef != tt.erd.AccountId {
						t.Errorf("AccountRef mismatch: got %s, want %s",
							awsResource.AccountRef, tt.erd.AccountId)
					}
				}
			}
		})
	}
}
