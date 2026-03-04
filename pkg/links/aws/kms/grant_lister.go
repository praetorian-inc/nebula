package kms

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// KMSGrantLister is a Janus link that takes AWS::KMS::Key resources and outputs
// AWS::KMS::Grant resources for each grant found on the key. This enables listing
// grants as first-class resources since CloudControl does not support AWS::KMS::Grant.
//
// Input: AWS::KMS::Key resources (from CloudControl with native KMS fallback)
// Output: AWS::KMS::Grant resources (one per grant found)
type KMSGrantLister struct {
	*base.AwsReconBaseLink
}

func NewKMSGrantLister(configs ...cfg.Config) chain.Link {
	l := &KMSGrantLister{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *KMSGrantLister) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "KMS Grant Lister"}
}

func (l *KMSGrantLister) Process(resource types.EnrichedResourceDescription) error {
	// Only process KMS keys
	if resource.TypeName != "AWS::KMS::Key" {
		return nil
	}

	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Warn("Could not set up client config for KMS grant lister", "error", err)
		return nil
	}

	client := kms.NewFromConfig(config)

	// Convert properties to map
	var propsMap map[string]interface{}
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			propsMap = make(map[string]interface{})
		}
	case map[string]interface{}:
		propsMap = props
	default:
		propsMap = make(map[string]interface{})
	}

	// Get the key ID from properties or identifier
	keyID := resource.Identifier
	if kid, ok := propsMap["KeyId"].(string); ok && kid != "" {
		keyID = kid
	}

	// Get key ARN
	keyArn := ""
	if ka, ok := propsMap["KeyArn"].(string); ok {
		keyArn = ka
	}

	// Describe the key to check if it's AWS managed (skip those)
	describeOutput, err := client.DescribeKey(l.Context(), &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		slog.Warn("Failed to describe KMS key", "id", keyID, "error", err)
		return nil
	}

	// Skip AWS managed keys (they cannot have custom grants)
	if describeOutput.KeyMetadata.KeyManager == kmstypes.KeyManagerTypeAws {
		slog.Debug("Skipping AWS managed key", "id", keyID)
		return nil
	}

	// If we don't have the ARN yet, get it from describe output
	if keyArn == "" {
		keyArn = aws.ToString(describeOutput.KeyMetadata.Arn)
	}

	// List all grants on this key
	return l.listAndSendGrants(client, keyID, keyArn, resource.Region, resource.AccountId)
}

// listAndSendGrants retrieves all grants for a KMS key and sends each as a resource
func (l *KMSGrantLister) listAndSendGrants(client *kms.Client, keyID, keyArn, region, accountID string) error {
	paginator := kms.NewListGrantsPaginator(client, &kms.ListGrantsInput{
		KeyId: aws.String(keyID),
	})

	var grantCount int
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(l.Context())
		if err != nil {
			slog.Warn("Failed to list KMS grants", "keyId", keyID, "error", err)
			return nil
		}

		for _, grant := range output.Grants {
			grantResource := l.buildGrantResource(grant, keyID, keyArn, region, accountID)
			if err := l.Send(grantResource); err != nil {
				slog.Warn("Failed to send KMS grant", "grantId", aws.ToString(grant.GrantId), "error", err)
			}
			grantCount++
		}
	}

	slog.Debug("Listed KMS grants", "keyId", keyID, "count", grantCount)
	return nil
}

// buildGrantResource creates an EnrichedResourceDescription for a grant
func (l *KMSGrantLister) buildGrantResource(grant kmstypes.GrantListEntry, keyID, keyArn, region, accountID string) types.EnrichedResourceDescription {
	grantID := aws.ToString(grant.GrantId)

	// Build properties map
	props := map[string]interface{}{
		"GrantId":          grantID,
		"KeyId":            keyID,
		"KeyArn":           keyArn,
		"GranteePrincipal": aws.ToString(grant.GranteePrincipal),
		"Operations":       convertGrantOperations(grant.Operations),
	}

	if grant.RetiringPrincipal != nil {
		props["RetiringPrincipal"] = aws.ToString(grant.RetiringPrincipal)
	}
	if grant.Name != nil {
		props["Name"] = aws.ToString(grant.Name)
	}
	if grant.IssuingAccount != nil {
		props["IssuingAccount"] = aws.ToString(grant.IssuingAccount)
	}
	if grant.CreationDate != nil {
		props["CreationDate"] = grant.CreationDate.String()
	}
	if grant.Constraints != nil {
		props["Constraints"] = convertGrantConstraints(grant.Constraints)
	}

	// Parse key ARN for the resource
	parsedArn, _ := arn.Parse(keyArn)

	return types.EnrichedResourceDescription{
		Identifier: grantID,
		TypeName:   "AWS::KMS::Grant",
		Region:     region,
		Properties: props,
		AccountId:  accountID,
		Arn:        parsedArn, // Use key ARN as base
		// Store the full grant identifier in properties for reference
	}
}

// convertGrantOperations converts KMS grant operations to string slice
func convertGrantOperations(ops []kmstypes.GrantOperation) []string {
	var result []string
	for _, op := range ops {
		result = append(result, string(op))
	}
	return result
}

// convertGrantConstraints converts grant constraints to a map
func convertGrantConstraints(c *kmstypes.GrantConstraints) map[string]interface{} {
	result := make(map[string]interface{})
	if c.EncryptionContextEquals != nil {
		result["EncryptionContextEquals"] = c.EncryptionContextEquals
	}
	if c.EncryptionContextSubset != nil {
		result["EncryptionContextSubset"] = c.EncryptionContextSubset
	}
	return result
}

// extractAccountFromArn extracts the AWS account ID from an ARN string
func extractAccountFromArn(arnStr string) string {
	parts := strings.Split(arnStr, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
