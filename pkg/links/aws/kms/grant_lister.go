package kms

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
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
	// Only process KMS keys and replica keys
	if resource.TypeName != "AWS::KMS::Key" && resource.TypeName != "AWS::KMS::ReplicaKey" {
		slog.Debug("Skipping non-KMS key resource", "type", resource.TypeName, "id", resource.Identifier)
		return nil
	}

	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to create AWS config for KMS grant lister",
			"region", resource.Region,
			"keyId", resource.Identifier,
			"error", err)
		return nil
	}

	client := kms.NewFromConfig(config)

	// Convert properties to map
	var propsMap map[string]interface{}
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			slog.Debug("Failed to parse properties JSON, using empty map",
				"keyId", resource.Identifier,
				"error", err)
			propsMap = make(map[string]interface{})
		}
	case map[string]interface{}:
		propsMap = props
	default:
		slog.Debug("Properties not a map or string, using empty map",
			"keyId", resource.Identifier,
			"type", resource.Properties)
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

	// Try to use upstream metadata to avoid redundant DescribeKey API calls.
	// The native KMS fallback path populates KeyManager, KeyState, and Arn in properties.
	keyManager, hasKeyManager := propsMap["KeyManager"].(string)
	keyStateStr, hasKeyState := propsMap["KeyState"].(string)

	if hasKeyManager && hasKeyState {
		// Skip AWS managed keys (they cannot have custom grants)
		if keyManager == string(kmstypes.KeyManagerTypeAws) {
			slog.Debug("Skipping AWS managed key - cannot have custom grants",
				"keyId", keyID,
				"region", resource.Region)
			return nil
		}

		// Skip disabled or pending deletion keys
		if keyStateStr == string(kmstypes.KeyStateDisabled) || keyStateStr == string(kmstypes.KeyStatePendingDeletion) {
			slog.Debug("Skipping key in non-active state",
				"keyId", keyID,
				"state", keyStateStr,
				"region", resource.Region)
			return nil
		}
	} else {
		// Metadata not available upstream — call DescribeKey
		describeOutput, err := client.DescribeKey(l.Context(), &kms.DescribeKeyInput{
			KeyId: aws.String(keyID),
		})
		if err != nil {
			if isKMSAccessDeniedError(err) {
				message.Warning("Access denied describing KMS key %s in %s - skipping grant enumeration",
					keyID, resource.Region)
				slog.Warn("Access denied for DescribeKey - likely restricted key policy",
					"keyId", keyID,
					"region", resource.Region,
					"error", err)
			} else if isKMSKeyNotFoundError(err) {
				slog.Debug("KMS key not found, may have been deleted",
					"keyId", keyID,
					"region", resource.Region)
			} else {
				slog.Error("Failed to describe KMS key",
					"keyId", keyID,
					"region", resource.Region,
					"error", err)
			}
			return nil
		}

		// Skip AWS managed keys (they cannot have custom grants)
		if describeOutput.KeyMetadata.KeyManager == kmstypes.KeyManagerTypeAws {
			slog.Debug("Skipping AWS managed key - cannot have custom grants",
				"keyId", keyID,
				"region", resource.Region)
			return nil
		}

		// Skip disabled or pending deletion keys
		keyState := describeOutput.KeyMetadata.KeyState
		if keyState == kmstypes.KeyStateDisabled || keyState == kmstypes.KeyStatePendingDeletion {
			slog.Debug("Skipping key in non-active state",
				"keyId", keyID,
				"state", keyState,
				"region", resource.Region)
			return nil
		}

		// Get ARN from describe output if not available
		if keyArn == "" {
			keyArn = aws.ToString(describeOutput.KeyMetadata.Arn)
		}
	}

	// message.Info("Listing grants for KMS key %s in %s", keyID, resource.Region)

	// List all grants on this key
	return l.listAndSendGrants(client, keyID, keyArn, resource.Region, resource.AccountId)
}

// listAndSendGrants retrieves all grants for a KMS key and sends each as a resource
func (l *KMSGrantLister) listAndSendGrants(client *kms.Client, keyID, keyArn, region, accountID string) error {
	paginator := kms.NewListGrantsPaginator(client, &kms.ListGrantsInput{
		KeyId: aws.String(keyID),
		Limit: aws.Int32(100), // Max allowed by AWS API to reduce requests
	})

	var grantCount int
	var pageCount int
	for paginator.HasMorePages() {
		pageCount++
		output, err := paginator.NextPage(l.Context())
		if err != nil {
			if isKMSAccessDeniedError(err) {
				message.Warning("Access denied listing grants for KMS key %s in %s", keyID, region)
				slog.Warn("Access denied for ListGrants - requires kms:ListGrants permission",
					"keyId", keyID,
					"region", region,
					"error", err)
			} else {
				slog.Error("Failed to list KMS grants",
					"keyId", keyID,
					"region", region,
					"page", pageCount,
					"error", err)
			}
			return nil
		}

		for _, grant := range output.Grants {
			grantResource := l.buildGrantResource(grant, keyID, keyArn, region, accountID)
			if err := l.Send(grantResource); err != nil {
				slog.Error("Failed to send KMS grant resource",
					"grantId", aws.ToString(grant.GrantId),
					"keyId", keyID,
					"error", err)
				continue
			}
			grantCount++
		}
	}

	if grantCount > 0 {
		message.Info("Found %d grant(s) on KMS key %s in %s", grantCount, keyID, region)
	}
	slog.Debug("Completed grant enumeration",
		"keyId", keyID,
		"region", region,
		"grantCount", grantCount,
		"pages", pageCount)
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
		"Operations":       ConvertGrantOperations(grant.Operations),
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
		props["Constraints"] = ConvertGrantConstraints(grant.Constraints)
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

// extractAccountFromArn extracts the AWS account ID from an ARN string
func extractAccountFromArn(arnStr string) string {
	parts := strings.Split(arnStr, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// isKMSAccessDeniedError checks if the error is due to access denied (permission issue)
func isKMSAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}

	// Check for AWS API error
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "AccessDeniedException" ||
			code == "AccessDenied" ||
			strings.Contains(code, "AccessDenied")
	}

	// Fallback to string matching
	errorStr := err.Error()
	return strings.Contains(errorStr, "AccessDenied") ||
		strings.Contains(errorStr, "access denied") ||
		strings.Contains(errorStr, "not authorized")
}

// isKMSKeyNotFoundError checks if the error indicates the key was not found
func isKMSKeyNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "NotFoundException" ||
			code == "InvalidKeyId" ||
			strings.HasPrefix(code, "InvalidKey")
	}

	errorStr := err.Error()
	return strings.Contains(errorStr, "NotFoundException") ||
		strings.Contains(errorStr, "does not exist")
}
