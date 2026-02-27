package lambda

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSLambdaFunctionURL struct {
	*base.AwsReconLink
}

func NewAWSLambdaFunctionURL(configs ...cfg.Config) chain.Link {
	l := &AWSLambdaFunctionURL{}
	l.AwsReconLink = base.NewAwsReconLink(l, configs...)
	return l
}

func (l *AWSLambdaFunctionURL) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::Lambda::Function" {
		slog.Debug("Skipping non-Lambda function", "resource", resource.TypeName)
		return nil
	}

	// Get all Function URLs (base function + aliases)
	functionURLs, err := l.getAllFunctionURLs(resource)
	if err != nil {
		slog.Debug("Error retrieving function URLs", "resource", resource.Identifier, "error", err)
		return nil
	}

	if len(functionURLs) == 0 {
		slog.Debug("No function URLs configured", "resource", resource.Identifier)
		return nil
	}

	// Add the function URLs to the resource properties
	updatedERD, err := l.addFunctionURLsToProperties(resource, functionURLs)
	if err != nil {
		slog.Error("Failed to add function URLs to properties", "error", err)
		return l.Send(resource)
	}

	return l.Send(updatedERD)
}

// getAllFunctionURLs retrieves all Function URLs using ListFunctionUrlConfigs API
// This is more efficient and works with basic view-only permissions
func (l *AWSLambdaFunctionURL) getAllFunctionURLs(resource *types.EnrichedResourceDescription) ([]FunctionURLInfo, error) {
	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	lambdaClient := lambda.NewFromConfig(config)

	// Use ListFunctionUrlConfigs with pagination - API returns max 50 items per page
	// Works with view-only permissions unlike GetFunctionUrlConfig with qualifiers
	input := &lambda.ListFunctionUrlConfigsInput{
		FunctionName: aws.String(resource.Identifier),
	}

	// Use paginator to handle pagination automatically (API max 50 items per page)
	var allURLs []FunctionURLInfo
	paginator := lambda.NewListFunctionUrlConfigsPaginator(lambdaClient, input)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(l.Context())
		if err != nil {
			return nil, fmt.Errorf("failed to list function URL configs: %w", err)
		}

		for _, urlConfig := range output.FunctionUrlConfigs {
			if urlConfig.FunctionUrl == nil || urlConfig.FunctionArn == nil {
				continue
			}

			// Parse qualifier (alias) from ARN: arn:aws:lambda:region:account:function:name[:qualifier]
			qualifier := parseQualifierFromArn(*urlConfig.FunctionArn)

			allURLs = append(allURLs, FunctionURLInfo{
				FunctionName: resource.Identifier,
				Qualifier:    qualifier,
				FunctionURL:  *urlConfig.FunctionUrl,
				AuthType:     string(urlConfig.AuthType),
			})
		}
	}

	return allURLs, nil
}

// parseQualifierFromArn extracts the qualifier (alias/version) from a Lambda ARN
func parseQualifierFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) == 8 {
		return parts[7]
	}
	return ""
}

func (l *AWSLambdaFunctionURL) addFunctionURLsToProperties(resource *types.EnrichedResourceDescription, functionURLs []FunctionURLInfo) (*types.EnrichedResourceDescription, error) {
	var propsMap map[string]any

	if resource.Properties == nil {
		propsMap = make(map[string]any)
	} else {
		propsStr, ok := resource.Properties.(string)
		if !ok {
			propsBytes, err := json.Marshal(resource.Properties)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal properties: %w", err)
			}
			propsStr = string(propsBytes)
		}

		// Handle double-escaped JSON strings
		if len(propsStr) > 0 && propsStr[0] == '"' {
			var unescaped string
			if err := json.Unmarshal([]byte(propsStr), &unescaped); err != nil {
				return nil, fmt.Errorf("failed to unescape properties: %w", err)
			}
			propsStr = unescaped
		}

		if err := json.Unmarshal([]byte(propsStr), &propsMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal properties: %w", err)
		}
	}

	// Add the function URLs to properties
	// Keep backward compatibility: set FunctionUrl from the base function URL (if any)
	// Scan full slice since AWS API doesn't guarantee ordering
	for _, fu := range functionURLs {
		if fu.Qualifier == "" {
			propsMap["FunctionUrl"] = fu.FunctionURL
			break
		}
	}

	// Add complete list of all Function URLs (base + aliases)
	propsMap["FunctionUrls"] = functionURLs

	// Marshal back to JSON string
	updatedPropsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated properties: %w", err)
	}

	// Create a copy of the original ERD with updated properties
	updatedERD := *resource
	updatedERD.Properties = string(updatedPropsBytes)

	return &updatedERD, nil
}
