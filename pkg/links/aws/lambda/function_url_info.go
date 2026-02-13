package lambda

// FunctionURLInfo is a JSON-friendly representation of a Lambda Function URL configuration.
//
// This struct is derived from the AWS SDK's types.FunctionUrlConfig
// (github.com/aws/aws-sdk-go-v2/service/lambda/types.FunctionUrlConfig) but provides:
//   - Pre-extracted FunctionName and Qualifier fields (parsed from FunctionArn)
//   - Simplified AuthType as string instead of FunctionUrlAuthType enum
//   - Helper methods for common operations (IsAlias, QualifiedName)
//
// The SDK's FunctionUrlConfig contains the raw FunctionArn which must be parsed
// to extract the qualifier (alias/version). This struct pre-computes those values
// for cleaner JSON output and easier downstream consumption.
//
// Note: Public access detection is handled by AwsResourcePolicyChecker which evaluates
// the lambda:FunctionUrlAuthType condition as part of comprehensive IAM policy analysis.
type FunctionURLInfo struct {
	FunctionName string `json:"FunctionName"`
	Qualifier    string `json:"Qualifier,omitempty"` // Alias name; empty for base function
	FunctionURL  string `json:"FunctionUrl"`
	AuthType     string `json:"AuthType"` // "NONE" or "AWS_IAM"
}

// IsAlias returns true if this Function URL is for an alias (not base function or $LATEST).
// Note: This method treats numeric version qualifiers (e.g., "1", "42") as aliases.
// In practice, Lambda Function URLs can only be created for $LATEST or aliases,
// not numeric versions, so this distinction is moot for ListFunctionUrlConfigs results.
func (f FunctionURLInfo) IsAlias() bool {
	return f.Qualifier != "" && f.Qualifier != "$LATEST"
}

// QualifiedName returns the qualified function name:
// - "function-name" for base function or $LATEST
// - "function-name:alias" for aliases
func (f FunctionURLInfo) QualifiedName() string {
	if f.IsAlias() {
		return f.FunctionName + ":" + f.Qualifier
	}
	return f.FunctionName
}
