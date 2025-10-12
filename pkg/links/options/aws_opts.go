package options

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AwsAccessKeyIdOpt = types.Option{
	Name:        "access-key-id",
	Short:       "k",
	Description: "AWS access key ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"),
}

var AwsAccountIdOpt = types.Option{
	Name:        "account-id",
	Short:       "i",
	Description: "AWS account ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("[0-9]{12}"),
}

var AwsRegionOpt = types.Option{
	Name:        "region",
	Short:       "r",
	Description: "AWS region",
	Required:    true,
	Type:        types.String,
	Value:       "us-east-1",
}

var AwsRegionsOpt = types.Option{
	Name:        "regions",
	Short:       "r",
	Description: "Comma separated list of AWS regions. Can be 'all' for all regions.",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceTypeOpt = types.Option{
	Name:        "resource-type",
	Short:       "t",
	Description: "AWS Cloud Control resource type",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|ALL|all)$"),
}

var FindSecretsTypes = []string{
	"AWS::CloudFormation::Stack",
	"AWS::Lambda::Function",
	"AWS::Lambda::Function::Code",
	"AWS::EC2::Instance",
	"AWS::ECR::Repository",
	"AWS::ECR::PublicRepository",
	"AWS::ECS::TaskDefinition",
	"AWS::SSM::Parameter",
	"AWS::SSM::Document",
	"AWS::StepFunctions::StateMachine",
	"ALL",
}

var AwsFindSecretsResourceType = types.Option{
	Name:        "secret-resource-types",
	Short:       "t",
	Description: "Comma separated list of AWS services. Currently supported types: " + strings.Join(FindSecretsTypes, ", "),
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueList:   FindSecretsTypes,
}

var AwsResourceIdOpt = types.Option{
	Name:        "resource-id",
	Short:       "i",
	Description: "AWS Cloud Control resource identifier",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsResourceNameOpt = types.Option{
	Name:        "name",
	Short:       "n",
	Description: "AWS resource name",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsSummaryServicesOpt = types.Option{
	Name:        "summary",
	Short:       "s",
	Description: "Use the cost explorer API to get a summary of services",
	Required:    false,
	Type:        types.Bool,
	Value:       "",
}

var AwsActionOpt = types.Option{
	Name:        "action",
	Short:       "a",
	Description: "AWS IAM action",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var AwsProfileOpt = types.Option{
	Name:        "profile",
	Short:       "p",
	Description: "AWS shared credentials profile",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsProfileListOpt = types.Option{
	Name:        "profile-list",
	Short:       "l",
	Description: "List of AWS shared credentials profiles",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var AwsScanTypeOpt = types.Option{
	Name:        "scan-type",
	Short:       "s",
	Description: "Scan type - 'full' for all resources or 'summary' for key services",
	Required:    true,
	Type:        types.String,
	Value:       "full",
	ValueList:   []string{"full", "summary"},
}

var AwsCacheDirOpt = types.Option{
	Name:        "cache-dir",
	Description: "Directory to store API response cache files",
	Required:    false,
	Type:        types.String,
	Value:       filepath.Join(os.TempDir(), "nebula-cache"),
}

var AwsCacheExtOpt = types.Option{
	Name:        "cache-ext",
	Description: "Name of AWS API response cache files extension \nWarning! Changing the cache file extension may lead to unintended file deletion during automatic cache cleanup.",
	Required:    false,
	Type:        types.String,
	Value:       ".aws-cache",
}

var AwsCacheTTLOpt = types.Option{
	Name:        "cache-ttl",
	Description: "TTL for cached responses in seconds",
	Required:    false,
	Type:        types.Int,
	Value:       "3600",
}

var AwsDisableCacheOpt = types.Option{
	Name:        "disable-cache",
	Description: "Disable API response caching",
	Required:    false,
	Type:        types.Bool,
	Value:       "false",
}

var AwsCacheErrorRespOpt = types.Option{
	Name:        "cache-error-resp",
	Description: "Cache error response",
	Required:    false,
	Type:        types.Bool,
	Value:       "false",
}

var AwsCacheErrorRespTypesOpt = types.Option{
	Name:        "cache-error-resp-type",
	Description: "A comma-separated list of strings specifying cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error.",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

// Janus Options

func AwsRegions() cfg.Param {
	return cfg.NewParam[[]string]("regions", "AWS regions to scan").
		WithDefault([]string{"all"}).
		WithRegex(regexp.MustCompile(`(?i)^[a-z]{2}\-([a-z]+\-){1,2}\d|all$`)).
		WithShortcode("r")
}

func AwsProfile() cfg.Param {
	return cfg.NewParam[string]("profile", "AWS profile to use").
		WithShortcode("p")
}

func AwsProfileDir() cfg.Param {
	return cfg.NewParam[string]("profile-dir", "Set to override the default AWS profile directory")
}

func AwsResourceType() cfg.ParamImpl[[]string] {
	return cfg.NewParam[[]string]("resource-type", "AWS Cloud Control resource type").
		WithRegex(regexp.MustCompile("^(AWS::[a-zA-Z0-9:]+|all|ALL)$")).
		WithShortcode("t").
		WithDefault([]string{"all"})
}

func AwsResourceArn() cfg.Param {
	return cfg.NewParam[[]string]("resource-arn", "AWS Cloud Control resource ARN").
		WithShortcode("a").
		WithRegex(regexp.MustCompile("^arn:aws:.*$")).
		AsRequired()
}

func AwsCacheDir() cfg.Param {
	return cfg.NewParam[string]("cache-dir", "Directory to store API response cache files").
		WithDefault(filepath.Join(os.TempDir(), "nebula-cache"))
}

func AwsCacheExt() cfg.Param {
	return cfg.NewParam[string]("cache-ext", "Name of AWS API response cache files extension").
		WithDefault(".aws-cache")
}

func AwsCacheTTL() cfg.Param {
	return cfg.NewParam[int]("cache-ttl", "TTL for cached responses in seconds").
		WithDefault(3600)
}

func AwsCacheErrorTypes() cfg.Param {
	return cfg.NewParam[string]("cache-error-resp-type", "A comma-separated list of strings specifying cache error response types, e.g., TypeNotFoundException, AccessDeniedException. Use all to represent any error.")
}

func AwsOrgPoliciesFile() cfg.Param {
	return cfg.NewParam[string]("org-policies", "Path to AWS organization policies JSON file from get-org-policies module").
		WithShortcode("o")
}

func AwsGaadFile() cfg.Param {
	return cfg.NewParam[string]("gaad-file", "Path to AWS GAAD (GetAccountAuthorizationDetails) JSON file from account-auth-details module").
		WithShortcode("g")
}

func AwsResourcePoliciesFile() cfg.Param {
	return cfg.NewParam[string]("resource-policies-file", "Path to AWS resource policies JSON file from resource-policies module").
		WithShortcode("rp")
}

func AwsCacheErrorResp() cfg.Param {
	return cfg.NewParam[bool]("cache-error-resp", "Cache error response").
		WithDefault(false)
}

func AwsDisableCache() cfg.Param {
	return cfg.NewParam[bool]("disable-cache", "Disable API response caching").
		WithDefault(false)
}

func AwsOrgPolicies() cfg.Param {
	return cfg.NewParam[string]("org-policies", "Enable organization policies").
		WithShortcode("op")
}

func AwsReconBaseOptions() []cfg.Param {
	return []cfg.Param{
		AwsProfile(),
		AwsProfileDir(),
		AwsCacheDir(),
		AwsCacheExt(),
		AwsCacheTTL(),
		AwsCacheErrorTypes(),
		AwsCacheErrorResp(),
		AwsDisableCache(),
		AwsOpsecLevel(),
	}
}

func AwsCommonReconOptions() []cfg.Param {
	baseOpts := AwsReconBaseOptions()
	return append(baseOpts, []cfg.Param{
		AwsRegions(),
		AwsResourceType(),
	}...)
}

func AwsAccessKeyId() cfg.Param {
	return cfg.NewParam[[]string]("access-key-id", "AWS access key ID").
		WithRegex(regexp.MustCompile("([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}")).
		WithShortcode("k").
		AsRequired()
}

func AwsAccountId() cfg.Param {
	return cfg.NewParam[[]string]("account-id", "AWS account ID").
		WithRegex(regexp.MustCompile("[0-9]{12}")).
		WithShortcode("i").
		AsRequired()
}

func AwsAction() cfg.Param {
	return cfg.NewParam[[]string]("action", "AWS IAM action").
		WithShortcode("a").
		AsRequired()
}

func AwsRoleArn() cfg.Param {
	return cfg.NewParam[string]("role-arn", "AWS Role ARN to assume for console access").
		WithShortcode("R")
}

func AwsSessionDuration() cfg.Param {
	return cfg.NewParam[int]("duration", "Session duration in seconds (900-3600)").
		WithShortcode("d").
		WithDefault(3600)
}

func AwsMfaToken() cfg.Param {
	return cfg.NewParam[string]("mfa-token", "MFA token code for role assumption").
		WithShortcode("m")
}

func AwsRoleSessionName() cfg.Param {
	return cfg.NewParam[string]("role-session-name", "Name for the assumed role session").
		WithDefault("nebula-console-session")
}

func AwsFederationName() cfg.Param {
	return cfg.NewParam[string]("federation-name", "Name for federation token").
		WithDefault("nebula-federation")
}

func AwsEnableEC2SecurityEnrichment() cfg.Param {
	return cfg.NewParam[bool]("enable-ec2-security-enrichment", "Enable EC2 security group enrichment for public resources").
		WithShortcode("e").
		WithDefault(false)
}

func AwsCdkQualifiers() cfg.Param {
	return cfg.NewParam[[]string]("cdk-qualifiers", "CDK bootstrap qualifiers to check").
		WithDefault([]string{"hnb659fds"}).
		WithShortcode("q")
}

func AwsOpsecLevel() cfg.Param {
	return cfg.NewParam[string]("opsec_level", "Operational security level for AWS operations").
		WithDefault("none")
}

func AwsApolloOfflineOptions() []cfg.Param {
	baseOpts := AwsReconBaseOptions()
	return append(baseOpts, []cfg.Param{
		AwsOrgPoliciesFile(),
		AwsGaadFile(),
		AwsResourcePoliciesFile(),
	}...)
}
