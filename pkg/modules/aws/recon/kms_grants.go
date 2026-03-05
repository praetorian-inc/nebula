package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/kms"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	AwsListKMSGrants.New().Initialize()
	registry.Register("aws", "recon", AwsListKMSGrants.Metadata().Properties()["id"].(string), *AwsListKMSGrants)
}

// AwsListKMSGrants lists KMS grants by first listing KMS keys via CloudControl
// (which has native KMS API fallback) and then listing grants on each key.
// This addresses the limitation that AWS::KMS::Grant is not supported by CloudControl.
//
// Flow: CloudControl (AWS::KMS::Key) → KMSGrantLister → Output (AWS::KMS::Grant)
var AwsListKMSGrants = chain.NewModule(
	cfg.NewMetadata(
		"AWS List KMS Grants",
		"List KMS grants in an AWS account. Lists KMS keys first, then enumerates grants on each key.",
	).WithProperties(map[string]any{
		"id":          "kms-grants",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/grants.html",
			"https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html",
		},
	}).WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	// Preprocessor handles resource type input (default is AWS::KMS::Key)
	general.NewResourceTypePreprocessor(&cloudcontrol.AWSCloudControl{}),
	// CloudControl lists KMS keys (with native API fallback for restricted policies)
	cloudcontrol.NewAWSCloudControl,
	// KMSGrantLister takes keys and outputs grants
	kms.NewKMSGrantLister,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "kms-grants"),
	// Default to listing KMS keys and replica keys (grants are enumerated from keys)
	cfg.WithArg("resource-type", []string{"AWS::KMS::Key", "AWS::KMS::ReplicaKey"}),
)
