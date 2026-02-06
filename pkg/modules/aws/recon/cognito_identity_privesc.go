package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cognito"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// CognitoIdentityPoolResources defines the supported resource types for this module.
type CognitoIdentityPoolResources struct{}

func (c *CognitoIdentityPoolResources) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.CloudResourceType("AWS::Cognito::IdentityPool"),
	}
}

func init() {
	registry.Register("aws", "recon", AwsCognitoIdentityPrivesc.Metadata().Properties()["id"].(string), *AwsCognitoIdentityPrivesc)
}

var AwsCognitoIdentityPrivesc = chain.NewModule(
	cfg.NewMetadata(
		"Cognito Identity Pool Unauthenticated Access Detection",
		"Detects Cognito Identity Pools allowing unauthenticated access and analyzes IAM role permissions",
	).WithProperties(map[string]any{
		"id":          "cognito-identity-privesc",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html",
			"https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_unauth/",
		},
	}).WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	general.NewResourceTypePreprocessor(&CognitoIdentityPoolResources{}),
	cloudcontrol.NewAWSCloudControl,
	cognito.NewCognitoIdentityPoolDescribe,
	cognito.NewCognitoIdentityPoolRoleAnalyzer,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "cognito-identity-privesc"),
	cfg.WithArg("resource-type", []string{"AWS::Cognito::IdentityPool"}),
)
