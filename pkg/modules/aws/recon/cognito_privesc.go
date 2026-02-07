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

func init() {
	registry.Register("aws", "recon", AwsCognitoPrivesc.Metadata().Properties()["id"].(string), *AwsCognitoPrivesc)
}

type CognitoPrivescResourceTypes struct{}

func (c *CognitoPrivescResourceTypes) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.CloudResourceType("AWS::Cognito::UserPool"),
	}
}

var cognitoPrivescResourceTypes = &CognitoPrivescResourceTypes{}

var AwsCognitoPrivesc = chain.NewModule(
	cfg.NewMetadata(
		"Cognito Privilege Escalation Detection",
		"Detects AWS Cognito User Pool misconfigurations that could allow privilege escalation via writable custom attributes, clients without secrets, and self-signup enabled. Identifies user pools where attackers could modify their own attributes to gain elevated privileges.",
	).WithProperties(map[string]any{
		"id":          "cognito-privesc",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://medium.com/@un1quely/aws-cognito-privilege-escalation-using-custom-attributes-editing-in-user-pool-2f8d6eaa3c7f",
			"https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/",
			"https://trustoncloud.com/blog/exploit-two-of-the-most-common-vulnerabilities-in-amazon-cognito-with-cloudgoat/",
			"https://rhinosecuritylabs.com/aws/attacking-aws-cognito-with-pacu-p2/",
		},
	}).WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	general.NewResourceTypePreprocessor(cognitoPrivescResourceTypes),
	cloudcontrol.NewAWSCloudControl,           // Enumerate user pools
	cognito.NewCognitoUserPoolGetDomains,      // Get domains + self-signup detection
	cognito.NewCognitoUserPoolDescribeClients, // Get client info + HasClientSecret
	cognito.NewCognitoUserPoolSchemaAnalyzer,  // Analyze writable privilege attributes
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewRuntimeMarkdownOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	options.AwsRegions(),
).WithInputParam(
	cfg.NewParam[string]("filename", "Base filename for output").
		WithDefault("cognito-privesc").
		WithShortcode("f"),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "cognito-privesc"),
	cfg.WithArg("resource-type", []string{"AWS::Cognito::UserPool"}),
)
