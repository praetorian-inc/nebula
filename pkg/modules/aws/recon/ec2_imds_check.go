package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("aws", "recon", AWSEC2IMDSCheck.Metadata().Properties()["id"].(string), *AWSEC2IMDSCheck)
}

var AWSEC2IMDSCheck = chain.NewModule(
	cfg.NewMetadata(
		"AWS EC2 IMDSv2 Enforcement Check",
		"Scan EC2 instances for IMDSv2 enforcement. Reports instances that allow IMDSv1, which is vulnerable to SSRF-based credential theft.",
	).WithProperties(map[string]any{
		"id":          "ec2-imds-check",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
		},
	}).WithChainInputParam(
		options.AwsResourceType().Name(),
	),
).WithLinks(
	general.NewResourceTypePreprocessor(EC2IMDSCheckProcessorInstance),
	cloudcontrol.NewAWSCloudControl,
	ec2.NewAWSEC2IMDSCheck,
).WithOutputters(
	outputters.NewRiskConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
	outputters.NewProofFileOutputter,
).WithInputParam(
	options.AwsResourceType().WithDefault([]string{"AWS::EC2::Instance"}),
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "ec2-imds-check"),
).WithStrictness(
	chain.Lax,
)

type EC2IMDSCheckProcessor struct{}

func (p *EC2IMDSCheckProcessor) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSEC2Instance,
	}
}

var EC2IMDSCheckProcessorInstance = &EC2IMDSCheckProcessor{}
