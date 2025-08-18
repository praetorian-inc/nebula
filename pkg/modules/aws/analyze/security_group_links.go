package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "analyze", AWSSecurityGroupLinks.Metadata().Properties()["id"].(string), *AWSSecurityGroupLinks)
}

var AWSSecurityGroupLinks = chain.NewModule(
	cfg.NewMetadata(
		"AWS Security Group Links",
		"Correlates network resources to security groups.",
	).WithProperties(map[string]any{
		"id":          "security-group-links",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html",
			"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html",
		},
	},
	),
).WithLinks(
	aws.NewSecurityGroupLinks,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.AwsSecurityGroupIds(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.AwsRegions(),
).WithConfigs(
	cfg.WithArg("module-name", "security-group-links"),
).WithAutoRun()
