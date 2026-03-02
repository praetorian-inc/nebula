package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/kms"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsKMSGrantPrivesc.Metadata().Properties()["id"].(string), *AwsKMSGrantPrivesc)
}

var AwsKMSGrantPrivesc = chain.NewModule(
	cfg.NewMetadata(
		"KMS Grant Privilege Escalation Detection",
		"Detects KMS keys vulnerable to grant-based privilege escalation through CreateGrant permissions or overly permissive existing grants",
	).WithProperties(map[string]any{
		"id":          "kms-grant-privesc",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/grants.html",
			"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
			"https://github.com/RhinoSecurityLabs/pacu",
		},
	}),
).WithLinks(
	// Use native KMS API to list keys instead of CloudControl.
	// CloudControl's KMS handler calls DescribeKey internally during ListResources,
	// and fails the entire listing if ANY key has a restricted key policy that denies
	// DescribeKey (e.g., keys using explicit key policy model without IAM delegation).
	// The native KMS ListKeys API only requires kms:ListKeys permission.
	kms.NewKMSKeyLister,
	kms.NewKMSKeyDescribe,
	kms.NewKMSGrantPrivescAnalyzer,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "kms-grant-privesc"),
).WithAutoRun()
