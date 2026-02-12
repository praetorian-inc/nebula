package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ecs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	ECSEcscape.New().Initialize()
	registry.Register("aws", "recon", ECSEcscape.Metadata().Properties()["id"].(string), *ECSEcscape)
}

var ECSEcscape = chain.NewModule(
	cfg.NewMetadata(
		"ECS ECScape Vulnerability Detection",
		"Detects ECS clusters vulnerable to the ECScape credential theft attack (EC2 launch type only).",
	).WithProperties(map[string]any{
		"id":          "ecs-ecscape",
		"platform":    "aws",
		"category":    "recon",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://github.com/naorhaziz/ecscape",
			"https://hackingthe.cloud/aws/exploitation/ecs-breakout/",
		},
		"description": "ECScape is a privilege escalation vulnerability in Amazon ECS (EC2 launch type) that enables " +
			"low-privileged tasks to hijack IAM credentials of other tasks running on the same container instance. " +
			"This module identifies vulnerable clusters by detecting EC2-based ECS deployments with multiple services " +
			"that could co-locate on shared hosts.",
	}),
).WithLinks(
	ecs.NewEcsEcscapeAnalyzer,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewERDConsoleOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.AwsProfile(),
	options.AwsOrgPoliciesFile(),
).WithConfigs(
	cfg.WithArg("module-name", "ecs-ecscape"),
	cfg.WithArg("opsec_level", "moderate"),
).WithAutoRun()
