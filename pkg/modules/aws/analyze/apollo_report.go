package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "analyze", ApolloReport.Metadata().Properties()["id"].(string), *ApolloReport)
}

var ApolloReport = chain.NewModule(
	cfg.NewMetadata(
		"Apollo Report",
		"Generates analysis reports from Apollo graph database including privilege escalation paths and external trust relationships",
	).WithProperties(map[string]any{
		"id":          "apollo-report",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	aws.NewApolloReport,
).WithOutputters(
	outputters.NewApolloReportOutputter,
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	cfg.NewParam[string]("report-type", "Type of report to generate: all, privesc, external-trust").
		WithDefault("all").
		WithShortcode("t"),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "apollo-report"),
).WithAutoRun()
