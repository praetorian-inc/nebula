package recon

import (
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsGetConsole struct {
	modules.BaseModule
}

var AwsGetConsoleOptions = []*types.Option{
	&options.AwsRoleArnOpt,
	&options.AwsDurationOpt,
	&options.AwsRegionOpt,
	&options.AwsMfaTokenOpt,
	&options.AwsRoleSessionNameOpt,
}

var AwsGetConsoleOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

var AwsGetConsoleMetadata = modules.Metadata{
	Id:          "get-console",
	Name:        "AWS Get Console",
	Description: "Retrieve the AWS console URL for the given profile",
	Platform:    modules.AWS,
	Authors:     []string{"Bernard Yip"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsGetConsole(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		stages.AwsGetConsoleURL,
		stages.ToString[string],
	)

	if err != nil {
		return nil, nil, err
	}

	return stages.Generator([]string{"console"}), pipeline, nil
}
