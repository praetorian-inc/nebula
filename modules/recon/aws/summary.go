package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

type AwsSummary struct {
	modules.BaseModule
}

var AwsSummaryOptions = []*types.Option{}

var AwsSummaryOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
	op.NewJsonFileProvider,
}

var AwsSummaryMetadata = modules.Metadata{
	Id:          "summary",
	Name:        "AWS Summary",
	Description: "Use cost explorer to summarize the services and regions in use.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

// func NewAwsSummary(options []*types.Option, run types.Run) (modules.Module, error) {
// 	return &AwsSummary{
// 		BaseModule: modules.BaseModule{
// 			Metadata:        AwsSummaryMetadata,
// 			Options:         options,
// 			Run:             run,
// 			OutputProviders: modules.RenderOutputProviders(nil, options),
// 		}}, nil
// }

func NewAwsSummary(opts []*types.Option) (<-chan string, stages.Stage[string, map[string][]string], error) {
	pipeline, err := stages.ChainStages[string, map[string][]string](
		AwsSummaryStage,
	)

	if err != nil {
		return nil, nil, err
	}

	return stages.Generator([]string{"summary"}), pipeline, nil
}

func AwsSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan map[string][]string {
	out := make(chan map[string][]string)
	go func() {
		defer close(out)
		cfg, err := helpers.GetAWSCfg("", types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)

		for range in {
			if err != nil {
				fmt.Println("Failed to load AWS config:", err)
				return
			}

			// Get all regions
			serviceRegions, err := utils.GetServiceAndRegions(cfg)
			if err != nil {
				fmt.Println("Failed to get regions:", err)
				return
			}

			// Iterate over each region
			for service, regions := range serviceRegions {
				fmt.Println("Service:", service)
				for _, region := range regions {
					fmt.Println("  Region:", region)
					if region == "NoRegion" {
						continue
					}
				}
			}
			out <- serviceRegions
		}
	}()
	return out
}

func ListResources(cfg aws.Config, rtype string) ([]*cloudcontrol.ListResourcesOutput, error) {
	fmt.Printf("%v\n", rtype)
	cc := cloudcontrol.NewFromConfig(cfg)
	params := &cloudcontrol.ListResourcesInput{}
	var results []*cloudcontrol.ListResourcesOutput

	params.TypeName = &rtype

	for {
		res, err := cc.ListResources(context.TODO(), params)

		if err != nil {
			fmt.Println("Error listing resources:", err)
			return nil, err
		}

		fmt.Printf("desc: %v\n", res.ResourceDescriptions)
		fmt.Printf("Next: %v\n", res.NextToken)
		results = append(results, res)

		if res.NextToken == nil {
			break
		}
	}

	return results, nil
}
