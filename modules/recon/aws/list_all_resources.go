package recon

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type ResourceSummary struct {
	ResourceType string
	Count        int
	Regions      []string
}

var AwsListAllResourcesOptions = []*types.Option{
	&options.AwsRegionsOpt,
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		"list-all-"+strconv.FormatInt(time.Now().Unix(), 10)),
}

var AwsListAllResourcesMetadata = modules.Metadata{
	Id:          "list-all",
	Name:        "List All Resources",
	Description: "List all resources in an AWS account using Resource Groups Tagging API.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References: []string{
		"https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html",
	},
}

var AwsListAllResourcesOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

var AllAwsRegions = []string{
	"af-south-1",
	"ap-east-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-northeast-3",
	"ap-south-1",
	"ap-south-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-southeast-3",
	"ap-southeast-4",
	"ap-southeast-5",
	"ca-central-1",
	"ca-west-1",
	"cn-north-1",
	"cn-northwest-1",
	"eu-central-1",
	"eu-central-2",
	"eu-north-1",
	"eu-south-1",
	"eu-south-2",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"il-central-1",
	"me-central-1",
	"me-south-1",
	"sa-east-1",
	"us-east-1",
	"us-east-2",
	"us-gov-east-1",
	"us-gov-west-1",
	"us-west-1",
	"us-west-2",
}

func NewAwsListAllResources(opts []*types.Option) (<-chan string, stages.Stage[string, interface{}], error) {
	// First create a pipeline for collecting resources
	resourcePipeline, err := stages.ChainStages[string, []types.EnrichedResourceDescription](
		listAllResourcesStage,
		stages.AggregateOutput[types.EnrichedResourceDescription],
	)
	if err != nil {
		return nil, nil, err
	}

	// Create the final pipeline that produces both JSON and Markdown
	pipeline := func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan interface{} {
		out := make(chan interface{})

		go func() {
			defer close(out)
			resources := <-resourcePipeline(ctx, opts, in)
			out <- resources                              // For JSON
			out <- ProcessResourcesForMarkdown(resources) // For Markdown
		}()

		return out
	}

	return stages.Generator([]string{"all"}), pipeline, nil
}

func listAllResourcesStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)

	go func() {
		defer close(out)

		profile := types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value
		regionsOpt := types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value

		var regions []string
		if regionsOpt == "ALL" {
			regions = AllAwsRegions
			logs.ConsoleLogger().Info("Using all AWS regions")
		} else {
			var err error
			regions, err = helpers.ParseRegionsOption(regionsOpt, profile)
			if err != nil {
				logs.ConsoleLogger().Error("Error parsing regions: " + err.Error())
				return
			}
		}

		for _, region := range regions {
			cfg, err := helpers.GetAWSCfg(region, profile)
			if err != nil {
				logs.ConsoleLogger().Error("Error getting AWS config for region " + region + ": " + err.Error())
				continue
			}

			// Get account ID for enrichment
			accountId, err := helpers.GetAccountId(cfg)
			if err != nil {
				// Skip regions where we get InvalidClientTokenId error, this indicates that the region is not activated
				// There is probably a cleaner solution to check the regions activated per service but it would add significant overhead and recursion
				// Decided on just ignoring the specific error
				if strings.Contains(err.Error(), "InvalidClientTokenId") {
					logs.ConsoleLogger().Debug("Skipping disabled region: " + region)
					continue
				}
				logs.ConsoleLogger().Error("Error getting account ID: " + err.Error())
				continue
			}

			client := resourcegroupstaggingapi.NewFromConfig(cfg)
			input := &resourcegroupstaggingapi.GetResourcesInput{}

			for {
				resp, err := client.GetResources(ctx, input)
				if err != nil {
					// Also skip resource listing for InvalidClientTokenId errors
					if strings.Contains(err.Error(), "InvalidClientTokenId") {
						logs.ConsoleLogger().Debug("Skipping resource listing for disabled region: " + region)
						break
					}
					logs.ConsoleLogger().Error("Error getting resources for region " + region + ": " + err.Error())
					break
				}

				for _, resource := range resp.ResourceTagMappingList {
					// Extract the resource type and ID from the ARN
					resourceArn, err := helpers.NewArn(*resource.ResourceARN)
					if err != nil {
						logs.ConsoleLogger().Error("Error parsing ARN: " + err.Error())
						continue
					}

					// Create enriched resource description
					enrichedResource := types.EnrichedResourceDescription{
						Identifier: *resource.ResourceARN,
						TypeName:   resourceArn.Service,
						Region:     region,
						AccountId:  accountId,
						Properties: resource.Tags,
					}

					out <- enrichedResource
				}

				// Handle pagination
				if resp.PaginationToken == nil || *resp.PaginationToken == "" {
					break
				}
				input.PaginationToken = resp.PaginationToken
			}
		}
	}()

	return out
}

func ProcessResourcesForMarkdown(resources []types.EnrichedResourceDescription) types.MarkdownTable {
	// Map to store summaries
	summaries := make(map[string]*ResourceSummary)

	// Process each resource
	for _, res := range resources {
		if summary, exists := summaries[res.TypeName]; exists {
			summary.Count++
			// Add region if not already present
			found := false
			for _, r := range summary.Regions {
				if r == res.Region {
					found = true
					break
				}
			}
			if !found {
				summary.Regions = append(summary.Regions, res.Region)
			}
		} else {
			summaries[res.TypeName] = &ResourceSummary{
				ResourceType: res.TypeName,
				Count:        1,
				Regions:      []string{res.Region},
			}
		}
	}

	// Convert map to slice for sorting
	var summarySlice []ResourceSummary
	for _, v := range summaries {
		// Sort regions for consistent output
		sort.Strings(v.Regions)
		summarySlice = append(summarySlice, *v)
	}

	// Sort by resource type
	sort.Slice(summarySlice, func(i, j int) bool {
		return summarySlice[i].ResourceType < summarySlice[j].ResourceType
	})

	// Create markdown table data
	headers := []string{"Resource Type", "Count", "Regions"}
	rows := make([][]string, len(summarySlice))

	for i, summary := range summarySlice {
		rows[i] = []string{
			summary.ResourceType,
			strconv.Itoa(summary.Count),
			strings.Join(summary.Regions, ", "),
		}
	}

	// Create markdown table
	return types.MarkdownTable{
		TableHeading: "AWS Resource Summary",
		Headers:      headers,
		Rows:         rows,
	}
}
