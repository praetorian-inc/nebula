package recon

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// This stage differs from the CloudControlListResources recon stage as it uses tag editor
// Tag editor uses far fewer API calls and can provide a high-level overview of all the resources on the account
// Tag editor serves the purpose of this module which is to provide a glimpse into the services running on the account
func listAllResourcesStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)

	go func() {
		defer close(out)

		profile := types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value
		regionsOpt := types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value

		var regions []string
		if strings.EqualFold(regionsOpt, "ALL") {
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

		var wg sync.WaitGroup

		// Process each region
		for _, region := range regions {
			// Adding concurrency as we aren't actually creating a lot of API calls and this should not hit the AWS rate limit
			// We can revisit this if we are finding that we are hitting the limit
			wg.Add(1)
			go func(region string) {
				defer wg.Done()

				logs.ConsoleLogger().Info("Processing region: " + region)
				cfg, err := helpers.GetAWSCfg(region, profile)
				if err != nil {
					logs.ConsoleLogger().Error("Error getting AWS config for region " + region + ": " + err.Error())
					return
				}

				// Get account ID for enrichment
				accountId, err := helpers.GetAccountId(cfg)
				if err != nil {
					if strings.Contains(err.Error(), "InvalidClientTokenId") {
						logs.ConsoleLogger().Info("Skipping disabled region: " + region)
						return
					}
					logs.ConsoleLogger().Error("Error getting account ID: " + err.Error())
					return
				}

				client := resourcegroupstaggingapi.NewFromConfig(cfg)
				input := &resourcegroupstaggingapi.GetResourcesInput{}

				for {
					resp, err := client.GetResources(ctx, input)
					if err != nil {
						// Instead of trying to handle disabled regions which might lead to false positives if EC2 is disabled for a region
						// We will just handle the invalid region error and return
						// With concurrency, this does not add any additional time and is actually faster than preparing the valid regions ahead of time
						if strings.Contains(err.Error(), "InvalidClientTokenId") {
							logs.ConsoleLogger().Debug("Skipping resource listing for disabled region: " + region)
							return
						}
						logs.ConsoleLogger().Error("Error getting resources for region " + region + ": " + err.Error())
						return
					}

					for _, resource := range resp.ResourceTagMappingList {
						resourceArn, err := helpers.NewArn(*resource.ResourceARN)
						if err != nil {
							logs.ConsoleLogger().Error("Error parsing ARN: " + err.Error())
							continue
						}

						enrichedResource := types.EnrichedResourceDescription{
							Identifier: *resource.ResourceARN,
							TypeName:   resourceArn.Service,
							Region:     region,
							AccountId:  accountId,
							Properties: resource.Tags,
						}

						select {
						case <-ctx.Done():
							return
						case out <- enrichedResource:
						}
					}

					if resp.PaginationToken == nil || *resp.PaginationToken == "" {
						break
					}
					input.PaginationToken = resp.PaginationToken
				}
			}(region)
		}

		// Wait for all regions to complete
		wg.Wait()
	}()

	return out
}

// Markdown formatting to create a summary table
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
