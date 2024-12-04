package recon

import (
	"context"
	"fmt"
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
			regions = helpers.Regions
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
	summaries := make(map[string]map[string]int)
	activeRegions := make(map[string]bool)
	uniqueTypes := make(map[string]bool)
	var accountId string

	// Process each resource
	for _, res := range resources {
		accountId = res.AccountId
		uniqueTypes[res.TypeName] = true

		if _, exists := summaries[res.TypeName]; !exists {
			summaries[res.TypeName] = make(map[string]int)
		}
		summaries[res.TypeName][res.Region]++
		if summaries[res.TypeName][res.Region] > 0 {
			activeRegions[res.Region] = true
		}
	}

	var regions []string
	for region := range activeRegions {
		regions = append(regions, region)
	}

	// Sort in reverse order
	sort.Slice(regions, func(i, j int) bool {
		return regions[i] > regions[j] // Changed from < to >
	})

	var resourceTypes []string
	for resType := range uniqueTypes {
		resourceTypes = append(resourceTypes, resType)
	}
	sort.Strings(resourceTypes)

	headers := []string{"Type"}
	headers = append(headers, regions...)

	rows := make([][]string, len(resourceTypes))
	for i, resType := range resourceTypes {
		row := make([]string, len(headers))
		row[0] = resType
		for j, region := range regions {
			count := summaries[resType][region]
			if count == 0 {
				row[j+1] = "" // Empty string instead of "0"
			} else {
				row[j+1] = strconv.Itoa(count)
			}
		}
		rows[i] = row
	}

	return types.MarkdownTable{
		TableHeading: fmt.Sprintf("AWS Resource Summary [%s]", accountId),
		Headers:      headers,
		Rows:         rows,
	}
}
