package stages

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsCloudControlListResources lists resources of a given type in a given region using the Cloud Control API.
// This should be the primary method of listing resources in AWS.
func AwsCloudControlListResources(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudControlListResources")
	out := make(chan types.EnrichedResourceDescription)

	// Start a goroutine to process resources
	go func() {
		// Ensure channel is closed when we're done
		defer close(out)

		logger.Info("Listing resources")

		// Get profile and validate regions
		profile := options.GetOptionByName("profile", opts).Value
		regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
		if err != nil {
			logger.Error("Failed to parse regions: " + err.Error())
			return
		}

		// Set up AWS config and validate credentials
		config, err := helpers.GetAWSCfg(regions[0], profile, opts)
		if err != nil {
			logger.Error("Failed to get AWS config: " + err.Error())
			return
		}

		// Validate AWS credentials
		acctId, err := helpers.GetAccountId(config)
		if err != nil {
			logger.Error("Failed to get AWS account ID - check credentials and connectivity: " + err.Error())
			return
		}

		var wg sync.WaitGroup

		// Process each resource type
		for resourceType := range rtype {
			// Process each region
			for _, region := range regions {
				// Skip non us-east-1 regions for global services
				if helpers.IsGlobalService(resourceType) && region != "us-east-1" {
					continue
				}

				logger.Info("Listing resources of type " + resourceType + " in region: " + region)

				wg.Add(1)
				go func(region string, resourceType string) {
					defer wg.Done()

					// Get region-specific config
					regionConfig, err := helpers.GetAWSCfg(region, profile, opts)
					if err != nil {
						logger.Error("Failed to get region config for " + region + ": " + err.Error())
						return
					}

					cc := cloudcontrol.NewFromConfig(regionConfig)
					params := &cloudcontrol.ListResourcesInput{
						TypeName: &resourceType,
					}

					for {
						select {
						case <-ctx.Done():
							return
						default:
							res, err := cc.ListResources(ctx, params)
							if err != nil {
								if strings.Contains(err.Error(), "TypeNotFoundException") {
									logger.Info("Resource type " + resourceType + " is not available in region " + region)
									return
								}
								logger.Debug(err.Error())
								return
							}

							var resourceWg sync.WaitGroup
							for _, resource := range res.ResourceDescriptions {
								resourceWg.Add(1)
								go func(resource *cctypes.ResourceDescription) {
									defer resourceWg.Done()

									erd := types.EnrichedResourceDescription{
										Identifier: *resource.Identifier,
										TypeName:   resourceType,
										Region:     region,
										Properties: *resource.Properties,
										AccountId:  acctId,
									}
									erd.Arn = erd.ToArn()

									select {
									case out <- erd:
									case <-ctx.Done():
										return
									}
								}(&resource)
							}
							resourceWg.Wait()

							if res.NextToken == nil {
								break
							}
							params.NextToken = res.NextToken
						}
					}

					logger.Info("Completed collecting resource type " + resourceType + " in region: " + region)
				}(region, resourceType)
			}
		}

		// Wait for all goroutines to complete
		wg.Wait()
	}()

	return out
}

// AwsCloudControlGetResource gets a single resource using the Cloud Control API.
func AwsCloudControlGetResource(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudControlGetResource")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Getting resource to populate properties")
	go func() {
		defer close(out)
		for resource := range in {
			logger.Info("Now getting resource: " + resource.Identifier)
			cfg, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			cc := cloudcontrol.NewFromConfig(cfg)

			params := &cloudcontrol.GetResourceInput{
				Identifier: &resource.Identifier,
				TypeName:   &resource.TypeName,
			}

			retries := 3
			backoff := 1000

			for i := 0; i < retries; i++ {
				res, err := cc.GetResource(ctx, params)
				if err != nil && strings.Contains(err.Error(), "ThrottlingException") {
					logger.Info("ThrottlingException encountered. Retrying in " + strconv.Itoa(backoff) + "ms")
					b := time.Duration(backoff) * time.Millisecond * time.Duration(i)
					time.Sleep(b)
					continue
				}

				if err != nil {
					logger.Error("Error getting resource: %s, %s", resource.Identifier, err)
					break
				}

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: res.ResourceDescription.Properties,
					AccountId:  resource.AccountId,
				}
				break
			}
		}
	}()
	return out
}
