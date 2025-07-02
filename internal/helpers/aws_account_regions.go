package helpers

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/praetorian-inc/nebula/pkg/types"
	"sync"
)

// Cache to store active regions per profile using sync.Map
var regionsCache sync.Map

// GetActiveRegions retrieves a list of active AWS regions for the specified profile.
// If bypassCache is true, it fetches the regions from AWS even if they are cached.
func GetActiveRegions(profile string, opts []*types.Option, bypassCache bool) ([]string, error) {

	logger.Debug("GetActiveRegions:", "profile", profile, "bypassCache", bypassCache)

	if !bypassCache {
		if cachedRegions, ok := regionsCache.Load(profile); ok {
			logger.Debug("GetActiveRegions: using cached regions", "regions", cachedRegions)
			return cachedRegions.([]string), nil
		}
	}

	// Load the AWS configuration for the specified profile
	cfg, err := GetAWSCfg("us-east-1", profile, opts)
	if err != nil {
		return nil, err
	}

	// Create an Account client
	accountClient := account.NewFromConfig(cfg)

	// Initialize the paginator
	paginator := account.NewListRegionsPaginator(accountClient, &account.ListRegionsInput{
		RegionOptStatusContains: []awstypes.RegionOptStatus{
			awstypes.RegionOptStatusEnabled,
			awstypes.RegionOptStatusEnabledByDefault,
		},
	})

	var activeRegions []string

	// Iterate over paginated results
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}

		// Extract active region names
		for _, region := range output.Regions {
			activeRegions = append(activeRegions, aws.ToString(region.RegionName))
		}
	}

	// Cache the result
	regionsCache.Store(profile, activeRegions)

	logger.Debug("GetActiveRegions:", "regions", activeRegions)

	return activeRegions, nil
}
