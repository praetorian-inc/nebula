package iam

import (
	"context"
	"sync"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/message"
)

// Additional optimizations for the SDK collector
// This file contains the optimized subscription processing methods

// processSubscriptionsOptimizedSDK processes multiple subscriptions with cross-subscription batching optimizations
func (l *SDKComprehensiveCollectorLink) processSubscriptionsOptimizedSDK(
	subscriptionIDs []string,
) map[string]interface{} {

	overallStart := l.logCollectionStart("Optimized Subscription Processing")
	l.Logger.Info("Starting optimized subscription processing with Resource Graph batching")
	message.Info("Collecting Azure RM data with Resource Graph optimization...")

	allData := make(map[string]interface{})

	// OPTIMIZATION 1: Batch Resource Graph queries across ALL subscriptions
	batchStart := l.logCollectionStart("Batched Resource Graph Collection")
	batchedResources, batchedResourceGroups := l.collectAllResourcesWithBatching(subscriptionIDs)
	l.logCollectionEnd("Batched Resource Graph Collection", batchStart, len(batchedResources)+len(batchedResourceGroups))

	// OPTIMIZATION 2: Process subscriptions in parallel for individual collections
	type subResult struct {
		subscriptionID string
		data           map[string]interface{}
		err            error
	}

	subChan := make(chan string, len(subscriptionIDs))
	resultChan := make(chan subResult, len(subscriptionIDs))

	// Still use single worker but with optimized per-subscription processing
	var wg sync.WaitGroup
	numWorkers := 1

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subscriptionID := range subChan {
				l.Logger.Info("Processing subscription with optimization", "subscription", subscriptionID)

				// Use pre-collected batched resources
				subscriptionResources := l.filterResourcesBySubscription(batchedResources, subscriptionID)
				subscriptionResourceGroups := l.filterResourcesBySubscription(batchedResourceGroups, subscriptionID)

				data, err := l.collectAllAzureRMDataOptimizedSDK(subscriptionID, subscriptionResources, subscriptionResourceGroups)
				resultChan <- subResult{
					subscriptionID: subscriptionID,
					data:           data,
					err:            err,
				}
			}
		}()
	}

	// Send subscriptions to workers
	for _, subscriptionID := range subscriptionIDs {
		subChan <- subscriptionID
	}
	close(subChan)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		if result.err != nil {
			l.Logger.Error("Failed to process subscription", "subscription", result.subscriptionID, "error", result.err)
			continue
		}
		allData[result.subscriptionID] = result.data
	}

	// Calculate total resource counts across all subscriptions
	var totalItems int
	for _, subData := range allData {
		if subMap, ok := subData.(map[string]interface{}); ok {
			for _, data := range subMap {
				if slice, ok := data.([]interface{}); ok {
					totalItems += len(slice)
				}
			}
		}
	}

	l.logCollectionEnd("Optimized Subscription Processing", overallStart, totalItems)
	message.Info("Azure RM data collection completed! Processed %d subscriptions with Resource Graph batching", len(allData))
	return allData
}

// collectAllResourcesWithBatching collects resources and resource groups for ALL subscriptions in batched queries
func (l *SDKComprehensiveCollectorLink) collectAllResourcesWithBatching(subscriptionIDs []string) ([]interface{}, []interface{}) {
	ctx := l.Context()

	l.Logger.Info("Starting batched Resource Graph collection", "subscriptions", len(subscriptionIDs))

	// Convert subscription IDs to string pointers for ARM API
	var subscriptionPtrs []*string
	for i := range subscriptionIDs {
		subscriptionPtrs = append(subscriptionPtrs, &subscriptionIDs[i])
	}

	// BATCHED QUERY 1: All resources across all subscriptions
	resourcesQuery := `
		resources
		| project id, name, type, location, resourceGroup, subscriptionId, tags, identity, properties, zones, kind, sku, plan
		| order by subscriptionId asc, type asc`

	l.Logger.Info("Executing batched resources query across all subscriptions")
	var allResources []interface{}

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:         &resourcesQuery,
		Subscriptions: subscriptionPtrs, // Query ALL subscriptions at once!
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			l.Logger.Error("Batched Resource Graph resources query failed", "error", err)
			break
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &allResources)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	// BATCHED QUERY 2: All resource groups across all subscriptions
	resourceGroupsQuery := `
		resourcecontainers
		| where type == "microsoft.resources/subscriptions/resourcegroups"
		| project id, name, type, location, subscriptionId, tags, properties
		| order by subscriptionId asc, name asc`

	l.Logger.Info("Executing batched resource groups query across all subscriptions")
	var allResourceGroups []interface{}

	queryRequest = armresourcegraph.QueryRequest{
		Query:         &resourceGroupsQuery,
		Subscriptions: subscriptionPtrs, // Query ALL subscriptions at once!
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			l.Logger.Error("Batched Resource Graph resource groups query failed", "error", err)
			break
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &allResourceGroups)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	l.Logger.Info("Completed batched Resource Graph queries", "resources", len(allResources), "resourceGroups", len(allResourceGroups))
	return allResources, allResourceGroups
}

// filterResourcesBySubscription filters pre-collected resources by subscription ID
func (l *SDKComprehensiveCollectorLink) filterResourcesBySubscription(allResources []interface{}, subscriptionID string) []interface{} {
	var filtered []interface{}

	for _, resource := range allResources {
		if resourceMap, ok := resource.(map[string]interface{}); ok {
			if subID, ok := resourceMap["subscriptionId"].(string); ok && subID == subscriptionID {
				filtered = append(filtered, resource)
			}
		}
	}

	return filtered
}

// collectAllAzureRMDataOptimizedSDK collects Azure RM data for a subscription using pre-collected resources
func (l *SDKComprehensiveCollectorLink) collectAllAzureRMDataOptimizedSDK(subscriptionID string, preCollectedResources, preCollectedResourceGroups []interface{}) (map[string]interface{}, error) {
	azurermData := make(map[string]interface{})

	overallStart := l.logCollectionStart("Azure RM Data (Optimized) - " + subscriptionID)
	l.Logger.Info("Processing subscription with pre-collected Resource Graph data", "subscription", subscriptionID, "resources", len(preCollectedResources), "resourceGroups", len(preCollectedResourceGroups))

	// Use pre-collected data instead of individual queries!
	azurermData["azureResources"] = preCollectedResources
	azurermData["azureResourceGroups"] = preCollectedResourceGroups

	// Collection 1: Role Assignments via Authorization SDK (unchanged - requires individual subscription processing)
	startTime := l.logCollectionStart("role assignments - " + subscriptionID)
	subscriptionRoleAssignments, resourceGroupRoleAssignments, resourceLevelRoleAssignments, managementGroupRoleAssignments, tenantRoleAssignments, err := l.collectAllRoleAssignmentsSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect role assignments via SDK", "subscription", subscriptionID, "error", err)
		azurermData["subscriptionRoleAssignments"] = []interface{}{}
		azurermData["resourceGroupRoleAssignments"] = []interface{}{}
		azurermData["resourceLevelRoleAssignments"] = []interface{}{}
		azurermData["managementGroupRoleAssignments"] = []interface{}{}
		azurermData["tenantRoleAssignments"] = []interface{}{}
		l.logCollectionEnd("role assignments - " + subscriptionID, startTime, 0)
	} else {
		azurermData["subscriptionRoleAssignments"] = subscriptionRoleAssignments
		azurermData["resourceGroupRoleAssignments"] = resourceGroupRoleAssignments
		azurermData["resourceLevelRoleAssignments"] = resourceLevelRoleAssignments
		azurermData["managementGroupRoleAssignments"] = managementGroupRoleAssignments
		azurermData["tenantRoleAssignments"] = tenantRoleAssignments
		totalRoleAssignments := len(subscriptionRoleAssignments) + len(resourceGroupRoleAssignments) + len(resourceLevelRoleAssignments) + len(managementGroupRoleAssignments) + len(tenantRoleAssignments)
		l.logCollectionEnd("role assignments - " + subscriptionID, startTime, totalRoleAssignments)
	}

	// Collection 2: Role Definitions via Authorization SDK (unchanged)
	startTime = l.logCollectionStart("role definitions - " + subscriptionID)
	roleDefinitions, err := l.collectAllRoleDefinitionsSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect role definitions via SDK", "subscription", subscriptionID, "error", err)
		azurermData["azureRoleDefinitions"] = []interface{}{}
		l.logCollectionEnd("role definitions - " + subscriptionID, startTime, 0)
	} else {
		azurermData["azureRoleDefinitions"] = roleDefinitions
		l.logCollectionEnd("role definitions - " + subscriptionID, startTime, len(roleDefinitions))
	}

	// Skip Key Vault access policies collection for now (as in original)
	azurermData["keyVaultAccessPolicies"] = []interface{}{}

	// Calculate total resource counts for final summary
	totalItems := len(preCollectedResources) + len(preCollectedResourceGroups) + len(roleDefinitions)
	l.logCollectionEnd("Azure RM Data (Optimized) - " + subscriptionID, overallStart, totalItems)
	return azurermData, nil
}

// collectAllGraphDataSDKOptimized collects all Azure AD data using Microsoft Graph SDK with parallel processing optimizations
func (l *SDKComprehensiveCollectorLink) collectAllGraphDataSDKOptimized() (map[string]interface{}, error) {
	azureADData := make(map[string]interface{})
	ctx := l.Context()

	overallStart := l.logCollectionStart("Azure AD Graph SDK Collection (Optimized)")
	l.Logger.Info("Starting parallel Graph SDK data collection")
	message.Info("Collecting Azure AD data with parallel processing...")

	// OPTIMIZATION: Collect independent data types in parallel
	type collectionResult struct {
		name string
		data []interface{}
		err  error
	}

	// Channel to collect results
	resultChan := make(chan collectionResult, 9)

	// Start all independent collections in parallel
	collections := []struct {
		name string
		fn   func(context.Context) ([]interface{}, error)
	}{
		{"users", l.collectAllUsersWithPagination},
		{"groups", l.collectAllGroupsWithPagination},
		{"servicePrincipals", l.collectAllServicePrincipalsWithPagination},
		{"applications", l.collectAllApplicationsWithPagination},
		{"devices", l.collectAllDevicesWithPagination},
		{"directoryRoles", l.collectAllDirectoryRolesWithPagination},
		{"roleDefinitions", l.collectAllRoleDefinitionsWithPagination},
		{"conditionalAccessPolicies", l.collectAllConditionalAccessPoliciesWithPagination},
		{"oauth2PermissionGrants", l.collectAllOAuth2PermissionGrantsWithPagination},
	}

	// Launch goroutines for independent collections (with controlled concurrency)
	semaphore := make(chan struct{}, 3) // Limit to 3 concurrent Graph API collections
	var wg sync.WaitGroup

	for _, collection := range collections {
		wg.Add(1)
		go func(name string, fn func(context.Context) ([]interface{}, error)) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			startTime := l.logCollectionStart(name + " (parallel)")
			data, err := fn(ctx)
			if err != nil {
				l.logCollectionEnd(name + " (parallel)", startTime, 0)
			} else {
				l.logCollectionEnd(name + " (parallel)", startTime, len(data))
			}
			resultChan <- collectionResult{name: name, data: data, err: err}
		}(collection.name, collection.fn)
	}

	// Close result channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results from parallel operations
	for result := range resultChan {
		if result.err != nil {
			l.Logger.Error("Failed to collect data type", "type", result.name, "error", result.err)
			azureADData[result.name] = []interface{}{} // Empty array on error
		} else {
			azureADData[result.name] = result.data
			l.Logger.Info("Completed parallel collection", "type", result.name, "items", len(result.data))
		}
	}

	// DEPENDENT COLLECTIONS: These require data from above collections and use batching
	// Collection: Directory role assignments (depends on directory roles - BATCHED)
	startTime := l.logCollectionStart("directoryRoleAssignments (batched)")
	directoryRoleAssignments, err := l.collectAllDirectoryRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory role assignments via SDK", "error", err)
		azureADData["directoryRoleAssignments"] = []interface{}{}
		l.logCollectionEnd("directoryRoleAssignments (batched)", startTime, 0)
	} else {
		azureADData["directoryRoleAssignments"] = directoryRoleAssignments
		l.logCollectionEnd("directoryRoleAssignments (batched)", startTime, len(directoryRoleAssignments))
	}

	// Collection: Group Memberships (depends on groups - BATCHED)
	startTime = l.logCollectionStart("groupMemberships (batched)")
	groupMemberships, err := l.collectAllGroupMembershipsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect group memberships via SDK", "error", err)
		azureADData["groupMemberships"] = []interface{}{}
		l.logCollectionEnd("groupMemberships (batched)", startTime, 0)
	} else {
		azureADData["groupMemberships"] = groupMemberships
		l.logCollectionEnd("groupMemberships (batched)", startTime, len(groupMemberships))
	}

	// Collection: App role assignments (depends on service principals - BATCHED)
	startTime = l.logCollectionStart("appRoleAssignments (batched)")
	appRoleAssignments, err := l.collectAllAppRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect app role assignments via SDK", "error", err)
		azureADData["appRoleAssignments"] = []interface{}{}
		l.logCollectionEnd("appRoleAssignments (batched)", startTime, 0)
	} else {
		azureADData["appRoleAssignments"] = appRoleAssignments
		l.logCollectionEnd("appRoleAssignments (batched)", startTime, len(appRoleAssignments))
	}

	// Calculate total resource counts for final summary
	var totalItems int
	for _, data := range azureADData {
		if slice, ok := data.([]interface{}); ok {
			totalItems += len(slice)
		}
	}

	l.logCollectionEnd("Azure AD Graph SDK Collection (Optimized)", overallStart, totalItems)
	message.Info("Azure AD data collection completed with parallel processing and batching!")
	return azureADData, nil
}