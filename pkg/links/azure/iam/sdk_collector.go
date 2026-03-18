package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/google/uuid"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/rolemanagement"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// SDKComprehensiveCollectorLink collects comprehensive Azure IAM data using Azure SDKs
// Uses standard Azure authentication (az login) instead of refresh token approach
type SDKComprehensiveCollectorLink struct {
	*chain.Base

	// Azure SDK clients
	graphClient          *msgraphsdk.GraphServiceClient
	subscriptionClient   *armsubscriptions.Client
	roleDefClient        *armauthorization.RoleDefinitionsClient
	resourceGraphClient  *armresourcegraph.Client
	managementGroupClient *armmanagementgroups.Client
	resourceClient       *armresources.Client

	// HTTP client for batch operations
	httpClient *http.Client

	// Credential for all SDK clients
	credential azidentity.DefaultAzureCredential
}

func NewSDKComprehensiveCollectorLink(configs ...cfg.Config) chain.Link {
	l := &SDKComprehensiveCollectorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *SDKComprehensiveCollectorLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

// writeCheckpoint writes intermediate collection data to disk for progress tracking
func (l *SDKComprehensiveCollectorLink) writeCheckpoint(name string, data interface{}) {
	outputDir, err := cfg.As[string](l.Arg("output"))
	if err != nil || outputDir == "" {
		outputDir = "nebula-output"
	}
	checkpointDir := filepath.Join(outputDir, "checkpoints")
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		l.Logger.Error("Failed to create checkpoint directory", "error", err)
		return
	}

	filePath := filepath.Join(checkpointDir, name)
	tmpPath := filePath + ".tmp"

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		l.Logger.Error("Failed to marshal checkpoint", "name", name, "error", err)
		return
	}

	if err := os.WriteFile(tmpPath, jsonData, 0644); err != nil {
		l.Logger.Error("Failed to write checkpoint", "name", name, "error", err)
		return
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		l.Logger.Error("Failed to finalize checkpoint", "name", name, "error", err)
		return
	}

	l.Logger.Info("Checkpoint saved", "name", name, "items", countCheckpointItems(data), "bytes", len(jsonData))
}

// normalizeScope normalizes an Azure scope string for consistent comparison.
// Azure scopes are case-insensitive but APIs return inconsistent casing
// (e.g., "resourceGroups" vs "resourcegroups"). This lowercases the entire
// scope and trims trailing slashes so all downstream comparisons work.
func normalizeScope(scope string) string {
	return strings.ToLower(strings.TrimRight(scope, "/"))
}

// countCheckpointItems returns the item count for checkpoint logging
func countCheckpointItems(data interface{}) int {
	switch v := data.(type) {
	case []interface{}:
		return len(v)
	case map[string]interface{}:
		return len(v)
	default:
		return 1
	}
}

func (l *SDKComprehensiveCollectorLink) Process(input interface{}) error {
	// Get parameters
	subscriptions, _ := cfg.As[[]string](l.Arg("subscription"))

	l.Logger.Info("Starting comprehensive Azure IAM collection via SDKs", "subscriptions_input", subscriptions)

	// Initialize Azure SDK clients with standard authentication
	if err := l.initializeSDKClients(); err != nil {
		return fmt.Errorf("failed to initialize SDK clients: %v", err)
	}

	// Handle subscription discovery
	var subscriptionIDs []string
	if len(subscriptions) == 0 || (len(subscriptions) == 1 && strings.EqualFold(subscriptions[0], "all")) {
		l.Logger.Info("Discovering subscriptions using SDK")

		allSubs, err := l.listSubscriptionsWithSDK()
		if err != nil {
			l.Logger.Error("Failed to list subscriptions", "error", err)
			return err
		}

		subscriptionIDs = allSubs
		l.Logger.Info("Found subscriptions", "count", len(subscriptionIDs))
	} else {
		// Use the provided subscriptions
		subscriptionIDs = subscriptions
		l.Logger.Info("Using provided subscriptions", "subscriptions", subscriptionIDs)
	}

	// Get tenant ID from current context
	ctx := l.Context()
	tenantID, err := l.getTenantIDFromContext(ctx)
	if err != nil {
		l.Logger.Error("Failed to get tenant ID", "error", err)
		return fmt.Errorf("failed to get tenant ID: %v", err)
	}

	// STEP 1: Collect Azure AD data ONCE for the entire tenant
	l.Logger.Info("Collecting Azure AD data via Graph SDK (once for all subscriptions)")
	message.Info("Collecting Azure AD data via Graph SDK...")

	azureADData, err := l.collectAllGraphDataSDKOptimized()
	if err != nil {
		l.Logger.Error("Failed to collect Graph SDK data", "error", err)
		return err
	}

	message.Info("Graph SDK collector completed successfully! Collected %d object types", len(azureADData))

	// STEP 2: Collect PIM data ONCE for the entire tenant using Graph SDK
	l.Logger.Info("Collecting PIM data via Graph SDK (once for all subscriptions)")
	message.Info("Collecting PIM data via Graph SDK...")

	pimData, err := l.collectAllPIMDataSDK()
	if err != nil {
		l.Logger.Error("Failed to collect PIM data via SDK", "error", err)
		return err
	}

	message.Info("PIM SDK collector completed successfully! Collected %d assignment types", len(pimData))
	if eligible, ok := pimData["eligible_assignments"]; ok {
		l.writeCheckpoint("15-pim-eligible.json", eligible)
	}
	if active, ok := pimData["active_assignments"]; ok {
		l.writeCheckpoint("16-pim-active.json", active)
	}

	// STEP 3: Collect Management Groups hierarchy using SDK
	l.Logger.Info("Collecting Management Groups hierarchy via SDK")
	message.Info("Collecting Management Groups hierarchy via SDK...")

	managementGroupsData, err := l.getManagementGroupHierarchyViaARG(tenantID)
	if err != nil {
		l.Logger.Warn("Failed to collect Management Groups data via ARG, continuing without it", "error", err)
		message.Info("Warning: Failed to collect Management Groups data: %v", err)
		managementGroupsData = []interface{}{}
	}

	message.Info("Management Groups SDK collector completed! Collected %d management groups", len(managementGroupsData))
	l.writeCheckpoint("17-management-groups.json", managementGroupsData)

	// STEP 3.5: Collect management group and tenant-scoped RBAC assignments (once per tenant)
	l.Logger.Info("Collecting management group and tenant RBAC assignments via ARG")
	message.Info("Collecting management group/tenant RBAC assignments...")

	mgRBACData, err := l.collectManagementGroupAndTenantRBAC()
	if err != nil {
		l.Logger.Warn("Failed to collect MG/tenant RBAC, continuing without it", "error", err)
		message.Info("Warning: Failed to collect MG/tenant RBAC: %v", err)
		mgRBACData = []interface{}{}
	}

	message.Info("MG/tenant RBAC collection completed! Collected %d assignments", len(mgRBACData))
	l.writeCheckpoint("17b-mg-tenant-rbac.json", mgRBACData)

	// STEP 4: Process subscriptions using optimized batched SDK clients
	l.Logger.Info("Processing %d subscriptions with optimized batched SDK clients", len(subscriptionIDs))
	allSubscriptionData := l.processSubscriptionsOptimizedSDK(subscriptionIDs)

	// Create consolidated data structure (exact same format as HTTP version)
	consolidatedData := map[string]interface{}{
		"collection_metadata": map[string]interface{}{
			"tenant_id":               tenantID,
			"collection_timestamp":    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"subscriptions_processed": len(subscriptionIDs),
			"collector_versions": map[string]interface{}{
				"nebula_collector": "comprehensive_sdk",
				"graph_collector":     "sdk_completed",
				"pim_collector":       "sdk_completed",
				"azurerm_collector":   "sdk_completed",
			},
		},
		"azure_ad":              azureADData,
		"pim":                   pimData,
		"management_groups":     managementGroupsData,
		"management_group_rbac": mgRBACData,
		"azure_resources":       allSubscriptionData,
	}

	// Calculate totals for summary (same logic as HTTP version)
	adTotal := 0
	for _, data := range azureADData {
		if dataSlice, ok := data.([]interface{}); ok {
			adTotal += len(dataSlice)
		}
	}

	pimTotal := 0
	for _, data := range pimData {
		if dataSlice, ok := data.([]interface{}); ok {
			pimTotal += len(dataSlice)
		}
	}

	azurermTotal := 0
	for _, subData := range allSubscriptionData {
		if subDataMap, ok := subData.(map[string]interface{}); ok {
			for _, data := range subDataMap {
				if dataSlice, ok := data.([]interface{}); ok {
					azurermTotal += len(dataSlice)
				}
			}
		}
	}

	managementGroupsTotal := len(managementGroupsData)
	mgRBACTotal := len(mgRBACData)

	// Add summary metadata
	consolidatedData["collection_metadata"].(map[string]interface{})["data_summary"] = map[string]interface{}{
		"total_azure_ad_objects":     adTotal,
		"total_pim_objects":          pimTotal,
		"total_management_groups":    managementGroupsTotal,
		"total_mg_rbac_assignments":  mgRBACTotal,
		"total_azurerm_objects":      azurermTotal,
		"total_objects":              adTotal + pimTotal + managementGroupsTotal + mgRBACTotal + azurermTotal,
	}

	message.Info("=== Azure IAM Collection Summary (SDK) ====")
	message.Info("Tenant: %s", tenantID)
	message.Info("Total Azure AD objects: %d", adTotal)
	message.Info("Total PIM objects: %d", pimTotal)
	message.Info("Total Management Groups: %d", managementGroupsTotal)
	message.Info("Total MG/tenant RBAC assignments: %d", mgRBACTotal)
	message.Info("Total AzureRM objects: %d", azurermTotal)
	message.Info("🎉 Azure IAM SDK collection completed successfully!")

	// Send consolidated data to outputter
	l.Send(consolidatedData)
	return nil
}

// initializeSDKClients initializes all Azure SDK clients with standard authentication
func (l *SDKComprehensiveCollectorLink) initializeSDKClients() error {
	// Use standard Azure SDK authentication (az login)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get default Azure credentials: %v", err)
	}

	l.credential = *cred

	// Initialize Microsoft Graph SDK client
	l.graphClient, err = msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return fmt.Errorf("failed to create Graph SDK client: %v", err)
	}

	// Initialize Azure Resource Manager SDK clients
	l.subscriptionClient, err = armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create subscriptions client: %v", err)
	}

	// Note: Authorization client will be created per subscription in collectAllRoleAssignmentsSDK
	// since it requires subscription ID in constructor

	l.roleDefClient, err = armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create role definitions client: %v", err)
	}

	l.resourceGraphClient, err = armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create resource graph client: %v", err)
	}

	l.managementGroupClient, err = armmanagementgroups.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create management groups client: %v", err)
	}

	l.resourceClient, err = armresources.NewClient("", cred, nil) // subscription set per call
	if err != nil {
		return fmt.Errorf("failed to create resources client: %v", err)
	}

	// Initialize HTTP client for batch operations
	l.httpClient = &http.Client{
		Timeout: 120 * time.Second, // Increased timeout for batch operations
	}

	l.Logger.Info("Successfully initialized all Azure SDK clients and HTTP client")
	return nil
}

// getTenantIDFromContext gets the tenant ID from the current authentication context
func (l *SDKComprehensiveCollectorLink) getTenantIDFromContext(ctx context.Context) (string, error) {
	// Use Graph API to get the organization details which includes tenant ID
	orgResponse, err := l.graphClient.Organization().Get(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get organization details: %v", err)
	}

	orgs := orgResponse.GetValue()
	if len(orgs) == 0 {
		return "", fmt.Errorf("no organization found in current context")
	}

	tenantID := *orgs[0].GetId()
	l.Logger.Info("Retrieved tenant ID from context", "tenant_id", tenantID)
	return tenantID, nil
}

// getAccessToken gets an access token for Microsoft Graph API using the credential
func (l *SDKComprehensiveCollectorLink) getAccessToken(ctx context.Context) (string, error) {
	// Create a new credential instance for token generation
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create credential for token: %v", err)
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %v", err)
	}
	return token.Token, nil
}

// callGraphBatchAPI makes batch Graph API call using HTTP client with retry logic
func (l *SDKComprehensiveCollectorLink) callGraphBatchAPI(ctx context.Context, accessToken string, requests []map[string]interface{}) (map[string]interface{}, error) {
	batchURL := "https://graph.microsoft.com/v1.0/$batch"

	batchPayload := map[string]interface{}{
		"requests": requests,
	}

	batchPayloadJSON, err := json.Marshal(batchPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch payload: %v", err)
	}

	// Implement retry logic for transient failures
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", batchURL, strings.NewReader(string(batchPayloadJSON)))
		if err != nil {
			return nil, fmt.Errorf("failed to create batch request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Nebula-IAM-Collector/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("batch request failed after %d attempts: %v", maxRetries, err)
			}
			l.Logger.Debug("Batch request attempt failed, retrying", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond) // Exponential backoff
			continue
		}
		// Handle rate limiting (429) and server errors (5xx) with retry
		if resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
			resp.Body.Close()
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("batch API call failed with status %d after %d attempts", resp.StatusCode, maxRetries)
			}
			l.Logger.Debug("Batch request rate limited or server error, retrying", "attempt", attempt+1, "status", resp.StatusCode)
			retryAfter := time.Second // Default retry delay
			if resp.StatusCode == 429 {
				// Check for Retry-After header
				if retryAfterHeader := resp.Header.Get("Retry-After"); retryAfterHeader != "" {
					if seconds, err := strconv.Atoi(retryAfterHeader); err == nil && seconds > 0 && seconds <= 60 {
						retryAfter = time.Duration(seconds) * time.Second
					}
				}
			}
			time.Sleep(retryAfter)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("batch API call failed with status %d", resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode batch response: %v", err)
		}

		return result, nil
	}

	return nil, fmt.Errorf("unexpected end of retry loop")
}

// batchWork represents a single batch of requests to execute
type batchWork struct {
	index    int
	requests []map[string]interface{}
}

// batchResult represents the result of a single batch execution
type batchResult struct {
	index     int
	responses []interface{}
	err       error
}

// executeBatchesConcurrently runs multiple batch API calls in parallel with W workers.
// Results are returned indexed by batchWork.index for ordered processing.
// Rate limiting is handled by callGraphBatchAPI's existing retry+429 logic.
func (l *SDKComprehensiveCollectorLink) executeBatchesConcurrently(
	ctx context.Context, accessToken string, batches []batchWork, maxWorkers int,
) []batchResult {
	if maxWorkers < 1 {
		maxWorkers = 5
	}

	results := make([]batchResult, len(batches))
	workChan := make(chan batchWork, len(batches))
	var wg sync.WaitGroup

	// Feed work
	for _, b := range batches {
		workChan <- b
	}
	close(workChan)

	// Spawn workers
	var completed int64
	totalBatches := int64(len(batches))
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				batchResponse, err := l.callGraphBatchAPI(ctx, accessToken, work.requests)
				n := atomic.AddInt64(&completed, 1)
				if n%50 == 0 || n == totalBatches {
					l.Logger.Info("Concurrent batch progress", "completed", n, "total", totalBatches)
				}
				if err != nil {
					results[work.index] = batchResult{index: work.index, err: err}
					continue
				}

				responses, _ := batchResponse["responses"].([]interface{})
				results[work.index] = batchResult{index: work.index, responses: responses}
			}
		}()
	}

	wg.Wait()
	return results
}

// followPaginationLink follows @odata.nextLink pagination for individual Graph API responses.
// Used when a batch response item has more results than fit in a single page (>100 items).
func (l *SDKComprehensiveCollectorLink) followPaginationLink(ctx context.Context, accessToken string, nextLink string) []interface{} {
	var allItems []interface{}

	for nextLink != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextLink, nil)
		if err != nil {
			l.Logger.Debug("Failed to create pagination request", "error", err)
			break
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			l.Logger.Debug("Pagination request failed", "error", err)
			break
		}

		if resp.StatusCode == 429 {
			// Rate limited — wait and retry
			resp.Body.Close()
			retryAfter := time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, err := strconv.Atoi(ra); err == nil && seconds > 0 && seconds <= 60 {
					retryAfter = time.Duration(seconds) * time.Second
				}
			}
			l.Logger.Info("Pagination rate limited", "retryAfter", retryAfter)
			time.Sleep(retryAfter)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			l.Logger.Debug("Pagination request returned non-200", "status", resp.StatusCode)
			break
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			l.Logger.Debug("Failed to decode pagination response", "error", err)
			break
		}
		resp.Body.Close()

		if value, ok := result["value"].([]interface{}); ok {
			allItems = append(allItems, value...)
		}

		// Check for next page
		if nl, ok := result["@odata.nextLink"].(string); ok && nl != "" {
			nextLink = nl
		} else {
			break
		}
	}

	return allItems
}

// filterSPDirectoryRolesFromExisting filters directoryRoleAssignments to find those
// where the principal is a service principal. This replaces the expensive memberOf scan.
func (l *SDKComprehensiveCollectorLink) filterSPDirectoryRolesFromExisting(
	directoryRoleAssignments []interface{}, servicePrincipals []interface{},
) []interface{} {
	spIDs := make(map[string]bool, len(servicePrincipals))
	for _, sp := range servicePrincipals {
		if spMap, ok := sp.(map[string]interface{}); ok {
			if id, ok := spMap["id"].(string); ok {
				spIDs[id] = true
			}
		}
	}

	var filtered []interface{}
	for _, a := range directoryRoleAssignments {
		if aMap, ok := a.(map[string]interface{}); ok {
			if pid, ok := aMap["principalId"].(string); ok && spIDs[pid] {
				filtered = append(filtered, a)
			}
		}
	}
	l.Logger.Info("Filtered SP directory roles from existing assignments", "spCount", len(spIDs), "matched", len(filtered))
	return filtered
}

// performanceMetrics tracks collection performance for benchmarking
type performanceMetrics struct {
	collectionName string
	startTime      time.Time
	endTime        time.Time
	itemCount      int
	duration       time.Duration
}

// logCollectionStart logs the start of a collection with timing
func (l *SDKComprehensiveCollectorLink) logCollectionStart(collectionName string) time.Time {
	startTime := time.Now()
	l.Logger.Info("Starting collection", "collection", collectionName, "startTime", startTime.Format(time.RFC3339))
	return startTime
}

// logCollectionEnd logs the end of a collection with timing and metrics
func (l *SDKComprehensiveCollectorLink) logCollectionEnd(collectionName string, startTime time.Time, itemCount int) {
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	l.Logger.Info("Completed collection",
		"collection", collectionName,
		"startTime", startTime.Format(time.RFC3339),
		"endTime", endTime.Format(time.RFC3339),
		"duration", duration.String(),
		"itemCount", itemCount,
		"itemsPerSecond", fmt.Sprintf("%.2f", float64(itemCount)/duration.Seconds()))

	// Debug-level detailed metrics
	l.Logger.Debug("Collection performance metrics",
		"collection", collectionName,
		"durationMs", duration.Milliseconds(),
		"durationSeconds", fmt.Sprintf("%.3f", duration.Seconds()),
		"itemCount", itemCount,
		"avgTimePerItem", (duration / time.Duration(max(itemCount, 1))).String())
}

// logBatchStart logs the start of a batch operation
func (l *SDKComprehensiveCollectorLink) logBatchStart(collectionName string, batchNumber, totalBatches int) time.Time {
	startTime := time.Now()
	l.Logger.Debug("Starting batch",
		"collection", collectionName,
		"batch", fmt.Sprintf("%d/%d", batchNumber, totalBatches),
		"startTime", startTime.Format(time.RFC3339Nano))
	return startTime
}

// logBatchEnd logs the end of a batch operation
func (l *SDKComprehensiveCollectorLink) logBatchEnd(collectionName string, batchNumber, totalBatches int, startTime time.Time, itemCount int) {
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	l.Logger.Debug("Completed batch",
		"collection", collectionName,
		"batch", fmt.Sprintf("%d/%d", batchNumber, totalBatches),
		"duration", duration.String(),
		"itemCount", itemCount,
		"batchItemsPerSecond", fmt.Sprintf("%.2f", float64(itemCount)/duration.Seconds()))
}

// max helper function for avoiding division by zero
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// createOptimizedRequestConfig creates request configuration with $select parameters for better performance
func (l *SDKComprehensiveCollectorLink) createOptimizedRequestConfig(selectFields []string) interface{} {
	if len(selectFields) == 0 {
		return nil
	}

	// For now, return nil and add query parameters in future optimization
	// The SDK will use default configuration which is sufficient for the batching improvements
	return nil
}

// listSubscriptionsWithSDK lists subscriptions using the subscriptions SDK client
func (l *SDKComprehensiveCollectorLink) listSubscriptionsWithSDK() ([]string, error) {
	ctx := l.Context()

	pager := l.subscriptionClient.NewListPager(nil)
	var subscriptionIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get subscriptions page: %v", err)
		}

		for _, sub := range page.Value {
			if sub.SubscriptionID != nil && sub.State != nil &&
			   *sub.State == armsubscriptions.SubscriptionStateEnabled {
				subscriptionIDs = append(subscriptionIDs, *sub.SubscriptionID)
			}
		}
	}

	return subscriptionIDs, nil
}

// collectAllGraphDataSDK collects all Azure AD data using Microsoft Graph SDK
func (l *SDKComprehensiveCollectorLink) collectAllGraphDataSDK() (map[string]interface{}, error) {
	azureADData := make(map[string]interface{})
	collectionErrors := make(map[string]string)
	ctx := l.Context()

	overallStart := l.logCollectionStart("Azure AD Graph SDK Collection")
	l.Logger.Info("Collecting Azure AD objects via Graph SDK")

	// Collection 1: Users (with pagination)
	startTime := l.logCollectionStart("users")
	message.Info("Collecting users from Graph SDK...")

	users, err := l.collectAllUsersWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect users via paginated SDK", "error", err)
		azureADData["users"] = []interface{}{} // Empty array on error
		collectionErrors["users"] = err.Error()
		l.logCollectionEnd("users", startTime, 0)
	} else {
		azureADData["users"] = users
		l.logCollectionEnd("users", startTime, len(users))
		l.writeCheckpoint("01-users.json", users)
	}

	// Collection 2: Groups (with pagination)
	startTime = l.logCollectionStart("groups")
	message.Info("Collecting groups from Graph SDK...")

	groups, err := l.collectAllGroupsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect groups via paginated SDK", "error", err)
		azureADData["groups"] = []interface{}{} // Empty array on error
		collectionErrors["groups"] = err.Error()
		l.logCollectionEnd("groups", startTime, 0)
	} else {
		azureADData["groups"] = groups
		l.logCollectionEnd("groups", startTime, len(groups))
		l.writeCheckpoint("02-groups.json", groups)
	}

	// Collection 3: Service Principals (with pagination)
	startTime = l.logCollectionStart("servicePrincipals")
	message.Info("Collecting service principals from Graph SDK...")

	servicePrincipals, err := l.collectAllServicePrincipalsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect service principals via paginated SDK", "error", err)
		azureADData["servicePrincipals"] = []interface{}{} // Empty array on error
		collectionErrors["servicePrincipals"] = err.Error()
		l.logCollectionEnd("servicePrincipals", startTime, 0)
	} else {
		azureADData["servicePrincipals"] = servicePrincipals
		l.logCollectionEnd("servicePrincipals", startTime, len(servicePrincipals))
		l.writeCheckpoint("03-service-principals.json", servicePrincipals)
	}

	// Collection 4: Applications (with pagination)
	startTime = l.logCollectionStart("applications")
	message.Info("Collecting applications from Graph SDK...")

	applications, err := l.collectAllApplicationsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect applications via paginated SDK", "error", err)
		azureADData["applications"] = []interface{}{} // Empty array on error
		collectionErrors["applications"] = err.Error()
		l.logCollectionEnd("applications", startTime, 0)
	} else {
		azureADData["applications"] = applications
		l.logCollectionEnd("applications", startTime, len(applications))
		l.writeCheckpoint("04-applications.json", applications)
	}

	// Collection 5: Devices (with pagination)
	startTime = l.logCollectionStart("devices")
	message.Info("Collecting devices from Graph SDK...")

	devices, err := l.collectAllDevicesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect devices via paginated SDK", "error", err)
		azureADData["devices"] = []interface{}{} // Empty array on error
		collectionErrors["devices"] = err.Error()
		l.logCollectionEnd("devices", startTime, 0)
	} else {
		azureADData["devices"] = devices
		l.logCollectionEnd("devices", startTime, len(devices))
		l.writeCheckpoint("05-devices.json", devices)
	}

	// Collection 6: Directory Roles (with pagination)
	startTime = l.logCollectionStart("directoryRoles")
	message.Info("Collecting directory roles from Graph SDK...")

	directoryRoles, err := l.collectAllDirectoryRolesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory roles via paginated SDK", "error", err)
		azureADData["directoryRoles"] = []interface{}{} // Empty array on error
		collectionErrors["directoryRoles"] = err.Error()
		l.logCollectionEnd("directoryRoles", startTime, 0)
	} else {
		azureADData["directoryRoles"] = directoryRoles
		l.logCollectionEnd("directoryRoles", startTime, len(directoryRoles))
		l.writeCheckpoint("06-directory-roles.json", directoryRoles)
	}

	// Collection 7: Role Definitions (with pagination)
	startTime = l.logCollectionStart("roleDefinitions")
	message.Info("Collecting role definitions from Graph SDK...")

	roleDefinitions, err := l.collectAllRoleDefinitionsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect role definitions via paginated SDK", "error", err)
		azureADData["roleDefinitions"] = []interface{}{} // Empty array on error
		collectionErrors["roleDefinitions"] = err.Error()
		l.logCollectionEnd("roleDefinitions", startTime, 0)
	} else {
		azureADData["roleDefinitions"] = roleDefinitions
		l.logCollectionEnd("roleDefinitions", startTime, len(roleDefinitions))
		l.writeCheckpoint("07-role-definitions-entra.json", roleDefinitions)
	}

	// Collection 8: Conditional Access Policies (with pagination)
	startTime = l.logCollectionStart("conditionalAccessPolicies")
	message.Info("Collecting conditional access policies from Graph SDK...")

	conditionalAccessPolicies, err := l.collectAllConditionalAccessPoliciesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect conditional access policies via paginated SDK", "error", err)
		azureADData["conditionalAccessPolicies"] = []interface{}{} // Empty array on error
		collectionErrors["conditionalAccessPolicies"] = err.Error()
		l.logCollectionEnd("conditionalAccessPolicies", startTime, 0)
	} else {
		azureADData["conditionalAccessPolicies"] = conditionalAccessPolicies
		l.logCollectionEnd("conditionalAccessPolicies", startTime, len(conditionalAccessPolicies))
		l.writeCheckpoint("08-conditional-access.json", conditionalAccessPolicies)
	}

	// Collection 8b: Named Locations (used by CA policies)
	startTime = l.logCollectionStart("namedLocations")
	message.Info("Collecting named locations from Graph SDK...")
	namedLocations, err := l.collectAllNamedLocationsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect named locations via paginated SDK", "error", err)
		azureADData["namedLocations"] = []interface{}{} // Empty array on error
		collectionErrors["namedLocations"] = err.Error()
		l.logCollectionEnd("namedLocations", startTime, 0)
	} else {
		azureADData["namedLocations"] = namedLocations
		l.logCollectionEnd("namedLocations", startTime, len(namedLocations))
		l.writeCheckpoint("08b-named-locations.json", namedLocations)
	}

	// Collection 8c: Administrative Units
	startTime = l.logCollectionStart("administrativeUnits")
	message.Info("Collecting administrative units from Graph SDK...")
	administrativeUnits, err := l.collectAllAdministrativeUnitsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect administrative units via paginated SDK", "error", err)
		azureADData["administrativeUnits"] = []interface{}{} // Empty array on error
		collectionErrors["administrativeUnits"] = err.Error()
		l.logCollectionEnd("administrativeUnits", startTime, 0)
	} else {
		azureADData["administrativeUnits"] = administrativeUnits
		l.logCollectionEnd("administrativeUnits", startTime, len(administrativeUnits))
		l.writeCheckpoint("08c-administrative-units.json", administrativeUnits)
	}

	// Collection 9: Directory Role Assignments (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("directoryRoleAssignments")
	message.Info("Collecting directory role assignments from Graph SDK...")
	directoryRoleAssignments, err := l.collectAllDirectoryRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory role assignments via paginated SDK", "error", err)
		azureADData["directoryRoleAssignments"] = []interface{}{} // Empty array on error
		collectionErrors["directoryRoleAssignments"] = err.Error()
		l.logCollectionEnd("directoryRoleAssignments", startTime, 0)
	} else {
		azureADData["directoryRoleAssignments"] = directoryRoleAssignments
		l.logCollectionEnd("directoryRoleAssignments", startTime, len(directoryRoleAssignments))
		l.writeCheckpoint("10-directory-role-assignments.json", directoryRoleAssignments)
	}

	// Collection 9b: Service Principal Directory Roles
	// Use memberOf workaround to discover SP role assignments that /directoryRoles/{id}/members silently omits
	startTime = l.logCollectionStart("spDirectoryRoles")
	message.Info("Collecting SP directory roles via memberOf workaround...")
	spDirectoryRoles, spDirRolesErr := l.collectServicePrincipalDirectoryRolesSDK(servicePrincipals)
	if spDirRolesErr != nil {
		l.Logger.Error("Failed to collect SP directory roles via memberOf", "error", spDirRolesErr)
	}
	if len(spDirectoryRoles) > 0 {
		// Merge into existing directoryRoleAssignments, deduplicating by principalId+roleId
		existing := azureADData["directoryRoleAssignments"].([]interface{})
		seen := make(map[string]bool)
		for _, a := range existing {
			if m, ok := a.(map[string]interface{}); ok {
				key := fmt.Sprintf("%v-%v", m["principalId"], m["roleId"])
				seen[key] = true
			}
		}
		added := 0
		for _, a := range spDirectoryRoles {
			if m, ok := a.(map[string]interface{}); ok {
				key := fmt.Sprintf("%v-%v", m["principalId"], m["roleId"])
				if !seen[key] {
					existing = append(existing, a)
					seen[key] = true
					added++
				}
			}
		}
		azureADData["directoryRoleAssignments"] = existing
		l.Logger.Info("Merged SP directory role assignments", "new_from_memberOf", added, "total", len(existing))
	}
	l.logCollectionEnd("spDirectoryRoles", startTime, len(spDirectoryRoles))
	l.writeCheckpoint("13-sp-directory-roles.json", azureADData["directoryRoleAssignments"])

	// Collection 10: Group Memberships (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("groupMemberships")
	message.Info("Collecting group memberships from Graph SDK...")
	groupMemberships, err := l.collectAllGroupMembershipsWithPagination(ctx, groups)
	if err != nil {
		l.Logger.Error("Failed to collect group memberships via SDK", "error", err)
		azureADData["groupMemberships"] = []interface{}{} // Empty array on error
		collectionErrors["groupMemberships"] = err.Error()
		l.logCollectionEnd("groupMemberships", startTime, 0)
	} else {
		azureADData["groupMemberships"] = groupMemberships
		l.logCollectionEnd("groupMemberships", startTime, len(groupMemberships))
		l.writeCheckpoint("11-group-memberships.json", groupMemberships)
	}

	// Collection 11: OAuth2 Permission Grants (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("oauth2PermissionGrants")
	message.Info("Collecting OAuth2 permission grants from Graph SDK...")
	oauth2Grants, err := l.collectAllOAuth2PermissionGrantsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect OAuth2 permission grants via SDK", "error", err)
		azureADData["oauth2PermissionGrants"] = []interface{}{} // Empty array on error
		collectionErrors["oauth2PermissionGrants"] = err.Error()
		l.logCollectionEnd("oauth2PermissionGrants", startTime, 0)
	} else {
		azureADData["oauth2PermissionGrants"] = oauth2Grants
		l.logCollectionEnd("oauth2PermissionGrants", startTime, len(oauth2Grants))
		l.writeCheckpoint("09-oauth2-permission-grants.json", oauth2Grants)
	}

	// Collection 12: App Role Assignments (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("appRoleAssignments")
	message.Info("Collecting app role assignments from Graph SDK...")
	appRoleAssignments, err := l.collectAllAppRoleAssignmentsWithPagination(ctx, servicePrincipals)
	if err != nil {
		l.Logger.Error("Failed to collect app role assignments via SDK", "error", err)
		azureADData["appRoleAssignments"] = []interface{}{} // Empty array on error
		collectionErrors["appRoleAssignments"] = err.Error()
		l.logCollectionEnd("appRoleAssignments", startTime, 0)
	} else {
		azureADData["appRoleAssignments"] = appRoleAssignments
		l.logCollectionEnd("appRoleAssignments", startTime, len(appRoleAssignments))
		l.writeCheckpoint("12-app-role-assignments.json", appRoleAssignments)
	}

	// Collection 13: Group Ownership (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("groupOwnership")
	message.Info("Collecting group ownership from Graph SDK...")
	groupOwnership, err := l.collectGroupOwnershipSDK(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect group ownership via SDK", "error", err)
		azureADData["groupOwnership"] = []interface{}{} // Empty array on error
		collectionErrors["groupOwnership"] = err.Error()
		l.logCollectionEnd("groupOwnership", startTime, 0)
	} else {
		azureADData["groupOwnership"] = groupOwnership
		l.logCollectionEnd("groupOwnership", startTime, len(groupOwnership))
		l.writeCheckpoint("14a-group-ownership.json", groupOwnership)
	}

	// Collection 14: Service Principal Ownership (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("servicePrincipalOwnership")
	message.Info("Collecting service principal ownership from Graph SDK...")
	servicePrincipalOwnership, err := l.collectServicePrincipalOwnershipSDK(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect service principal ownership via SDK", "error", err)
		azureADData["servicePrincipalOwnership"] = []interface{}{} // Empty array on error
		collectionErrors["servicePrincipalOwnership"] = err.Error()
		l.logCollectionEnd("servicePrincipalOwnership", startTime, 0)
	} else {
		azureADData["servicePrincipalOwnership"] = servicePrincipalOwnership
		l.logCollectionEnd("servicePrincipalOwnership", startTime, len(servicePrincipalOwnership))
		l.writeCheckpoint("14b-sp-ownership.json", servicePrincipalOwnership)
	}

	// Collection 15: Application Ownership (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("applicationOwnership")
	message.Info("Collecting application ownership from Graph SDK...")
	applicationOwnership, err := l.collectApplicationOwnershipSDK(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect application ownership via SDK", "error", err)
		azureADData["applicationOwnership"] = []interface{}{} // Empty array on error
		collectionErrors["applicationOwnership"] = err.Error()
		l.logCollectionEnd("applicationOwnership", startTime, 0)
	} else {
		azureADData["applicationOwnership"] = applicationOwnership
		l.logCollectionEnd("applicationOwnership", startTime, len(applicationOwnership))
		l.writeCheckpoint("14c-app-ownership.json", applicationOwnership)
	}

	// Collection 16: User Manager Relationships
	startTime = l.logCollectionStart("userManagers")
	message.Info("Collecting user manager relationships from Graph SDK...")
	l.enrichUsersWithManagerSDK(ctx, azureADData)
	l.logCollectionEnd("userManagers", startTime, 0)

	// Credential Enrichment (CRITICAL for iam-push compatibility)
	l.Logger.Info("Enriching applications with credential metadata")
	l.enrichApplicationsWithCredentialMetadataSDK(azureADData)
	l.writeCheckpoint("14-credential-enrichment.json", azureADData["applications"])

	l.Logger.Info("Enriching service principals with credential metadata")
	l.enrichServicePrincipalsWithCredentialMetadataSDK(azureADData)
	l.writeCheckpoint("14a-sp-credential-enrichment.json", azureADData["servicePrincipals"])

	// Calculate total resource counts for final summary
	totalItems := len(users) + len(groups) + len(servicePrincipals) + len(applications) + len(devices) +
			len(directoryRoles) + len(roleDefinitions) + len(conditionalAccessPolicies) +
			len(directoryRoleAssignments) + len(groupMemberships) + len(oauth2Grants) + len(appRoleAssignments) +
			len(groupOwnership) + len(servicePrincipalOwnership) + len(applicationOwnership)

	if len(collectionErrors) > 0 {
		azureADData["_collectionErrors"] = collectionErrors
		l.Logger.Warn("Some collections encountered errors", "failedCollections", len(collectionErrors))
		for key, errMsg := range collectionErrors {
			l.Logger.Warn("Collection error", "collection", key, "error", errMsg)
		}
	}

	l.logCollectionEnd("Azure AD Graph SDK Collection", overallStart, totalItems)
	return azureADData, nil
}

// collectGroupOwnershipSDK collects group ownership relationships using Graph SDK
// Produces output format identical to HTTP version for iam-push compatibility
func (l *SDKComprehensiveCollectorLink) collectGroupOwnershipSDK(ctx context.Context) ([]interface{}, error) {
	var ownerships []interface{}

	startTime := l.logCollectionStart("groupOwnership")
	l.Logger.Info("Collecting group ownership via Graph SDK batch API")

	// Get all groups first
	groupsResponse, err := l.graphClient.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups: %v", err)
	}

	groups := groupsResponse.GetValue()
	l.Logger.Info("Getting owners for groups", "count", len(groups))

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	// Process groups in batches of 10 (matching HTTP version batch size)
	batchSize := 10

	for i := 0; i < len(groups); i += batchSize {
		end := i + batchSize
		if end > len(groups) {
			end = len(groups)
		}
		batchGroups := groups[i:end]

		// Create batch requests for group owners
		var batchRequests []map[string]interface{}
		groupDataMap := make(map[string]map[string]interface{})

		for j, group := range batchGroups {
			if group == nil || group.GetId() == nil {
				continue
			}

			groupID := *group.GetId()
			groupName := ""
			if group.GetDisplayName() != nil {
				groupName = *group.GetDisplayName()
			}

			groupDataMap[fmt.Sprintf("group_%d", j)] = map[string]interface{}{
				"id":          groupID,
				"displayName": groupName,
			}

			// Add owners request (matching HTTP version URL)
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("group_%d_owners", j),
				"method": "GET",
				"url":    fmt.Sprintf("/groups/%s/owners?$select=id,displayName,userType,appId,mail,onPremisesSyncEnabled", groupID),
			})
		}

		// Execute batch request using existing callGraphBatchAPI method
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for group ownership", "error", err)
				continue
			}

			// Process batch results (matching HTTP version processing)
			if responses, ok := batchResults["responses"].([]interface{}); ok {
				for _, response := range responses {
					if respMap, ok := response.(map[string]interface{}); ok {
						if body, ok := respMap["body"].(map[string]interface{}); ok {
							if value, ok := body["value"].([]interface{}); ok {
								for _, owner := range value {
									if ownerMap, ok := owner.(map[string]interface{}); ok {
										ownerID, _ := ownerMap["id"].(string)

										// Extract group ID from request ID
										requestID, _ := respMap["id"].(string)
										groupIndex := strings.Replace(strings.Replace(requestID, "group_", "", 1), "_owners", "", 1)

										// Find corresponding group
										if groupData, exists := groupDataMap[fmt.Sprintf("group_%s", groupIndex)]; exists {
											groupID := groupData["id"].(string)
											groupName := groupData["displayName"].(string)

											// Output format MUST match HTTP version exactly
											ownership := map[string]interface{}{
												"groupId":        groupID,
												"groupName":      groupName,
												"ownerId":        ownerID,
												"ownerName":      ownerMap["displayName"],
												"ownerType":      ownerMap["@odata.type"],
												"permissionType": "GroupOwnership",
												"role":           "Owner",
											}
											ownerships = append(ownerships, ownership)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Add delay between batches (matching HTTP version)
		time.Sleep(200 * time.Millisecond)
	}

	l.logCollectionEnd("groupOwnership", startTime, len(ownerships))
	return ownerships, nil
}

// collectServicePrincipalOwnershipSDK collects service principal ownership relationships
// Produces output format identical to HTTP version for iam-push compatibility
func (l *SDKComprehensiveCollectorLink) collectServicePrincipalOwnershipSDK(ctx context.Context) ([]interface{}, error) {
	var ownerships []interface{}

	startTime := l.logCollectionStart("servicePrincipalOwnership")
	l.Logger.Info("Collecting service principal ownership via Graph SDK batch API")

	// Get all service principals first
	spResponse, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get service principals: %v", err)
	}

	servicePrincipals := spResponse.GetValue()
	l.Logger.Info("Getting owners for service principals", "count", len(servicePrincipals))

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	// Process service principals in batches of 10
	batchSize := 10

	for i := 0; i < len(servicePrincipals); i += batchSize {
		end := i + batchSize
		if end > len(servicePrincipals) {
			end = len(servicePrincipals)
		}
		batchSPs := servicePrincipals[i:end]

		// Create batch requests for SP owners
		var batchRequests []map[string]interface{}
		spDataMap := make(map[string]map[string]interface{})

		for j, sp := range batchSPs {
			if sp == nil || sp.GetId() == nil {
				continue
			}

			spID := *sp.GetId()
			spName := ""
			if sp.GetDisplayName() != nil {
				spName = *sp.GetDisplayName()
			}

			spDataMap[fmt.Sprintf("sp_%d", j)] = map[string]interface{}{
				"id":          spID,
				"displayName": spName,
			}

			// Add owners request
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("sp_%d_owners", j),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/owners?$select=id,displayName,userType,appId,mail,onPremisesSyncEnabled", spID),
			})
		}

		// Execute batch request
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for SP ownership", "error", err)
				continue
			}

			// Process batch results
			if responses, ok := batchResults["responses"].([]interface{}); ok {
				for _, response := range responses {
					if respMap, ok := response.(map[string]interface{}); ok {
						if body, ok := respMap["body"].(map[string]interface{}); ok {
							if value, ok := body["value"].([]interface{}); ok {
								for _, owner := range value {
									if ownerMap, ok := owner.(map[string]interface{}); ok {
										ownerID, _ := ownerMap["id"].(string)

										// Extract SP ID from request ID
										requestID, _ := respMap["id"].(string)
										spIndex := strings.Replace(strings.Replace(requestID, "sp_", "", 1), "_owners", "", 1)

										// Find corresponding service principal
										if spData, exists := spDataMap[fmt.Sprintf("sp_%s", spIndex)]; exists {
											spID := spData["id"].(string)
											spName := spData["displayName"].(string)

											// Output format MUST match HTTP version exactly
											ownership := map[string]interface{}{
												"servicePrincipalId":   spID,
												"servicePrincipalName": spName,
												"ownerId":              ownerID,
												"ownerName":            ownerMap["displayName"],
												"ownerType":            ownerMap["@odata.type"],
												"permissionType":       "ServicePrincipalOwnership",
												"role":                 "Owner",
											}
											ownerships = append(ownerships, ownership)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Add delay between batches
		time.Sleep(200 * time.Millisecond)
	}

	l.logCollectionEnd("servicePrincipalOwnership", startTime, len(ownerships))
	return ownerships, nil
}

// collectServicePrincipalDirectoryRolesSDK collects directory role assignments for service principals
// using the memberOf approach to work around Graph API asymmetry bug where SPs don't appear
// in directoryRoles/{id}/members. Matches HTTP version (collector.go:1770-1913).
func (l *SDKComprehensiveCollectorLink) collectServicePrincipalDirectoryRolesSDK(servicePrincipals []interface{}) ([]interface{}, error) {
	if len(servicePrincipals) == 0 {
		return nil, fmt.Errorf("no service principals provided")
	}

	ctx := l.Context()
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token for SP directory roles: %v", err)
	}

	var assignments []interface{}

	batchSize := 20
	for batchIdx := 0; batchIdx < len(servicePrincipals); batchIdx += batchSize {
		end := batchIdx + batchSize
		if end > len(servicePrincipals) {
			end = len(servicePrincipals)
		}
		batchSPs := servicePrincipals[batchIdx:end]

		var batchRequests []map[string]interface{}
		for i, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}
			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("%d", i+1),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/memberOf", spID),
			})
		}

		if len(batchRequests) == 0 {
			continue
		}

		batchResponse, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
		if err != nil {
			continue
		}

		responses, ok := batchResponse["responses"].([]interface{})
		if !ok {
			continue
		}

		// Build SP index map for matching responses by ID (Graph batch API doesn't guarantee order)
		spIndexMap := make(map[int]map[string]interface{})
		for i, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}
			spIndexMap[i+1] = spMap
		}

		for _, responseInterface := range responses {
			response, ok := responseInterface.(map[string]interface{})
			if !ok {
				continue
			}

			respIDStr, ok := response["id"].(string)
			if !ok {
				continue
			}
			respID, err := strconv.Atoi(respIDStr)
			if err != nil {
				continue
			}

			spMap, exists := spIndexMap[respID]
			if !exists {
				continue
			}

			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}

			if status, ok := response["status"].(float64); ok && status == 200 {
				if body, ok := response["body"].(map[string]interface{}); ok {
					if memberObjects, ok := body["value"].([]interface{}); ok {
						for _, memberObj := range memberObjects {
							memberMap, ok := memberObj.(map[string]interface{})
							if !ok {
								continue
							}

							// Filter for directory roles only
							odataType, ok := memberMap["@odata.type"].(string)
							if !ok || odataType != "#microsoft.graph.directoryRole" {
								continue
							}

							roleID, ok := memberMap["id"].(string)
							if !ok {
								continue
							}

							assignment := map[string]interface{}{
								"roleId":         roleID,
								"roleTemplateId": memberMap["roleTemplateId"],
								"roleName":       memberMap["displayName"],
								"principalId":    spID,
								"principalType":  "#microsoft.graph.servicePrincipal",
							}
							assignments = append(assignments, assignment)
						}
					}
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	l.Logger.Info("Collected SP directory roles via memberOf workaround", "count", len(assignments))
	return assignments, nil
}

// collectApplicationOwnershipSDK collects application ownership relationships
// Uses $expand=owners approach for better performance
func (l *SDKComprehensiveCollectorLink) collectApplicationOwnershipSDK(ctx context.Context) ([]interface{}, error) {
	var applicationOwnerships []interface{}

	startTime := l.logCollectionStart("applicationOwnership")
	l.Logger.Info("Collecting application ownership via Graph SDK")

	// Get access token for raw HTTP call with $expand
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %v", err)
	}

	// Use paginated collection with $expand=owners
	applications, err := l.collectPaginatedGraphDataSDK(accessToken, "/applications?$expand=owners")
	if err != nil {
		return nil, fmt.Errorf("failed to get applications with owners: %v", err)
	}

	l.Logger.Info("Processing application ownership", "applications", len(applications))

	for _, app := range applications {
		appMap, ok := app.(map[string]interface{})
		if !ok {
			continue
		}

		appID, _ := appMap["id"].(string)
		appName, _ := appMap["displayName"].(string)

		if owners, ok := appMap["owners"].([]interface{}); ok {
			for _, owner := range owners {
				ownerMap, ok := owner.(map[string]interface{})
				if !ok {
					continue
				}

				ownerID, _ := ownerMap["id"].(string)
				ownerType, _ := ownerMap["@odata.type"].(string)
				ownerName, _ := ownerMap["displayName"].(string)

				// Output format MUST match HTTP version exactly
				ownership := map[string]interface{}{
					"applicationId":   appID,
					"applicationName": appName,
					"ownerId":         ownerID,
					"ownerName":       ownerName,
					"ownerType":       ownerType,
					"role":            "Owner",
					"permissionType":  "ApplicationOwnership",
				}
				applicationOwnerships = append(applicationOwnerships, ownership)
			}
		}
	}

	l.logCollectionEnd("applicationOwnership", startTime, len(applicationOwnerships))
	return applicationOwnerships, nil
}

// collectPaginatedGraphDataSDK is a helper to collect paginated Graph API data using HTTP client
func (l *SDKComprehensiveCollectorLink) collectPaginatedGraphDataSDK(accessToken string, endpoint string) ([]interface{}, error) {
	var allResults []interface{}
	ctx := l.Context()

	baseURL := "https://graph.microsoft.com/v1.0"
	url := baseURL + endpoint

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to execute request: %v", err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("Graph API call failed with status %d", resp.StatusCode)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}
		resp.Body.Close()

		if value, ok := result["value"].([]interface{}); ok {
			allResults = append(allResults, value...)
		}

		// Handle pagination
		if nextLink, ok := result["@odata.nextLink"].(string); ok && nextLink != "" {
			url = nextLink
		} else {
			url = ""
		}
	}

	return allResults, nil
}

// enrichApplicationsWithCredentialMetadataSDK processes application data and embeds credential metadata
// Produces output format identical to HTTP version
func (l *SDKComprehensiveCollectorLink) enrichApplicationsWithCredentialMetadataSDK(azureADData map[string]interface{}) {
	applicationsData, ok := azureADData["applications"]
	if !ok {
		l.Logger.Warn("No applications data found for credential enrichment")
		return
	}

	applications, ok := applicationsData.([]interface{})
	if !ok {
		l.Logger.Warn("Applications data is not in expected format")
		return
	}

	enrichedCount := 0
	for _, appInterface := range applications {
		app, ok := appInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Analyze key credentials (certificates)
		keyCredentials := l.analyzeKeyCredentialsSDK(app)
		if len(keyCredentials) > 0 {
			app["credentialSummary_keyCredentials"] = keyCredentials
			enrichedCount++
		}

		// Analyze password credentials (client secrets)
		passwordCredentials := l.analyzePasswordCredentialsSDK(app)
		if len(passwordCredentials) > 0 {
			app["credentialSummary_passwordCredentials"] = passwordCredentials
			enrichedCount++
		}

		// Add overall credential summary (matching HTTP version fields exactly)
		app["credentialSummary_totalCredentials"] = len(keyCredentials) + len(passwordCredentials)
		app["credentialSummary_hasCredentials"] = (len(keyCredentials) + len(passwordCredentials)) > 0
	}

	l.Logger.Info("Enriched applications with credential metadata", "count", enrichedCount)
}

// enrichServicePrincipalsWithCredentialMetadataSDK processes SP data and embeds credential metadata
func (l *SDKComprehensiveCollectorLink) enrichServicePrincipalsWithCredentialMetadataSDK(azureADData map[string]interface{}) {
	spsData, ok := azureADData["servicePrincipals"]
	if !ok {
		l.Logger.Warn("No service principals data found for credential enrichment")
		return
	}

	sps, ok := spsData.([]interface{})
	if !ok {
		l.Logger.Warn("Service principals data is not in expected format")
		return
	}

	enrichedCount := 0
	for _, spInterface := range sps {
		sp, ok := spInterface.(map[string]interface{})
		if !ok {
			continue
		}

		keyCredentials := l.analyzeKeyCredentialsSDK(sp)
		if len(keyCredentials) > 0 {
			sp["credentialSummary_keyCredentials"] = keyCredentials
			enrichedCount++
		}

		passwordCredentials := l.analyzePasswordCredentialsSDK(sp)
		if len(passwordCredentials) > 0 {
			sp["credentialSummary_passwordCredentials"] = passwordCredentials
			enrichedCount++
		}

		sp["credentialSummary_totalCredentials"] = len(keyCredentials) + len(passwordCredentials)
		sp["credentialSummary_hasCredentials"] = (len(keyCredentials) + len(passwordCredentials)) > 0
	}

	l.Logger.Info("Enriched service principals with credential metadata", "count", enrichedCount)
}

// analyzeKeyCredentialsSDK processes keyCredentials array and returns summary
func (l *SDKComprehensiveCollectorLink) analyzeKeyCredentialsSDK(app map[string]interface{}) []map[string]interface{} {
	keyCredsInterface, ok := app["keyCredentials"]
	if !ok {
		return []map[string]interface{}{}
	}

	keyCreds, ok := keyCredsInterface.([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}

	var credSummary []map[string]interface{}
	for _, credInterface := range keyCreds {
		cred, ok := credInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Output format MUST match HTTP version exactly
		summary := map[string]interface{}{
			"type":          "certificate",
			"keyId":         cred["keyId"],
			"displayName":   cred["displayName"],
			"usage":         cred["usage"],
			"startDateTime": cred["startDateTime"],
			"endDateTime":   cred["endDateTime"],
		}
		credSummary = append(credSummary, summary)
	}

	return credSummary
}

// analyzePasswordCredentialsSDK processes passwordCredentials array and returns summary
func (l *SDKComprehensiveCollectorLink) analyzePasswordCredentialsSDK(app map[string]interface{}) []map[string]interface{} {
	passwordCredsInterface, ok := app["passwordCredentials"]
	if !ok {
		return []map[string]interface{}{}
	}

	passwordCreds, ok := passwordCredsInterface.([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}

	var credSummary []map[string]interface{}
	for _, credInterface := range passwordCreds {
		cred, ok := credInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Output format MUST match HTTP version exactly
		summary := map[string]interface{}{
			"type":          "clientSecret",
			"keyId":         cred["keyId"],
			"displayName":   cred["displayName"],
			"hint":          cred["hint"],
			"startDateTime": cred["startDateTime"],
			"endDateTime":   cred["endDateTime"],
		}
		credSummary = append(credSummary, summary)
	}

	return credSummary
}

// collectAllPIMDataSDK collects all PIM data using Graph SDK (official PIM APIs)
// This is a major upgrade from the current HTTP implementation which uses legacy internal APIs
func (l *SDKComprehensiveCollectorLink) collectAllPIMDataSDK() (map[string]interface{}, error) {
	pimData := make(map[string]interface{})
	ctx := l.Context()

	overallStart := l.logCollectionStart("PIM Data Collection")
	l.Logger.Info("Collecting PIM data via official Graph SDK APIs")

	// Collection 1: Eligible Role Assignments (with pagination)
	startTime := l.logCollectionStart("PIM eligible assignments")
	message.Info("Collecting PIM eligible assignments from Graph SDK...")

	eligibleAssignments, err := l.collectAllPIMEligibleWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect eligible assignments via paginated SDK", "error", err)
		pimData["eligible_assignments"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("PIM eligible assignments", startTime, 0)
	} else {
		pimData["eligible_assignments"] = eligibleAssignments
		l.logCollectionEnd("PIM eligible assignments", startTime, len(eligibleAssignments))
	}

	// Collection 2: Active Role Assignments (with pagination)
	startTime = l.logCollectionStart("PIM active assignments")
	message.Info("Collecting PIM active assignments from Graph SDK...")

	activeAssignments, err := l.collectAllPIMActiveWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect active assignments via paginated SDK", "error", err)
		pimData["active_assignments"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("PIM active assignments", startTime, 0)
	} else {
		pimData["active_assignments"] = activeAssignments
		l.logCollectionEnd("PIM active assignments", startTime, len(activeAssignments))
	}

	// Collection 3: Role Management Policies (new data not available in HTTP version)
	// TODO: Re-enable when API endpoint is available in SDK
	l.Logger.Info("Skipping PIM role management policies - API not available in current SDK version")
	/*
	policiesResponse, err := l.graphClient.RoleManagement().Directory().RoleManagementPolicies().Get(ctx, nil)
	if err != nil {
		l.Logger.Error("Failed to collect role management policies via SDK", "error", err)
		// Continue without policies - this is additional data not in HTTP version
	} else {
		policies := policiesResponse.GetValue()
		policyInterfaces := make([]interface{}, len(policies))
		for i, policy := range policies {
			policyMap := map[string]interface{}{
				"id":                 *policy.GetId(),
				"displayName":        stringPtrToInterface(policy.GetDisplayName()),
				"description":        stringPtrToInterface(policy.GetDescription()),
				"isOrganizationDefault": boolPtrToInterface(policy.GetIsOrganizationDefault()),
				"lastModifiedDateTime": timeToInterface(policy.GetLastModifiedDateTime()),
				// Rules and other complex objects can be added later
			}
			policyInterfaces[i] = policyMap
		}
		pimData["role_management_policies"] = policyInterfaces
		l.Logger.Info("Collected role management policies via SDK", "count", len(policies))
	}
	*/

	// Collection 4: Policy Assignments (new data not available in HTTP version)
	// TODO: Re-enable when API endpoint is available in SDK
	l.Logger.Info("Skipping PIM role management policy assignments - API not available in current SDK version")
	/*
	assignmentsResponse, err := l.graphClient.RoleManagement().Directory().RoleManagementPolicyAssignments().Get(ctx, nil)
	if err != nil {
		l.Logger.Error("Failed to collect role management policy assignments via SDK", "error", err)
		// Continue without policy assignments - this is additional data
	} else {
		assignments := assignmentsResponse.GetValue()
		assignmentInterfaces := make([]interface{}, len(assignments))
		for i, assignment := range assignments {
			assignmentMap := map[string]interface{}{
				"id":                 *assignment.GetId(),
				"policyId":           stringPtrToInterface(assignment.GetPolicyId()),
				"roleDefinitionId":   stringPtrToInterface(assignment.GetRoleDefinitionId()),
				"scopeId":            stringPtrToInterface(assignment.GetScopeId()),
				"scopeType":          stringPtrToInterface(assignment.GetScopeType()),
			}
			assignmentInterfaces[i] = assignmentMap
		}
		pimData["role_management_policy_assignments"] = assignmentInterfaces
		l.Logger.Info("Collected role management policy assignments via SDK", "count", len(assignments))
	}
	*/

	// Calculate total PIM resource counts for final summary
	totalPIMItems := len(eligibleAssignments) + len(activeAssignments)
	l.logCollectionEnd("PIM Data Collection", overallStart, totalPIMItems)
	return pimData, nil
}

// getManagementGroupHierarchyViaSDK gets management groups hierarchy using SDK
// getManagementGroupHierarchyViaARG gets management groups and subscriptions with full hierarchy using Azure Resource Graph
// This matches the HTTP version's output exactly, including ParentId, HierarchyLevel, and managementGroupAncestorsChain
func (l *SDKComprehensiveCollectorLink) getManagementGroupHierarchyViaARG(tenantID string) ([]interface{}, error) {
	ctx := l.Context()

	l.Logger.Info("Collecting management groups hierarchy via Resource Graph")

	// KQL query matching the HTTP version exactly
	kqlQuery := fmt.Sprintf(`
		resourcecontainers
		| where type == "microsoft.management/managementgroups" or type == "microsoft.resources/subscriptions"
		| extend ParentId = case(
			type == "microsoft.management/managementgroups" and isnotempty(properties.details.parent.name), strcat("/providers/Microsoft.Management/managementGroups/", properties.details.parent.name),
			type == "microsoft.resources/subscriptions" and isnotempty(properties.managementGroupAncestorsChain), properties.managementGroupAncestorsChain[0].name,
			""
		)
		| extend HierarchyLevel = case(
			type == "microsoft.management/managementgroups", array_length(properties.details.managementGroupAncestorsChain),
			type == "microsoft.resources/subscriptions", array_length(properties.managementGroupAncestorsChain) + 1,
			0
		)
		| extend managementGroupAncestorsChain = case(
			type == "microsoft.management/managementgroups", properties.details.managementGroupAncestorsChain,
			type == "microsoft.resources/subscriptions", properties.managementGroupAncestorsChain,
			dynamic([])
		)
		| extend ResourceType = case(
			type == "microsoft.management/managementgroups", "ManagementGroup",
			type == "microsoft.resources/subscriptions", "Subscription",
			""
		)
		| where tenantId == "%s"
		| project id, name, type, ResourceType, ParentId, HierarchyLevel, managementGroupAncestorsChain, properties, tenantId
		| order by HierarchyLevel asc, name asc`, tenantID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:   &kqlQuery,
		Options: &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var allResults []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("Resource Graph management groups query failed: %v", err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &allResults)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	l.Logger.Info("Retrieved management hierarchy via Resource Graph", "total_resources", len(allResults))

	// Separate management groups and subscriptions for logging
	mgCount := 0
	subCount := 0
	for _, item := range allResults {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if resourceType, exists := itemMap["ResourceType"]; exists {
				switch resourceType {
				case "ManagementGroup":
					mgCount++
				case "Subscription":
					subCount++
				}
			}
		}
	}
	l.Logger.Info("Resource breakdown", "management_groups", mgCount, "subscriptions", subCount)

	return allResults, nil
}

// processSubscriptionsParallelSDK processes multiple subscriptions in parallel using SDK clients
func (l *SDKComprehensiveCollectorLink) processSubscriptionsParallelSDK(
	subscriptionIDs []string,
) map[string]interface{} {
	type subResult struct {
		subscriptionID string
		data           map[string]interface{}
		err            error
	}

	subChan := make(chan string, len(subscriptionIDs))
	resultChan := make(chan subResult, len(subscriptionIDs))

	// Use single worker to avoid concurrency issues with Azure SDK rate limiting
	// Multiple workers can cause API throttling and authentication conflicts
	var wg sync.WaitGroup
	numWorkers := 1

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subscriptionID := range subChan {
				l.Logger.Info("Processing subscription via SDK", "subscription", subscriptionID)
				data, err := l.collectAllAzureRMDataSDK(subscriptionID)
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
	allSubscriptionData := make(map[string]interface{})
	for result := range resultChan {
		if result.err != nil {
			l.Logger.Error("Failed to collect data for subscription via SDK",
				"subscription", result.subscriptionID, "error", result.err)
			continue
		}
		allSubscriptionData[result.subscriptionID] = result.data
		l.Logger.Info("Successfully processed subscription via SDK",
			"subscription", result.subscriptionID)
	}

	return allSubscriptionData
}

// collectAllAzureRMDataSDK collects all Azure RM data for a subscription using SDK clients
func (l *SDKComprehensiveCollectorLink) collectAllAzureRMDataSDK(subscriptionID string) (map[string]interface{}, error) {
	azurermData := make(map[string]interface{})

	l.Logger.Info("Collecting Azure RM data via SDK", "subscription", subscriptionID)

	// Collection 1: Resources via Resource Graph
	l.Logger.Info("Collecting Azure resources via Resource Graph SDK", "subscription", subscriptionID)

	resources, err := l.collectAzureResourcesViaGraphSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect resources via Resource Graph SDK", "error", err)
		azurermData["azureResources"] = []interface{}{}
	} else {
		azurermData["azureResources"] = resources
		l.Logger.Info("Collected resources via Resource Graph SDK", "count", len(resources), "subscription", subscriptionID)
	}

	// Collection 1.5: Resource Groups via Resource Graph (for compatibility)
	l.Logger.Info("Collecting Azure resource groups via Resource Graph SDK", "subscription", subscriptionID)
	resourceGroups, err := l.collectAzureResourceGroupsSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect resource groups via Resource Graph SDK", "error", err)
		azurermData["azureResourceGroups"] = []interface{}{}
	} else {
		azurermData["azureResourceGroups"] = resourceGroups
		l.Logger.Info("Collected resource groups via Resource Graph SDK", "count", len(resourceGroups), "subscription", subscriptionID)
	}

	// Collection 1.6: Key Vault Access Policies (for compatibility)
	l.Logger.Info("Collecting Key Vault access policies via Resource Graph SDK", "subscription", subscriptionID)
	keyVaultPolicies, err := l.collectKeyVaultAccessPoliciesSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect Key Vault access policies via SDK", "error", err)
		azurermData["keyVaultAccessPolicies"] = []interface{}{}
	} else {
		azurermData["keyVaultAccessPolicies"] = keyVaultPolicies
		l.Logger.Info("Collected Key Vault access policies via SDK", "count", len(keyVaultPolicies), "subscription", subscriptionID)
	}

	// Collection 2: Role Assignments via Authorization SDK (CRITICAL for iam-push compatibility)
	l.Logger.Info("Collecting role assignments via Authorization SDK")
	subscriptionRoleAssignments, resourceGroupRoleAssignments, resourceLevelRoleAssignments, managementGroupRoleAssignments, tenantRoleAssignments, err := l.collectAllRoleAssignmentsSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect role assignments via SDK", "error", err)
		// Set empty arrays on error but continue
		azurermData["subscriptionRoleAssignments"] = []interface{}{}
		azurermData["resourceGroupRoleAssignments"] = []interface{}{}
		azurermData["resourceLevelRoleAssignments"] = []interface{}{}
		azurermData["managementGroupRoleAssignments"] = []interface{}{}
		azurermData["tenantRoleAssignments"] = []interface{}{}
	} else {
		azurermData["subscriptionRoleAssignments"] = subscriptionRoleAssignments
		azurermData["resourceGroupRoleAssignments"] = resourceGroupRoleAssignments
		azurermData["resourceLevelRoleAssignments"] = resourceLevelRoleAssignments
		azurermData["managementGroupRoleAssignments"] = managementGroupRoleAssignments
		azurermData["tenantRoleAssignments"] = tenantRoleAssignments

		totalCount := len(subscriptionRoleAssignments) + len(resourceGroupRoleAssignments) + len(resourceLevelRoleAssignments) + len(managementGroupRoleAssignments) + len(tenantRoleAssignments)
		l.Logger.Info("Collected role assignments via SDK", "total", totalCount,
			"subscription", len(subscriptionRoleAssignments),
			"resourceGroup", len(resourceGroupRoleAssignments),
			"resource", len(resourceLevelRoleAssignments),
			"managementGroup", len(managementGroupRoleAssignments),
			"tenant", len(tenantRoleAssignments))
	}

	// Collection 3: Role Definitions via Authorization SDK
	l.Logger.Info("Collecting role definitions via Authorization SDK")
	roleDefinitions, err := l.collectAllRoleDefinitionsSDK(subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to collect role definitions via SDK", "error", err)
		azurermData["azureRoleDefinitions"] = []interface{}{} // Empty array on error
	} else {
		azurermData["azureRoleDefinitions"] = roleDefinitions
		l.Logger.Info("Collected role definitions via SDK", "count", len(roleDefinitions))
	}

	// Apply deduplication to RBAC assignments (matching HTTP version behavior)
	l.deduplicateRBACAssignments(azurermData)

	return azurermData, nil
}

// collectAzureResourcesViaGraphSDK collects Azure resources using Resource Graph SDK
func (l *SDKComprehensiveCollectorLink) collectAzureResourcesViaGraphSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()

	// KQL query similar to the HTTP version but using SDK
	query := fmt.Sprintf(`
		resources
		| where subscriptionId == '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, tags, identity, properties, zones, kind, sku, plan
		| order by type asc`, subscriptionID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var resources []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("Resource Graph SDK query failed: %v", err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &resources)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	return resources, nil
}

// collectAzureResourceGroupsSDK collects Azure resource groups using Resource Graph SDK
func (l *SDKComprehensiveCollectorLink) collectAzureResourceGroupsSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()

	// KQL query to get resource groups for this subscription
	query := fmt.Sprintf(`
		resourcecontainers
		| where type == "microsoft.resources/subscriptions/resourcegroups"
		| where subscriptionId == '%s'
		| project id, name, type, location, subscriptionId, tags, properties
		| order by name asc`, subscriptionID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var resourceGroups []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("Resource Graph SDK query failed for resource groups: %v", err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &resourceGroups)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	return resourceGroups, nil
}

// collectKeyVaultAccessPoliciesSDK collects Key Vault access policies using Resource Graph SDK
func (l *SDKComprehensiveCollectorLink) collectKeyVaultAccessPoliciesSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()

	// KQL query to get Key Vault access policies for this subscription
	query := fmt.Sprintf(`
		resources
		| where type == "microsoft.keyvault/vaults"
		| where subscriptionId == '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, properties.accessPolicies
		| extend accessPolicies = properties_accessPolicies
		| where isnotnull(accessPolicies) and array_length(accessPolicies) > 0
		| mvexpand policy = accessPolicies
		| project id, name, type, location, resourceGroup, subscriptionId, policy
		| order by name asc`, subscriptionID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var accessPolicies []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("Resource Graph SDK query failed for Key Vault access policies: %v", err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &accessPolicies)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	return accessPolicies, nil
}

// collectRoleAssignmentsViaSDK collects role assignments using Authorization SDK
// TODO: Re-implement when SDK API issues are resolved
/*
func (l *SDKComprehensiveCollectorLink) collectRoleAssignmentsViaSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()
	var roleAssignments []interface{}

	// Create a subscription-scoped authorization client
	authClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, &l.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization client: %v", err)
	}

	pager := authClient.NewListForSubscriptionPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get role assignments page: %v", err)
		}

		for _, ra := range page.Value {
			if ra == nil || ra.ID == nil {
				continue
			}

			raMap := map[string]interface{}{
				"id":                 *ra.ID,
				"name":               stringPtrToInterface(ra.Name),
				"type":               stringPtrToInterface(ra.Type),
				"principalId":        stringPtrToInterface(ra.Properties.PrincipalID),
				"roleDefinitionId":   stringPtrToInterface(ra.Properties.RoleDefinitionID),
				"scope":              stringPtrToInterface(ra.Properties.Scope),
				"principalType":      stringPtrToInterface(ra.Properties.PrincipalType),
				"createdOn":          timeToInterface(ra.Properties.CreatedOn),
				"updatedOn":          timeToInterface(ra.Properties.UpdatedOn),
			}

			roleAssignments = append(roleAssignments, raMap)
		}
	}

	return roleAssignments, nil
}
*/

// TODO: Re-implement role definitions collection when SDK issues resolved
/*
// collectRoleDefinitionsViaSDK collects role definitions using Authorization SDK
func (l *SDKComprehensiveCollectorLink) collectRoleDefinitionsViaSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()
	var roleDefinitions []interface{}

	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := l.roleDefClient.NewListPager(scope, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get role definitions page: %v", err)
		}

		for _, rd := range page.Value {
			if rd == nil || rd.ID == nil {
				continue
			}

			rdMap := map[string]interface{}{
				"id":          *rd.ID,
				"name":        stringPtrToInterface(rd.Name),
				"type":        stringPtrToInterface(rd.Type),
				"roleName":    stringPtrToInterface(rd.Properties.RoleName),
				"description": stringPtrToInterface(rd.Properties.Description),
				"roleType":    stringPtrToInterface(rd.Properties.RoleType),
				"createdOn":   timeToInterface(rd.Properties.CreatedOn),
				"updatedOn":   timeToInterface(rd.Properties.UpdatedOn),
			}

			// Add permissions if available
			if rd.Properties != nil && rd.Properties.Permissions != nil {
				permissions := make([]interface{}, len(rd.Properties.Permissions))
				for i, perm := range rd.Properties.Permissions {
					permMap := map[string]interface{}{
						"actions":     stringSliceToInterface(perm.Actions),
						"notActions":  stringSliceToInterface(perm.NotActions),
						"dataActions": stringSliceToInterface(perm.DataActions),
						"notDataActions": stringSliceToInterface(perm.NotDataActions),
					}
					permissions[i] = permMap
				}
				rdMap["permissions"] = permissions
			}

			roleDefinitions = append(roleDefinitions, rdMap)
		}
	}

	return roleDefinitions, nil
}
*/

// collectAllRoleAssignmentsSDK collects all role assignments for a subscription using Azure Resource Graph
// This matches the HTTP version's approach (collector.go:517-636) which uses ARG to get principalType and other fields
func (l *SDKComprehensiveCollectorLink) collectAllRoleAssignmentsSDK(subscriptionID string) ([]interface{}, []interface{}, []interface{}, []interface{}, []interface{}, error) {
	ctx := l.Context()
	var subscriptionRoleAssignments []interface{}
	var resourceGroupRoleAssignments []interface{}
	var resourceLevelRoleAssignments []interface{}
	var managementGroupRoleAssignments []interface{}
	var tenantRoleAssignments []interface{}

	l.Logger.Info("Starting role assignments collection via Resource Graph", "subscription", subscriptionID)

	// Use same KQL query as HTTP version (collector.go:525-534) to get principalType
	query := fmt.Sprintf(`
		authorizationresources
		| where type =~ 'microsoft.authorization/roleassignments'
		| where subscriptionId == '%s'
		| extend principalId = tostring(properties.principalId)
		| extend roleDefinitionId = tostring(properties.roleDefinitionId)
		| extend scope = tostring(properties.scope)
		| extend principalType = tostring(properties.principalType)
		| project id, name, subscriptionId, principalId, roleDefinitionId, scope, principalType, properties
		| order by scope asc`, subscriptionID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&subscriptionID},
		Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var allAssignments []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("Resource Graph RBAC query failed for subscription %s: %v", subscriptionID, err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &allAssignments)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	// Group assignments by scope type (matching HTTP version's grouping logic at collector.go:601-631)
	for _, assignment := range allAssignments {
		assignmentMap, ok := assignment.(map[string]interface{})
		if !ok {
			continue
		}

		scope, _ := assignmentMap["scope"].(string)
		scope = normalizeScope(scope)
		assignmentMap["scope"] = scope

		switch {
		case strings.HasPrefix(scope, "/providers/microsoft.management/managementgroups/"):
			managementGroupRoleAssignments = append(managementGroupRoleAssignments, assignmentMap)
		case scope == "/" || scope == "":
			tenantRoleAssignments = append(tenantRoleAssignments, assignmentMap)
		case strings.Count(scope, "/") == 2:
			// /subscriptions/{subscription-id}
			subscriptionRoleAssignments = append(subscriptionRoleAssignments, assignmentMap)
		case strings.Contains(scope, "/resourcegroups/") && strings.Count(scope, "/") == 4:
			// /subscriptions/{sub}/resourcegroups/{rg}
			resourceGroupRoleAssignments = append(resourceGroupRoleAssignments, assignmentMap)
		default:
			// Resource-level or other
			resourceLevelRoleAssignments = append(resourceLevelRoleAssignments, assignmentMap)
		}
	}

	l.Logger.Info("Completed role assignments collection via Resource Graph",
		"subscription", subscriptionID,
		"total", len(allAssignments),
		"subscriptionLevel", len(subscriptionRoleAssignments),
		"resourceGroupLevel", len(resourceGroupRoleAssignments),
		"resourceLevel", len(resourceLevelRoleAssignments),
		"managementGroupLevel", len(managementGroupRoleAssignments),
		"tenantLevel", len(tenantRoleAssignments))

	return subscriptionRoleAssignments, resourceGroupRoleAssignments, resourceLevelRoleAssignments, managementGroupRoleAssignments, tenantRoleAssignments, nil
}

// collectManagementGroupAndTenantRBAC collects RBAC assignments scoped to management groups
// and tenant root. These are NOT returned by per-subscription ARG queries because they have
// no subscriptionId, so this must be called once per tenant.
func (l *SDKComprehensiveCollectorLink) collectManagementGroupAndTenantRBAC() ([]interface{}, error) {
	ctx := l.Context()

	query := `
		authorizationresources
		| where type =~ 'microsoft.authorization/roleassignments'
		| where isempty(subscriptionId)
			or properties.scope startswith '/providers/Microsoft.Management/managementGroups/'
			or properties.scope == '/'
		| extend principalId = tostring(properties.principalId)
		| extend roleDefinitionId = tostring(properties.roleDefinitionId)
		| extend scope = tostring(properties.scope)
		| extend principalType = tostring(properties.principalType)
		| project id, name, subscriptionId, principalId, roleDefinitionId, scope, principalType, properties`

	resultFormat := armresourcegraph.ResultFormatObjectArray
	queryRequest := armresourcegraph.QueryRequest{
		Query:   &query,
		Options: &armresourcegraph.QueryRequestOptions{ResultFormat: &resultFormat},
	}

	var allAssignments []interface{}
	for {
		response, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("Resource Graph MG/tenant RBAC query failed: %v", err)
		}

		if response.Data != nil {
			decodeResourceGraphData(response.Data, &allAssignments)
		}

		if response.SkipToken == nil || len(*response.SkipToken) == 0 {
			break
		}
		queryRequest.Options.SkipToken = response.SkipToken
	}

	// Normalize scopes on ingestion
	for _, assignment := range allAssignments {
		if assignmentMap, ok := assignment.(map[string]interface{}); ok {
			if scope, ok := assignmentMap["scope"].(string); ok {
				assignmentMap["scope"] = normalizeScope(scope)
			}
		}
	}

	l.Logger.Info("Collected management group and tenant RBAC assignments",
		"total", len(allAssignments))

	return allAssignments, nil
}

// deduplicateRBACAssignments removes duplicate RBAC assignments by ID across all scope levels
// This matches the HTTP version's deduplication behavior (collector.go lines 1104-1155)
func (l *SDKComprehensiveCollectorLink) deduplicateRBACAssignments(azurermData map[string]interface{}) {
	seenAssignments := make(map[string]bool)

	deduplicateAssignments := func(assignments []interface{}) []interface{} {
		var unique []interface{}
		for _, assignment := range assignments {
			if assignmentMap, ok := assignment.(map[string]interface{}); ok {
				if id, ok := assignmentMap["id"].(string); ok && id != "" {
					if !seenAssignments[id] {
						seenAssignments[id] = true
						unique = append(unique, assignment)
					}
				}
			}
		}
		return unique
	}

	// Apply to subscription-level assignments
	if val, exists := azurermData["subscriptionRoleAssignments"]; exists {
		if assignments, ok := val.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["subscriptionRoleAssignments"] = deduplicated
			l.Logger.Info("Subscription RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply to resource group-level assignments
	if val, exists := azurermData["resourceGroupRoleAssignments"]; exists {
		if assignments, ok := val.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["resourceGroupRoleAssignments"] = deduplicated
			l.Logger.Info("Resource Group RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply to resource-level assignments
	if val, exists := azurermData["resourceLevelRoleAssignments"]; exists {
		if assignments, ok := val.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["resourceLevelRoleAssignments"] = deduplicated
			l.Logger.Info("Resource-level RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply to management group-level assignments (SDK-only scope, not in HTTP)
	if val, exists := azurermData["managementGroupRoleAssignments"]; exists {
		if assignments, ok := val.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["managementGroupRoleAssignments"] = deduplicated
			l.Logger.Info("Management Group RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply to tenant-level assignments (SDK-only scope, not in HTTP)
	if val, exists := azurermData["tenantRoleAssignments"]; exists {
		if assignments, ok := val.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["tenantRoleAssignments"] = deduplicated
			l.Logger.Info("Tenant RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	totalUnique := len(seenAssignments)
	l.Logger.Info("Total RBAC assignment deduplication complete", "total_unique_assignments", totalUnique)
}

// collectAllRoleDefinitionsSDK collects all role definitions for a subscription using Authorization SDK
func (l *SDKComprehensiveCollectorLink) collectAllRoleDefinitionsSDK(subscriptionID string) ([]interface{}, error) {
	ctx := l.Context()
	var allRoleDefinitions []interface{}

	l.Logger.Info("Starting role definitions collection via SDK", "subscription", subscriptionID)

	// Get all role definitions for the subscription with pagination
	pager := l.roleDefClient.NewListPager(fmt.Sprintf("/subscriptions/%s", subscriptionID), nil)

	totalCount := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get role definitions page: %v", err)
		}

		for _, roleDef := range page.Value {
			if roleDef == nil || roleDef.ID == nil || roleDef.Properties == nil {
				continue
			}

			// Extract role definition details
			roleDefMap := map[string]interface{}{
				"id":           *roleDef.ID,
				"name":         stringPtrToInterface(roleDef.Name),
				"type":         stringPtrToInterface(roleDef.Type),
				"roleName":     stringPtrToInterface(roleDef.Properties.RoleName),
				"roleType":     stringPtrToInterface(roleDef.Properties.RoleType),
				"description":  stringPtrToInterface(roleDef.Properties.Description),
			}

			// Add permissions if available
			if roleDef.Properties.Permissions != nil {
				permissions := make([]interface{}, 0)
				for _, perm := range roleDef.Properties.Permissions {
					if perm == nil {
						continue
					}
					permMap := map[string]interface{}{}

					if perm.Actions != nil {
						actions := make([]string, 0)
						for _, action := range perm.Actions {
							if action != nil {
								actions = append(actions, *action)
							}
						}
						permMap["actions"] = actions
					}

					if perm.NotActions != nil {
						notActions := make([]string, 0)
						for _, notAction := range perm.NotActions {
							if notAction != nil {
								notActions = append(notActions, *notAction)
							}
						}
						permMap["notActions"] = notActions
					}

					// Note: DataActions and NotDataActions are not available on armauthorization.Permission
					// in this SDK version. The HTTP version gets them via the full ARM API response.
					// These fields are only present on data-plane roles (e.g., Storage Blob Data Reader).
					// Include as empty for schema compatibility.
					permMap["dataActions"] = []string{}
					permMap["notDataActions"] = []string{}

					permissions = append(permissions, permMap)
				}
				roleDefMap["permissions"] = permissions
			}

			allRoleDefinitions = append(allRoleDefinitions, roleDefMap)
			totalCount++
		}
	}

	l.Logger.Info("Completed role definitions collection via SDK", "subscription", subscriptionID, "count", totalCount)
	return allRoleDefinitions, nil
}

// Helper functions to convert SDK types to interfaces for compatibility with iam-push

func stringPtrToInterface(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func uuidPtrToInterface(u *uuid.UUID) interface{} {
	if u == nil {
		return nil
	}
	return u.String()
}

func boolPtrToInterface(b *bool) interface{} {
	if b == nil {
		return nil
	}
	return *b
}

func stringSliceToInterface(slice []string) interface{} {
	if slice == nil {
		return []interface{}{}
	}
	result := make([]interface{}, len(slice))
	for i, s := range slice {
		result[i] = s
	}
	return result
}

func timeToInterface(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

// stateToInterface converts conditional access policy state to interface
func stateToInterface(state interface{}) interface{} {
	if state == nil {
		return nil
	}
	// Convert state enum to string representation
	return fmt.Sprintf("%v", state)
}

// actionToInterface converts PIM action enum to interface
func actionToInterface(action interface{}) interface{} {
	if action == nil {
		return nil
	}
	// Convert action enum to string representation
	return fmt.Sprintf("%v", action)
}

// ============================================================================
// PAGINATION HELPER FUNCTIONS
// ============================================================================

// collectAllUsersWithPagination collects all users using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllUsersWithPagination(ctx context.Context) ([]interface{}, error) {
	var allUsers []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated user collection")

	// Get first page with $select to include userType (not returned by default)
	requestConfig := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: []string{
				"id", "displayName", "userPrincipalName", "mail", "jobTitle",
				"department", "accountEnabled", "userType", "createdDateTime",
				"businessPhones", "givenName", "surname", "mobilePhone",
				"officeLocation", "preferredLanguage", "onPremisesSyncEnabled",
				"signInActivity", "riskState", "riskLevel", "riskLastUpdatedDateTime",
			},
		},
	}
	response, err := l.graphClient.Users().Get(ctx, requestConfig)
	if err != nil {
		// signInActivity and risk fields require Azure AD P1/P2 license; retry without them
		l.Logger.Warn("User collection failed with extended fields, retrying without P2 fields", "error", err)
		requestConfig.QueryParameters.Select = []string{
			"id", "displayName", "userPrincipalName", "mail", "jobTitle",
			"department", "accountEnabled", "userType", "createdDateTime",
			"businessPhones", "givenName", "surname", "mobilePhone",
			"officeLocation", "preferredLanguage", "onPremisesSyncEnabled",
		}
		response, err = l.graphClient.Users().Get(ctx, requestConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get first page of users: %v", err)
		}
	}

	for {
		pageCount++
		users := response.GetValue()
		l.Logger.Info("Processing user page", "page", pageCount, "objects", len(users))

		// Convert users from current page
		for _, user := range users {
			// GetUserType() may return nil even with $select due to SDK backing store behavior.
			// Fall back to backing store and additional data.
			var userType interface{}
			if ut := user.GetUserType(); ut != nil {
				userType = *ut
			} else if bs := user.GetBackingStore(); bs != nil {
				if val, err := bs.Get("userType"); err == nil && val != nil {
					if s, ok := val.(*string); ok && s != nil {
						userType = *s
					}
				}
			}
			if userType == nil {
				if ad := user.GetAdditionalData(); ad != nil {
					if val, ok := ad["userType"]; ok {
						userType = val
					}
				}
			}
			userMap := map[string]interface{}{
				"id":                *user.GetId(),
				"displayName":       stringPtrToInterface(user.GetDisplayName()),
				"userPrincipalName": stringPtrToInterface(user.GetUserPrincipalName()),
				"mail":              stringPtrToInterface(user.GetMail()),
				"jobTitle":          stringPtrToInterface(user.GetJobTitle()),
				"department":        stringPtrToInterface(user.GetDepartment()),
				"accountEnabled":    boolPtrToInterface(user.GetAccountEnabled()),
				"userType":          userType,
				"createdDateTime":   timeToInterface(user.GetCreatedDateTime()),
				"businessPhones":    stringSliceToInterface(user.GetBusinessPhones()),
				"givenName":         stringPtrToInterface(user.GetGivenName()),
				"surname":           stringPtrToInterface(user.GetSurname()),
				"mobilePhone":       stringPtrToInterface(user.GetMobilePhone()),
				"officeLocation":    stringPtrToInterface(user.GetOfficeLocation()),
				"preferredLanguage":    stringPtrToInterface(user.GetPreferredLanguage()),
				"onPremisesSyncEnabled": boolPtrToInterface(user.GetOnPremisesSyncEnabled()),
			}

			// Extract risk and signIn fields (require Azure AD P1/P2 license, may be nil)
			if ad := user.GetAdditionalData(); ad != nil {
				if riskState, ok := ad["riskState"]; ok {
					userMap["riskState"] = riskState
				}
				if riskLevel, ok := ad["riskLevel"]; ok {
					userMap["riskLevel"] = riskLevel
				}
				if riskLastUpdated, ok := ad["riskLastUpdatedDateTime"]; ok {
					userMap["riskLastUpdatedDateTime"] = riskLastUpdated
				}
				if signInActivity, ok := ad["signInActivity"]; ok {
					userMap["signInActivity"] = signInActivity
				}
			}

			allUsers = append(allUsers, userMap)
		}

		totalObjects += len(users)

		// Check if there's a next page using the @odata.nextLink
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page using the @odata.nextLink URL
		response, err = l.graphClient.Users().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of users", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated user collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allUsers, nil
}

// collectAllGroupsWithPagination collects all groups using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllGroupsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allGroups []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated group collection")

	// Get first page (SDK already uses optimized pagination internally)
	response, err := l.graphClient.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of groups: %v", err)
	}

	for {
		pageCount++
		groups := response.GetValue()
		l.Logger.Info("Processing group page", "page", pageCount, "objects", len(groups))

		// Convert groups from current page (matching HTTP version fields exactly)
		for _, group := range groups {
			groupMap := map[string]interface{}{
				"id":                      *group.GetId(),
				"displayName":             stringPtrToInterface(group.GetDisplayName()),
				"description":             stringPtrToInterface(group.GetDescription()),
				"groupTypes":              stringSliceToInterface(group.GetGroupTypes()),
				"membershipRule":          stringPtrToInterface(group.GetMembershipRule()),
				"mailEnabled":             boolPtrToInterface(group.GetMailEnabled()),
				"securityEnabled":         boolPtrToInterface(group.GetSecurityEnabled()),
				"createdDateTime":         timeToInterface(group.GetCreatedDateTime()),
				"isAssignableToRole":      boolPtrToInterface(group.GetIsAssignableToRole()),
				"visibility":              stringPtrToInterface(group.GetVisibility()),
				"onPremisesSyncEnabled":   boolPtrToInterface(group.GetOnPremisesSyncEnabled()),
			}
			allGroups = append(allGroups, groupMap)
		}

		totalObjects += len(groups)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.Groups().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of groups", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated group collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allGroups, nil
}

// collectAllServicePrincipalsWithPagination collects all service principals using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllServicePrincipalsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allSPs []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated service principal collection")

	// Get first page (SDK already uses optimized pagination internally)
	response, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of service principals: %v", err)
	}

	for {
		pageCount++
		sps := response.GetValue()
		l.Logger.Info("Processing service principal page", "page", pageCount, "objects", len(sps))

		// Convert service principals from current page (matching HTTP version fields exactly)
		for _, sp := range sps {
			// Extract createdDateTime from additional data if available
			var createdDateTime interface{}
			if additionalData := sp.GetAdditionalData(); additionalData != nil {
				if val, ok := additionalData["createdDateTime"]; ok {
					createdDateTime = val
				}
			}

			spMap := map[string]interface{}{
				"id":                         *sp.GetId(),
				"appId":                      stringPtrToInterface(sp.GetAppId()),
				"displayName":                stringPtrToInterface(sp.GetDisplayName()),
				"servicePrincipalType":       stringPtrToInterface(sp.GetServicePrincipalType()),
				"accountEnabled":             boolPtrToInterface(sp.GetAccountEnabled()),
				"createdDateTime":            createdDateTime,
				"replyUrls":                  stringSliceToInterface(sp.GetReplyUrls()),
				"signInAudience":             stringPtrToInterface(sp.GetSignInAudience()),
				"appOwnerOrganizationId":     uuidPtrToInterface(sp.GetAppOwnerOrganizationId()),
			}

			// Extract keyCredentials (certificates)
			if keyCreds := sp.GetKeyCredentials(); keyCreds != nil {
				var keyCredsList []interface{}
				for _, kc := range keyCreds {
					if kc == nil {
						continue
					}
					kcMap := map[string]interface{}{
						"keyId":         uuidPtrToInterface(kc.GetKeyId()),
						"displayName":   stringPtrToInterface(kc.GetDisplayName()),
						"usage":         stringPtrToInterface(kc.GetUsage()),
						"startDateTime": timeToInterface(kc.GetStartDateTime()),
						"endDateTime":   timeToInterface(kc.GetEndDateTime()),
					}
					if kc.GetTypeEscaped() != nil {
						kcMap["type"] = *kc.GetTypeEscaped()
					}
					keyCredsList = append(keyCredsList, kcMap)
				}
				spMap["keyCredentials"] = keyCredsList
			} else {
				spMap["keyCredentials"] = []interface{}{}
			}

			// Extract passwordCredentials (client secrets)
			if pwdCreds := sp.GetPasswordCredentials(); pwdCreds != nil {
				var pwdCredsList []interface{}
				for _, pc := range pwdCreds {
					if pc == nil {
						continue
					}
					pcMap := map[string]interface{}{
						"keyId":         uuidPtrToInterface(pc.GetKeyId()),
						"displayName":   stringPtrToInterface(pc.GetDisplayName()),
						"hint":          stringPtrToInterface(pc.GetHint()),
						"startDateTime": timeToInterface(pc.GetStartDateTime()),
						"endDateTime":   timeToInterface(pc.GetEndDateTime()),
					}
					pwdCredsList = append(pwdCredsList, pcMap)
				}
				spMap["passwordCredentials"] = pwdCredsList
			} else {
				spMap["passwordCredentials"] = []interface{}{}
			}

			allSPs = append(allSPs, spMap)
		}

		totalObjects += len(sps)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.ServicePrincipals().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of service principals", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated service principal collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allSPs, nil
}

// collectAllApplicationsWithPagination collects all applications using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllApplicationsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allApps []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated application collection")

	// Get first page (SDK already uses optimized pagination internally)
	response, err := l.graphClient.Applications().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of applications: %v", err)
	}

	for {
		pageCount++
		apps := response.GetValue()
		l.Logger.Info("Processing application page", "page", pageCount, "objects", len(apps))

		// Convert applications from current page
		for _, app := range apps {
			appMap := map[string]interface{}{
				"id":              *app.GetId(),
				"displayName":     stringPtrToInterface(app.GetDisplayName()),
				"appId":           stringPtrToInterface(app.GetAppId()),
				"createdDateTime": timeToInterface(app.GetCreatedDateTime()),
				"signInAudience":  stringPtrToInterface(app.GetSignInAudience()),
			}

			// Add reply URLs if available
			if app.GetWeb() != nil && app.GetWeb().GetRedirectUris() != nil {
				appMap["replyUrls"] = stringSliceToInterface(app.GetWeb().GetRedirectUris())
			} else {
				appMap["replyUrls"] = []interface{}{}
			}

			// Extract keyCredentials (certificates) - CRITICAL for credential enrichment
			if keyCreds := app.GetKeyCredentials(); keyCreds != nil {
				var keyCredsList []interface{}
				for _, kc := range keyCreds {
					if kc == nil {
						continue
					}
					kcMap := map[string]interface{}{
						"keyId":         uuidPtrToInterface(kc.GetKeyId()),
						"displayName":   stringPtrToInterface(kc.GetDisplayName()),
						"usage":         stringPtrToInterface(kc.GetUsage()),
						"startDateTime": timeToInterface(kc.GetStartDateTime()),
						"endDateTime":   timeToInterface(kc.GetEndDateTime()),
					}
					if kc.GetTypeEscaped() != nil {
						kcMap["type"] = *kc.GetTypeEscaped()
					}
					keyCredsList = append(keyCredsList, kcMap)
				}
				appMap["keyCredentials"] = keyCredsList
			} else {
				appMap["keyCredentials"] = []interface{}{}
			}

			// Extract passwordCredentials (client secrets) - CRITICAL for credential enrichment
			if pwdCreds := app.GetPasswordCredentials(); pwdCreds != nil {
				var pwdCredsList []interface{}
				for _, pc := range pwdCreds {
					if pc == nil {
						continue
					}
					pcMap := map[string]interface{}{
						"keyId":         uuidPtrToInterface(pc.GetKeyId()),
						"displayName":   stringPtrToInterface(pc.GetDisplayName()),
						"hint":          stringPtrToInterface(pc.GetHint()),
						"startDateTime": timeToInterface(pc.GetStartDateTime()),
						"endDateTime":   timeToInterface(pc.GetEndDateTime()),
					}
					pwdCredsList = append(pwdCredsList, pcMap)
				}
				appMap["passwordCredentials"] = pwdCredsList
			} else {
				appMap["passwordCredentials"] = []interface{}{}
			}

			// Extract requiredResourceAccess (API permissions the app requests)
			if rra := app.GetRequiredResourceAccess(); rra != nil {
				var rraList []interface{}
				for _, ra := range rra {
					if ra == nil {
						continue
					}
					raMap := map[string]interface{}{
						"resourceAppId": stringPtrToInterface(ra.GetResourceAppId()),
					}
					if accesses := ra.GetResourceAccess(); accesses != nil {
						var accessList []interface{}
						for _, access := range accesses {
							if access == nil {
								continue
							}
							accessMap := map[string]interface{}{
								"id": uuidPtrToInterface(access.GetId()),
							}
							if access.GetTypeEscaped() != nil {
								accessMap["type"] = *access.GetTypeEscaped()
							}
							accessList = append(accessList, accessMap)
						}
						raMap["resourceAccess"] = accessList
					}
					rraList = append(rraList, raMap)
				}
				appMap["requiredResourceAccess"] = rraList
			} else {
				appMap["requiredResourceAccess"] = []interface{}{}
			}

			allApps = append(allApps, appMap)
		}

		totalObjects += len(apps)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.Applications().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of applications", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated application collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allApps, nil
}

// collectAllPIMEligibleWithPagination collects all PIM eligible assignments using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllPIMEligibleWithPagination(ctx context.Context) ([]interface{}, error) {
	var allEligible []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated PIM eligible assignment collection")

	// Get first page with $expand to get principal and role definition display names
	requestConfig := &rolemanagement.DirectoryRoleEligibilitySchedulesRequestBuilderGetRequestConfiguration{
		QueryParameters: &rolemanagement.DirectoryRoleEligibilitySchedulesRequestBuilderGetQueryParameters{
			Expand: []string{"principal", "roleDefinition"},
		},
	}
	response, err := l.graphClient.RoleManagement().Directory().RoleEligibilitySchedules().Get(ctx, requestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of PIM eligible assignments: %v", err)
	}

	for {
		pageCount++
		schedules := response.GetValue()
		l.Logger.Info("Processing PIM eligible page", "page", pageCount, "objects", len(schedules))

		// Convert schedules from current page
		for _, schedule := range schedules {
			scheduleMap := map[string]interface{}{
				"id":                 *schedule.GetId(),
				"principalId":        stringPtrToInterface(schedule.GetPrincipalId()),
				"roleDefinitionId":   stringPtrToInterface(schedule.GetRoleDefinitionId()),
				"directoryScopeId":   stringPtrToInterface(schedule.GetDirectoryScopeId()),
				"status":             stringPtrToInterface(schedule.GetStatus()),
				"createdDateTime":    timeToInterface(schedule.GetCreatedDateTime()),
				"memberType":         stringPtrToInterface(schedule.GetMemberType()),
				// Additional fields for compatibility
				"assignmentState":    "Eligible",
				"assignmentType":     "Eligible",
			}

			// Extract expanded principal display name
			if principal := schedule.GetPrincipal(); principal != nil {
				scheduleMap["principalDisplayName"] = nil
				if additionalData := principal.GetAdditionalData(); additionalData != nil {
					if displayName, ok := additionalData["displayName"]; ok {
						scheduleMap["principalDisplayName"] = displayName
					}
				}
			}

			// Extract expanded role definition display name
			if roleDef := schedule.GetRoleDefinition(); roleDef != nil {
				scheduleMap["roleDefinitionDisplayName"] = stringPtrToInterface(roleDef.GetDisplayName())
			}

			// Extract scheduleInfo (start/end times for the assignment)
			if scheduleInfo := schedule.GetScheduleInfo(); scheduleInfo != nil {
				siMap := map[string]interface{}{
					"startDateTime": timeToInterface(scheduleInfo.GetStartDateTime()),
				}
				if expiration := scheduleInfo.GetExpiration(); expiration != nil {
					expMap := map[string]interface{}{
						"endDateTime": timeToInterface(expiration.GetEndDateTime()),
					}
					if expiration.GetTypeEscaped() != nil {
						expMap["type"] = expiration.GetTypeEscaped().String()
					}
					siMap["expiration"] = expMap
				}
				scheduleMap["scheduleInfo"] = siMap
			}

			allEligible = append(allEligible, scheduleMap)
		}

		totalObjects += len(schedules)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page (WithUrl preserves $expand from original request)
		response, err = l.graphClient.RoleManagement().Directory().RoleEligibilitySchedules().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of PIM eligible assignments", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated PIM eligible collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allEligible, nil
}

// collectAllPIMActiveWithPagination collects all PIM active assignments using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllPIMActiveWithPagination(ctx context.Context) ([]interface{}, error) {
	var allActive []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated PIM active assignment collection")

	// Get first page with $expand to get principal and role definition display names
	requestConfig := &rolemanagement.DirectoryRoleAssignmentSchedulesRequestBuilderGetRequestConfiguration{
		QueryParameters: &rolemanagement.DirectoryRoleAssignmentSchedulesRequestBuilderGetQueryParameters{
			Expand: []string{"principal", "roleDefinition"},
		},
	}
	response, err := l.graphClient.RoleManagement().Directory().RoleAssignmentSchedules().Get(ctx, requestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of PIM active assignments: %v", err)
	}

	for {
		pageCount++
		schedules := response.GetValue()
		l.Logger.Info("Processing PIM active page", "page", pageCount, "objects", len(schedules))

		// Convert schedules from current page
		for _, schedule := range schedules {
			scheduleMap := map[string]interface{}{
				"id":                 *schedule.GetId(),
				"principalId":        stringPtrToInterface(schedule.GetPrincipalId()),
				"roleDefinitionId":   stringPtrToInterface(schedule.GetRoleDefinitionId()),
				"directoryScopeId":   stringPtrToInterface(schedule.GetDirectoryScopeId()),
				"status":             stringPtrToInterface(schedule.GetStatus()),
				"createdDateTime":    timeToInterface(schedule.GetCreatedDateTime()),
				"memberType":         stringPtrToInterface(schedule.GetMemberType()),
				"assignmentType":     stringPtrToInterface(schedule.GetAssignmentType()),
				// Additional fields for compatibility
				"assignmentState":    "Active",
			}

			// Extract expanded principal display name
			if principal := schedule.GetPrincipal(); principal != nil {
				scheduleMap["principalDisplayName"] = nil
				if additionalData := principal.GetAdditionalData(); additionalData != nil {
					if displayName, ok := additionalData["displayName"]; ok {
						scheduleMap["principalDisplayName"] = displayName
					}
				}
			}

			// Extract expanded role definition display name
			if roleDef := schedule.GetRoleDefinition(); roleDef != nil {
				scheduleMap["roleDefinitionDisplayName"] = stringPtrToInterface(roleDef.GetDisplayName())
			}

			// Extract scheduleInfo (start/end times for the assignment)
			if scheduleInfo := schedule.GetScheduleInfo(); scheduleInfo != nil {
				siMap := map[string]interface{}{
					"startDateTime": timeToInterface(scheduleInfo.GetStartDateTime()),
				}
				if expiration := scheduleInfo.GetExpiration(); expiration != nil {
					expMap := map[string]interface{}{
						"endDateTime": timeToInterface(expiration.GetEndDateTime()),
					}
					if expiration.GetTypeEscaped() != nil {
						expMap["type"] = expiration.GetTypeEscaped().String()
					}
					siMap["expiration"] = expMap
				}
				scheduleMap["scheduleInfo"] = siMap
			}

			allActive = append(allActive, scheduleMap)
		}

		totalObjects += len(schedules)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page (WithUrl preserves $expand from original request)
		response, err = l.graphClient.RoleManagement().Directory().RoleAssignmentSchedules().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of PIM active assignments", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated PIM active collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allActive, nil
}

// collectAllDevicesWithPagination collects all devices using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllDevicesWithPagination(ctx context.Context) ([]interface{}, error) {
	var allDevices []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated device collection")

	// Get first page
	response, err := l.graphClient.Devices().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of devices: %v", err)
	}

	for {
		pageCount++
		devices := response.GetValue()
		l.Logger.Info("Processing device page", "page", pageCount, "objects", len(devices))

		// Convert devices from current page (matching HTTP version fields exactly)
		for _, device := range devices {
			// Try to get createdDateTime from additionalData first (matches HTTP $select field),
			// fall back to registrationDateTime if not available
			var createdDateTime interface{}
			if additionalData := device.GetAdditionalData(); additionalData != nil {
				if val, ok := additionalData["createdDateTime"]; ok {
					createdDateTime = val
				}
			}
			if createdDateTime == nil {
				createdDateTime = timeToInterface(device.GetRegistrationDateTime())
			}

			deviceMap := map[string]interface{}{
				"id":                              *device.GetId(),
				"displayName":                     stringPtrToInterface(device.GetDisplayName()),
				"deviceId":                        stringPtrToInterface(device.GetDeviceId()),
				"operatingSystem":                 stringPtrToInterface(device.GetOperatingSystem()),
				"operatingSystemVersion":           stringPtrToInterface(device.GetOperatingSystemVersion()),
				"isCompliant":                     boolPtrToInterface(device.GetIsCompliant()),
				"isManaged":                       boolPtrToInterface(device.GetIsManaged()),
				"accountEnabled":                  boolPtrToInterface(device.GetAccountEnabled()),
				"createdDateTime":                 createdDateTime,
				"trustType":                       stringPtrToInterface(device.GetTrustType()),
				"approximateLastSignInDateTime":   timeToInterface(device.GetApproximateLastSignInDateTime()),
			}
			allDevices = append(allDevices, deviceMap)
		}

		totalObjects += len(devices)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.Devices().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of devices", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated device collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allDevices, nil
}

// collectAllDirectoryRolesWithPagination collects all directory roles using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllDirectoryRolesWithPagination(ctx context.Context) ([]interface{}, error) {
	var allRoles []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated directory role collection")

	// Get first page
	response, err := l.graphClient.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of directory roles: %v", err)
	}

	for {
		pageCount++
		roles := response.GetValue()
		l.Logger.Info("Processing directory role page", "page", pageCount, "objects", len(roles))

		// Convert roles from current page
		for _, role := range roles {
			roleMap := map[string]interface{}{
				"id":               *role.GetId(),
				"displayName":      stringPtrToInterface(role.GetDisplayName()),
				"description":      stringPtrToInterface(role.GetDescription()),
				"roleTemplateId":   stringPtrToInterface(role.GetRoleTemplateId()),
			}
			allRoles = append(allRoles, roleMap)
		}

		totalObjects += len(roles)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.DirectoryRoles().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of directory roles", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated directory role collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allRoles, nil
}

// collectAllRoleDefinitionsWithPagination collects all role definitions using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllRoleDefinitionsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allRoleDefs []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated role definition collection")

	// Get first page
	response, err := l.graphClient.RoleManagement().Directory().RoleDefinitions().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of role definitions: %v", err)
	}

	for {
		pageCount++
		roleDefs := response.GetValue()
		l.Logger.Info("Processing role definition page", "page", pageCount, "objects", len(roleDefs))

		// Convert role definitions from current page
		for _, roleDef := range roleDefs {
			roleDefMap := map[string]interface{}{
				"id":           *roleDef.GetId(),
				"displayName":  stringPtrToInterface(roleDef.GetDisplayName()),
				"description":  stringPtrToInterface(roleDef.GetDescription()),
				"isBuiltIn":    boolPtrToInterface(roleDef.GetIsBuiltIn()),
				"isEnabled":    boolPtrToInterface(roleDef.GetIsEnabled()),
				"templateId":   stringPtrToInterface(roleDef.GetTemplateId()),
			}

			// Add role permissions if available (critical for iam-push relationships)
			if roleDef.GetRolePermissions() != nil && len(roleDef.GetRolePermissions()) > 0 {
				var permissions []interface{}
				for _, perm := range roleDef.GetRolePermissions() {
					permMap := map[string]interface{}{}
					if perm.GetAllowedResourceActions() != nil {
						permMap["allowedResourceActions"] = stringSliceToInterface(perm.GetAllowedResourceActions())
					}
					if perm.GetCondition() != nil {
						permMap["condition"] = *perm.GetCondition()
					}
					permissions = append(permissions, permMap)
				}
				roleDefMap["rolePermissions"] = permissions
			} else {
				roleDefMap["rolePermissions"] = []interface{}{}
			}

			allRoleDefs = append(allRoleDefs, roleDefMap)
		}

		totalObjects += len(roleDefs)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.RoleManagement().Directory().RoleDefinitions().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of role definitions", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated role definition collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allRoleDefs, nil
}

// collectAllDirectoryRoleAssignmentsWithPagination collects all directory role assignments using batched Graph API calls
//
// Performance Optimization: This function uses Microsoft Graph's $batch API to dramatically improve performance:
// - Reduces API calls from N (one per directory role) to N/15 (batched requests)
// - Expected 10-15x performance improvement for tenants with many directory roles
// - Maintains backward compatibility with existing data structures
// - Includes robust fallback mechanisms for batch failures or authentication issues
func (l *SDKComprehensiveCollectorLink) collectAllDirectoryRoleAssignmentsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Starting optimized batched directory role assignments collection")
	message.Info("Collecting directory role assignments from Graph SDK (batched)...")

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		l.Logger.Error("Failed to get access token, falling back to individual SDK calls", "error", err)
		return l.collectAllDirectoryRoleAssignmentsWithPaginationFallback(ctx)
	}

	// First, collect all directory roles
	var allRoles []interface{}
	directoryRolesResponse, err := l.graphClient.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get directory roles: %v", err)
	}

	// Process all pages of directory roles to collect role information
	for {
		roles := directoryRolesResponse.GetValue()
		l.Logger.Info("Collecting directory roles page", "roles", len(roles))

		for _, role := range roles {
			if role == nil || role.GetId() == nil {
				continue
			}

			roleMap := map[string]interface{}{
				"id": *role.GetId(),
			}
			if role.GetDisplayName() != nil {
				roleMap["displayName"] = *role.GetDisplayName()
			}
			if role.GetRoleTemplateId() != nil {
				roleMap["roleTemplateId"] = *role.GetRoleTemplateId()
			}
			allRoles = append(allRoles, roleMap)
		}

		// Check for next page of roles
		odataNextLink := directoryRolesResponse.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break
		}

		directoryRolesResponse, err = l.graphClient.DirectoryRoles().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of directory roles", "error", err)
			break
		}
	}

	l.Logger.Info("Collected all directory roles, starting batched member collection", "totalRoles", len(allRoles))

	// Process roles in batches for member collection
	batchSize := 15 // Microsoft Graph API batch limit is 20, use 15 for buffer
	for i := 0; i < len(allRoles); i += batchSize {
		end := i + batchSize
		if end > len(allRoles) {
			end = len(allRoles)
		}
		batchRoles := allRoles[i:end]

		l.Logger.Info("Processing role batch", "batch", fmt.Sprintf("%d/%d", (i/batchSize)+1, (len(allRoles)+batchSize-1)/batchSize), "roles", len(batchRoles))

		// Create batch requests for role members
		var batchRequests []map[string]interface{}
		roleDataMap := make(map[string]interface{})

		for j, role := range batchRoles {
			roleMap, ok := role.(map[string]interface{})
			if !ok {
				continue
			}

			roleID, ok := roleMap["id"].(string)
			if !ok {
				continue
			}

			roleDataMap[fmt.Sprintf("role_%d", j)] = roleMap

			// Add members request to batch
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("role_%d_members", j),
				"method": "GET",
				"url":    fmt.Sprintf("/directoryRoles/%s/members", roleID),
			})
		}

		// Execute batch request
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for directory role assignments, falling back to individual calls", "error", err)
				// Fallback to individual calls for this batch
				batchAssignments, err := l.processBatchRolesFallback(ctx, batchRoles)
				if err != nil {
					l.Logger.Error("Fallback processing failed for batch", "error", err)
					continue
				}
				allAssignments = append(allAssignments, batchAssignments...)
				totalObjects += len(batchAssignments)
				continue
			}

			// Process batch results
			if responses, ok := batchResults["responses"].([]interface{}); ok {
				for _, response := range responses {
					if respMap, ok := response.(map[string]interface{}); ok {
						// Check response status
						status, _ := respMap["status"].(float64)
						if status != 200 {
							l.Logger.Debug("Batch response failed", "status", status, "id", respMap["id"])
							continue
						}

						if body, ok := respMap["body"].(map[string]interface{}); ok {
							if value, ok := body["value"].([]interface{}); ok {
								for _, member := range value {
									if memberMap, ok := member.(map[string]interface{}); ok {
										memberID, ok := memberMap["id"].(string)
										if !ok {
											continue
										}

										// Extract role ID from request ID
										requestID, _ := respMap["id"].(string)
										roleIndex := strings.Replace(strings.Replace(requestID, "role_", "", 1), "_members", "", 1)

										// Find corresponding role
										if roleData, exists := roleDataMap[fmt.Sprintf("role_%s", roleIndex)]; exists {
											if roleInfo, ok := roleData.(map[string]interface{}); ok {
												roleID, _ := roleInfo["id"].(string)
												roleName, _ := roleInfo["displayName"].(string)
												roleTemplateId, _ := roleInfo["roleTemplateId"].(string)

												assignment := map[string]interface{}{
													"roleId":         roleID,
													"roleTemplateId": roleTemplateId,
													"roleName":       roleName,
													"principalId":    memberID,
												}

												// Add principal type if available
												if principalType, ok := memberMap["@odata.type"].(string); ok {
													assignment["principalType"] = principalType
												} else {
													assignment["principalType"] = "#microsoft.graph.directoryObject"
												}

												allAssignments = append(allAssignments, assignment)
												totalObjects++
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Small delay to avoid throttling
		time.Sleep(100 * time.Millisecond)
	}

	l.Logger.Info("Completed optimized batched directory role assignments collection", "totalAssignments", totalObjects, "totalRoles", len(allRoles))
	message.Info("Directory role assignments collection completed successfully! Collected %d assignments from %d roles", totalObjects, len(allRoles))
	return allAssignments, nil
}

// collectAllConditionalAccessPoliciesWithPagination collects all conditional access policies using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllConditionalAccessPoliciesWithPagination(ctx context.Context) ([]interface{}, error) {
	var allPolicies []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated conditional access policy collection")

	// Get first page
	response, err := l.graphClient.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of conditional access policies: %v", err)
	}

	for {
		pageCount++
		policies := response.GetValue()
		l.Logger.Info("Processing conditional access policy page", "page", pageCount, "objects", len(policies))

		// Convert policies from current page
		for _, policy := range policies {
			policyMap := map[string]interface{}{
				"id":               *policy.GetId(),
				"displayName":      stringPtrToInterface(policy.GetDisplayName()),
				"description":      stringPtrToInterface(policy.GetDescription()),
				"state":            stateToInterface(policy.GetState()),
				"createdDateTime":  timeToInterface(policy.GetCreatedDateTime()),
				"modifiedDateTime": timeToInterface(policy.GetModifiedDateTime()),
			}

			// Extract conditions
			if conditions := policy.GetConditions(); conditions != nil {
				conditionsMap := map[string]interface{}{}

				// User conditions
				if users := conditions.GetUsers(); users != nil {
					conditionsMap["users"] = map[string]interface{}{
						"includeUsers":  stringSliceToInterface(users.GetIncludeUsers()),
						"excludeUsers":  stringSliceToInterface(users.GetExcludeUsers()),
						"includeGroups": stringSliceToInterface(users.GetIncludeGroups()),
						"excludeGroups": stringSliceToInterface(users.GetExcludeGroups()),
						"includeRoles":  stringSliceToInterface(users.GetIncludeRoles()),
						"excludeRoles":  stringSliceToInterface(users.GetExcludeRoles()),
					}
				}

				// Application conditions
				if apps := conditions.GetApplications(); apps != nil {
					conditionsMap["applications"] = map[string]interface{}{
						"includeApplications": stringSliceToInterface(apps.GetIncludeApplications()),
						"excludeApplications": stringSliceToInterface(apps.GetExcludeApplications()),
						"includeUserActions":  stringSliceToInterface(apps.GetIncludeUserActions()),
					}
				}

				// Location conditions
				if locations := conditions.GetLocations(); locations != nil {
					conditionsMap["locations"] = map[string]interface{}{
						"includeLocations": stringSliceToInterface(locations.GetIncludeLocations()),
						"excludeLocations": stringSliceToInterface(locations.GetExcludeLocations()),
					}
				}

				// Platform conditions
				if platforms := conditions.GetPlatforms(); platforms != nil {
					includePlatforms := []interface{}{}
					for _, p := range platforms.GetIncludePlatforms() {
						includePlatforms = append(includePlatforms, p.String())
					}
					excludePlatforms := []interface{}{}
					for _, p := range platforms.GetExcludePlatforms() {
						excludePlatforms = append(excludePlatforms, p.String())
					}
					conditionsMap["platforms"] = map[string]interface{}{
						"includePlatforms": includePlatforms,
						"excludePlatforms": excludePlatforms,
					}
				}

				// Client app types
				if clientAppTypes := conditions.GetClientAppTypes(); clientAppTypes != nil {
					types := []interface{}{}
					for _, cat := range clientAppTypes {
						types = append(types, cat.String())
					}
					conditionsMap["clientAppTypes"] = types
				}

				// Risk levels
				if signInRiskLevels := conditions.GetSignInRiskLevels(); signInRiskLevels != nil {
					levels := []interface{}{}
					for _, rl := range signInRiskLevels {
						levels = append(levels, rl.String())
					}
					conditionsMap["signInRiskLevels"] = levels
				}
				if userRiskLevels := conditions.GetUserRiskLevels(); userRiskLevels != nil {
					levels := []interface{}{}
					for _, rl := range userRiskLevels {
						levels = append(levels, rl.String())
					}
					conditionsMap["userRiskLevels"] = levels
				}

				policyMap["conditions"] = conditionsMap
			}

			// Extract grant controls
			if grantControls := policy.GetGrantControls(); grantControls != nil {
				gcMap := map[string]interface{}{
					"operator": stringPtrToInterface(grantControls.GetOperator()),
				}
				if builtInControls := grantControls.GetBuiltInControls(); builtInControls != nil {
					controls := []interface{}{}
					for _, c := range builtInControls {
						controls = append(controls, c.String())
					}
					gcMap["builtInControls"] = controls
				}
				if termsOfUse := grantControls.GetTermsOfUse(); termsOfUse != nil {
					gcMap["termsOfUse"] = stringSliceToInterface(termsOfUse)
				}
				policyMap["grantControls"] = gcMap
			}

			// Extract session controls
			if sessionControls := policy.GetSessionControls(); sessionControls != nil {
				scMap := map[string]interface{}{}
				if signInFreq := sessionControls.GetSignInFrequency(); signInFreq != nil {
					freqMap := map[string]interface{}{
						"isEnabled": boolPtrToInterface(signInFreq.GetIsEnabled()),
					}
					if signInFreq.GetValue() != nil {
						freqMap["value"] = *signInFreq.GetValue()
					}
					if signInFreq.GetTypeEscaped() != nil {
						freqMap["type"] = signInFreq.GetTypeEscaped().String()
					}
					scMap["signInFrequency"] = freqMap
				}
				if persistentBrowser := sessionControls.GetPersistentBrowser(); persistentBrowser != nil {
					pbMap := map[string]interface{}{
						"isEnabled": boolPtrToInterface(persistentBrowser.GetIsEnabled()),
					}
					if persistentBrowser.GetMode() != nil {
						pbMap["mode"] = persistentBrowser.GetMode().String()
					}
					scMap["persistentBrowser"] = pbMap
				}
				if disableResilience := sessionControls.GetDisableResilienceDefaults(); disableResilience != nil {
					scMap["disableResilienceDefaults"] = *disableResilience
				}
				policyMap["sessionControls"] = scMap
			}

			allPolicies = append(allPolicies, policyMap)
		}

		totalObjects += len(policies)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.Identity().ConditionalAccess().Policies().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of conditional access policies", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated conditional access policy collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allPolicies, nil
}

// enrichUsersWithManagerSDK adds managerId to each user by querying the manager relationship
func (l *SDKComprehensiveCollectorLink) enrichUsersWithManagerSDK(ctx context.Context, azureADData map[string]interface{}) {
	usersData, ok := azureADData["users"]
	if !ok {
		return
	}
	users, ok := usersData.([]interface{})
	if !ok {
		return
	}

	enrichedCount := 0
	for _, userInterface := range users {
		userMap, ok := userInterface.(map[string]interface{})
		if !ok {
			continue
		}
		userID, ok := userMap["id"].(string)
		if !ok || userID == "" {
			continue
		}

		manager, err := l.graphClient.Users().ByUserId(userID).Manager().Get(ctx, nil)
		if err != nil {
			continue // Not all users have managers (e.g., top-level accounts)
		}
		if manager != nil {
			if ad := manager.GetAdditionalData(); ad != nil {
				if id, ok := ad["id"]; ok {
					userMap["managerId"] = id
					enrichedCount++
				}
			}
		}
	}

	l.Logger.Info("Enriched users with manager relationships", "count", enrichedCount)
}

// collectAllNamedLocationsWithPagination collects all named locations using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllNamedLocationsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allLocations []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated named location collection")

	response, err := l.graphClient.Identity().ConditionalAccess().NamedLocations().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of named locations: %v", err)
	}

	for {
		pageCount++
		locations := response.GetValue()
		l.Logger.Info("Processing named location page", "page", pageCount, "objects", len(locations))

		for _, location := range locations {
			locMap := map[string]interface{}{
				"id":              location.GetId(),
				"displayName":     stringPtrToInterface(location.GetDisplayName()),
				"createdDateTime": timeToInterface(location.GetCreatedDateTime()),
			}

			if additionalData := location.GetAdditionalData(); additionalData != nil {
				if isTrusted, ok := additionalData["isTrusted"]; ok {
					locMap["isTrusted"] = isTrusted
				}
				if ipRanges, ok := additionalData["ipRanges"]; ok {
					locMap["ipRanges"] = ipRanges
				}
				if countriesAndRegions, ok := additionalData["countriesAndRegions"]; ok {
					locMap["countriesAndRegions"] = countriesAndRegions
				}
				if odataType, ok := additionalData["@odata.type"]; ok {
					locMap["locationType"] = odataType
				}
			}

			allLocations = append(allLocations, locMap)
		}

		totalObjects += len(locations)

		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break
		}

		response, err = l.graphClient.Identity().ConditionalAccess().NamedLocations().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of named locations", "error", err, "page", pageCount+1)
			break
		}
	}

	l.Logger.Info("Completed paginated named location collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allLocations, nil
}

// collectAllAdministrativeUnitsWithPagination collects all administrative units using proper pagination
func (l *SDKComprehensiveCollectorLink) collectAllAdministrativeUnitsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allUnits []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated administrative unit collection")

	response, err := l.graphClient.Directory().AdministrativeUnits().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of administrative units: %v", err)
	}

	for {
		pageCount++
		units := response.GetValue()
		l.Logger.Info("Processing administrative unit page", "page", pageCount, "objects", len(units))

		for _, unit := range units {
			unitMap := map[string]interface{}{
				"id":              *unit.GetId(),
				"displayName":     stringPtrToInterface(unit.GetDisplayName()),
				"description":     stringPtrToInterface(unit.GetDescription()),
				"visibility":      stringPtrToInterface(unit.GetVisibility()),
			}
			if membershipType := unit.GetMembershipType(); membershipType != nil {
				unitMap["membershipType"] = *membershipType
			}
			if membershipRule := unit.GetMembershipRule(); membershipRule != nil {
				unitMap["membershipRule"] = *membershipRule
			}
			allUnits = append(allUnits, unitMap)
		}

		totalObjects += len(units)

		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break
		}

		response, err = l.graphClient.Directory().AdministrativeUnits().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of administrative units", "error", err, "page", pageCount+1)
			break
		}
	}

	l.Logger.Info("Completed paginated administrative unit collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allUnits, nil
}

// decodeResourceGraphData extracts resource data from Resource Graph response and appends to resources slice
func decodeResourceGraphData(responseData interface{}, resources *[]interface{}) {
	if responseData == nil {
		return
	}

	// The response.Data is typically a map or slice - convert appropriately
	if dataSlice, ok := responseData.([]interface{}); ok {
		*resources = append(*resources, dataSlice...)
	} else if dataMap, ok := responseData.(map[string]interface{}); ok {
		if rows, exists := dataMap["rows"]; exists {
			if rowsSlice, ok := rows.([]interface{}); ok {
				// Convert rows to structured objects if needed
				for _, row := range rowsSlice {
					if rowSlice, ok := row.([]interface{}); ok && len(rowSlice) > 0 {
						// Create resource object from row data
						// This is a simplified conversion - may need refinement
						resourceObj := map[string]interface{}{
							"id": rowSlice[0],
						}
						if len(rowSlice) > 1 { resourceObj["name"] = rowSlice[1] }
						if len(rowSlice) > 2 { resourceObj["type"] = rowSlice[2] }
						if len(rowSlice) > 3 { resourceObj["location"] = rowSlice[3] }
						if len(rowSlice) > 4 { resourceObj["resourceGroup"] = rowSlice[4] }
						if len(rowSlice) > 5 { resourceObj["subscriptionId"] = rowSlice[5] }

						*resources = append(*resources, resourceObj)
					}
				}
			}
		}
	}
}

// collectAllGroupMembershipsWithPagination collects all group membership relationships using concurrent batched Graph API calls.
// If preCollectedGroups is non-nil and non-empty, uses those instead of re-fetching.
// Uses concurrent workers for batch execution and handles intra-batch pagination for large groups.
func (l *SDKComprehensiveCollectorLink) collectAllGroupMembershipsWithPagination(ctx context.Context, preCollectedGroups ...[]interface{}) ([]interface{}, error) {
	var allMemberships []interface{}
	totalObjects := 0

	l.Logger.Info("Starting concurrent batched group memberships collection")
	message.Info("Collecting group memberships from Graph SDK (concurrent batched)...")

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		l.Logger.Error("Failed to get access token, falling back to individual SDK calls", "error", err)
		return l.collectAllGroupMembershipsWithPaginationFallback(ctx)
	}

	// Use pre-collected groups if provided, otherwise fetch
	var allGroups []interface{}
	if len(preCollectedGroups) > 0 && len(preCollectedGroups[0]) > 0 {
		// Extract just id and displayName from pre-collected groups
		for _, g := range preCollectedGroups[0] {
			if gMap, ok := g.(map[string]interface{}); ok {
				if id, ok := gMap["id"].(string); ok {
					groupMap := map[string]interface{}{"id": id}
					if dn, ok := gMap["displayName"].(string); ok {
						groupMap["displayName"] = dn
					}
					allGroups = append(allGroups, groupMap)
				}
			}
		}
		l.Logger.Info("Using pre-collected groups for membership collection", "totalGroups", len(allGroups))
	} else {
		// Fetch groups from scratch (fallback)
		groupsResponse, err := l.graphClient.Groups().Get(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get groups for membership collection: %v", err)
		}
		for {
			groups := groupsResponse.GetValue()
			for _, group := range groups {
				if group == nil || group.GetId() == nil {
					continue
				}
				groupMap := map[string]interface{}{"id": *group.GetId()}
				if group.GetDisplayName() != nil {
					groupMap["displayName"] = *group.GetDisplayName()
				}
				allGroups = append(allGroups, groupMap)
			}
			odataNextLink := groupsResponse.GetOdataNextLink()
			if odataNextLink == nil || *odataNextLink == "" {
				break
			}
			groupsResponse, err = l.graphClient.Groups().WithUrl(*odataNextLink).Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get next page of groups", "error", err)
				break
			}
		}
		l.Logger.Info("Fetched groups for membership collection", "totalGroups", len(allGroups))
	}

	// Build all batch work upfront
	batchSize := 20 // Graph API batch limit
	var batches []batchWork
	// groupDataMaps stores per-batch group lookup maps
	type batchMeta struct {
		groupDataMap map[string]interface{}
	}
	var batchMetas []batchMeta

	for i := 0; i < len(allGroups); i += batchSize {
		end := i + batchSize
		if end > len(allGroups) {
			end = len(allGroups)
		}
		batchGroups := allGroups[i:end]

		var batchRequests []map[string]interface{}
		groupDataMap := make(map[string]interface{})

		for j, group := range batchGroups {
			groupMap, ok := group.(map[string]interface{})
			if !ok {
				continue
			}
			groupID, ok := groupMap["id"].(string)
			if !ok {
				continue
			}
			groupDataMap[fmt.Sprintf("group_%d", j)] = groupMap
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("group_%d_members", j),
				"method": "GET",
				"url":    fmt.Sprintf("/groups/%s/members", groupID),
			})
		}

		if len(batchRequests) > 0 {
			batches = append(batches, batchWork{index: len(batches), requests: batchRequests})
			batchMetas = append(batchMetas, batchMeta{groupDataMap: groupDataMap})
		}
	}

	l.Logger.Info("Executing concurrent group membership batches", "totalBatches", len(batches), "workers", 5, "totalGroups", len(allGroups))

	// Execute all batches concurrently with 5 workers
	results := l.executeBatchesConcurrently(ctx, accessToken, batches, 5)

	// Phase 1: Extract first-page members and identify groups needing pagination
	type groupResult struct {
		groupID   string
		firstPage []interface{}
		nextLink  string
	}
	var smallGroups []groupResult  // groups with <=100 members (no pagination needed)
	var largeGroups []groupResult  // groups with >100 members (need pagination follow-up)

	for idx, result := range results {
		if result.err != nil {
			l.Logger.Error("Batch failed for group memberships", "batch", idx, "error", result.err)
			continue
		}

		meta := batchMetas[idx]

		for _, response := range result.responses {
			respMap, ok := response.(map[string]interface{})
			if !ok {
				continue
			}

			status, _ := respMap["status"].(float64)
			if status != 200 {
				l.Logger.Debug("Batch response failed", "status", status, "id", respMap["id"])
				continue
			}

			body, ok := respMap["body"].(map[string]interface{})
			if !ok {
				continue
			}

			// Extract group ID from request ID
			requestID, _ := respMap["id"].(string)
			groupIndex := strings.Replace(strings.Replace(requestID, "group_", "", 1), "_members", "", 1)
			groupData, exists := meta.groupDataMap[fmt.Sprintf("group_%s", groupIndex)]
			if !exists {
				continue
			}
			groupInfo, ok := groupData.(map[string]interface{})
			if !ok {
				continue
			}
			groupID, _ := groupInfo["id"].(string)

			var firstPage []interface{}
			if value, ok := body["value"].([]interface{}); ok {
				firstPage = value
			}

			if nextLink, ok := body["@odata.nextLink"].(string); ok && nextLink != "" {
				largeGroups = append(largeGroups, groupResult{groupID: groupID, firstPage: firstPage, nextLink: nextLink})
			} else {
				smallGroups = append(smallGroups, groupResult{groupID: groupID, firstPage: firstPage})
			}
		}
	}

	l.Logger.Info("Batch results parsed", "smallGroups", len(smallGroups), "largeGroups", len(largeGroups))

	// Phase 2: Parallel pagination for large groups
	type paginatedResult struct {
		groupID string
		members []interface{}
	}
	paginatedResults := make([]paginatedResult, len(largeGroups))

	if len(largeGroups) > 0 {
		var pgWg sync.WaitGroup
		sem := make(chan struct{}, 10) // 10 concurrent pagination workers
		var pgCompleted int64

		for i, lg := range largeGroups {
			pgWg.Add(1)
			sem <- struct{}{}
			go func(idx int, g groupResult) {
				defer pgWg.Done()
				defer func() { <-sem }()
				additional := l.followPaginationLink(ctx, accessToken, g.nextLink)
				allMembers := make([]interface{}, 0, len(g.firstPage)+len(additional))
				allMembers = append(allMembers, g.firstPage...)
				allMembers = append(allMembers, additional...)
				paginatedResults[idx] = paginatedResult{groupID: g.groupID, members: allMembers}
				n := atomic.AddInt64(&pgCompleted, 1)
				if n%10 == 0 || n == int64(len(largeGroups)) {
					l.Logger.Info("Pagination progress", "completed", n, "total", len(largeGroups))
				}
			}(i, lg)
		}
		pgWg.Wait()
		l.Logger.Info("All large group pagination complete", "groups", len(largeGroups))
	}

	// Phase 3: Merge all memberships
	addMemberships := func(groupID string, members []interface{}) {
		for _, member := range members {
			memberMap, ok := member.(map[string]interface{})
			if !ok {
				continue
			}
			memberID, ok := memberMap["id"].(string)
			if !ok {
				continue
			}
			membership := map[string]interface{}{
				"groupId":  groupID,
				"memberId": memberID,
			}
			if memberType, ok := memberMap["@odata.type"].(string); ok {
				membership["memberType"] = memberType
			}
			allMemberships = append(allMemberships, membership)
			totalObjects++
		}
	}

	for _, sg := range smallGroups {
		addMemberships(sg.groupID, sg.firstPage)
	}
	for _, pr := range paginatedResults {
		addMemberships(pr.groupID, pr.members)
	}

	l.Logger.Info("Completed concurrent batched group memberships collection", "totalMemberships", totalObjects, "totalGroups", len(allGroups))
	message.Info("Group memberships collection completed! Collected %d memberships from %d groups", totalObjects, len(allGroups))
	return allMemberships, nil
}

// collectAllGroupMembershipsWithPaginationFallback is the original implementation used as fallback
func (l *SDKComprehensiveCollectorLink) collectAllGroupMembershipsWithPaginationFallback(ctx context.Context) ([]interface{}, error) {
	var allMemberships []interface{}
	totalObjects := 0

	l.Logger.Info("Using fallback method for group memberships collection")
	message.Info("Collecting group memberships from Graph SDK (fallback)...")

	// Get first page of groups
	groupsResponse, err := l.graphClient.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups for membership collection: %v", err)
	}

	// Process all pages of groups
	for {
		groups := groupsResponse.GetValue()
		l.Logger.Info("Processing groups page (fallback)", "groups", len(groups))

		// Process each group in current page
		for _, group := range groups {
			if group == nil || group.GetId() == nil {
				continue
			}

			groupId := *group.GetId()
			groupDisplayName := ""
			if group.GetDisplayName() != nil {
				groupDisplayName = *group.GetDisplayName()
			}

			l.Logger.Debug("Processing group (fallback)", "groupId", groupId, "displayName", groupDisplayName)

			// Get members of this group with pagination
			membersResponse, err := l.graphClient.Groups().ByGroupId(groupId).Members().Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get members for group", "groupId", groupId, "error", err)
				continue
			}

			// Process all pages of members
			for membersResponse != nil {
				members := membersResponse.GetValue()
				l.Logger.Debug("Processing members page (fallback)", "groupId", groupId, "members", len(members))

				// Convert members to membership relationships
				for _, member := range members {
					if member == nil || member.GetId() == nil {
						continue
					}

					membershipMap := map[string]interface{}{
						"groupId":  groupId,
						"memberId": *member.GetId(),
					}

					// Add member type if available
					if member.GetOdataType() != nil {
						membershipMap["memberType"] = *member.GetOdataType()
					}

					allMemberships = append(allMemberships, membershipMap)
					totalObjects++
				}

				// Check for next page
				odataNextLink := membersResponse.GetOdataNextLink()
				if odataNextLink == nil || *odataNextLink == "" {
					break
				}

				// Get next page of members
				membersResponse, err = l.graphClient.Groups().ByGroupId(groupId).Members().WithUrl(*odataNextLink).Get(ctx, nil)
				if err != nil {
					l.Logger.Error("Failed to get next page of members", "groupId", groupId, "error", err)
					break
				}
			}
		}

		// Check for next page of groups
		odataNextLink := groupsResponse.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break
		}

		groupsResponse, err = l.graphClient.Groups().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of groups", "error", err)
			break
		}
	}

	l.Logger.Info("Completed fallback group memberships collection", "totalMemberships", totalObjects)
	message.Info("Group memberships collection completed successfully! Collected %d memberships (fallback mode)", totalObjects)
	return allMemberships, nil
}

// processBatchGroupsFallback processes a batch of groups using individual SDK calls when batch fails
func (l *SDKComprehensiveCollectorLink) processBatchGroupsFallback(ctx context.Context, batchGroups []interface{}) ([]interface{}, error) {
	var memberships []interface{}

	for _, group := range batchGroups {
		groupMap, ok := group.(map[string]interface{})
		if !ok {
			continue
		}

		groupID, ok := groupMap["id"].(string)
		if !ok {
			continue
		}

		l.Logger.Debug("Processing group (batch fallback)", "groupId", groupID)

		// Get members using SDK
		membersResponse, err := l.graphClient.Groups().ByGroupId(groupID).Members().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get members for group (batch fallback)", "groupId", groupID, "error", err)
			continue
		}

		// Process all pages of members
		for membersResponse != nil {
			members := membersResponse.GetValue()

			// Convert members to membership relationships
			for _, member := range members {
				if member == nil || member.GetId() == nil {
					continue
				}

				membershipMap := map[string]interface{}{
					"groupId":  groupID,
					"memberId": *member.GetId(),
				}

				// Add member type if available
				if member.GetOdataType() != nil {
					membershipMap["memberType"] = *member.GetOdataType()
				}

				memberships = append(memberships, membershipMap)
			}

			// Check for next page
			odataNextLink := membersResponse.GetOdataNextLink()
			if odataNextLink == nil || *odataNextLink == "" {
				break
			}

			// Get next page of members
			membersResponse, err = l.graphClient.Groups().ByGroupId(groupID).Members().WithUrl(*odataNextLink).Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get next page of members (batch fallback)", "groupId", groupID, "error", err)
				break
			}
		}
	}

	return memberships, nil
}

// collectAllDirectoryRoleAssignmentsWithPaginationFallback is the original implementation used as fallback
func (l *SDKComprehensiveCollectorLink) collectAllDirectoryRoleAssignmentsWithPaginationFallback(ctx context.Context) ([]interface{}, error) {
	var allAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Using fallback method for directory role assignments collection")
	message.Info("Collecting directory role assignments from Graph SDK (fallback)...")

	// First, get all directory roles
	directoryRolesResponse, err := l.graphClient.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get directory roles: %v", err)
	}

	directoryRoles := directoryRolesResponse.GetValue()
	l.Logger.Info("Processing directory role assignments (fallback)", "roles", len(directoryRoles))

	// For each directory role, get its members
	for _, role := range directoryRoles {
		if role == nil || role.GetId() == nil {
			continue
		}

		roleId := *role.GetId()
		roleName := ""
		if role.GetDisplayName() != nil {
			roleName = *role.GetDisplayName()
		}
		roleTemplateId := ""
		if role.GetRoleTemplateId() != nil {
			roleTemplateId = *role.GetRoleTemplateId()
		}

		l.Logger.Debug("Processing role (fallback)", "roleId", roleId, "roleName", roleName)

		// Get members of this directory role with pagination
		membersResponse, err := l.graphClient.DirectoryRoles().ByDirectoryRoleId(roleId).Members().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get members for directory role", "roleId", roleId, "error", err)
			continue
		}

		// Process all pages of members
		for membersResponse != nil {
			members := membersResponse.GetValue()
			l.Logger.Debug("Processing members page (fallback)", "roleId", roleId, "members", len(members))

			// Convert members to assignments
			for _, member := range members {
				if member == nil {
					continue
				}

				memberMap := map[string]interface{}{
					"roleId":         roleId,
					"roleTemplateId": roleTemplateId,
					"roleName":       roleName,
				}

				// Extract principal information based on type
				if member.GetId() != nil {
					memberMap["principalId"] = *member.GetId()
				}

				// Determine principal type from OData type
				odataType := member.GetOdataType()
				if odataType != nil {
					memberMap["principalType"] = *odataType
				} else {
					// Fallback to generic type
					memberMap["principalType"] = "#microsoft.graph.directoryObject"
				}

				allAssignments = append(allAssignments, memberMap)
				totalObjects++
			}

			// Check for next page
			odataNextLink := membersResponse.GetOdataNextLink()
			if odataNextLink == nil || *odataNextLink == "" {
				break
			}

			// Get next page of members
			membersResponse, err = l.graphClient.DirectoryRoles().ByDirectoryRoleId(roleId).Members().WithUrl(*odataNextLink).Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get next page of members", "roleId", roleId, "error", err)
				break
			}
		}
	}

	l.Logger.Info("Completed fallback directory role assignments collection", "totalAssignments", totalObjects)
	message.Info("Directory role assignments collection completed successfully! Collected %d assignments (fallback mode)", totalObjects)
	return allAssignments, nil
}

// processBatchRolesFallback processes a batch of roles using individual SDK calls when batch fails
func (l *SDKComprehensiveCollectorLink) processBatchRolesFallback(ctx context.Context, batchRoles []interface{}) ([]interface{}, error) {
	var assignments []interface{}

	for _, role := range batchRoles {
		roleMap, ok := role.(map[string]interface{})
		if !ok {
			continue
		}

		roleID, ok := roleMap["id"].(string)
		if !ok {
			continue
		}

		l.Logger.Debug("Processing role (batch fallback)", "roleId", roleID)

		// Get members using SDK
		membersResponse, err := l.graphClient.DirectoryRoles().ByDirectoryRoleId(roleID).Members().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get members for directory role (batch fallback)", "roleId", roleID, "error", err)
			continue
		}

		roleName, _ := roleMap["displayName"].(string)
		roleTemplateId, _ := roleMap["roleTemplateId"].(string)

		// Process all pages of members
		for membersResponse != nil {
			members := membersResponse.GetValue()

			// Convert members to assignments
			for _, member := range members {
				if member == nil || member.GetId() == nil {
					continue
				}

				assignmentMap := map[string]interface{}{
					"roleId":         roleID,
					"roleTemplateId": roleTemplateId,
					"roleName":       roleName,
					"principalId":    *member.GetId(),
				}

				// Add principal type if available
				if member.GetOdataType() != nil {
					assignmentMap["principalType"] = *member.GetOdataType()
				} else {
					assignmentMap["principalType"] = "#microsoft.graph.directoryObject"
				}

				assignments = append(assignments, assignmentMap)
			}

			// Check for next page
			odataNextLink := membersResponse.GetOdataNextLink()
			if odataNextLink == nil || *odataNextLink == "" {
				break
			}

			// Get next page of members
			membersResponse, err = l.graphClient.DirectoryRoles().ByDirectoryRoleId(roleID).Members().WithUrl(*odataNextLink).Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get next page of members (batch fallback)", "roleId", roleID, "error", err)
				break
			}
		}
	}

	return assignments, nil
}

// collectAllOAuth2PermissionGrantsWithPagination collects all OAuth2 permission grants using Graph SDK
func (l *SDKComprehensiveCollectorLink) collectAllOAuth2PermissionGrantsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allGrants []interface{}
	pageCount := 0
	totalObjects := 0

	l.Logger.Info("Starting paginated OAuth2 permission grants collection")

	// Get first page
	response, err := l.graphClient.Oauth2PermissionGrants().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of OAuth2 permission grants: %v", err)
	}

	for {
		pageCount++
		grants := response.GetValue()
		l.Logger.Info("Processing OAuth2 grants page", "page", pageCount, "objects", len(grants))

		// Convert grants from current page
		for _, grant := range grants {
			grantMap := map[string]interface{}{
				"id":           *grant.GetId(),
				"clientId":     stringPtrToInterface(grant.GetClientId()),
				"resourceId":   stringPtrToInterface(grant.GetResourceId()),
				"principalId":  stringPtrToInterface(grant.GetPrincipalId()),
				"scope":        stringPtrToInterface(grant.GetScope()),
				"consentType":  stringPtrToInterface(grant.GetConsentType()),
			}
			allGrants = append(allGrants, grantMap)
		}

		totalObjects += len(grants)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
		response, err = l.graphClient.Oauth2PermissionGrants().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of OAuth2 permission grants", "error", err, "page", pageCount+1)
			break // Continue with what we have
		}
	}

	l.Logger.Info("Completed paginated OAuth2 permission grants collection", "totalPages", pageCount, "totalObjects", totalObjects)
	return allGrants, nil
}

// collectAllAppRoleAssignmentsWithPagination collects all app role assignments using concurrent batched Graph API calls.
// If preCollectedSPs is non-nil and non-empty, uses those instead of re-fetching.
// Uses concurrent workers and handles intra-batch pagination.
func (l *SDKComprehensiveCollectorLink) collectAllAppRoleAssignmentsWithPagination(ctx context.Context, preCollectedSPs ...[]interface{}) ([]interface{}, error) {
	var allAppRoleAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Starting concurrent batched app role assignments collection")
	message.Info("Collecting app role assignments from Graph SDK (concurrent batched)...")

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		l.Logger.Error("Failed to get access token, falling back to individual SDK calls", "error", err)
		return l.collectAllAppRoleAssignmentsWithPaginationFallback(ctx)
	}

	// Use pre-collected SPs if provided, otherwise fetch
	var allServicePrincipals []interface{}
	if len(preCollectedSPs) > 0 && len(preCollectedSPs[0]) > 0 {
		for _, sp := range preCollectedSPs[0] {
			if spMap, ok := sp.(map[string]interface{}); ok {
				if id, ok := spMap["id"].(string); ok {
					m := map[string]interface{}{"id": id}
					if dn, ok := spMap["displayName"].(string); ok {
						m["displayName"] = dn
					}
					allServicePrincipals = append(allServicePrincipals, m)
				}
			}
		}
		l.Logger.Info("Using pre-collected service principals for app role assignments", "totalSPs", len(allServicePrincipals))
	} else {
		// Fetch SPs from scratch (fallback)
		servicePrincipalsResponse, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get service principals for app role assignments: %v", err)
		}
		for {
			sps := servicePrincipalsResponse.GetValue()
			for _, sp := range sps {
				if sp == nil || sp.GetId() == nil {
					continue
				}
				spMap := map[string]interface{}{"id": *sp.GetId()}
				if sp.GetDisplayName() != nil {
					spMap["displayName"] = *sp.GetDisplayName()
				}
				allServicePrincipals = append(allServicePrincipals, spMap)
			}
			odataNextLink := servicePrincipalsResponse.GetOdataNextLink()
			if odataNextLink == nil || *odataNextLink == "" {
				break
			}
			servicePrincipalsResponse, err = l.graphClient.ServicePrincipals().WithUrl(*odataNextLink).Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get next page of service principals", "error", err)
				break
			}
		}
		l.Logger.Info("Fetched service principals for app role assignments", "totalSPs", len(allServicePrincipals))
	}

	// Build all batch work upfront
	// 10 SPs per batch = 20 requests (Graph API max)
	batchSize := 10
	var batches []batchWork
	type spBatchMeta struct {
		spDataMap map[string]interface{}
	}
	var batchMetas []spBatchMeta

	for i := 0; i < len(allServicePrincipals); i += batchSize {
		end := i + batchSize
		if end > len(allServicePrincipals) {
			end = len(allServicePrincipals)
		}
		batchSPs := allServicePrincipals[i:end]

		var batchRequests []map[string]interface{}
		spDataMap := make(map[string]interface{})

		for j, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}
			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}
			spDataMap[fmt.Sprintf("sp_%d", j)] = spMap

			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("sp_%d_assignedTo", j),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignedTo", spID),
			})
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("sp_%d_assignments", j),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignments", spID),
			})
		}

		if len(batchRequests) > 0 {
			batches = append(batches, batchWork{index: len(batches), requests: batchRequests})
			batchMetas = append(batchMetas, spBatchMeta{spDataMap: spDataMap})
		}
	}

	l.Logger.Info("Executing concurrent app role assignment batches", "totalBatches", len(batches), "workers", 5, "totalSPs", len(allServicePrincipals))

	// Execute all batches concurrently with 5 workers
	results := l.executeBatchesConcurrently(ctx, accessToken, batches, 5)

	// Process results in order
	for idx, result := range results {
		if result.err != nil {
			l.Logger.Error("Batch failed for app role assignments", "batch", idx, "error", result.err)
			continue
		}

		meta := batchMetas[idx]

		for _, response := range result.responses {
			respMap, ok := response.(map[string]interface{})
			if !ok {
				continue
			}

			status, _ := respMap["status"].(float64)
			if status != 200 {
				l.Logger.Debug("Batch response failed", "status", status, "id", respMap["id"])
				continue
			}

			body, ok := respMap["body"].(map[string]interface{})
			if !ok {
				continue
			}

			// Extract SP index and assignment type from request ID
			requestID, _ := respMap["id"].(string)
			var spIndex string
			var assignmentType string

			if strings.Contains(requestID, "_assignedTo") {
				spIndex = strings.Replace(strings.Replace(requestID, "sp_", "", 1), "_assignedTo", "", 1)
				assignmentType = "AppRoleAssignedTo"
			} else if strings.Contains(requestID, "_assignments") {
				spIndex = strings.Replace(strings.Replace(requestID, "sp_", "", 1), "_assignments", "", 1)
				assignmentType = "AppRoleAssignments"
			} else {
				continue
			}

			spData, exists := meta.spDataMap[fmt.Sprintf("sp_%s", spIndex)]
			if !exists {
				continue
			}
			spInfo, ok := spData.(map[string]interface{})
			if !ok {
				continue
			}
			spID, _ := spInfo["id"].(string)
			spDisplayName, _ := spInfo["displayName"].(string)

			// Determine direction (matching HTTP version field)
			direction := "assigned_to"
			if assignmentType == "AppRoleAssignedTo" {
				direction = "assigned_from"
			}

			// Process assignments from first page
			var assignments []interface{}
			if value, ok := body["value"].([]interface{}); ok {
				assignments = append(assignments, value...)
			}

			// Handle pagination for SPs with many assignments
			if nextLink, ok := body["@odata.nextLink"].(string); ok && nextLink != "" {
				additional := l.followPaginationLink(ctx, accessToken, nextLink)
				assignments = append(assignments, additional...)
			}

			for _, assignment := range assignments {
				assignmentMap, ok := assignment.(map[string]interface{})
				if !ok {
					continue
				}
				assignmentID, ok := assignmentMap["id"].(string)
				if !ok {
					continue
				}

				appRoleAssignment := map[string]interface{}{
					"id":                          assignmentID,
					"assignmentType":              assignmentType,
					"serviceOnSpId":               spID,
					"direction":                   direction,
					"servicePrincipalId":          spID,
					"servicePrincipalDisplayName": spDisplayName,
				}

				if v, ok := assignmentMap["principalId"].(string); ok {
					appRoleAssignment["principalId"] = v
				}
				if v, ok := assignmentMap["principalDisplayName"].(string); ok {
					appRoleAssignment["principalDisplayName"] = v
				}
				if v, ok := assignmentMap["principalType"].(string); ok {
					appRoleAssignment["principalType"] = v
				}
				if v, ok := assignmentMap["resourceId"].(string); ok {
					appRoleAssignment["resourceId"] = v
				}
				if v, ok := assignmentMap["resourceDisplayName"].(string); ok {
					appRoleAssignment["resourceDisplayName"] = v
				}
				if v, ok := assignmentMap["appRoleId"].(string); ok {
					appRoleAssignment["appRoleId"] = v
				}
				if v, ok := assignmentMap["createdDateTime"].(string); ok {
					appRoleAssignment["createdDateTime"] = v
				}

				allAppRoleAssignments = append(allAppRoleAssignments, appRoleAssignment)
				totalObjects++
			}
		}
	}

	l.Logger.Info("Completed concurrent batched app role assignments collection", "totalAssignments", totalObjects, "totalSPs", len(allServicePrincipals))
	message.Info("App role assignments collection completed! Collected %d assignments from %d service principals", totalObjects, len(allServicePrincipals))
	return allAppRoleAssignments, nil
}

// collectAllAppRoleAssignmentsWithPaginationFallback is the original implementation used as fallback
func (l *SDKComprehensiveCollectorLink) collectAllAppRoleAssignmentsWithPaginationFallback(ctx context.Context) ([]interface{}, error) {
	var allAppRoleAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Using fallback method for app role assignments collection")
	message.Info("Collecting app role assignments from Graph SDK (fallback)...")

	// Get first page of service principals
	servicePrincipalsResponse, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get service principals for app role assignments: %v", err)
	}

	// Process all pages of service principals
	for {
		servicePrincipals := servicePrincipalsResponse.GetValue()
		l.Logger.Info("Processing service principals page (fallback)", "servicePrincipals", len(servicePrincipals))

		// For each service principal in current page, get both appRoleAssignedTo and appRoleAssignments
		for _, sp := range servicePrincipals {
			if sp == nil || sp.GetId() == nil {
				continue
			}

			spId := *sp.GetId()
			spDisplayName := ""
			if sp.GetDisplayName() != nil {
				spDisplayName = *sp.GetDisplayName()
			}

			l.Logger.Debug("Processing service principal (fallback)", "spId", spId, "displayName", spDisplayName)

			// Get appRoleAssignedTo (roles assigned TO this service principal)
			assignedToResponse, err := l.graphClient.ServicePrincipals().ByServicePrincipalId(spId).AppRoleAssignedTo().Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get appRoleAssignedTo for service principal", "spId", spId, "error", err)
			} else {
				// Process all pages of appRoleAssignedTo
				for assignedToResponse != nil {
					assignments := assignedToResponse.GetValue()
					l.Logger.Debug("Processing appRoleAssignedTo page (fallback)", "spId", spId, "assignments", len(assignments))

					for _, assignment := range assignments {
						if assignment == nil || assignment.GetId() == nil {
							continue
						}

						assignmentMap := map[string]interface{}{
							"id":               *assignment.GetId(),
							"principalId":      uuidPtrToInterface(assignment.GetPrincipalId()),
							"principalDisplayName": stringPtrToInterface(assignment.GetPrincipalDisplayName()),
							"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
							"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
							"resourceDisplayName": stringPtrToInterface(assignment.GetResourceDisplayName()),
							"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
							"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
							"assignmentType":   "AppRoleAssignedTo",
							"direction":        "assigned_from",
							"servicePrincipalId":          spId,
							"servicePrincipalDisplayName": spDisplayName,
						}
						allAppRoleAssignments = append(allAppRoleAssignments, assignmentMap)
						totalObjects++
					}

					// Check for next page
					odataNextLink := assignedToResponse.GetOdataNextLink()
					if odataNextLink == nil || *odataNextLink == "" {
						break
					}

					// Get next page
					assignedToResponse, err = l.graphClient.ServicePrincipals().ByServicePrincipalId(spId).AppRoleAssignedTo().WithUrl(*odataNextLink).Get(ctx, nil)
					if err != nil {
						l.Logger.Error("Failed to get next page of appRoleAssignedTo", "spId", spId, "error", err)
						break
					}
				}
			}

			// Get appRoleAssignments (roles assigned BY this service principal to others)
			assignmentsResponse, err := l.graphClient.ServicePrincipals().ByServicePrincipalId(spId).AppRoleAssignments().Get(ctx, nil)
			if err != nil {
				l.Logger.Error("Failed to get appRoleAssignments for service principal", "spId", spId, "error", err)
			} else {
				// Process all pages of appRoleAssignments
				for assignmentsResponse != nil {
					assignments := assignmentsResponse.GetValue()
					l.Logger.Debug("Processing appRoleAssignments page (fallback)", "spId", spId, "assignments", len(assignments))

					for _, assignment := range assignments {
						if assignment == nil || assignment.GetId() == nil {
							continue
						}

						assignmentMap := map[string]interface{}{
							"id":               *assignment.GetId(),
							"principalId":      uuidPtrToInterface(assignment.GetPrincipalId()),
							"principalDisplayName": stringPtrToInterface(assignment.GetPrincipalDisplayName()),
							"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
							"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
							"resourceDisplayName": stringPtrToInterface(assignment.GetResourceDisplayName()),
							"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
							"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
							"assignmentType":   "AppRoleAssignments",
							"direction":        "assigned_to",
							"servicePrincipalId":          spId,
							"servicePrincipalDisplayName": spDisplayName,
						}
						allAppRoleAssignments = append(allAppRoleAssignments, assignmentMap)
						totalObjects++
					}

					// Check for next page
					odataNextLink := assignmentsResponse.GetOdataNextLink()
					if odataNextLink == nil || *odataNextLink == "" {
						break
					}

					// Get next page
					assignmentsResponse, err = l.graphClient.ServicePrincipals().ByServicePrincipalId(spId).AppRoleAssignments().WithUrl(*odataNextLink).Get(ctx, nil)
					if err != nil {
						l.Logger.Error("Failed to get next page of appRoleAssignments", "spId", spId, "error", err)
						break
					}
				}
			}
		}

		// Check for next page of service principals
		odataNextLink := servicePrincipalsResponse.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break
		}

		servicePrincipalsResponse, err = l.graphClient.ServicePrincipals().WithUrl(*odataNextLink).Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get next page of service principals", "error", err)
			break
		}
	}

	l.Logger.Info("Completed fallback app role assignments collection", "totalAssignments", totalObjects)
	message.Info("App role assignments collection completed successfully! Collected %d assignments (fallback mode)", totalObjects)
	return allAppRoleAssignments, nil
}

// processBatchServicePrincipalsFallback processes a batch of service principals using individual SDK calls when batch fails
func (l *SDKComprehensiveCollectorLink) processBatchServicePrincipalsFallback(ctx context.Context, batchSPs []interface{}) ([]interface{}, error) {
	var assignments []interface{}

	for _, sp := range batchSPs {
		spMap, ok := sp.(map[string]interface{})
		if !ok {
			continue
		}

		spID, ok := spMap["id"].(string)
		if !ok {
			continue
		}

		spDisplayName, _ := spMap["displayName"].(string)

		l.Logger.Debug("Processing service principal (batch fallback)", "spId", spID)

		// Get appRoleAssignedTo using SDK
		assignedToResponse, err := l.graphClient.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignedTo().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get appRoleAssignedTo for service principal (batch fallback)", "spId", spID, "error", err)
		} else {
			for assignedToResponse != nil {
				assignedToAssignments := assignedToResponse.GetValue()

				for _, assignment := range assignedToAssignments {
					if assignment == nil || assignment.GetId() == nil {
						continue
					}

					assignmentMap := map[string]interface{}{
						"id":                          *assignment.GetId(),
						"principalId":                 uuidPtrToInterface(assignment.GetPrincipalId()),
						"principalDisplayName":        stringPtrToInterface(assignment.GetPrincipalDisplayName()),
						"principalType":               stringPtrToInterface(assignment.GetPrincipalType()),
						"resourceId":                  uuidPtrToInterface(assignment.GetResourceId()),
						"resourceDisplayName":         stringPtrToInterface(assignment.GetResourceDisplayName()),
						"appRoleId":                   uuidPtrToInterface(assignment.GetAppRoleId()),
						"createdDateTime":             timeToInterface(assignment.GetCreatedDateTime()),
						"assignmentType":              "AppRoleAssignedTo",
						"direction":                   "assigned_from",
						"servicePrincipalId":          spID,
						"servicePrincipalDisplayName": spDisplayName,
					}
					assignments = append(assignments, assignmentMap)
				}

				odataNextLink := assignedToResponse.GetOdataNextLink()
				if odataNextLink == nil || *odataNextLink == "" {
					break
				}

				assignedToResponse, err = l.graphClient.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignedTo().WithUrl(*odataNextLink).Get(ctx, nil)
				if err != nil {
					l.Logger.Error("Failed to get next page of appRoleAssignedTo (batch fallback)", "spId", spID, "error", err)
					break
				}
			}
		}

		// Get appRoleAssignments using SDK
		assignmentsResponse, err := l.graphClient.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignments().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get appRoleAssignments for service principal (batch fallback)", "spId", spID, "error", err)
		} else {
			for assignmentsResponse != nil {
				roleAssignments := assignmentsResponse.GetValue()

				for _, assignment := range roleAssignments {
					if assignment == nil || assignment.GetId() == nil {
						continue
					}

					assignmentMap := map[string]interface{}{
						"id":                          *assignment.GetId(),
						"principalId":                 uuidPtrToInterface(assignment.GetPrincipalId()),
						"principalDisplayName":        stringPtrToInterface(assignment.GetPrincipalDisplayName()),
						"principalType":               stringPtrToInterface(assignment.GetPrincipalType()),
						"resourceId":                  uuidPtrToInterface(assignment.GetResourceId()),
						"resourceDisplayName":         stringPtrToInterface(assignment.GetResourceDisplayName()),
						"appRoleId":                   uuidPtrToInterface(assignment.GetAppRoleId()),
						"createdDateTime":             timeToInterface(assignment.GetCreatedDateTime()),
						"assignmentType":              "AppRoleAssignments",
						"direction":                   "assigned_to",
						"servicePrincipalId":          spID,
						"servicePrincipalDisplayName": spDisplayName,
					}
					assignments = append(assignments, assignmentMap)
				}

				odataNextLink := assignmentsResponse.GetOdataNextLink()
				if odataNextLink == nil || *odataNextLink == "" {
					break
				}

				assignmentsResponse, err = l.graphClient.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignments().WithUrl(*odataNextLink).Get(ctx, nil)
				if err != nil {
					l.Logger.Error("Failed to get next page of appRoleAssignments (batch fallback)", "spId", spID, "error", err)
					break
				}
			}
		}
	}

	return assignments, nil
}

