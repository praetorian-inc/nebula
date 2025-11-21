package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
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

	azureADData, err := l.collectAllGraphDataSDK()
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

	// STEP 3: Collect Management Groups hierarchy using SDK
	l.Logger.Info("Collecting Management Groups hierarchy via SDK")
	message.Info("Collecting Management Groups hierarchy via SDK...")

	managementGroupsData, err := l.getManagementGroupHierarchyViaSDK()
	if err != nil {
		l.Logger.Warn("Failed to collect Management Groups data via SDK, continuing without it", "error", err)
		message.Info("Warning: Failed to collect Management Groups data: %v", err)
		managementGroupsData = []interface{}{}
	}

	message.Info("Management Groups SDK collector completed! Collected %d management groups", len(managementGroupsData))

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
		"azure_ad":           azureADData,
		"pim":                pimData,
		"management_groups":  managementGroupsData,
		"azure_resources":    allSubscriptionData,
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

	// Add summary metadata
	consolidatedData["collection_metadata"].(map[string]interface{})["data_summary"] = map[string]interface{}{
		"total_azure_ad_objects":     adTotal,
		"total_pim_objects":          pimTotal,
		"total_management_groups":    managementGroupsTotal,
		"total_azurerm_objects":      azurermTotal,
		"total_objects":              adTotal + pimTotal + managementGroupsTotal + azurermTotal,
	}

	message.Info("=== Azure IAM Collection Summary (SDK) ====")
	message.Info("Tenant: %s", tenantID)
	message.Info("Total Azure AD objects: %d", adTotal)
	message.Info("Total PIM objects: %d", pimTotal)
	message.Info("Total Management Groups: %d", managementGroupsTotal)
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
		defer resp.Body.Close()

		// Handle rate limiting (429) and server errors (5xx) with retry
		if resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
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
		l.logCollectionEnd("users", startTime, 0)
	} else {
		azureADData["users"] = users
		l.logCollectionEnd("users", startTime, len(users))
	}

	// Collection 2: Groups (with pagination)
	startTime = l.logCollectionStart("groups")
	message.Info("Collecting groups from Graph SDK...")

	groups, err := l.collectAllGroupsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect groups via paginated SDK", "error", err)
		azureADData["groups"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("groups", startTime, 0)
	} else {
		azureADData["groups"] = groups
		l.logCollectionEnd("groups", startTime, len(groups))
	}

	// Collection 3: Service Principals (with pagination)
	startTime = l.logCollectionStart("servicePrincipals")
	message.Info("Collecting service principals from Graph SDK...")

	servicePrincipals, err := l.collectAllServicePrincipalsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect service principals via paginated SDK", "error", err)
		azureADData["servicePrincipals"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("servicePrincipals", startTime, 0)
	} else {
		azureADData["servicePrincipals"] = servicePrincipals
		l.logCollectionEnd("servicePrincipals", startTime, len(servicePrincipals))
	}

	// Collection 4: Applications (with pagination)
	startTime = l.logCollectionStart("applications")
	message.Info("Collecting applications from Graph SDK...")

	applications, err := l.collectAllApplicationsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect applications via paginated SDK", "error", err)
		azureADData["applications"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("applications", startTime, 0)
	} else {
		azureADData["applications"] = applications
		l.logCollectionEnd("applications", startTime, len(applications))
	}

	// Collection 5: Devices (with pagination)
	startTime = l.logCollectionStart("devices")
	message.Info("Collecting devices from Graph SDK...")

	devices, err := l.collectAllDevicesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect devices via paginated SDK", "error", err)
		azureADData["devices"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("devices", startTime, 0)
	} else {
		azureADData["devices"] = devices
		l.logCollectionEnd("devices", startTime, len(devices))
	}

	// Collection 6: Directory Roles (with pagination)
	startTime = l.logCollectionStart("directoryRoles")
	message.Info("Collecting directory roles from Graph SDK...")

	directoryRoles, err := l.collectAllDirectoryRolesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory roles via paginated SDK", "error", err)
		azureADData["directoryRoles"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("directoryRoles", startTime, 0)
	} else {
		azureADData["directoryRoles"] = directoryRoles
		l.logCollectionEnd("directoryRoles", startTime, len(directoryRoles))
	}

	// Collection 7: Role Definitions (with pagination)
	startTime = l.logCollectionStart("roleDefinitions")
	message.Info("Collecting role definitions from Graph SDK...")

	roleDefinitions, err := l.collectAllRoleDefinitionsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect role definitions via paginated SDK", "error", err)
		azureADData["roleDefinitions"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("roleDefinitions", startTime, 0)
	} else {
		azureADData["roleDefinitions"] = roleDefinitions
		l.logCollectionEnd("roleDefinitions", startTime, len(roleDefinitions))
	}

	// Collection 8: Conditional Access Policies (with pagination)
	startTime = l.logCollectionStart("conditionalAccessPolicies")
	message.Info("Collecting conditional access policies from Graph SDK...")

	conditionalAccessPolicies, err := l.collectAllConditionalAccessPoliciesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect conditional access policies via paginated SDK", "error", err)
		azureADData["conditionalAccessPolicies"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("conditionalAccessPolicies", startTime, 0)
	} else {
		azureADData["conditionalAccessPolicies"] = conditionalAccessPolicies
		l.logCollectionEnd("conditionalAccessPolicies", startTime, len(conditionalAccessPolicies))
	}

	// Collection 9: Directory Role Assignments (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("directoryRoleAssignments")
	message.Info("Collecting directory role assignments from Graph SDK...")
	directoryRoleAssignments, err := l.collectAllDirectoryRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory role assignments via paginated SDK", "error", err)
		azureADData["directoryRoleAssignments"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("directoryRoleAssignments", startTime, 0)
	} else {
		azureADData["directoryRoleAssignments"] = directoryRoleAssignments
		l.logCollectionEnd("directoryRoleAssignments", startTime, len(directoryRoleAssignments))
	}

	// Collection 10: Group Memberships (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("groupMemberships")
	message.Info("Collecting group memberships from Graph SDK...")
	groupMemberships, err := l.collectAllGroupMembershipsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect group memberships via SDK", "error", err)
		azureADData["groupMemberships"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("groupMemberships", startTime, 0)
	} else {
		azureADData["groupMemberships"] = groupMemberships
		l.logCollectionEnd("groupMemberships", startTime, len(groupMemberships))
	}

	// Collection 11: OAuth2 Permission Grants (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("oauth2PermissionGrants")
	message.Info("Collecting OAuth2 permission grants from Graph SDK...")
	oauth2Grants, err := l.collectAllOAuth2PermissionGrantsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect OAuth2 permission grants via SDK", "error", err)
		azureADData["oauth2PermissionGrants"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("oauth2PermissionGrants", startTime, 0)
	} else {
		azureADData["oauth2PermissionGrants"] = oauth2Grants
		l.logCollectionEnd("oauth2PermissionGrants", startTime, len(oauth2Grants))
	}

	// Collection 12: App Role Assignments (CRITICAL for iam-push compatibility)
	startTime = l.logCollectionStart("appRoleAssignments")
	message.Info("Collecting app role assignments from Graph SDK...")
	appRoleAssignments, err := l.collectAllAppRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect app role assignments via SDK", "error", err)
		azureADData["appRoleAssignments"] = []interface{}{} // Empty array on error
		l.logCollectionEnd("appRoleAssignments", startTime, 0)
	} else {
		azureADData["appRoleAssignments"] = appRoleAssignments
		l.logCollectionEnd("appRoleAssignments", startTime, len(appRoleAssignments))
	}

	// Calculate total resource counts for final summary
	totalItems := len(users) + len(groups) + len(servicePrincipals) + len(applications) + len(devices) +
			len(directoryRoles) + len(roleDefinitions) + len(conditionalAccessPolicies) +
			len(directoryRoleAssignments) + len(groupMemberships) + len(oauth2Grants) + len(appRoleAssignments)

	l.logCollectionEnd("Azure AD Graph SDK Collection", overallStart, totalItems)
	return azureADData, nil
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
func (l *SDKComprehensiveCollectorLink) getManagementGroupHierarchyViaSDK() ([]interface{}, error) {
	ctx := l.Context()
	var managementGroups []interface{}

	l.Logger.Info("Collecting management groups via SDK")

	// Use Management Groups client to list all management groups
	pager := l.managementGroupClient.NewListPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get management groups page: %v", err)
		}

		for _, mg := range page.Value {
			if mg == nil || mg.ID == nil {
				continue
			}

			mgMap := map[string]interface{}{
				"id":   *mg.ID,
				"name": stringPtrToInterface(mg.Name),
				"type": "microsoft.management/managementgroups",
				"properties": map[string]interface{}{
					"displayName": stringPtrToInterface(mg.Properties.DisplayName),
					"tenantId":    stringPtrToInterface(mg.Properties.TenantID),
				},
				// Additional fields for Neo4j compatibility
				"ResourceType":   "ManagementGroup",
				"HierarchyLevel": 0, // Will be calculated later if needed
			}

			// Add parent information if available (simplified for now)
			// TODO: Get parent details from expanded properties if needed
			mgMap["ParentId"] = nil

			managementGroups = append(managementGroups, mgMap)
		}
	}

	l.Logger.Info("Collected management groups via SDK", "count", len(managementGroups))
	return managementGroups, nil
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

// collectAllRoleAssignmentsSDK collects all role assignments for a subscription using Authorization SDK
func (l *SDKComprehensiveCollectorLink) collectAllRoleAssignmentsSDK(subscriptionID string) ([]interface{}, []interface{}, []interface{}, []interface{}, []interface{}, error) {
	ctx := l.Context()
	var subscriptionRoleAssignments []interface{}
	var resourceGroupRoleAssignments []interface{}
	var resourceLevelRoleAssignments []interface{}
	var managementGroupRoleAssignments []interface{}
	var tenantRoleAssignments []interface{}

	l.Logger.Info("Starting role assignments collection via SDK", "subscription", subscriptionID)

	// Create role assignments client with specific subscription ID
	authClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, &l.credential, nil)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create role assignments client for subscription %s: %v", subscriptionID, err)
	}

	// Get all role assignments for the subscription with pagination
	pager := authClient.NewListPager(&armauthorization.RoleAssignmentsClientListOptions{})

	totalCount := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to get role assignments page: %v", err)
		}

		for _, assignment := range page.Value {
			if assignment == nil || assignment.ID == nil || assignment.Properties == nil {
				continue
			}

			// Extract assignment details
			assignmentMap := map[string]interface{}{
				"id":                 *assignment.ID,
				"name":               stringPtrToInterface(assignment.Name),
				"type":               stringPtrToInterface(assignment.Type),
				"principalId":        stringPtrToInterface(assignment.Properties.PrincipalID),
				// PrincipalType not available in this SDK version, will be filled from Graph API lookup if needed
				"roleDefinitionId":   stringPtrToInterface(assignment.Properties.RoleDefinitionID),
				"scope":              stringPtrToInterface(assignment.Properties.Scope),
			}

			// Categorize by scope type
			scope := ""
			if assignment.Properties.Scope != nil {
				scope = *assignment.Properties.Scope
			}

			// Determine scope type based on the scope string structure
			switch {
			case strings.HasPrefix(scope, "/providers/Microsoft.Management/managementGroups/"):
				// Management group-level: /providers/Microsoft.Management/managementGroups/{mg-id}
				managementGroupRoleAssignments = append(managementGroupRoleAssignments, assignmentMap)
			case scope == "/" || scope == "":
				// Tenant root-level: / or empty scope
				tenantRoleAssignments = append(tenantRoleAssignments, assignmentMap)
			case strings.Contains(scope, "/subscriptions/"):
				if strings.Count(scope, "/") == 2 {
					// Subscription-level: /subscriptions/{subscription-id}
					subscriptionRoleAssignments = append(subscriptionRoleAssignments, assignmentMap)
				} else if strings.Contains(scope, "/resourceGroups/") && strings.Count(scope, "/") == 4 {
					// Resource group-level: /subscriptions/{subscription-id}/resourceGroups/{rg-name}
					resourceGroupRoleAssignments = append(resourceGroupRoleAssignments, assignmentMap)
				} else {
					// Resource-level: /subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/{provider}/{resource}
					resourceLevelRoleAssignments = append(resourceLevelRoleAssignments, assignmentMap)
				}
			}

			totalCount++
		}
	}

	l.Logger.Info("Completed role assignments collection via SDK",
		"subscription", subscriptionID,
		"total", totalCount,
		"subscriptionLevel", len(subscriptionRoleAssignments),
		"resourceGroupLevel", len(resourceGroupRoleAssignments),
		"resourceLevel", len(resourceLevelRoleAssignments),
		"managementGroupLevel", len(managementGroupRoleAssignments),
		"tenantLevel", len(tenantRoleAssignments))

	return subscriptionRoleAssignments, resourceGroupRoleAssignments, resourceLevelRoleAssignments, managementGroupRoleAssignments, tenantRoleAssignments, nil
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

					// DataActions and NotDataActions are not available in this SDK version
					// They can be added later when the SDK supports them

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

	// Get first page (SDK already uses optimized pagination internally)
	response, err := l.graphClient.Users().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of users: %v", err)
	}

	for {
		pageCount++
		users := response.GetValue()
		l.Logger.Info("Processing user page", "page", pageCount, "objects", len(users))

		// Convert users from current page
		for _, user := range users {
			userMap := map[string]interface{}{
				"id":                *user.GetId(),
				"displayName":       stringPtrToInterface(user.GetDisplayName()),
				"userPrincipalName": stringPtrToInterface(user.GetUserPrincipalName()),
				"mail":              stringPtrToInterface(user.GetMail()),
				"jobTitle":          stringPtrToInterface(user.GetJobTitle()),
				"department":        stringPtrToInterface(user.GetDepartment()),
				"accountEnabled":    boolPtrToInterface(user.GetAccountEnabled()),
				"userType":          stringPtrToInterface(user.GetUserType()),
				"createdDateTime":   timeToInterface(user.GetCreatedDateTime()),
				"businessPhones":    stringSliceToInterface(user.GetBusinessPhones()),
				"givenName":         stringPtrToInterface(user.GetGivenName()),
				"surname":           stringPtrToInterface(user.GetSurname()),
				"mobilePhone":       stringPtrToInterface(user.GetMobilePhone()),
				"officeLocation":    stringPtrToInterface(user.GetOfficeLocation()),
				"preferredLanguage": stringPtrToInterface(user.GetPreferredLanguage()),
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
				"id":                    *group.GetId(),
				"displayName":           stringPtrToInterface(group.GetDisplayName()),
				"description":           stringPtrToInterface(group.GetDescription()),
				"groupTypes":            stringSliceToInterface(group.GetGroupTypes()),
				"membershipRule":        stringPtrToInterface(group.GetMembershipRule()),
				"mailEnabled":           boolPtrToInterface(group.GetMailEnabled()),
				"securityEnabled":       boolPtrToInterface(group.GetSecurityEnabled()),
				"createdDateTime":       timeToInterface(group.GetCreatedDateTime()),
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
			spMap := map[string]interface{}{
				"id":                         *sp.GetId(),
				"appId":                      stringPtrToInterface(sp.GetAppId()),
				"displayName":                stringPtrToInterface(sp.GetDisplayName()),
				"servicePrincipalType":       stringPtrToInterface(sp.GetServicePrincipalType()),
				"accountEnabled":             boolPtrToInterface(sp.GetAccountEnabled()),
				"createdDateTime":            nil, // Not available in SDK
				"replyUrls":                  stringSliceToInterface(sp.GetReplyUrls()),
				"signInAudience":             stringPtrToInterface(sp.GetSignInAudience()),
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

	// Get first page
	response, err := l.graphClient.RoleManagement().Directory().RoleEligibilitySchedules().Get(ctx, nil)
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
			allEligible = append(allEligible, scheduleMap)
		}

		totalObjects += len(schedules)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
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

	// Get first page
	response, err := l.graphClient.RoleManagement().Directory().RoleAssignmentSchedules().Get(ctx, nil)
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
			allActive = append(allActive, scheduleMap)
		}

		totalObjects += len(schedules)

		// Check if there's a next page
		odataNextLink := response.GetOdataNextLink()
		if odataNextLink == nil || *odataNextLink == "" {
			break // No more pages
		}

		// Get next page
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
			deviceMap := map[string]interface{}{
				"id":                    *device.GetId(),
				"displayName":           stringPtrToInterface(device.GetDisplayName()),
				"deviceId":              stringPtrToInterface(device.GetDeviceId()),
				"operatingSystem":       stringPtrToInterface(device.GetOperatingSystem()),
				"operatingSystemVersion": stringPtrToInterface(device.GetOperatingSystemVersion()),
				"isCompliant":           boolPtrToInterface(device.GetIsCompliant()),
				"isManaged":             boolPtrToInterface(device.GetIsManaged()),
				"accountEnabled":        boolPtrToInterface(device.GetAccountEnabled()),
				"createdDateTime":       timeToInterface(device.GetRegistrationDateTime()),
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
				"state":            stateToInterface(policy.GetState()),
				"createdDateTime":  timeToInterface(policy.GetCreatedDateTime()),
				"modifiedDateTime": timeToInterface(policy.GetModifiedDateTime()),
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

// collectAllGroupMembershipsWithPagination collects all group membership relationships using batched Graph API calls
//
// Performance Optimization: This function uses Microsoft Graph's $batch API to dramatically improve performance:
// - Reduces API calls from N (one per group) to N/15 (batched requests)
// - Expected 10-15x performance improvement for tenants with many groups
// - Maintains backward compatibility with existing data structures
// - Includes robust fallback mechanisms for batch failures or authentication issues
func (l *SDKComprehensiveCollectorLink) collectAllGroupMembershipsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allMemberships []interface{}
	totalObjects := 0

	l.Logger.Info("Starting optimized batched group memberships collection")
	message.Info("Collecting group memberships from Graph SDK (batched)...")

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		l.Logger.Error("Failed to get access token, falling back to individual SDK calls", "error", err)
		return l.collectAllGroupMembershipsWithPaginationFallback(ctx)
	}

	// Collect all groups first using SDK (as before)
	var allGroups []interface{}
	groupsResponse, err := l.graphClient.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups for membership collection: %v", err)
	}

	// Process all pages of groups to collect group information
	for {
		groups := groupsResponse.GetValue()
		l.Logger.Info("Collecting groups page", "groups", len(groups))

		for _, group := range groups {
			if group == nil || group.GetId() == nil {
				continue
			}

			groupMap := map[string]interface{}{
				"id": *group.GetId(),
			}
			if group.GetDisplayName() != nil {
				groupMap["displayName"] = *group.GetDisplayName()
			}
			allGroups = append(allGroups, groupMap)
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

	l.Logger.Info("Collected all groups, starting batched member collection", "totalGroups", len(allGroups))

	// Process groups in batches for member collection
	// Microsoft Graph API batch limit is 20 requests per batch
	// We use 15 to leave some buffer for other concurrent operations
	batchSize := 15
	for i := 0; i < len(allGroups); i += batchSize {
		end := i + batchSize
		if end > len(allGroups) {
			end = len(allGroups)
		}
		batchGroups := allGroups[i:end]

		l.Logger.Info("Processing group batch", "batch", fmt.Sprintf("%d/%d", (i/batchSize)+1, (len(allGroups)+batchSize-1)/batchSize), "groups", len(batchGroups))

		// Create batch requests for group members
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

			// Add members request to batch
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("group_%d_members", j),
				"method": "GET",
				"url":    fmt.Sprintf("/groups/%s/members", groupID),
			})
		}

		// Execute batch request
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for group memberships, falling back to individual calls", "error", err)
				// Fallback to individual calls for this batch
				batchMemberships, err := l.processBatchGroupsFallback(ctx, batchGroups)
				if err != nil {
					l.Logger.Error("Fallback processing failed for batch", "error", err)
					continue
				}
				allMemberships = append(allMemberships, batchMemberships...)
				totalObjects += len(batchMemberships)
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

										// Extract group ID from request ID
										requestID, _ := respMap["id"].(string)
										groupIndex := strings.Replace(strings.Replace(requestID, "group_", "", 1), "_members", "", 1)

										// Find corresponding group
										if groupData, exists := groupDataMap[fmt.Sprintf("group_%s", groupIndex)]; exists {
											if groupInfo, ok := groupData.(map[string]interface{}); ok {
												groupID, _ := groupInfo["id"].(string)

												membership := map[string]interface{}{
													"groupId":  groupID,
													"memberId": memberID,
												}

												// Add member type if available
												if memberType, ok := memberMap["@odata.type"].(string); ok {
													membership["memberType"] = memberType
												}

												allMemberships = append(allMemberships, membership)
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

	l.Logger.Info("Completed optimized batched group memberships collection", "totalMemberships", totalObjects, "totalGroups", len(allGroups))
	message.Info("Group memberships collection completed successfully! Collected %d memberships from %d groups", totalObjects, len(allGroups))
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

// collectAllAppRoleAssignmentsWithPagination collects all app role assignments using batched Graph API calls
//
// Performance Optimization: This function uses Microsoft Graph's $batch API to dramatically improve performance:
// - Reduces API calls from 2N (two per service principal) to 2N/15 (batched requests)
// - Expected 10-15x performance improvement for tenants with many service principals
// - Maintains backward compatibility with existing data structures
// - Includes robust fallback mechanisms for batch failures or authentication issues
func (l *SDKComprehensiveCollectorLink) collectAllAppRoleAssignmentsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allAppRoleAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Starting optimized batched app role assignments collection")
	message.Info("Collecting app role assignments from Graph SDK (batched)...")

	// Get access token for batch API calls
	accessToken, err := l.getAccessToken(ctx)
	if err != nil {
		l.Logger.Error("Failed to get access token, falling back to individual SDK calls", "error", err)
		return l.collectAllAppRoleAssignmentsWithPaginationFallback(ctx)
	}

	// First, collect all service principals
	var allServicePrincipals []interface{}
	servicePrincipalsResponse, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get service principals for app role assignments: %v", err)
	}

	// Process all pages of service principals to collect SP information
	for {
		servicePrincipals := servicePrincipalsResponse.GetValue()
		l.Logger.Info("Collecting service principals page", "servicePrincipals", len(servicePrincipals))

		for _, sp := range servicePrincipals {
			if sp == nil || sp.GetId() == nil {
				continue
			}

			spMap := map[string]interface{}{
				"id": *sp.GetId(),
			}
			if sp.GetDisplayName() != nil {
				spMap["displayName"] = *sp.GetDisplayName()
			}
			allServicePrincipals = append(allServicePrincipals, spMap)
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

	l.Logger.Info("Collected all service principals, starting batched app role assignments collection", "totalServicePrincipals", len(allServicePrincipals))

	// Process service principals in batches for app role assignments collection
	// Since we need 2 requests per SP (appRoleAssignedTo + appRoleAssignments), we use smaller batches
	batchSize := 7 // Use 7 SPs per batch = 14 requests per batch (under the 20 request limit)
	for i := 0; i < len(allServicePrincipals); i += batchSize {
		end := i + batchSize
		if end > len(allServicePrincipals) {
			end = len(allServicePrincipals)
		}
		batchSPs := allServicePrincipals[i:end]

		l.Logger.Info("Processing service principal batch", "batch", fmt.Sprintf("%d/%d", (i/batchSize)+1, (len(allServicePrincipals)+batchSize-1)/batchSize), "servicePrincipals", len(batchSPs))

		// Create batch requests for both appRoleAssignedTo and appRoleAssignments
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

			// Add appRoleAssignedTo request to batch (roles assigned TO this service principal)
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("sp_%d_assignedTo", j),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignedTo", spID),
			})

			// Add appRoleAssignments request to batch (roles assigned BY this service principal)
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("sp_%d_assignments", j),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignments", spID),
			})
		}

		// Execute batch request
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(ctx, accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for app role assignments, falling back to individual calls", "error", err)
				// Fallback to individual calls for this batch
				batchAssignments, err := l.processBatchServicePrincipalsFallback(ctx, batchSPs)
				if err != nil {
					l.Logger.Error("Fallback processing failed for batch", "error", err)
					continue
				}
				allAppRoleAssignments = append(allAppRoleAssignments, batchAssignments...)
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
								for _, assignment := range value {
									if assignmentMap, ok := assignment.(map[string]interface{}); ok {
										assignmentID, ok := assignmentMap["id"].(string)
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

										// Find corresponding service principal
										if spData, exists := spDataMap[fmt.Sprintf("sp_%s", spIndex)]; exists {
											if spInfo, ok := spData.(map[string]interface{}); ok {
												spID, _ := spInfo["id"].(string)

												appRoleAssignment := map[string]interface{}{
													"id":               assignmentID,
													"assignmentType":   assignmentType,
													"serviceOnSpId":    spID, // Reference to the service principal
												}

												// Add standard app role assignment fields
												if principalId, ok := assignmentMap["principalId"].(string); ok {
													appRoleAssignment["principalId"] = principalId
												}
												if principalType, ok := assignmentMap["principalType"].(string); ok {
													appRoleAssignment["principalType"] = principalType
												}
												if resourceId, ok := assignmentMap["resourceId"].(string); ok {
													appRoleAssignment["resourceId"] = resourceId
												}
												if appRoleId, ok := assignmentMap["appRoleId"].(string); ok {
													appRoleAssignment["appRoleId"] = appRoleId
												}
												if createdDateTime, ok := assignmentMap["createdDateTime"].(string); ok {
													appRoleAssignment["createdDateTime"] = createdDateTime
												}

												allAppRoleAssignments = append(allAppRoleAssignments, appRoleAssignment)
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

	l.Logger.Info("Completed optimized batched app role assignments collection", "totalAssignments", totalObjects, "totalServicePrincipals", len(allServicePrincipals))
	message.Info("App role assignments collection completed successfully! Collected %d assignments from %d service principals", totalObjects, len(allServicePrincipals))
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
							"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
							"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
							"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
							"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
							"assignmentType":   "AppRoleAssignedTo",
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
							"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
							"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
							"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
							"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
							"assignmentType":   "AppRoleAssignments",
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

		l.Logger.Debug("Processing service principal (batch fallback)", "spId", spID)

		// Get appRoleAssignedTo using SDK
		assignedToResponse, err := l.graphClient.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignedTo().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get appRoleAssignedTo for service principal (batch fallback)", "spId", spID, "error", err)
		} else {
			// Process all pages of appRoleAssignedTo
			for assignedToResponse != nil {
				assignedToAssignments := assignedToResponse.GetValue()

				for _, assignment := range assignedToAssignments {
					if assignment == nil || assignment.GetId() == nil {
						continue
					}

					assignmentMap := map[string]interface{}{
						"id":               *assignment.GetId(),
						"principalId":      uuidPtrToInterface(assignment.GetPrincipalId()),
						"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
						"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
						"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
						"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
						"assignmentType":   "AppRoleAssignedTo",
					}
					assignments = append(assignments, assignmentMap)
				}

				// Check for next page
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
			// Process all pages of appRoleAssignments
			for assignmentsResponse != nil {
				roleAssignments := assignmentsResponse.GetValue()

				for _, assignment := range roleAssignments {
					if assignment == nil || assignment.GetId() == nil {
						continue
					}

					assignmentMap := map[string]interface{}{
						"id":               *assignment.GetId(),
						"principalId":      uuidPtrToInterface(assignment.GetPrincipalId()),
						"principalType":    stringPtrToInterface(assignment.GetPrincipalType()),
						"resourceId":       uuidPtrToInterface(assignment.GetResourceId()),
						"appRoleId":        uuidPtrToInterface(assignment.GetAppRoleId()),
						"createdDateTime":  timeToInterface(assignment.GetCreatedDateTime()),
						"assignmentType":   "AppRoleAssignments",
					}
					assignments = append(assignments, assignmentMap)
				}

				// Check for next page
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

