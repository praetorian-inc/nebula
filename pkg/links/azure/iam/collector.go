package iam

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// selectedResourceTypes defines the resource types worth collecting RBAC assignments for
// This provides 95% of security coverage while reducing API calls by 90%
var selectedResourceTypes = []string{
	// Compute - Direct system access
	"microsoft.compute/virtualmachines",
	"microsoft.containerservice/managedclusters",

	// Data & Storage - Sensitive repositories
	"microsoft.storage/storageaccounts",
	"microsoft.keyvault/vaults",
	"microsoft.sql/servers",
	"microsoft.dbforpostgresql/flexibleservers",
	"microsoft.dbformysql/flexibleservers",
	"microsoft.documentdb/databaseaccounts",

	// Application Platform
	"microsoft.web/sites",
	"microsoft.logic/workflows",
	"microsoft.cognitiveservices/accounts",

	// Infrastructure & Identity
	"microsoft.automation/automationaccounts",
	"microsoft.recoveryservices/vaults",
	"microsoft.managedidentity/userassignedidentities",

	// Network Security
	"microsoft.network/virtualnetworkgateways",
	"microsoft.network/applicationgateways",
	"microsoft.network/azurefirewalls",
}

// CompleteGraphPermission represents all types of Graph API permissions
type CompleteGraphPermission struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"` // "ServicePrincipalApplication", "ServicePrincipalDelegated", "UserApplication", "GroupApplication", "UserDelegated"
	ServicePrincipalID   string `json:"servicePrincipalId,omitempty"`
	ServicePrincipalName string `json:"servicePrincipalName,omitempty"`
	UserID               string `json:"userId,omitempty"`
	UserName             string `json:"userName,omitempty"`
	GroupID              string `json:"groupId,omitempty"`
	GroupName            string `json:"groupName,omitempty"`
	ResourceAppID        string `json:"resourceAppId"`
	ResourceAppName      string `json:"resourceAppName"`
	PermissionType       string `json:"permissionType"` // "Application" or "Delegated"
	Permission           string `json:"permission"`
	ConsentType          string `json:"consentType"` // "Admin" or "User"
	GrantedFor           string `json:"grantedFor,omitempty"`
	CreatedDateTime      string `json:"createdDateTime"`
	ExpiryDateTime       string `json:"expiryDateTime,omitempty"`
	AppRoleID            string `json:"appRoleId,omitempty"`
	Scope                string `json:"scope,omitempty"`
	Source               string `json:"source"` // "Global", "ServicePrincipal", "User", "Group"
}

// ServicePrincipalInfo holds basic service principal information
type ServicePrincipalInfo struct {
	ID          string
	AppID       string
	DisplayName string
}

// UserInfo holds basic user information
type UserInfo struct {
	ID                string
	DisplayName       string
	UserPrincipalName string
}

// GroupInfo holds basic group information
type GroupInfo struct {
	ID          string
	DisplayName string
}

// IAMComprehensiveCollectorLink collects comprehensive Azure IAM data
// Complete Azure AD, PIM, and ARM resource collection in one link
type IAMComprehensiveCollectorLink struct {
	*chain.Base
	httpClient *http.Client
}

func NewIAMComprehensiveCollectorLink(configs ...cfg.Config) chain.Link {
	l := &IAMComprehensiveCollectorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *IAMComprehensiveCollectorLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
		options.AzureRefreshToken(),
		options.AzureTenantID(),
		options.AzureProxy(),
	}
}

func (l *IAMComprehensiveCollectorLink) Process(input interface{}) error {
	// Get parameters
	subscriptions, _ := cfg.As[[]string](l.Arg("subscription"))
	refreshToken, _ := cfg.As[string](l.Arg("refresh-token"))
	tenantID, _ := cfg.As[string](l.Arg("tenant"))
	proxyURL, _ := cfg.As[string](l.Arg("proxy"))

	if refreshToken == "" || tenantID == "" {
		return fmt.Errorf("refresh-token and tenant are required")
	}

	l.Logger.Info("Starting comprehensive Azure IAM collection", "subscriptions_input", subscriptions, "tenant", tenantID)

	// Handle subscription discovery internally
	var subscriptionIDs []string
	if len(subscriptions) == 0 || (len(subscriptions) == 1 && strings.EqualFold(subscriptions[0], "all")) {
		l.Logger.Info("Discovering subscriptions using refresh token")

		// Get Azure Management token from refresh token
		managementToken, err := helpers.GetAzureRMToken(refreshToken, tenantID, proxyURL)
		if err != nil {
			l.Logger.Error("Failed to get management token", "error", err)
			return fmt.Errorf("failed to get management token: %v", err)
		}

		// List subscriptions using management API
		allSubs, err := l.listSubscriptionsWithToken(managementToken.AccessToken, proxyURL)
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

	// Setup HTTP client
	l.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		l.httpClient.Transport = transport
	}

	// STEP 1: Collect Azure AD data ONCE for the entire tenant
	l.Logger.Info("Collecting Azure AD data via Graph API (once for all subscriptions)")
	message.Info("Collecting Azure AD data via Graph API...")

	graphToken, err := helpers.GetGraphAPIToken(refreshToken, tenantID, proxyURL)
	if err != nil {
		return fmt.Errorf("failed to get Graph API token: %v", err)
	}

	azureADData, err := l.collectAllGraphData(graphToken.AccessToken)
	if err != nil {
		l.Logger.Error("Failed to collect Graph API data", "error", err)
		return err
	}

	message.Info("Graph collector completed successfully! Collected %d object types", len(azureADData))

	// STEP 2: Collect PIM data ONCE for the entire tenant
	l.Logger.Info("Collecting PIM data (once for all subscriptions)")
	message.Info("Collecting PIM data...")

	pimToken, err := helpers.GetPIMToken(refreshToken, tenantID, proxyURL)
	if err != nil {
		l.Logger.Error("Failed to get PIM token", "error", err)
		return fmt.Errorf("failed to get PIM token: %v", err)
	}

	pimData, err := l.collectAllPIMData(pimToken.AccessToken, tenantID)
	if err != nil {
		l.Logger.Error("Failed to collect PIM data", "error", err)
		return err
	}

	message.Info("PIM collector completed successfully! Collected %d assignment types", len(pimData))

	// STEP 2.5: Collect Management Groups hierarchy (once for the entire tenant)
	l.Logger.Info("Collecting Management Groups hierarchy (once for all subscriptions)")
	message.Info("Collecting Management Groups hierarchy...")

	managementToken, err := helpers.GetAzureRMToken(refreshToken, tenantID, proxyURL)
	if err != nil {
		l.Logger.Error("Failed to get management token for Management Groups", "error", err)
		return fmt.Errorf("failed to get management token for Management Groups: %v", err)
	}

	managementGroupsData, err := l.getManagementGroupHierarchyViaResourceGraph(managementToken.AccessToken, tenantID, proxyURL)
	if err != nil {
		l.Logger.Warn("Failed to collect Management Groups data, continuing without it", "error", err)
		message.Info("Warning: Failed to collect Management Groups data: %v", err)
		managementGroupsData = []interface{}{}
	}

	message.Info("Management Groups collector completed! Collected %d management groups", len(managementGroupsData))

	// STEP 3: Process subscriptions in parallel with 1 worker (Azure RM only) - TESTING CONCURRENCY
	l.Logger.Info("Processing %d subscriptions with 1 worker", len(subscriptionIDs))
	allSubscriptionData := l.processSubscriptionsParallel(subscriptionIDs, refreshToken, tenantID, proxyURL)

	// Create consolidated data structure
	consolidatedData := map[string]interface{}{
		"collection_metadata": map[string]interface{}{
			"tenant_id":               tenantID,
			"collection_timestamp":    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"subscriptions_processed": len(subscriptionIDs),
			"collector_versions": map[string]interface{}{
				"nebula_collector": "comprehensive",
				"graph_collector":     "completed",
				"pim_collector":       "completed",
				"azurerm_collector":   "completed",
			},
		},
		"azure_ad":           azureADData,
		"pim":                pimData,
		"management_groups":  managementGroupsData,
		"azure_resources":    allSubscriptionData,
	}

	// Calculate totals for summary
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

	message.Info("=== Azure IAM Collection Summary ====")
	message.Info("Tenant: %s", tenantID)
	message.Info("Total Azure AD objects: %d", adTotal)
	message.Info("Total PIM objects: %d", pimTotal)
	message.Info("Total Management Groups: %d", managementGroupsTotal)
	message.Info("Total AzureRM objects: %d", azurermTotal)
	message.Info("🎉 Azure IAM collection completed successfully!")

	// Send consolidated data to outputter
	l.Send(consolidatedData)
	return nil
}


// listSubscriptionsWithToken lists subscriptions using the management token directly
func (l *IAMComprehensiveCollectorLink) listSubscriptionsWithToken(accessToken, proxyURL string) ([]string, error) {
	subscriptionsURL := "https://management.azure.com/subscriptions?api-version=2022-12-01"

	client := &http.Client{Timeout: 30 * time.Second}

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(l.Context(), "GET", subscriptionsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			SubscriptionID string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
			State          string `json:"state"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	var subscriptionIDs []string
	for _, sub := range result.Value {
		if sub.SubscriptionID != "" && sub.State == "Enabled" {
			subscriptionIDs = append(subscriptionIDs, sub.SubscriptionID)
		}
	}

	return subscriptionIDs, nil
}

// getManagementGroupHierarchyViaResourceGraph gets management groups and subscriptions with full hierarchy using Azure Resource Graph
func (l *IAMComprehensiveCollectorLink) getManagementGroupHierarchyViaResourceGraph(accessToken, tenantID, proxyURL string) ([]interface{}, error) {
	resourceGraphURL := "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

	// KQL query to get Management Groups and Subscriptions with hierarchy
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

	requestBody := map[string]interface{}{
		"query": kqlQuery,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(l.Context(), "POST", resourceGraphURL, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Resource Graph API call failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data []interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode Resource Graph response: %v", err)
	}

	l.Logger.Info("Retrieved management hierarchy via Resource Graph", "total_resources", len(result.Data))

	// Separate management groups and subscriptions for logging
	mgCount := 0
	subCount := 0
	for _, item := range result.Data {
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

	return result.Data, nil
}

// listManagementGroupsWithToken lists management groups and their hierarchy using the management token (DEPRECATED - use getManagementGroupHierarchyViaResourceGraph instead)
func (l *IAMComprehensiveCollectorLink) listManagementGroupsWithToken(accessToken, proxyURL string) ([]interface{}, error) {
	managementGroupsURL := "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2021-04-01&$expand=children&$recurse=true"

	client := &http.Client{Timeout: 30 * time.Second}

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(l.Context(), "GET", managementGroupsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API call failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Value []interface{} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	l.Logger.Info("Retrieved management groups", "count", len(result.Value))
	return result.Value, nil
}

// getAllRBACAssignmentsViaARG gets ALL RBAC assignments across subscriptions using Azure Resource Graph
func (l *IAMComprehensiveCollectorLink) getAllRBACAssignmentsViaARG(accessToken string, subscriptionIDs []string, proxyURL string) (map[string][]interface{}, error) {
	resourceGraphURL := "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

	// Build KQL query with subscription filtering
	var kqlQuery string
	if len(subscriptionIDs) > 0 {
		subscriptionFilter := "'" + strings.Join(subscriptionIDs, "','") + "'"
		kqlQuery = fmt.Sprintf(`
			authorizationresources
			| where type =~ 'microsoft.authorization/roleassignments'
			| where subscriptionId in (%s)
			| extend principalId = tostring(properties.principalId)
			| extend roleDefinitionId = tostring(properties.roleDefinitionId)
			| extend scope = tostring(properties.scope)
			| extend principalType = tostring(properties.principalType)
			| project id, name, subscriptionId, principalId, roleDefinitionId, scope, principalType, properties
			| order by scope asc`, subscriptionFilter)
	} else {
		// No subscription filter - get all assignments
		kqlQuery = `
			authorizationresources
			| where type =~ 'microsoft.authorization/roleassignments'
			| extend principalId = tostring(properties.principalId)
			| extend roleDefinitionId = tostring(properties.roleDefinitionId)
			| extend scope = tostring(properties.scope)
			| extend principalType = tostring(properties.principalType)
			| project id, name, subscriptionId, principalId, roleDefinitionId, scope, principalType, properties
			| order by scope asc`
	}

	requestBody := map[string]interface{}{
		"query": kqlQuery,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(l.Context(), "POST", resourceGraphURL, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Resource Graph API call failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data []interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode Resource Graph response: %v", err)
	}

	l.Logger.Info("Retrieved RBAC assignments via Resource Graph", "total_assignments", len(result.Data))

	// Group assignments by scope type
	groupedAssignments := map[string][]interface{}{
		"subscription":    []interface{}{},
		"resourceGroup":   []interface{}{},
		"resourceLevel":   []interface{}{},
	}

	for _, assignment := range result.Data {
		if assignmentMap, ok := assignment.(map[string]interface{}); ok {
			scope, exists := assignmentMap["scope"]
			if !exists {
				continue
			}

			scopeStr := fmt.Sprintf("%v", scope)

			// Determine scope type based on scope path structure
			if strings.Count(scopeStr, "/") == 2 {
				// /subscriptions/{subscription-id} = subscription level
				groupedAssignments["subscription"] = append(groupedAssignments["subscription"], assignment)
			} else if strings.Contains(scopeStr, "/resourceGroups/") && strings.Count(scopeStr, "/") == 4 {
				// /subscriptions/{sub}/resourceGroups/{rg} = resource group level
				groupedAssignments["resourceGroup"] = append(groupedAssignments["resourceGroup"], assignment)
			} else if strings.Contains(scopeStr, "/resourceGroups/") && strings.Count(scopeStr, "/") > 4 {
				// /subscriptions/{sub}/resourceGroups/{rg}/providers/... = resource level
				groupedAssignments["resourceLevel"] = append(groupedAssignments["resourceLevel"], assignment)
			} else {
				// Default to subscription level if unsure
				groupedAssignments["subscription"] = append(groupedAssignments["subscription"], assignment)
			}
		}
	}

	l.Logger.Info("RBAC assignment breakdown",
		"subscription_level", len(groupedAssignments["subscription"]),
		"resource_group_level", len(groupedAssignments["resourceGroup"]),
		"resource_level", len(groupedAssignments["resourceLevel"]))

	return groupedAssignments, nil
}

// getAllResourceGroupsViaARG gets all resource groups across subscriptions using Azure Resource Graph
func (l *IAMComprehensiveCollectorLink) getAllResourceGroupsViaARG(accessToken string, subscriptionIDs []string, proxyURL string) ([]interface{}, error) {
	resourceGraphURL := "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

	// Build KQL query with subscription filtering
	var kqlQuery string
	if len(subscriptionIDs) > 0 {
		subscriptionFilter := "'" + strings.Join(subscriptionIDs, "','") + "'"
		kqlQuery = fmt.Sprintf(`
			resourcecontainers
			| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
			| where subscriptionId in (%s)
			| project id, name, subscriptionId, location, tags, properties
			| order by subscriptionId asc, name asc`, subscriptionFilter)
	} else {
		// No subscription filter - get all resource groups
		kqlQuery = `
			resourcecontainers
			| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
			| project id, name, subscriptionId, location, tags, properties
			| order by subscriptionId asc, name asc`
	}

	requestBody := map[string]interface{}{
		"query": kqlQuery,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(l.Context(), "POST", resourceGraphURL, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Resource Graph API call failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data []interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode Resource Graph response: %v", err)
	}

	l.Logger.Info("Retrieved resource groups via Resource Graph", "total_resource_groups", len(result.Data))

	// Group by subscription for logging
	subCounts := make(map[string]int)
	for _, rg := range result.Data {
		if rgMap, ok := rg.(map[string]interface{}); ok {
			if subId, exists := rgMap["subscriptionId"]; exists {
				subIdStr := fmt.Sprintf("%v", subId)
				subCounts[subIdStr]++
			}
		}
	}

	l.Logger.Info("Resource groups by subscription", "breakdown", subCounts)

	return result.Data, nil
}

// getAllResourcesViaARGOptimized gets all Azure resources with a single ARG query (simplified)
func (l *IAMComprehensiveCollectorLink) getAllResourcesViaARGOptimized(accessToken string, subscriptionIDs []string, proxyURL string) ([]interface{}, error) {
	resourceGraphURL := "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

	// Single query to get all resources (no type discovery needed)
	var resourceQuery string
	if len(subscriptionIDs) > 0 {
		subscriptionFilter := "'" + strings.Join(subscriptionIDs, "','") + "'"
		resourceQuery = fmt.Sprintf(`
			resources
			| where subscriptionId in (%s)
			| project id, name, type, location, resourceGroup, subscriptionId, tags, identity, properties, zones, kind, sku, plan
			| order by subscriptionId asc, type asc`, subscriptionFilter)
	} else {
		resourceQuery = `
			resources
			| project id, name, type, location, resourceGroup, subscriptionId, tags, identity, properties, zones, kind, sku, plan
			| order by subscriptionId asc, type asc`
	}

	l.Logger.Info("Executing single ARG query for all resources")

	client := &http.Client{Timeout: 120 * time.Second} // Increased timeout for large result sets

	// Apply proxy if specified
	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport := &http.Transport{
			Proxy:           http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = transport
	}

	resourceRequestBody := map[string]interface{}{
		"query": resourceQuery,
	}

	resourceRequestBodyBytes, err := json.Marshal(resourceRequestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resource request body: %v", err)
	}

	resourceReq, err := http.NewRequestWithContext(l.Context(), "POST", resourceGraphURL, bytes.NewBuffer(resourceRequestBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create resource request: %v", err)
	}

	resourceReq.Header.Set("Authorization", "Bearer "+accessToken)
	resourceReq.Header.Set("Content-Type", "application/json")

	resourceResp, err := client.Do(resourceReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make resource request: %v", err)
	}
	defer resourceResp.Body.Close()

	if resourceResp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resourceResp.Body)
		return nil, fmt.Errorf("Resource query API call failed with status %d: %s", resourceResp.StatusCode, string(bodyBytes))
	}

	var resourceResult struct {
		Data []interface{} `json:"data"`
	}

	if err := json.NewDecoder(resourceResp.Body).Decode(&resourceResult); err != nil {
		return nil, fmt.Errorf("failed to decode resource response: %v", err)
	}

	l.Logger.Info("Retrieved Azure resources via single ARG query", "total_resources", len(resourceResult.Data))

	// Group by resource type for logging
	typeCounts := make(map[string]int)
	subCounts := make(map[string]int)
	for _, resource := range resourceResult.Data {
		if resourceMap, ok := resource.(map[string]interface{}); ok {
			if resType, exists := resourceMap["type"]; exists {
				resTypeStr := fmt.Sprintf("%v", resType)
				typeCounts[resTypeStr]++
			}
			if subId, exists := resourceMap["subscriptionId"]; exists {
				subIdStr := fmt.Sprintf("%v", subId)
				subCounts[subIdStr]++
			}
		}
	}

	l.Logger.Info("Resources by subscription", "breakdown", subCounts)

	// Log top 10 resource types
	topTypes := make([]string, 0)
	for resType := range typeCounts {
		topTypes = append(topTypes, fmt.Sprintf("%s:%d", resType, typeCounts[resType]))
		if len(topTypes) >= 10 {
			break
		}
	}
	l.Logger.Info("Top resource types", "types", topTypes)

	return resourceResult.Data, nil
}

// collectAllGraphData collects all Azure AD data using Microsoft Graph API
func (l *IAMComprehensiveCollectorLink) collectAllGraphData(accessToken string) (map[string]interface{}, error) {
	azureADData := make(map[string]interface{})

	// Collect all Graph API data types
	collections := []struct {
		name     string
		endpoint string
	}{
		// Users - include ALL fields needed by Neo4j importer (matching AzureDumper expectations)
		{"users", "/users?$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType,createdDateTime,businessPhones,givenName,surname,mobilePhone,officeLocation,preferredLanguage"},
		// Groups - include all fields needed by Neo4j importer
		{"groups", "/groups?$select=id,displayName,description,groupTypes,membershipRule,mailEnabled,securityEnabled,createdDateTime"},
		// Service Principals - include all fields needed by Neo4j importer
		{"servicePrincipals", "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,createdDateTime,replyUrls,signInAudience"},
		// Applications - include all fields needed by Neo4j importer
		{"applications", "/applications?$select=id,appId,displayName,createdDateTime,signInAudience,replyUrls"},
		// Devices - include all fields needed by Neo4j importer
		{"devices", "/devices?$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,isCompliant,isManaged,accountEnabled,createdDateTime"},
		// Directory roles and conditional access policies (these already work)
		{"directoryRoles", "/directoryRoles"},
		// Role definitions - needed for permission expansion in Neo4j importer
		{"roleDefinitions", "/roleManagement/directory/roleDefinitions?$select=id,displayName,description,rolePermissions,templateId,isBuiltIn"},
		{"conditionalAccessPolicies", "/identity/conditionalAccess/policies"},
	}

	for _, collection := range collections {
		l.Logger.Info(fmt.Sprintf("Collecting %s", collection.name))
		message.Info("Collecting %s from Graph API...", collection.name)

		data, err := l.collectPaginatedGraphData(accessToken, collection.endpoint)
		if err != nil {
			l.Logger.Error(fmt.Sprintf("Failed to collect %s", collection.name), "error", err)
			continue
		}

		azureADData[collection.name] = data
		l.Logger.Info(fmt.Sprintf("Collected %d %s", len(data), collection.name))
	}

	// Collect relationships
	l.Logger.Info("Collecting relationships")

	// Group memberships
	groupMemberships, err := l.collectGroupMemberships(accessToken)
	if err != nil {
		l.Logger.Error("Failed to collect group memberships", "error", err)
	} else {
		azureADData["groupMemberships"] = groupMemberships
	}

	// Directory role assignments
	l.Logger.Info("*** TRACE PRE-CALL: About to call collectDirectoryRoleAssignments ***")

	// Get the already-collected service principals to pass to the function
	var servicePrincipalsForDirectoryRoles []interface{}
	if spData, exists := azureADData["servicePrincipals"]; exists {
		if spList, ok := spData.([]interface{}); ok {
			servicePrincipalsForDirectoryRoles = spList
		}
	}

	roleAssignments, err := l.collectDirectoryRoleAssignments(accessToken, servicePrincipalsForDirectoryRoles)
	l.Logger.Info("*** TRACE POST-CALL: Returned from collectDirectoryRoleAssignments ***")
	if err != nil {
		l.Logger.Error("Failed to collect directory role assignments", "error", err)
	} else {
		azureADData["directoryRoleAssignments"] = roleAssignments
	}

	// OAuth2 permission grants
	oauth2Grants, err := l.collectPaginatedGraphData(accessToken, "/oauth2PermissionGrants")
	if err != nil {
		l.Logger.Error("Failed to collect OAuth2 permission grants", "error", err)
	} else {
		azureADData["oauth2PermissionGrants"] = oauth2Grants
	}

	// App role assignments
	appRoleAssignments, err := l.collectAppRoleAssignments(accessToken)
	if err != nil {
		l.Logger.Error("Failed to collect app role assignments", "error", err)
	} else {
		azureADData["appRoleAssignments"] = appRoleAssignments
	}

	// Collect application ownership data
	l.Logger.Info("Collecting application ownership")
	applicationOwnership, err := l.collectApplicationOwnership(accessToken)
	if err != nil {
		l.Logger.Error("Failed to collect application ownership", "error", err)
	} else {
		azureADData["applicationOwnership"] = applicationOwnership
	}

	// Collect application credential management permissions
	l.Logger.Info("Collecting application credential management permissions")
	credentialPerms, err := l.collectApplicationCredentialPermissions(accessToken)
	if err != nil {
		l.Logger.Error("Failed to collect application credential permissions", "error", err)
	} else {
		azureADData["applicationCredentialPermissions"] = credentialPerms
	}

	// Collect application RBAC permissions
	l.Logger.Info("Collecting application RBAC permissions")
	appRBAC, err := l.collectApplicationRBACPermissions(accessToken)
	if err != nil {
		l.Logger.Error("Failed to collect application RBAC permissions", "error", err)
	} else {
		azureADData["applicationRBACPermissions"] = appRBAC
	}

	return azureADData, nil
}

// collectAllPIMData collects all PIM data
func (l *IAMComprehensiveCollectorLink) collectAllPIMData(accessToken, tenantID string) (map[string]interface{}, error) {
	pimData := make(map[string]interface{})

	// Collect eligible assignments
	l.Logger.Info("Collecting PIM eligible assignments")
	eligibleAssignments, err := l.collectPIMAssignments(accessToken, "eligible", tenantID)
	if err != nil {
		l.Logger.Error("Failed to collect eligible assignments", "error", err)
	} else {
		pimData["eligible_assignments"] = eligibleAssignments
	}

	// Collect active assignments
	l.Logger.Info("Collecting PIM active assignments")
	activeAssignments, err := l.collectPIMAssignments(accessToken, "active", tenantID)
	if err != nil {
		l.Logger.Error("Failed to collect active assignments", "error", err)
	} else {
		pimData["active_assignments"] = activeAssignments
	}

	return pimData, nil
}

// collectAllAzureRMData collects all AzureRM data - optimized with Azure Resource Graph
func (l *IAMComprehensiveCollectorLink) collectAllAzureRMData(accessToken, subscriptionID, proxyURL string) (map[string]interface{}, error) {
	azurermData := make(map[string]interface{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	l.Logger.Info("Starting optimized Azure RM data collection with ARG")

	// Prepare subscription list for ARG queries
	subscriptionIDs := []string{subscriptionID}

	// Phase 1: Collect all data in parallel using ARG optimization
	wg.Add(5)

	// 1. All RBAC assignments via single ARG query (replaces subscription, RG, and resource-level RBAC)
	go func() {
		defer wg.Done()
		l.Logger.Info("Collecting ALL RBAC assignments via Azure Resource Graph")
		if allRBACAssignments, err := l.getAllRBACAssignmentsViaARG(accessToken, subscriptionIDs, proxyURL); err == nil {
			mu.Lock()
			// Split assignments by scope type for compatibility
			azurermData["subscriptionRoleAssignments"] = allRBACAssignments["subscription"]
			azurermData["resourceGroupRoleAssignments"] = allRBACAssignments["resourceGroup"]
			azurermData["resourceLevelRoleAssignments"] = allRBACAssignments["resource"]
			mu.Unlock()

			subCount := len(allRBACAssignments["subscription"])
			rgCount := len(allRBACAssignments["resourceGroup"])
			resCount := len(allRBACAssignments["resource"])
			totalCount := subCount + rgCount + resCount

			l.Logger.Info(fmt.Sprintf("Collected %d total RBAC assignments: %d subscription, %d resource group, %d resource-level",
				totalCount, subCount, rgCount, resCount))
		} else {
			l.Logger.Error("Failed to collect RBAC assignments via ARG", "error", err)
		}
	}()

	// 2. All resource groups via single ARG query
	go func() {
		defer wg.Done()
		l.Logger.Info("Collecting resource groups via Azure Resource Graph")
		if resourceGroups, err := l.getAllResourceGroupsViaARG(accessToken, subscriptionIDs, proxyURL); err == nil {
			mu.Lock()
			azurermData["azureResourceGroups"] = resourceGroups
			mu.Unlock()
			l.Logger.Info(fmt.Sprintf("Collected %d resource groups", len(resourceGroups)))
		} else {
			l.Logger.Error("Failed to collect resource groups via ARG", "error", err)
		}
	}()

	// 3. All Azure resources via optimized ARG queries
	go func() {
		defer wg.Done()
		l.Logger.Info("Collecting Azure resources via optimized Resource Graph API")
		if resources, err := l.getAllResourcesViaARGOptimized(accessToken, subscriptionIDs, proxyURL); err == nil {
			mu.Lock()
			azurermData["azureResources"] = resources
			mu.Unlock()
			l.Logger.Info(fmt.Sprintf("Collected %d Azure resources", len(resources)))
		} else {
			l.Logger.Error("Failed to collect Azure resources via ARG", "error", err)
		}
	}()

	// 4. Role definitions (keep individual API call)
	go func() {
		defer wg.Done()
		l.Logger.Info("Collecting role definitions")
		if roleDefinitions, err := l.collectRoleDefinitions(accessToken, subscriptionID); err == nil {
			mu.Lock()
			azurermData["azureRoleDefinitions"] = roleDefinitions
			mu.Unlock()
			l.Logger.Info(fmt.Sprintf("Collected %d role definitions", len(roleDefinitions)))
		} else {
			l.Logger.Error("Failed to collect role definitions", "error", err)
		}
	}()

	// 5. Key Vault access policies (keep parallel workers - depends on resources)
	go func() {
		defer wg.Done()
		l.Logger.Info("Waiting for Azure resources before collecting Key Vault access policies")

		// Wait for resources to be collected first
		for {
			mu.Lock()
			_, exists := azurermData["azureResources"]
			mu.Unlock()
			if exists {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// TEMPORARILY DISABLED: Key Vault access policy collection due to pagination hanging issues
		// TODO: Re-enable once pagination issues are fully resolved
		l.Logger.Info("Key Vault access policy collection temporarily disabled")
		/*
		l.Logger.Info("Collecting Key Vault access policies with 5 workers")
		mu.Lock()
		resourcesData := azurermData["azureResources"]
		mu.Unlock()

		if kvAccessPolicies, err := l.collectKeyVaultAccessPoliciesParallel(accessToken, subscriptionID, resourcesData.([]interface{})); err == nil {
			mu.Lock()
			azurermData["keyVaultAccessPolicies"] = kvAccessPolicies
			mu.Unlock()
			if kvAccessPolicies != nil {
				l.Logger.Info("Collected Key Vault access policies", "count", len(kvAccessPolicies))
			} else {
				l.Logger.Info("Collected Key Vault access policies", "count", 0)
			}
		} else {
			l.Logger.Error("Failed to collect Key Vault access policies", "error", err)
		}
		*/
	}()

	// Wait for all data collection to complete
	wg.Wait()

	// Apply deduplication to all role assignment collections
	seenAssignments := make(map[string]bool)

	// Helper function to deduplicate role assignments
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

	// Apply deduplication to subscription assignments
	if subscriptionAssignments, exists := azurermData["subscriptionRoleAssignments"]; exists {
		if assignments, ok := subscriptionAssignments.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["subscriptionRoleAssignments"] = deduplicated
			l.Logger.Info("Subscription RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply deduplication to resource group assignments
	if rgAssignments, exists := azurermData["resourceGroupRoleAssignments"]; exists {
		if assignments, ok := rgAssignments.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["resourceGroupRoleAssignments"] = deduplicated
			l.Logger.Info("Resource Group RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Apply deduplication to resource-level assignments
	if resourceAssignments, exists := azurermData["resourceLevelRoleAssignments"]; exists {
		if assignments, ok := resourceAssignments.([]interface{}); ok {
			originalCount := len(assignments)
			deduplicated := deduplicateAssignments(assignments)
			azurermData["resourceLevelRoleAssignments"] = deduplicated
			l.Logger.Info("Resource-level RBAC deduplication", "original", originalCount, "unique", len(deduplicated), "duplicates_removed", originalCount-len(deduplicated))
		}
	}

	// Log overall deduplication statistics
	totalUnique := len(seenAssignments)
	l.Logger.Info("Total RBAC assignment deduplication complete", "total_unique_assignments", totalUnique)

	l.Logger.Info("Parallel Azure RM data collection completed")
	return azurermData, nil
}

// Helper methods for API calls

// collectPaginatedGraphData collects paginated Graph API data
func (l *IAMComprehensiveCollectorLink) collectPaginatedGraphData(accessToken, endpoint string) ([]interface{}, error) {
	var allData []interface{}
	nextLink := fmt.Sprintf("https://graph.microsoft.com/v1.0%s", endpoint)

	for nextLink != "" {
		req, err := http.NewRequestWithContext(l.Context(), "GET", nextLink, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %v", err)
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
		}

		var result struct {
			Value    []interface{} `json:"value"`
			NextLink string        `json:"@odata.nextLink"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}
		resp.Body.Close()

		allData = append(allData, result.Value...)
		nextLink = result.NextLink

		if nextLink == "" {
			break
		}

		// Small delay to avoid throttling
		time.Sleep(100 * time.Millisecond)
	}

	return allData, nil
}

// collectPaginatedARMData collects data from Azure ARM APIs with nextLink pagination support
func (l *IAMComprehensiveCollectorLink) collectPaginatedARMData(accessToken, url string) ([]interface{}, error) {
	var allData []interface{}
	nextLink := url
	pageCount := 0
	maxPages := 100 // Safety limit to prevent infinite loops
	seenLinks := make(map[string]bool) // Detect circular nextLink references

	for nextLink != "" && pageCount < maxPages {
		// Check for circular references
		if seenLinks[nextLink] {
			l.Logger.Warn("Detected circular nextLink reference, breaking pagination loop", "url", nextLink)
			break
		}
		seenLinks[nextLink] = true
		pageCount++

		l.Logger.Debug("Fetching paginated ARM data", "page", pageCount, "url", nextLink)

		req, err := http.NewRequestWithContext(l.Context(), "GET", nextLink, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request (page %d): %v", pageCount, err)
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := l.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed (page %d): %v", pageCount, err)
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("API call failed (page %d) with status %d", pageCount, resp.StatusCode)
		}

		var result struct {
			Value    []interface{} `json:"value"`
			NextLink string        `json:"nextLink"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response (page %d): %v", pageCount, err)
		}
		resp.Body.Close()

		l.Logger.Debug("Retrieved ARM data page", "page", pageCount, "items", len(result.Value), "hasNextLink", result.NextLink != "")

		allData = append(allData, result.Value...)
		nextLink = result.NextLink

		if nextLink == "" {
			break
		}

		// Small delay to avoid throttling
		time.Sleep(100 * time.Millisecond)
	}

	if pageCount >= maxPages {
		l.Logger.Warn("Reached maximum page limit for ARM pagination", "maxPages", maxPages, "url", url)
	}

	l.Logger.Debug("ARM pagination completed", "totalPages", pageCount, "totalItems", len(allData))
	return allData, nil
}

// callGraphBatchAPI makes batch Graph API call
func (l *IAMComprehensiveCollectorLink) callGraphBatchAPI(accessToken string, requests []map[string]interface{}) (map[string]interface{}, error) {
	batchURL := "https://graph.microsoft.com/v1.0/$batch"

	batchPayload := map[string]interface{}{
		"requests": requests,
	}

	batchPayloadJSON, err := json.Marshal(batchPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch payload: %v", err)
	}

	req, err := http.NewRequestWithContext(l.Context(), "POST", batchURL, strings.NewReader(string(batchPayloadJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create batch request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	l.Logger.Info(fmt.Sprintf("Batch calling %d requests...", len(requests)))

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("batch request failed: %v", err)
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

// collectGroupMemberships collects all group membership relationships using batching
func (l *IAMComprehensiveCollectorLink) collectGroupMemberships(accessToken string) ([]interface{}, error) {
	groups, err := l.collectPaginatedGraphData(accessToken, "/groups")
	if err != nil {
		return nil, err
	}

	var memberships []interface{}
	l.Logger.Info(fmt.Sprintf("Getting members for %d groups using batch API...", len(groups)))

	// Process groups in batches of 10
	batchSize := 10

	for i := 0; i < len(groups); i += batchSize {
		end := i + batchSize
		if end > len(groups) {
			end = len(groups)
		}
		batchGroups := groups[i:end]

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

			// Add members request
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("group_%d_members", j),
				"method": "GET",
				"url":    fmt.Sprintf("/groups/%s/members", groupID),
			})
		}

		// Execute batch request
		if len(batchRequests) > 0 {
			batchResults, err := l.callGraphBatchAPI(accessToken, batchRequests)
			if err != nil {
				l.Logger.Error("Batch request failed for group memberships", "error", err)
				continue
			}

			// Process batch results
			if responses, ok := batchResults["responses"].([]interface{}); ok {
				for _, response := range responses {
					if respMap, ok := response.(map[string]interface{}); ok {
						if body, ok := respMap["body"].(map[string]interface{}); ok {
							if value, ok := body["value"].([]interface{}); ok {
								for _, member := range value {
									if memberMap, ok := member.(map[string]interface{}); ok {
										memberID := memberMap["id"].(string)

										// Extract group ID from request ID
										requestID := respMap["id"].(string)
										groupIndex := strings.Replace(strings.Replace(requestID, "group_", "", 1), "_members", "", 1)

										// Find corresponding group
										if groupData, exists := groupDataMap[fmt.Sprintf("group_%s", groupIndex)]; exists {
											if groupInfo, ok := groupData.(map[string]interface{}); ok {
												groupID := groupInfo["id"].(string)

												membership := map[string]interface{}{
													"groupId":    groupID,
													"memberId":   memberID,
													"memberType": memberMap["@odata.type"],
												}
												memberships = append(memberships, membership)
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

		// Add delay between batches
		time.Sleep(200 * time.Millisecond)
	}

	return memberships, nil
}

// collectDirectoryRoleAssignments collects directory role assignments
func (l *IAMComprehensiveCollectorLink) collectDirectoryRoleAssignments(accessToken string, servicePrincipals []interface{}) ([]interface{}, error) {
	l.Logger.Info("*** TRACE 1: Entering collectDirectoryRoleAssignments function ***")
	roles, err := l.collectPaginatedGraphData(accessToken, "/directoryRoles")
	if err != nil {
		l.Logger.Error("*** TRACE 2: Failed to get directory roles, exiting early ***", "error", err)
		return nil, err
	}
	l.Logger.Info(fmt.Sprintf("*** TRACE 3: Successfully got %d directory roles ***", len(roles)))

	var assignments []interface{}

	l.Logger.Info(fmt.Sprintf("Getting members for %d directory roles using batch API...", len(roles)))
	l.Logger.Info("*** TRACE 4: About to start main directory role loop ***")

	// Process directory roles in batches for member collection
	batchSize := 20 // Larger batch since these are simpler calls
	l.Logger.Info(fmt.Sprintf("*** TRACE 5: Starting loop with batchSize=%d, total roles=%d ***", batchSize, len(roles)))
	for batchIdx := 0; batchIdx < len(roles); batchIdx += batchSize {
		l.Logger.Info(fmt.Sprintf("*** TRACE 6: Processing batch starting at index %d ***", batchIdx))

		// Ensure batchIdx is within bounds
		if batchIdx >= len(roles) {
			break
		}

		end := batchIdx + batchSize
		if end > len(roles) {
			end = len(roles)
		}
		batchRoles := roles[batchIdx:end]

		l.Logger.Info(fmt.Sprintf("Batch calling %d requests...", len(batchRoles)))

		// Create batch requests for directory role members
		var batchRequests []map[string]interface{}
		for i, role := range batchRoles {
			roleMap, ok := role.(map[string]interface{})
			if !ok {
				continue
			}

			roleID, ok := roleMap["id"].(string)
			if !ok {
				continue
			}

			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("%d", i+1),
				"method": "GET",
				"url":    fmt.Sprintf("/directoryRoles/%s/members", roleID),
			})
		}

		if len(batchRequests) == 0 {
			l.Logger.Warn("*** TRACE 7: Empty batch requests, continuing to next batch ***")
			continue
		}

		// Make batch API call
		l.Logger.Info(fmt.Sprintf("*** TRACE 8: Making batch API call with %d requests ***", len(batchRequests)))
		batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
		if err != nil {
			l.Logger.Error("*** TRACE 9: Batch API call failed, continuing to next batch ***", "error", err, "batchIdx", batchIdx)
			continue
		}
		l.Logger.Info("*** TRACE 10: Batch API call succeeded ***")

		responses, ok := batchResponse["responses"].([]interface{})
		if !ok {
			l.Logger.Error("Invalid batch response format for directory role members")
			continue
		}

		// Process batch responses
		for i, role := range batchRoles {
			roleMap, ok := role.(map[string]interface{})
			if !ok {
				continue
			}

			roleID, ok := roleMap["id"].(string)
			if !ok {
				continue
			}

			if i >= len(responses) {
				continue
			}

			responseInterface := responses[i]
			response, ok := responseInterface.(map[string]interface{})
			if !ok {
				continue
			}

			if status, ok := response["status"].(float64); ok && status == 200 {
				if body, ok := response["body"].(map[string]interface{}); ok {
					if members, ok := body["value"].([]interface{}); ok {
						for _, member := range members {
							memberMap, ok := member.(map[string]interface{})
							if !ok {
								continue
							}

							memberID, ok := memberMap["id"].(string)
							if !ok {
								continue
							}

							assignment := map[string]interface{}{
								"roleId":         roleID,
								"roleTemplateId": roleMap["roleTemplateId"], // Add roleTemplateId for Neo4j matching
								"roleName":       roleMap["displayName"],
								"principalId":    memberID,
								"principalType":  memberMap["@odata.type"],
							}
							assignments = append(assignments, assignment)
						}
					}
				}
			}
		}

		l.Logger.Info(fmt.Sprintf("*** TRACE 11: Finished processing batch at index %d ***", batchIdx))
		time.Sleep(500 * time.Millisecond) // Brief pause between batches
	}

	l.Logger.Info("*** TRACE 12: MAIN LOOP COMPLETE - Exited normally after processing all batches ***")

	// BUGFIX: Also collect directory roles for service principals using memberOf approach
	// The /directoryRoles/{roleId}/members endpoint has a known asymmetry bug where service principals
	// don't appear in role membership lists, but they do appear when querying their memberOf
	l.Logger.Info("*** TRACE 13: About to start service principal collection ***")
	l.Logger.Info("Collecting service principal directory role assignments using memberOf approach...")
	servicePrincipalAssignments, err := l.collectServicePrincipalDirectoryRoles(accessToken, servicePrincipals)
	if err != nil {
		l.Logger.Error("*** TRACE 14: Service principal collection FAILED ***", "error", err)
	} else {
		assignments = append(assignments, servicePrincipalAssignments...)
		l.Logger.Info(fmt.Sprintf("*** TRACE 15: Successfully found %d additional directory role assignments from service principals ***", len(servicePrincipalAssignments)))
	}

	l.Logger.Info(fmt.Sprintf("*** TRACE 16: Returning from collectDirectoryRoleAssignments with %d total assignments ***", len(assignments)))
	return assignments, nil
}

// collectServicePrincipalDirectoryRoles collects directory role assignments for service principals
// using the memberOf approach to work around Graph API asymmetry bug
func (l *IAMComprehensiveCollectorLink) collectServicePrincipalDirectoryRoles(accessToken string, servicePrincipals []interface{}) ([]interface{}, error) {
	l.Logger.Info("*** TRACE SP-1: Entering collectServicePrincipalDirectoryRoles ***")

	// Use the already-collected service principals passed as parameter
	if servicePrincipals == nil || len(servicePrincipals) == 0 {
		l.Logger.Error("*** TRACE SP-2: No service principals provided ***")
		return nil, fmt.Errorf("no service principals provided")
	}

	l.Logger.Info(fmt.Sprintf("*** TRACE SP-3: Got %d service principals, checking for directory roles ***", len(servicePrincipals)))

	var assignments []interface{}

	// Process service principals in batches for memberOf collection
	batchSize := 20
	for batchIdx := 0; batchIdx < len(servicePrincipals); batchIdx += batchSize {
		// Ensure batchIdx is within bounds
		if batchIdx >= len(servicePrincipals) {
			break
		}

		end := batchIdx + batchSize
		if end > len(servicePrincipals) {
			end = len(servicePrincipals)
		}
		batchSPs := servicePrincipals[batchIdx:end]

		l.Logger.Info(fmt.Sprintf("*** TRACE SP-4: Processing SP batch %d with %d service principals ***", batchIdx/batchSize, len(batchSPs)))

		// Create batch requests for service principal memberOf
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

		l.Logger.Info(fmt.Sprintf("*** TRACE SP-5: Making batch API call for %d SP memberOf requests ***", len(batchRequests)))

		// Make batch API call
		batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
		if err != nil {
			l.Logger.Error("*** TRACE SP-6: Failed batch API call for SP memberOf ***", "error", err)
			continue
		}

		responses, ok := batchResponse["responses"].([]interface{})
		if !ok {
			l.Logger.Error("*** TRACE SP-7: Invalid batch response format for service principal memberOf ***")
			continue
		}

		l.Logger.Info(fmt.Sprintf("*** TRACE SP-8: Processing %d responses from batch ***", len(responses)))

		// Process batch responses
		for i, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}

			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}

			if i >= len(responses) {
				continue
			}

			responseInterface := responses[i]
			response, ok := responseInterface.(map[string]interface{})
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

							// Filter for directory roles only (client-side since server-side filter not supported)
							odataType, ok := memberMap["@odata.type"].(string)
							if !ok || odataType != "#microsoft.graph.directoryRole" {
								continue
							}

							roleID, ok := memberMap["id"].(string)
							if !ok {
								continue
							}

							l.Logger.Info(fmt.Sprintf("*** TRACE SP-9: Found SP %s has directory role %s ***", spID, roleID))

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

		time.Sleep(500 * time.Millisecond) // Brief pause between batches
	}

	l.Logger.Info(fmt.Sprintf("*** TRACE SP-10: Completed SP directory role collection, found %d assignments ***", len(assignments)))
	return assignments, nil
}

// collectAppRoleAssignments collects application role assignments using batch API
func (l *IAMComprehensiveCollectorLink) collectAppRoleAssignments(accessToken string) ([]interface{}, error) {
	servicePrincipals, err := l.collectPaginatedGraphData(accessToken, "/servicePrincipals")
	if err != nil {
		return nil, err
	}

	var allAppRoleAssignments []interface{}

	l.Logger.Info(fmt.Sprintf("Getting app role assignments for %d service principals using batch API...", len(servicePrincipals)))

	// Process service principals in batches of 10 (20 requests per batch - 2 per SP)
	batchSize := 10
	totalBatches := (len(servicePrincipals) + batchSize - 1) / batchSize

	for batchIdx := 0; batchIdx < len(servicePrincipals); batchIdx += batchSize {
		batchNum := (batchIdx / batchSize) + 1

		// Ensure batchIdx is within bounds
		if batchIdx >= len(servicePrincipals) {
			break
		}

		end := batchIdx + batchSize
		if end > len(servicePrincipals) {
			end = len(servicePrincipals)
		}
		batchSPs := servicePrincipals[batchIdx:end]

		l.Logger.Info(fmt.Sprintf("Batch calling %d requests...", len(batchSPs)*2))

		// Create batch requests (2 per service principal)
		var batchRequests []map[string]interface{}
		requestID := 1

		for _, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}

			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}

			// Request for assignments TO this service principal
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("%d", requestID),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignments?$select=id,appRoleId,principalId,principalDisplayName,principalType,resourceId,resourceDisplayName", spID),
			})
			requestID++

			// Request for assignments FROM this service principal
			batchRequests = append(batchRequests, map[string]interface{}{
				"id":     fmt.Sprintf("%d", requestID),
				"method": "GET",
				"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignedTo?$select=id,appRoleId,principalId,principalDisplayName,principalType,resourceId,resourceDisplayName", spID),
			})
			requestID++
		}

		if len(batchRequests) == 0 {
			continue
		}

		// Make batch API call
		batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
		if err != nil {
			l.Logger.Error(fmt.Sprintf("Failed to get batch response for batch %d", batchNum), "error", err)
			continue
		}

		responses, ok := batchResponse["responses"].([]interface{})
		if !ok {
			l.Logger.Error(fmt.Sprintf("Invalid batch response format for batch %d", batchNum))
			continue
		}

		// Process batch responses
		requestIdx := 0
		for _, sp := range batchSPs {
			spMap, ok := sp.(map[string]interface{})
			if !ok {
				continue
			}

			spID, ok := spMap["id"].(string)
			if !ok {
				continue
			}

			spName, _ := spMap["displayName"].(string)
			if spName == "" {
				spName = "Unknown"
			}

			// Process assignments TO this service principal
			if requestIdx < len(responses) {
				toResponseInterface := responses[requestIdx]
				if toResponse, ok := toResponseInterface.(map[string]interface{}); ok {
					if status, ok := toResponse["status"].(float64); ok && status == 200 {
						if body, ok := toResponse["body"].(map[string]interface{}); ok {
							if assignmentsTo, ok := body["value"].([]interface{}); ok {
								for _, assignment := range assignmentsTo {
									if assignmentMap, ok := assignment.(map[string]interface{}); ok {
										assignmentMap["direction"] = "assigned_to"
										assignmentMap["servicePrincipalId"] = spID
										assignmentMap["servicePrincipalDisplayName"] = spName
									}
								}
								allAppRoleAssignments = append(allAppRoleAssignments, assignmentsTo...)
							}
						}
					}
				}
			}
			requestIdx++

			// Process assignments FROM this service principal
			if requestIdx < len(responses) {
				fromResponseInterface := responses[requestIdx]
				if fromResponse, ok := fromResponseInterface.(map[string]interface{}); ok {
					if status, ok := fromResponse["status"].(float64); ok && status == 200 {
						if body, ok := fromResponse["body"].(map[string]interface{}); ok {
							if assignmentsFrom, ok := body["value"].([]interface{}); ok {
								for _, assignment := range assignmentsFrom {
									if assignmentMap, ok := assignment.(map[string]interface{}); ok {
										assignmentMap["direction"] = "assigned_from"
										assignmentMap["servicePrincipalId"] = spID
										assignmentMap["servicePrincipalDisplayName"] = spName
									}
								}
								allAppRoleAssignments = append(allAppRoleAssignments, assignmentsFrom...)
							}
						}
					}
				}
			}
			requestIdx++
		}

		time.Sleep(500 * time.Millisecond) // Brief pause between batches
	}

	l.Logger.Info(fmt.Sprintf("Collected %d application role assignments using %d batch calls", len(allAppRoleAssignments), totalBatches))
	return allAppRoleAssignments, nil
}

// collectPIMAssignments collects PIM assignments
func (l *IAMComprehensiveCollectorLink) collectPIMAssignments(accessToken, assignmentType, tenantID string) ([]interface{}, error) {
	// Use URL encoding for query parameters
	baseURL := "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadroles/roleAssignments"

	// Build query parameters separately to avoid URL truncation
	params := url.Values{}
	params.Add("$expand", "linkedEligibleRoleAssignment,subject,scopedResource,roleDefinition($expand=resource)")
	params.Add("$count", "true")

	var filterValue string
	switch assignmentType {
	case "eligible":
		filterValue = fmt.Sprintf("(roleDefinition/resource/id eq '%s') and (assignmentState eq 'Eligible')", tenantID)
	case "active":
		filterValue = fmt.Sprintf("(roleDefinition/resource/id eq '%s') and (assignmentState eq 'Active')", tenantID)
	default:
		return nil, fmt.Errorf("unknown assignment type: %s", assignmentType)
	}

	params.Add("$filter", filterValue)
	params.Add("$orderby", "roleDefinition/displayName")

	endpoint := baseURL + "?" + params.Encode()

	// Debug logging to see complete URL
	l.Logger.Info("PIM API URL constructed", "url", endpoint, "length", len(endpoint))

	req, err := http.NewRequestWithContext(l.Context(), "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
	}

	var result struct {
		Value []interface{} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return result.Value, nil
}

// collectAzureResourcesViaGraph collects all Azure resources using Resource Graph API
func (l *IAMComprehensiveCollectorLink) collectAzureResourcesViaGraph(accessToken, subscriptionID string) ([]interface{}, error) {
	resourceGraphURL := "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

	// Use comprehensive Resource Graph query
	kustoQuery := `resources|where ((type in~ ('microsoft.insights/workbooktemplates','microsoft.insights/workbooks','microsoft.insights/webtests','microsoft.insights/privatelinkscopes','microsoft.insights/components','microsoft.appplatform/spring','microsoft.cache/redis','microsoft.cache/redisenterprise/databases','microsoft.cache/redisenterprise','microsoft.visualstudio/account','astronomer.astro/organizations','microsoft.confluent/organizations','microsoft.datadog/monitors','dell.storage/filesystems','dynatrace.observability/monitors','microsoft.elastic/monitors','informatica.datamanagement/organizations','newrelic.observability/monitors','pinecone.vectordb/organizations','mongodb.atlas/organizations','microsoft.weightsandbiases/instances','liftrbasic.samplerp/organizations','lambdatest.hyperexecute/organizations','commvault.contentstore/cloudaccounts','arizeai.observabilityeval/organizations','neon.postgres/organizations','nginx.nginxplus/nginxdeployments','paloaltonetworks.cloudngfw/localrulestacks','paloaltonetworks.cloudngfw/globalrulestacks','paloaltonetworks.cloudngfw/firewalls','microsoft.liftrpilot/organizations','purestorage.block/storagepools','purestorage.block/reservations','purestorage.block/storagepools/avsstoragecontainers','qumulo.storage/filesystems','microsoft.resources/subscriptions/resourcegroups','microsoft.portal/virtual-privatedashboards','microsoft.portal/dashboards','microsoft.resourcegraph/queries','microsoft.azureactivedirectory/guestusages','microsoft.azureactivedirectory/ciamdirectories','microsoft.azureactivedirectory/b2cdirectories','microsoft.aad/domainservices','microsoft.aadiam/privatelinkforazuread','providers.test/statefulibizaengines','microsoft.edge/disconnectedoperations','microsoft.all/hcivirtualmachines','microsoft.azurestackhci/storagecontainers','microsoft.azurestackhci/clusters','microsoft.azurestackhci/networksecuritygroups','microsoft.azurestackhci/networkinterfaces','microsoft.azurestackhci/marketplacegalleryimages','microsoft.azurestackhci/logicalnetworks','microsoft.azurestackhci/galleryimages','microsoft.azurestackhci/clusters/updatesummaries','microsoft.azurestackhci/clusters/updates/updateruns','microsoft.azurestackhci/devicepools','private.aszlabhardware/labservers','private.aszlabhardware/reservations','private.aszlabhardware/servers','microsoft.deviceupdate/accounts','microsoft.cdn/profiles','microsoft.agfoodplatform/farmbeats','microsoft.agricultureplatform/agriservices','microsoft.analysisservices/servers','microsoft.fabric/capacities','microsoft.network/networkmanagers/verifierworkspaces','microsoft.mobilenetwork/packetcorecontrolplanes/packetcoredataplanes/attacheddatanetworks','microsoft.mobilenetwork/packetcorecontrolplanes','microsoft.mobilenetwork/mobilenetworks/datanetworks','microsoft.mobilenetwork/packetcorecontrolplanes/packetcoredataplanes','microsoft.mobilenetwork/mobilenetworks','microsoft.mobilenetwork/radioaccessnetworks','microsoft.mobilenetwork/mobilenetworks/services','microsoft.mobilenetwork/simgroups/sims','microsoft.mobilenetwork/simgroups','microsoft.mobilenetwork/mobilenetworks/simpolicies','microsoft.mobilenetwork/mobilenetworks/sites','microsoft.mobilenetwork/mobilenetworks/slices','microsoft.apimanagement/service/workspaces','microsoft.apicenter/services/workspaces','microsoft.apimanagement/service','microsoft.apimanagement/gateways','microsoft.apicenter/services','microsoft.solutions/applicationdefinitions','microsoft.solutions/applications','microsoft.vsonline/plans','microsoft.arc/allfairfax','microsoft.arc/all','microsoft.arc/kubernetesresources','microsoft.kubernetes/connectedclusters','microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/extensions','microsoft.kubernetesruntime/loadbalancers','microsoft.attestation/attestationproviders','microsoft.automanage/serviceprincipals','microsoft.automation/automationaccounts','microsoft.automation/automationaccounts/modules','microsoft.automation/automationaccounts/hybridrunbookworkergroups','microsoft.automation/automationaccounts/runbooks','microsoft.maintenance/maintenanceconfigurationsaumbladeresource','microsoft.updatemanager/updaterules','microsoft.appconfiguration/configurationstores','microsoft.azurefleet/fleets','microsoft.batch/batchaccounts','microsoft.resources/subscriptions','microsoft.botservice/botservices','microsoft.cdn/profiles/endpoints/origins','microsoft.cdn/profiles/securitypolicies','microsoft.cdn/profiles/secrets','microsoft.cdn/profiles/rulesets','microsoft.cdn/profiles/rulesets/rules','microsoft.cdn/profiles/afdendpoints/routes','microsoft.cdn/profiles/origingroups','microsoft.cdn/profiles/origingroups/origins','microsoft.cdn/profiles/afdendpoints','microsoft.cdn/profiles/customdomains','microsoft.cdn/profiles/endpoints','microsoft.cdn/profiles/endpoints/customdomains','microsoft.chaos/workspaces','microsoft.chaos/privateaccesses','microsoft.chaos/experiments','microsoft.classiccompute/virtualmachines','microsoft.classicstorage/storageaccounts/vmimages','microsoft.classicstorage/storageaccounts/osimages','microsoft.classicstorage/storageaccounts/disks','microsoft.sovereign/transparencylogs','microsoft.sovereign/landingzoneaccounts/landingzoneregistrations','microsoft.sovereign/landingzoneaccounts','microsoft.sovereign/landingzoneaccounts/landingzoneconfigurations','microsoft.hardwaresecuritymodules/cloudhsmclusters','microsoft.loadtestservice/supportedresourcetypes','microsoft.loadtestservice/playwrightworkspaces','microsoft.loadtestservice/loadtests','microsoft.loadtestservice/allservices','microsoft.classiccompute/domainnames/slots/roles','microsoft.classiccompute/domainnames','microsoft.compute/cloudservices','microsoft.cloudtest/pools','microsoft.cloudtest/images','microsoft.cloudtest/hostedpools','microsoft.cloudtest/buildcaches','microsoft.cloudtest/accounts','microsoft.codesigning/codesigningaccounts','microsoft.communication/communicationservices','microsoft.voiceservices/communicationsgateways/testlines','microsoft.voiceservices/communicationsgateways','microsoft.community/communitytrainings','microsoft.compute/virtualmachinescalesets','microsoft.compute/virtualmachines','microsoft.all/virtualmachines','microsoft.compute/sshpublickeys','microsoft.compute/proximityplacementgroups','microsoft.compute/virtualmachineflexinstances','microsoft.compute/standbypoolinstance','microsoft.compute/computefleetscalesets','microsoft.compute/computefleetinstances','microsoft.compute/hostgroups/hosts','microsoft.compute/hostgroups','microsoft.compute/capacityreservationgroups','microsoft.compute/availabilitysets','microsoft.computehub/windowsostype','microsoft.computehub/provisioningstatesucceededresources','microsoft.computehub/provisioningstatefailedresources','microsoft.computehub/powerstatestopped','microsoft.computehub/powerstaterunning','microsoft.computehub/powerstatedeallocated','microsoft.computehub/outages','microsoft.computehub/microsoftdefenderstandardsubscription','microsoft.computehub/microsoftdefenderfreetrialsubscription','microsoft.computehub/linuxostype','microsoft.computehub/healthevents','microsoft.computehub/computehubmain','microsoft.computehub/backup','microsoft.computehub/all','microsoft.computehub/advisorsecurity','microsoft.computehub/advisorreliability','microsoft.computehub/advisorperformance','microsoft.computehub/advisoroperationalexcellence','microsoft.computehub/advisorcost','microsoft.confidentialledger/ledgers','microsoft.confidentialledger/managedccfs','microsoft.containerregistry/registries/webhooks','microsoft.containerregistry/registries/tokens','microsoft.containerregistry/registries/scopemaps','microsoft.containerregistry/registries/replications','microsoft.containerregistry/registries','microsoft.kubernetesconfiguration/extensions','microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/fluxconfigurations','microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/fluxconfigurations','microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/namespaces','microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/namespaces','microsoft.containerinstance/containergroups','microsoft.containerservice/managedclusters/managednamespaces','microsoft.containerservice/managedclusters','microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/extensions','microsoft.redhatopenshift/openshiftclusters','microsoft.containerstorage/pools','microsoft.portalservices/extensions/deployments','microsoft.portalservices/extensions','microsoft.portalservices/extensions/slots','microsoft.portalservices/extensions/versions','microsoft.azuredatatransfer/pipelines','microsoft.azuredatatransfer/connections/flows','microsoft.azuredatatransfer/connections','microsoft.managedservices/registrationdefinitions','microsoft.dashboard/grafana','microsoft.databasewatcher/watchers','microsoft.databricks/workspaces','microsoft.databricks/accessconnectors','microsoft.datafactory/factories','microsoft.datafactory/datafactories','microsoft.datalakeanalytics/accounts','microsoft.datalakestore/accounts','microsoft.dataprotection/resourceguards','microsoft.dataprotection/backupvaults','microsoft.datashare/accounts','microsoft.securitydetonation/chambers','microsoft.devcenter/projects','microsoft.devcenter/projects/pools','microsoft.devcenter/plans','microsoft.devcenter/networkconnections','microsoft.devcenter/devcenters','microsoft.devcenter/devcenters/devboxdefinitions','microsoft.deviceregistry/convergedassets','microsoft.deviceregistry/schemaregistries','microsoft.deviceregistry/namespaces/assets','microsoft.deviceregistry/namespaces','microsoft.deviceregistry/devices','microsoft.deviceregistry/assetendpointprofiles','microsoft.deviceregistry/assets','microsoft.deviceupdate/updateaccounts','microsoft.deviceupdate/updateaccounts/updates','microsoft.deviceupdate/updateaccounts/deviceclasses','microsoft.deviceupdate/updateaccounts/deployments','microsoft.deviceupdate/updateaccounts/agents','microsoft.deviceupdate/updateaccounts/activedeployments','microsoft.devopsinfrastructure/pools','microsoft.devtestlab/labs/virtualmachines','microsoft.devtestlab/labs','microsoft.devtunnels/tunnelplans','microsoft.digitaltwins/digitaltwinsinstances','microsoft.discovery/workspaces','microsoft.discovery/workflows','microsoft.discovery/tools','microsoft.discovery/supercomputers','microsoft.discovery/storages','microsoft.discovery/workspaces/projects','microsoft.discovery/supercomputers/nodepools','microsoft.discovery/models','microsoft.discovery/datacontainers','microsoft.discovery/datacontainers/dataassets','microsoft.discovery/bookshelves','microsoft.discovery/agents','microsoft.compute/snapshots','microsoft.compute/galleries','microsoft.compute/restorepointcollections','microsoft.compute/restorepointcollections/restorepoints','microsoft.compute/galleries/images/versions','microsoft.virtualmachineimages/imagetemplates','microsoft.compute/images','microsoft.compute/galleries/images','microsoft.compute/galleries/applications/versions','microsoft.compute/galleries/applications','microsoft.compute/diskencryptionsets','microsoft.compute/diskaccesses','microsoft.compute/disks','microsoft.compute/locations/communitygalleries/images','microsoft.datamigration/sqlmigrationservices','microsoft.datamigration/dmscentermain','microsoft.datamigration/all','microsoft.datamigration/services/projects','microsoft.datamigration/services','microsoft.network/trafficmanagerprofiles','microsoft.network/dnszones','microsoft.network/dnsresolvers','microsoft.network/dnsforwardingrulesets','microsoft.network/dnsresolverpolicies','microsoft.network/dnsresolverdomainlists','microsoft.documentdb/mongoclusters','microsoft.dbforpostgresql/servergroupsv2','microsoft.documentdb/cassandraclusters','microsoft.documentdb/garnetclusters','microsoft.documentdb/fleetspacepotentialdatabaseaccountswithlocations','microsoft.documentdb/fleetspacepotentialdatabaseaccounts','microsoft.documentdb/fleets','microsoft.documentdb/databaseaccounts','microsoft.easm/workspaces','private.easm/workspaces','microsoft.impact/connectors','microsoft.cdn/edgeactions','microsoft.databoxedge/databoxedgedevices','microsoft.azurestackhci/edgemachines','microsoft.edgeorder/virtual_orderitems','microsoft.edgeorder/orderitems','microsoft.edgeorder/bootstrapconfigurations','microsoft.edgeorder/addresses','microsoft.elasticsan/elasticsans','microsoft.logic/workflows','microsoft.logic/integrationserviceenvironments/managedapis','microsoft.logic/templates','microsoft.logic/integrationaccounts','microsoft.web/connectiongateways','microsoft.web/customapis','microsoft.web/connections','microsoft.communication/emailservices','microsoft.communication/emailservices/domains','microsoft.eventgrid/namespaces/topicspaces','microsoft.eventgrid/topics','microsoft.eventgrid/systemtopics/eventsubscriptions','microsoft.eventgrid/systemtopics','microsoft.eventgrid/namespaces/topics/eventsubscriptions','microsoft.eventgrid/namespaces','microsoft.eventgrid/partnertopics','microsoft.eventgrid/partnerregistrations','microsoft.eventgrid/partnernamespaces','microsoft.eventgrid/partnerdestinations','microsoft.eventgrid/partnerconfigurations','microsoft.eventgrid/namespaces/topics','microsoft.eventgrid/domains/topics','microsoft.eventgrid/domains','microsoft.eventgrid/partnernamespaces/channels','microsoft.eventhub/namespaces/disasterrecoveryconfigs','microsoft.eventhub/namespaces/schemagroups','microsoft.eventhub/namespaces/eventhubs','microsoft.eventhub/clusters','microsoft.eventhub/namespaces','microsoft.experimentation/experimentworkspaces','microsoft.databox/jobs','microsoft.fairfieldgardens/provisioningresources','microsoft.fairfieldgardens/provisioningresources/provisioningpolicies','microsoft.fileshares/fileshares','microsoft.iotfirmwaredefense/workspaces','microsoft.fluidrelay/fluidrelayservers','microsoft.network/frontdoors','microsoft.hdinsight/clusters','microsoft.healthbot/healthbots','microsoft.healthdataaiservices/deidservices','microsoft.healthmodel/healthmodels','microsoft.hybridcompute/machines/microsoft.connectedvmwarevsphere/virtualmachineinstances','microsoft.connectedvmwarevsphere/virtualmachines','microsoft.connectedvmwarevsphere/vcenters','microsoft.hybridcompute/machinessoftwareassurance','microsoft.hybridcompute/machinespaygo','microsoft.hybridcompute/licenses','microsoft.hybridcompute/machinesesu','microsoft.hybridcompute/gateways','microsoft.hybridcompute/arcgatewayassociatedresources','microsoft.scvmm/vmmservers','microsoft.scvmm/virtualmachines','microsoft.hybridcompute/privatelinkscopes','microsoft.hybridconnectivity/publiccloudconnectors','microsoft.hybridconnectivity/publiccloudconnectors/gcpsyncedresources','microsoft.hybridconnectivity/publiccloudconnectors/awssyncedresources','microsoft.hybridcompute/machinessovereign','microsoft.hybridcompute/machines','microsoft.hybridcompute/arcserverwithwac','microsoft.machineconfiguration/baselinesettingsassignments','microsoft.extendedlocation/customlocations','microsoft.azurestackhci/virtualmachines','microsoft.all/arcvirtualmachines','microsoft.resourceconnector/appliances','microsoft.azurearcdata/sqlserverlicenses','microsoft.azurearcdata/sqlserverinstances/databases','microsoft.azurearcdata/sqlserverinstances','microsoft.azurearcdata/sqlserveresulicenses','microsoft.azurearcdata/sqlmanagedinstances','microsoft.azurearcdata/postgressqlserver','microsoft.azurearcdata/postgresinstances','microsoft.azurearcdata/mysqlserver','microsoft.azurearcdata/datacontrollers','microsoft.network/vpngateways','microsoft.network/networkvirtualappliances','microsoft.network/virtualwans','microsoft.network/virtualhubs','microsoft.network/virtualnetworkgateways','microsoft.network/routefilters','microsoft.network/p2svpngateways','microsoft.networkfunction/meshvpns','microsoft.network/localnetworkgateways','microsoft.network/ipgroups','microsoft.network/firewallpolicies','microsoft.networkfunction/azuretrafficcollectors','microsoft.network/expressroutegateways/expressrouteconnections','microsoft.network/expressroutegateways','microsoft.network/expressrouteports','microsoft.network/expressroutecircuits','microsoft.network/connections','microsoft.network/azurefirewalls','microsoft.network/bastionhosts','microsoft.network/applicationgateways','microsoft.servicenetworking/trafficcontrollers','microsoft.devhub/iacprofiles','microsoft.iotcentral/iotapps','microsoft.devices/iothubs','microsoft.devices/provisioningservices','microsoft.iotoperations/instances','microsoft.network/networkmanagers/ipampools','microsoft.storagesync/storagesyncservices','microsoft.keyvault/vaults','microsoft.containerservice/fleets/managednamespaces','microsoft.containerservice/fleets','microsoft.synapse/workspaces/kustopools/databases','microsoft.synapse/workspaces/kustopools','microsoft.kusto/clusters/databases','microsoft.kusto/clusters','microsoft.maps/accounts','microsoft.maps/accounts/creators','microsoft.computeschedule/scheduledactions','microsoft.maintenance/maintenanceconfigurations','microsoft.keyvault/managedhsms','microsoft.labservices/labaccounts/labs','microsoft.labservices/labplans','microsoft.labservices/labaccounts','microsoft.labservices/labs','microsoft.network/networkmanagers/routingconfigurations','microsoft.network/networkmanagers/securityuserconfigurations','microsoft.network/networkmanagers/securityadminconfigurations','microsoft.network/networkmanagers/networkgroups','microsoft.network/networkmanagers/connectivityconfigurations','microsoft.network/networkmanagers','microsoft.managedidentity/userassignedidentities','microsoft.saas/resources','microsoft.saas/applications','microsoft.saas/saasresources','microsoft.gallery/myareas/galleryitems','microsoft.professionalservice/resources','microsoft.migrate/projects','microsoft.machinelearningservices/workspacescreate','microsoft.machinelearningservices/workspaces','microsoft.machinelearningservices/aistudiocreate','microsoft.machinelearningservices/aistudio','microsoft.machinelearningservices/registries','microsoft.machinelearningservices/workspaces/onlineendpoints','microsoft.machinelearningservices/workspaces/onlineendpoints/deployments','microsoft.dashboard/dashboards','private.monitorgrafana/dashboards','microsoft.alertsmanagement/prometheusrulegroups','microsoft.monitor/accounts','microsoft.insights/datacollectionrulesresources','microsoft.insights/datacollectionrules','microsoft.insights/datacollectionendpoints','microsoft.insights/diagnosticsettings','microsoft.eventhub/namespaces/providers/diagnosticsettings','microsoft.monitor/pipelinegroups','microsoft.alertsmanagement/smartdetectoralertrules','microsoft.insights/metricalerts','microsoft.insights/scheduledqueryrules','microsoft.alertsmanagement/actionrules','microsoft.insights/activitylogalerts','microsoft.insights/actiongroups','microsoft.netapp/netappaccounts/capacitypools/volumes/volumequotarules','microsoft.netapp/netappaccounts/volumegroups','microsoft.netapp/scaleaccounts/scalecapacitypools/scalevolumes','microsoft.netapp/netappaccounts/capacitypools/volumes','microsoft.netapp/scaleaccounts/scalesnapshotpolicies','microsoft.netapp/netappaccounts/snapshotpolicies','microsoft.netapp/scaleaccounts/scalecapacitypools/scalevolumes/scalesnapshots','microsoft.netapp/netappaccounts/capacitypools/volumes/snapshots','microsoft.netapp/scaleaccounts/scalecapacitypools','microsoft.netapp/netappaccounts/capacitypools','microsoft.netapp/scaleaccounts/scalebackupvaults','microsoft.netapp/netappaccounts/backupvaults','microsoft.netapp/scaleaccounts/scalecapacitypools/scalevolumes/scalebackups','microsoft.netapp/netappaccounts/backupvaults/backups','microsoft.netapp/scaleaccounts/scalebackuppolicies','microsoft.netapp/netappaccounts/backuppolicies','microsoft.netapp/scaleaccounts','microsoft.netapp/netappaccounts','microsoft.network/frontdoorwebapplicationfirewallpolicies','microsoft.cdn/cdnwebapplicationfirewallpolicies','microsoft.network/applicationgatewaywebapplicationfirewallpolicies','microsoft.network/virtualnetworktaps','microsoft.network/privatednszones/virtualnetworklinks','microsoft.network/virtualnetworks','microsoft.network/serviceendpointpolicies','microsoft.network/routetables','microsoft.authorization/resourcemanagementprivatelinks','microsoft.classicnetwork/reservedips','microsoft.network/publicipprefixes','microsoft.network/publicipaddresses','microsoft.network/privatelinkservices','microsoft.management/managementgroups/providers/privatelinkassociations','microsoft.network/privateendpoints','microsoft.network/networkwatchers/flowlogs','microsoft.network/networkwatchers','microsoft.network/networksecuritygroups','microsoft.network/networkinterfaces','microsoft.network/natgateways','microsoft.network/loadbalancers','microsoft.connectedvmwarevsphere/virtualmachines/providers/guestconfigurationassignments','microsoft.compute/virtualmachinescalesets/providers/guestconfigurationassignments','microsoft.hybridcompute/machines/providers/guestconfigurationassignments','microsoft.compute/virtualmachines/providers/guestconfigurationassignments','microsoft.network/ddosprotectionplans','microsoft.network/customipprefixes','microsoft.classicnetwork/virtualnetworks','microsoft.classicnetwork/networksecuritygroups','microsoft.network/applicationsecuritygroups','microsoft.managednetworkfabric/routepolicies','microsoft.managednetworkfabric/fabricroutepolicies','microsoft.managednetworkfabric/networktaprules','microsoft.managednetworkfabric/networktaps','microsoft.managednetworkfabric/fabricnetworktaps','microsoft.managednetworkfabric/networkracks','microsoft.managednetworkfabric/networkpacketbrokers','microsoft.managednetworkfabric/fabricnetworkpacketbrokers','microsoft.managednetworkfabric/networkdevices/networkinterfaces','microsoft.managednetworkfabric/networkfabriccontrollers','microsoft.managednetworkfabric/networkfabrics','microsoft.managednetworkfabric/networkdevices','microsoft.managednetworkfabric/fabricnetworkdevices','microsoft.managednetworkfabric/neighborgroups','microsoft.managednetworkfabric/networkfabrics/networktonetworkinterconnects','microsoft.managednetworkfabric/l3isolationdomains','microsoft.managednetworkfabric/l2isolationdomains','microsoft.managednetworkfabric/ipprefixes','microsoft.managednetworkfabric/ipextendedcommunities','microsoft.managednetworkfabric/ipcommunities','microsoft.managednetworkfabric/internetgatewayrules','microsoft.managednetworkfabric/internetgateways','microsoft.managednetworkfabric/l3isolationdomains/internalnetworks','microsoft.managednetworkfabric/fabricresources','microsoft.managednetworkfabric/l3isolationdomains/externalnetworks','microsoft.managednetworkfabric/accesscontrollists','microsoft.networkcloud/volumes','microsoft.networkcloud/clustervolumes','microsoft.networkcloud/virtualmachines/consoles','microsoft.networkcloud/virtualmachines','microsoft.networkcloud/trunkednetworks','microsoft.networkcloud/clustertrunkednetworks','microsoft.networkcloud/storageappliances','microsoft.networkcloud/clusterstorageappliances','microsoft.networkcloud/kubernetesclusters/features','microsoft.networkcloud/kubernetesclusters','microsoft.networkcloud/l3networks','microsoft.networkcloud/clusterl3networks','microsoft.networkcloud/l2networks','microsoft.networkcloud/clusterl2networks','microsoft.networkcloud/racks','microsoft.networkcloud/clusterresources','microsoft.networkcloud/clusternetworks','microsoft.networkcloud/clusters/metricsconfigurations','microsoft.networkcloud/clustermanagers','microsoft.networkcloud/clusters/baremetalmachinekeysets','microsoft.networkcloud/clusters/bmckeysets','microsoft.networkcloud/clusters','microsoft.networkcloud/clustercloudservicesnetworks','microsoft.networkcloud/cloudservicesnetworks','microsoft.networkcloud/baremetalmachines','microsoft.networkcloud/kubernetesclusters/agentpools','microsoft.network/networksecurityperimeters','microsoft.network/networksecurityperimeters/profiles','microsoft.notificationhubs/namespaces/notificationhubs','microsoft.notificationhubs/namespaces','microsoft.resources/resourcegraphvisualizer','microsoft.resources/resourcechange','microsoft.onlineexperimentation/workspaces','microsoft.openenergyplatform/energyservices','microsoft.scom/managedinstances','microsoft.orbital/l2connections','microsoft.orbital/groundstations','microsoft.orbital/geocatalogs','microsoft.orbital/edgesites','microsoft.oriondb/clusters','microsoft.dbforpostgresql/flexibleservers','microsoft.dbformysql/flexibleservers','microsoft.durabletask/schedulers/taskhubs','microsoft.app/agents','microsoft.integrationspaces/spaces','microsoft.durabletask/schedulers','microsoft.logic/businessprocesses','microsoft.peering/peerings/registeredprefixes','microsoft.peering/peerings/registeredasns','microsoft.peering/peeringservices/prefixes','microsoft.peering/peeringservices','microsoft.peering/peerings','microsoft.azureplaywrightservice/accounts','microsoft.portalservices/dashboards','microsoft.powerbidedicated/capacities','microsoft.network/privatednszones','microsoft.programmableconnectivity/operatorapiplans','microsoft.programmableconnectivity/operatorapiconnections','microsoft.programmableconnectivity/gateways','microsoft.purview/accounts','microsoft.cognitiveservices/browsetexttranslation','microsoft.cognitiveservices/browsetextanalytics','microsoft.cognitiveservices/browsespeechservices','microsoft.cognitiveservices/browseqnamaker','microsoft.cognitiveservices/browsepersonalizer','microsoft.cognitiveservices/browseopenai','microsoft.cognitiveservices/browsemetricsadvisor','microsoft.cognitiveservices/browseluis','microsoft.cognitiveservices/browseimmersivereader','microsoft.cognitiveservices/browsehealthinsights','microsoft.cognitiveservices/browsehealthdecisionsupport','microsoft.cognitiveservices/browseformrecognizer','microsoft.cognitiveservices/browseface','microsoft.cognitiveservices/browsecustomvision','microsoft.cognitiveservices/browsecontentsafety','microsoft.cognitiveservices/browsecontentmoderator','microsoft.cognitiveservices/browsecomputervision','microsoft.cognitiveservices/accounts/projects','microsoft.cognitiveservices/accounts','microsoft.cognitiveservices/browseanomalydetector','microsoft.cognitiveservices/browseallservices','microsoft.cognitiveservices/browseallinone','microsoft.cognitiveservices/browseaiservices','microsoft.cognitiveservices/browseaifoundry','microsoft.quantum/workspaces','microsoft.recommendationsservice/accounts','microsoft.recommendationsservice/accounts/modeling','microsoft.recommendationsservice/accounts/serviceendpoints','microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems','microsoft.recoveryservices/vaults','microsoft.relay/namespaces/wcfrelays','microsoft.relay/namespaces','microsoft.relay/namespaces/hybridconnections','microsoft.billingbenefits/savingsplanorders','microsoft.billing/billingaccounts/savingsplanorders','microsoft.capacity/reservationorders','microsoft.billingbenefits/incentiveschedules/milestones','microsoft.billing/billingaccounts/incentiveschedules/milestones','microsoft.billingbenefits/maccs','microsoft.billingbenefits/discounts','microsoft.billingbenefits/savingsplanorders/savingsplans','microsoft.billing/billingaccounts/savingsplanorders/savingsplans','microsoft.capacity/reservationorders/reservations','microsoft.billingbenefits/credits','microsoft.billingbenefits/incentiveschedules','microsoft.billing/billingaccounts/incentiveschedules','microsoft.management/servicegroups','microsoft.relationships/servicegrouprelationships','microsoft.relationships/servicegroupmembernojoin','microsoft.relationships/servicegroupmember','microsoft.relationships/dependencyof','microsoft.resources/virtualsubscriptionsforresourcepicker','microsoft.resources/resourcechanges','microsoft.resources/deletedresources','microsoft.changesafety/stagemaps','microsoft.changesafety/changestates','microsoft.changesafety/changestates/stageprogressions','microsoft.management/managementgroups/microsoft.resources/deploymentstacks','microsoft.resources/deploymentstacks','microsoft.deploymentmanager/rollouts','microsoft.features/featureprovidernamespaces/featureconfigurations','microsoft.saashub/cloudservices/hidden','microsoft.hanaonazure/hanainstances','microsoft.baremetalinfrastructure/baremetalinstances','microsoft.azurelargeinstance/azurelargeinstances','microsoft.workloads/sapvirtualinstances','microsoft.workloads/sapvirtualinstances/databaseinstances','microsoft.workloads/sapvirtualinstances/centralinstances','microsoft.workloads/sapvirtualinstances/applicationinstances','microsoft.search/searchservices','microsoft.security/locations/alerts','microsoft.securityinsightsarg/sentinel','microsoft.servicebus/namespaces/topics','microsoft.servicebus/namespaces/topics/subscriptions','microsoft.servicebus/namespaces/queues','microsoft.servicebus/namespaces/disasterrecoveryconfigs','microsoft.servicebus/namespaces','microsoft.servicefabric/clusters','microsoft.servicefabric/managedclusters','microsoft.providerhub/providerregistrations','microsoft.providerhub/providerregistrations/resourcetyperegistrations','microsoft.providerhub/providerregistrations/resourcetyperegistrations/resourcetyperegistrations','microsoft.providerhub/providerregistrations/customrollouts','microsoft.providerhub/providerregistrations/defaultrollouts','microsoft.signalrservice/webpubsub/replicas','microsoft.signalrservice/webpubsub','microsoft.signalrservice/signalr/replicas','microsoft.signalrservice/signalr','microsoft.edge/sites','microsoft.edge/configurations','microsoft.azuresphere/catalogs','microsoft.datareplication/replicationvaults','microsoft.storage/storageaccounts','microsoft.classicstorage/storageaccounts','microsoft.storagecache/caches','microsoft.storagecache/amlfilesystems','microsoft.storagediscovery/storagediscoveryworkspaces','microsoft.storagehub/policycomplianceresources','microsoft.storagehub/all','microsoft.storagemover/storagemovers','microsoft.storageactions/storagetasks','microsoft.streamanalytics/clusters','microsoft.streamanalytics/streamingjobs','microsoft.support/supporttickets','microsoft.synapse/workspaces','microsoft.synapse/workspaces/sqlpools','microsoft.synapse/workspaces/bigdatapools','microsoft.synapse/workspaces/scopepools','microsoft.synapse/privatelinkhubs','microsoft.resources/deploymentscripts','microsoft.management/managementgroups/providers/templatespecs','microsoft.resources/templatespecs','microsoft.resources/builtintemplatespecs','microsoft.usagebilling/accounts/validationworkspaces/signoffs','microsoft.usagebilling/accounts/validationworkspaces','microsoft.usagebilling/accounts/pipelines/outputselectors','microsoft.usagebilling/accounts/pipelines','microsoft.usagebilling/accounts/pav2outputs','microsoft.usagebilling/accounts/metricexports','microsoft.usagebilling/accounts/inputs','microsoft.usagebilling/accounts/dataexports','microsoft.usagebilling/accounts','microsoft.mission/virtualenclaves/workloads','microsoft.mission/virtualenclaves','microsoft.mission/communities/transithubs','microsoft.mission/virtualenclaves/enclaveendpoints','microsoft.mission/enclaveconnections','microsoft.mission/communities/communityendpoints','microsoft.mission/communities','microsoft.mission/catalogs','microsoft.mission/approvals','microsoft.network/virtualnetworkappliances','microsoft.hybridnetwork/networkfunctions','microsoft.hybridnetwork/vendors','microsoft.hybridnetwork/devices','microsoft.hybridnetwork/sitenetworkservices','microsoft.hybridnetwork/sites','microsoft.hybridnetwork/publishers','microsoft.hybridnetwork/publishers/artifactstores','microsoft.hybridnetwork/publishers/artifactstores/artifactmanifests','microsoft.hybridnetwork/publishers/networkservicedesigngroups/networkservicedesignversions','microsoft.hybridnetwork/publishers/networkservicedesigngroups','microsoft.hybridnetwork/publishers/networkfunctiondefinitiongroups/networkfunctiondefinitionversions','microsoft.hybridnetwork/publishers/networkfunctiondefinitiongroups','microsoft.hybridnetwork/publishers/configurationgroupschemas','microsoft.hybridnetwork/configurationgroupvalues','microsoft.workloads/workloadinstance','microsoft.workloads/insights','microsoft.workloads/monitors','microsoft.desktopvirtualization/workspaces','microsoft.desktopvirtualization/scalingplans','microsoft.desktopvirtualization/hostpools','microsoft.desktopvirtualization/applicationgroups','microsoft.desktopvirtualization/appattachpackages','microsoft.zerotrustsegmentation/segmentationmanagers','private.zerotrustsegmentation/segmentationmanagers','microsoft.bing/accounts','microsoft.cloudhealth/healthmodels','microsoft.mixedreality/remoterenderingaccounts','microsoft.connectedcache/enterprisemcccustomers','microsoft.connectedcache/enterprisemcccustomers/enterprisemcccachenodes','microsoft.connectedcache/ispcustomers','microsoft.healthcareapis/workspaces/fhirservices','microsoft.healthcareapis/workspaces/iotconnectors','microsoft.test/healthdataaiservices','microsoft.healthcareapis/workspaces','microsoft.healthcareapis/services','microsoft.healthcareapis/workspaces/dicomservices','microsoft.manufacturingplatform/manufacturingdataservices','microsoft.operationalinsights/querypacks','microsoft.operationalinsights/workspaces','microsoft.operationsmanagement/solutions','microsoft.operationalinsights/clusters','microsoft.premonition/libraries/samples','microsoft.premonition/libraries','microsoft.premonition/libraries/analyses','microsoft.securitycopilot/capacities','private.serviceshubdev/connectors','microsoft.serviceshub/connectors','microsoft.videoindexer/accounts','oracle.database/resourceanchors','oracle.database/networkanchors','oracle.database/exadbvmclusters','oracle.database/exascaledbstoragevaults','oracle.database/cloudvmclusters','oracle.database/cloudexadatainfrastructures','oracle.database/oraclesubscriptions','oracle.database/dbsystems','oracle.database/autonomousdatabases','microsoft.azurescan/scanningaccounts','microsoft.sql/virtualclusters','microsoft.sqlvirtualmachine/sqlvirtualmachines','microsoft.sql/servers','microsoft.dbforpostgresql/servers','microsoft.dbformysql/servers','microsoft.dbformariadb/servers','microsoft.sql/managedinstances','microsoft.sql/managedinstances/databases','microsoft.sql/instancepools','microsoft.databasefleetmanager/fleets/tiers','microsoft.databasefleetmanager/fleets/fleetspaces','microsoft.databasefleetmanager/fleets/fleetspaces/databases','microsoft.databasefleetmanager/fleets','microsoft.sql/servers/elasticpools','microsoft.sql/servers/jobagents','microsoft.sql/servers/databases','microsoft.sql/azuresqlallresources','microsoft.sql/azuresql','microsoft.avs/privateclouds','microsoft.web/sites/slots','microsoft.web/sites','microsoft.web/serverfarms','microsoft.web/staticsites','microsoft.certificateregistration/certificateorders','microsoft.app/sessionpools','microsoft.app/jobs','microsoft.app/managedenvironments','microsoft.app/connectedenvironments','microsoft.app/containerapps','microsoft.web/kubeenvironments','microsoft.web/hostingenvironments','microsoft.domainregistration/domains')) or (isempty(type)))|where (type !~ ('dell.storage/filesystems'))|where (type !~ ('pinecone.vectordb/organizations'))|where (type !~ ('liftrbasic.samplerp/organizations'))|where (type !~ ('commvault.contentstore/cloudaccounts'))|where (type !~ ('paloaltonetworks.cloudngfw/globalrulestacks'))|where (type !~ ('microsoft.liftrpilot/organizations'))|where (type !~ ('microsoft.agfoodplatform/farmbeats'))|where (type !~ ('microsoft.agricultureplatform/agriservices'))|where (type !~ ('microsoft.arc/allfairfax'))|where (type !~ ('microsoft.arc/all'))|where (type !~ ('microsoft.cdn/profiles/securitypolicies'))|where (type !~ ('microsoft.cdn/profiles/secrets'))|where (type !~ ('microsoft.cdn/profiles/rulesets'))|where (type !~ ('microsoft.cdn/profiles/rulesets/rules'))|where (type !~ ('microsoft.cdn/profiles/afdendpoints/routes'))|where (type !~ ('microsoft.cdn/profiles/origingroups'))|where (type !~ ('microsoft.cdn/profiles/origingroups/origins'))|where (type !~ ('microsoft.cdn/profiles/afdendpoints'))|where (type !~ ('microsoft.cdn/profiles/customdomains'))|where (type !~ ('microsoft.chaos/workspaces'))|where (type !~ ('microsoft.chaos/privateaccesses'))|where (type !~ ('microsoft.sovereign/transparencylogs'))|where (type !~ ('microsoft.classiccompute/domainnames/slots/roles'))|where (type !~ ('microsoft.classiccompute/domainnames'))|where (type !~ ('microsoft.cloudtest/pools'))|where (type !~ ('microsoft.cloudtest/images'))|where (type !~ ('microsoft.cloudtest/hostedpools'))|where (type !~ ('microsoft.cloudtest/buildcaches'))|where (type !~ ('microsoft.cloudtest/accounts'))|where (type !~ ('microsoft.compute/virtualmachineflexinstances'))|where (type !~ ('microsoft.compute/standbypoolinstance'))|where (type !~ ('microsoft.compute/computefleetscalesets'))|where (type !~ ('microsoft.compute/computefleetinstances'))|where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))|where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))|where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/namespaces'))|where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/namespaces'))|where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/extensions'))|where (type !~ ('microsoft.portalservices/extensions/deployments'))|where (type !~ ('microsoft.portalservices/extensions'))|where (type !~ ('microsoft.portalservices/extensions/slots'))|where (type !~ ('microsoft.portalservices/extensions/versions'))|where (type !~ ('microsoft.deviceregistry/convergedassets'))|where (type !~ ('microsoft.deviceregistry/devices'))|where (type !~ ('microsoft.deviceupdate/updateaccounts'))|where (type !~ ('microsoft.deviceupdate/updateaccounts/updates'))|where (type !~ ('microsoft.deviceupdate/updateaccounts/deviceclasses'))|where (type !~ ('microsoft.deviceupdate/updateaccounts/deployments'))|where (type !~ ('microsoft.deviceupdate/updateaccounts/agents'))|where (type !~ ('microsoft.deviceupdate/updateaccounts/activedeployments'))|where (type !~ ('microsoft.discovery/supercomputers/nodepools'))|where (type !~ ('microsoft.discovery/datacontainers/dataassets'))|where (type !~ ('microsoft.documentdb/garnetclusters'))|where (type !~ ('microsoft.documentdb/fleetspacepotentialdatabaseaccountswithlocations'))|where (type !~ ('microsoft.documentdb/fleetspacepotentialdatabaseaccounts'))|where (type !~ ('private.easm/workspaces'))|where (type !~ ('microsoft.fairfieldgardens/provisioningresources'))|where (type !~ ('microsoft.fairfieldgardens/provisioningresources/provisioningpolicies'))|where (type !~ ('microsoft.healthmodel/healthmodels'))|where (type !~ ('microsoft.hybridcompute/machinessoftwareassurance'))|where (type !~ ('microsoft.hybridcompute/machinespaygo'))|where (type !~ ('microsoft.hybridcompute/machinesesu'))|where (type !~ ('microsoft.hybridcompute/arcgatewayassociatedresources'))|where (type !~ ('microsoft.hybridconnectivity/publiccloudconnectors/gcpsyncedresources'))|where (type !~ ('microsoft.hybridconnectivity/publiccloudconnectors/awssyncedresources'))|where (type !~ ('microsoft.hybridcompute/machinessovereign'))|where (type !~ ('microsoft.hybridcompute/arcserverwithwac'))|where (type !~ ('microsoft.network/networkvirtualappliances'))|where (type !~ ('microsoft.network/virtualhubs')) or ((kind =~ ('routeserver')))|where (type !~ ('microsoft.devhub/iacprofiles'))|where (type !~ ('microsoft.containerservice/fleets/managednamespaces'))|where (type !~ ('microsoft.gallery/myareas/galleryitems'))|where (type !~ ('private.monitorgrafana/dashboards'))|where (type !~ ('microsoft.insights/diagnosticsettings'))|where (type !~ ('microsoft.network/privatednszones/virtualnetworklinks'))|where not((type =~ ('microsoft.network/serviceendpointpolicies')) and ((kind =~ ('internal'))))|where (type !~ ('microsoft.managednetworkfabric/fabricroutepolicies'))|where (type !~ ('microsoft.managednetworkfabric/fabricnetworktaps'))|where (type !~ ('microsoft.managednetworkfabric/fabricnetworkpacketbrokers'))|where (type !~ ('microsoft.managednetworkfabric/fabricnetworkdevices'))|where (type !~ ('microsoft.managednetworkfabric/fabricresources'))|where (type !~ ('microsoft.networkcloud/clustervolumes'))|where (type !~ ('microsoft.networkcloud/clustertrunkednetworks'))|where (type !~ ('microsoft.networkcloud/clusterstorageappliances'))|where (type !~ ('microsoft.networkcloud/clusterl3networks'))|where (type !~ ('microsoft.networkcloud/clusterl2networks'))|where (type !~ ('microsoft.networkcloud/clusterresources'))|where (type !~ ('microsoft.networkcloud/clusternetworks'))|where (type !~ ('microsoft.networkcloud/clustercloudservicesnetworks'))|where (type !~ ('microsoft.resources/resourcegraphvisualizer'))|where (type !~ ('microsoft.orbital/l2connections'))|where (type !~ ('microsoft.orbital/groundstations'))|where (type !~ ('microsoft.orbital/edgesites'))|where (type !~ ('microsoft.oriondb/clusters'))|where (type !~ ('microsoft.recommendationsservice/accounts/modeling'))|where (type !~ ('microsoft.recommendationsservice/accounts/serviceendpoints'))|where (type !~ ('microsoft.relationships/servicegrouprelationships'))|where (type !~ ('microsoft.resources/virtualsubscriptionsforresourcepicker'))|where (type !~ ('microsoft.resources/deletedresources'))|where (type !~ ('microsoft.deploymentmanager/rollouts'))|where (type !~ ('microsoft.features/featureprovidernamespaces/featureconfigurations'))|where (type !~ ('microsoft.saashub/cloudservices/hidden'))|where (type !~ ('microsoft.providerhub/providerregistrations'))|where (type !~ ('microsoft.providerhub/providerregistrations/customrollouts'))|where (type !~ ('microsoft.providerhub/providerregistrations/defaultrollouts'))|where (type !~ ('microsoft.edge/configurations'))|where (type !~ ('microsoft.storagecache/caches'))|where not((type =~ ('microsoft.synapse/workspaces/sqlpools')) and ((kind =~ ('v3'))))|where (type !~ ('microsoft.mission/virtualenclaves/workloads'))|where (type !~ ('microsoft.mission/virtualenclaves'))|where (type !~ ('microsoft.mission/communities/transithubs'))|where (type !~ ('microsoft.mission/virtualenclaves/enclaveendpoints'))|where (type !~ ('microsoft.mission/enclaveconnections'))|where (type !~ ('microsoft.mission/communities/communityendpoints'))|where (type !~ ('microsoft.mission/communities'))|where (type !~ ('microsoft.mission/catalogs'))|where (type !~ ('microsoft.mission/approvals'))|where (type !~ ('microsoft.network/virtualnetworkappliances'))|where (type !~ ('microsoft.workloads/insights'))|where (type !~ ('microsoft.zerotrustsegmentation/segmentationmanagers'))|where (type !~ ('private.zerotrustsegmentation/segmentationmanagers'))|where (type !~ ('microsoft.connectedcache/enterprisemcccustomers/enterprisemcccachenodes'))|where (type !~ ('microsoft.premonition/libraries/samples'))|where (type !~ ('microsoft.premonition/libraries/analyses'))|where not((type =~ ('microsoft.sql/servers')) and ((kind =~ ('v12.0,analytics'))))|where not((type =~ ('microsoft.sql/servers/databases')) and ((kind in~ ('system','v2.0,system','v12.0,system','v12.0,system,serverless','v12.0,user,datawarehouse,gen2,analytics'))))|project id,name,type,kind,location,subscriptionId,resourceGroup,tags,extendedLocation,identity|sort by (tolower(tostring(name))) asc`

	requestBody := map[string]interface{}{
		"subscriptions": []string{subscriptionID},
		"query":         kustoQuery,
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequestWithContext(l.Context(), "POST", resourceGraphURL, strings.NewReader(string(requestBodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
	}

	var result struct {
		Data []interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return result.Data, nil
}

// collectAllRoleAssignments collects role assignments at subscription, resource group, and resource levels
func (l *IAMComprehensiveCollectorLink) collectAllRoleAssignments(accessToken, subscriptionID string) ([]interface{}, error) {
	var allAssignments []interface{}

	// Subscription level role assignments
	subscriptionScope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	subscriptionAssignments, err := l.getRoleAssignmentsForScope(accessToken, subscriptionScope)
	if err != nil {
		l.Logger.Error("Failed to get subscription role assignments", "error", err)
	} else {
		allAssignments = append(allAssignments, subscriptionAssignments...)
	}

	// Resource group level role assignments
	resourceGroups, err := l.getResourceGroups(accessToken, subscriptionID)
	if err != nil {
		l.Logger.Error("Failed to get resource groups", "error", err)
	} else {
		for _, rg := range resourceGroups {
			rgMap, ok := rg.(map[string]interface{})
			if !ok {
				continue
			}
			rgID, ok := rgMap["id"].(string)
			if !ok {
				continue
			}
			rgAssignments, err := l.getRoleAssignmentsForScope(accessToken, rgID)
			if err != nil {
				l.Logger.Debug("Failed to get resource group assignments", "resourceGroup", rgID, "error", err)
				continue
			}
			allAssignments = append(allAssignments, rgAssignments...)
		}
	}

	return allAssignments, nil
}

// getRoleAssignmentsForScope gets role assignments for a specific scope with pagination support
func (l *IAMComprehensiveCollectorLink) getRoleAssignmentsForScope(accessToken, scope string) ([]interface{}, error) {
	roleAssignmentsURL := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignments?api-version=2020-04-01-preview&$filter=atScope()", scope)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, roleAssignmentsURL)
}

// getResourceGroups gets all resource groups in the subscription with pagination support
func (l *IAMComprehensiveCollectorLink) getResourceGroups(accessToken, subscriptionID string) ([]interface{}, error) {
	resourceGroupsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2021-04-01", subscriptionID)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, resourceGroupsURL)
}

// collectRoleDefinitions collects all role definitions with pagination support
func (l *IAMComprehensiveCollectorLink) collectRoleDefinitions(accessToken, subscriptionID string) ([]interface{}, error) {
	roleDefinitionsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2018-01-01-preview", subscriptionID)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, roleDefinitionsURL)
}

// collectKeyVaultAccessPolicies collects Key Vault access policies
func (l *IAMComprehensiveCollectorLink) collectKeyVaultAccessPolicies(accessToken, subscriptionID string) ([]interface{}, error) {
	// First get all Key Vaults in the subscription
	keyVaultsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01", subscriptionID)

	req, err := http.NewRequestWithContext(l.Context(), "GET", keyVaultsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
	}

	var keyVaultsResult struct {
		Value []interface{} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&keyVaultsResult); err != nil {
		return nil, fmt.Errorf("failed to decode Key Vaults response: %v", err)
	}

	var allAccessPolicies []interface{}

	// For each Key Vault, extract access policies
	for _, kv := range keyVaultsResult.Value {
		kvMap, ok := kv.(map[string]interface{})
		if !ok {
			continue
		}

		kvName, ok := kvMap["name"].(string)
		if !ok {
			continue
		}

		kvID, ok := kvMap["id"].(string)
		if !ok {
			continue
		}

		if properties, ok := kvMap["properties"].(map[string]interface{}); ok {
			if accessPolicies, ok := properties["accessPolicies"].([]interface{}); ok {
				for _, policy := range accessPolicies {
					if policyMap, ok := policy.(map[string]interface{}); ok {
						// Add Key Vault context to each access policy
						enhancedPolicy := make(map[string]interface{})
						for k, v := range policyMap {
							enhancedPolicy[k] = v
						}
						enhancedPolicy["keyVaultName"] = kvName
						enhancedPolicy["keyVaultId"] = kvID
						allAccessPolicies = append(allAccessPolicies, enhancedPolicy)
					}
				}
			}
		}
	}

	return allAccessPolicies, nil
}

// collectSubscriptionRBACAssignments collects subscription-level RBAC assignments with pagination support
func (l *IAMComprehensiveCollectorLink) collectSubscriptionRBACAssignments(accessToken, subscriptionID string) ([]interface{}, error) {
	rbacURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", subscriptionID)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, rbacURL)
}

// collectResourceGroupRBACAssignments collects resource group-level RBAC assignments
func (l *IAMComprehensiveCollectorLink) collectResourceGroupRBACAssignments(accessToken, subscriptionID string) ([]interface{}, error) {
	// First get all resource groups
	resourceGroups, err := l.getResourceGroups(accessToken, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %v", err)
	}

	var allRGAssignments []interface{}

	// For each resource group, collect RBAC assignments
	for _, rg := range resourceGroups {
		rgMap, ok := rg.(map[string]interface{})
		if !ok {
			continue
		}

		rgName, ok := rgMap["name"].(string)
		if !ok {
			continue
		}

		rgRBACURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", subscriptionID, rgName)

		req, err := http.NewRequestWithContext(l.Context(), "GET", rgRBACURL, nil)
		if err != nil {
			l.Logger.Debug("Failed to create request for resource group", "rg", rgName, "error", err)
			continue
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := l.httpClient.Do(req)
		if err != nil {
			l.Logger.Debug("Request failed for resource group", "rg", rgName, "error", err)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			l.Logger.Debug("API call failed for resource group", "rg", rgName, "status", resp.StatusCode)
			continue
		}

		var result struct {
			Value []interface{} `json:"value"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			l.Logger.Debug("Failed to decode response for resource group", "rg", rgName, "error", err)
			continue
		}
		resp.Body.Close()

		allRGAssignments = append(allRGAssignments, result.Value...)

		// Add rate limiting
		time.Sleep(100 * time.Millisecond)
	}

	return allRGAssignments, nil
}

// shouldCollectRBACForResource determines if RBAC assignments should be collected for a resource type
func (l *IAMComprehensiveCollectorLink) shouldCollectRBACForResource(resourceType string) bool {
	for _, selectedType := range selectedResourceTypes {
		if strings.EqualFold(resourceType, selectedType) {
			return true
		}
	}
	return false
}

// collectSelectedResourceRBACAssignments collects RBAC assignments on selected high-value resources only
func (l *IAMComprehensiveCollectorLink) collectSelectedResourceRBACAssignments(accessToken, subscriptionID string, resources []interface{}) ([]interface{}, error) {
	// Process only selected resource types for RBAC assignments - optimized for performance
	var allResourceAssignments []interface{}
	var processedCount int

	l.Logger.Info(fmt.Sprintf("Processing %d resources, filtering for selected types only", len(resources)))

	// For each resource, check if it's a selected type, then get RBAC assignments
	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			continue
		}

		resourceID, ok := resourceMap["id"].(string)
		if !ok {
			continue
		}

		resourceType, ok := resourceMap["type"].(string)
		if !ok {
			continue
		}

		// Only collect RBAC assignments for selected resource types
		if !l.shouldCollectRBACForResource(resourceType) {
			continue
		}

		processedCount++

		resourceRBACURL := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignments?api-version=2020-04-01-preview&$filter=atScope()", resourceID)

		req, err := http.NewRequestWithContext(l.Context(), "GET", resourceRBACURL, nil)
		if err != nil {
			l.Logger.Debug("Failed to create request for resource", "resourceId", resourceID, "error", err)
			continue
		}

		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := l.httpClient.Do(req)
		if err != nil {
			l.Logger.Debug("Request failed for resource", "resourceId", resourceID, "error", err)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			l.Logger.Debug("API call failed for resource", "resourceId", resourceID, "status", resp.StatusCode)
			continue
		}

		var result struct {
			Value []interface{} `json:"value"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			l.Logger.Debug("Failed to decode response for resource", "resourceId", resourceID, "error", err)
			continue
		}
		resp.Body.Close()

		if len(result.Value) > 0 {
			allResourceAssignments = append(allResourceAssignments, result.Value...)
		}

		// Add rate limiting
		time.Sleep(100 * time.Millisecond)
	}

	l.Logger.Info(fmt.Sprintf("Optimization: Processed %d selected resources out of %d total resources (%.1f%% reduction)",
		processedCount, len(resources), (1.0-float64(processedCount)/float64(len(resources)))*100.0))

	return allResourceAssignments, nil
}

// collectResourceGroupRBACParallel collects resource group RBAC assignments using 3 workers
func (l *IAMComprehensiveCollectorLink) collectResourceGroupRBACParallel(accessToken, subscriptionID string) ([]interface{}, error) {
	// First get all resource groups
	resourceGroups, err := l.getResourceGroups(accessToken, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource groups: %v", err)
	}

	if len(resourceGroups) == 0 {
		return []interface{}{}, nil
	}

	l.Logger.Info(fmt.Sprintf("Processing %d resource groups with 5 workers", len(resourceGroups)))

	type result struct {
		rbac []interface{}
		err  error
	}

	rgChan := make(chan map[string]interface{}, len(resourceGroups))
	resultChan := make(chan result, len(resourceGroups))

	// Use 1 worker for resource groups - TESTING CONCURRENCY
	var wg sync.WaitGroup
	numWorkers := 1
	if len(resourceGroups) < 1 {
		numWorkers = len(resourceGroups)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for rg := range rgChan {
				rgName := rg["name"].(string)
				l.Logger.Debug("Worker processing resource group", "worker", workerID, "rg", rgName)
				rbac, err := l.getRGRoleAssignments(accessToken, subscriptionID, rgName)
				resultChan <- result{rbac: rbac, err: err}
			}
		}(i)
	}

	// Send work to workers
	for _, rg := range resourceGroups {
		rgChan <- rg.(map[string]interface{})
	}
	close(rgChan)

	// Wait for workers and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allRGAssignments []interface{}
	for res := range resultChan {
		if res.err != nil {
			l.Logger.Debug("Failed to get resource group RBAC assignments", "error", res.err)
			continue
		}
		if res.rbac != nil {
			allRGAssignments = append(allRGAssignments, res.rbac...)
		}
	}

	return allRGAssignments, nil
}

// collectSelectedResourceRBACParallel collects resource-level RBAC assignments using 3 workers
func (l *IAMComprehensiveCollectorLink) collectSelectedResourceRBACParallel(accessToken, subscriptionID string, resources []interface{}) ([]interface{}, error) {
	// Filter for selected resource types first
	var selectedResources []map[string]interface{}
	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			continue
		}
		resourceType, ok := resourceMap["type"].(string)
		if !ok {
			continue
		}
		// Only collect RBAC assignments for selected resource types
		if l.shouldCollectRBACForResource(resourceType) {
			selectedResources = append(selectedResources, resourceMap)
		}
	}

	if len(selectedResources) == 0 {
		return []interface{}{}, nil
	}

	l.Logger.Info(fmt.Sprintf("Processing %d selected resources with 5 workers", len(selectedResources)))

	type result struct {
		rbac []interface{}
		err  error
	}

	resourceChan := make(chan map[string]interface{}, len(selectedResources))
	resultChan := make(chan result, len(selectedResources))

	// Use 1 worker for resources - TESTING CONCURRENCY
	var wg sync.WaitGroup
	numWorkers := 1
	if len(selectedResources) < 1 {
		numWorkers = len(selectedResources)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for resource := range resourceChan {
				resourceID := resource["id"].(string)
				resourceType := resource["type"].(string)
				l.Logger.Debug("Worker processing resource", "worker", workerID, "type", resourceType, "id", resourceID)
				rbac, err := l.getResourceRoleAssignments(accessToken, resourceID)
				resultChan <- result{rbac: rbac, err: err}
			}
		}(i)
	}

	// Send work to workers
	for _, resource := range selectedResources {
		resourceChan <- resource
	}
	close(resourceChan)

	// Wait for workers and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allResourceAssignments []interface{}
	for res := range resultChan {
		if res.err != nil {
			l.Logger.Debug("Failed to get resource RBAC assignments", "error", res.err)
			continue
		}
		if res.rbac != nil {
			allResourceAssignments = append(allResourceAssignments, res.rbac...)
		}
	}

	return allResourceAssignments, nil
}

// collectKeyVaultAccessPoliciesParallel collects Key Vault access policies using 3 workers
func (l *IAMComprehensiveCollectorLink) collectKeyVaultAccessPoliciesParallel(accessToken, subscriptionID string, resources []interface{}) ([]interface{}, error) {
	// Filter for Key Vault resources only
	var keyVaults []map[string]interface{}
	for _, resource := range resources {
		resourceMap, ok := resource.(map[string]interface{})
		if !ok {
			continue
		}
		resourceType, ok := resourceMap["type"].(string)
		if !ok {
			continue
		}
		// Only process Key Vaults
		if strings.EqualFold(resourceType, "microsoft.keyvault/vaults") {
			keyVaults = append(keyVaults, resourceMap)
		}
	}

	if len(keyVaults) == 0 {
		return []interface{}{}, nil
	}

	l.Logger.Info(fmt.Sprintf("Processing %d Key Vaults with 5 workers", len(keyVaults)))

	type result struct {
		policies []interface{}
		err      error
	}

	kvChan := make(chan map[string]interface{}, len(keyVaults))
	resultChan := make(chan result, len(keyVaults))

	// Use 1 worker for Key Vaults - TESTING CONCURRENCY
	var wg sync.WaitGroup
	numWorkers := 1
	if len(keyVaults) < 1 {
		numWorkers = len(keyVaults)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for kv := range kvChan {
				kvName := kv["name"].(string)
				l.Logger.Debug("Worker processing Key Vault", "worker", workerID, "kv", kvName)
				policies, err := l.getKeyVaultAccessPolicies(accessToken, subscriptionID, kvName)
				resultChan <- result{policies: policies, err: err}
			}
		}(i)
	}

	// Send work to workers
	for _, kv := range keyVaults {
		kvChan <- kv
	}
	close(kvChan)

	// Wait for workers and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allPolicies []interface{}
	for res := range resultChan {
		if res.err != nil {
			l.Logger.Debug("Failed to get Key Vault access policies", "error", res.err)
			continue
		}
		if res.policies != nil {
			allPolicies = append(allPolicies, res.policies...)
		}
	}

	return allPolicies, nil
}

// getRGRoleAssignments gets RBAC assignments for a single resource group with pagination support
func (l *IAMComprehensiveCollectorLink) getRGRoleAssignments(accessToken, subscriptionID, rgName string) ([]interface{}, error) {
	rgRBACURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2020-10-01-preview", subscriptionID, rgName)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, rgRBACURL)
}

// getResourceRoleAssignments gets RBAC assignments for a single resource with pagination support
func (l *IAMComprehensiveCollectorLink) getResourceRoleAssignments(accessToken, resourceID string) ([]interface{}, error) {
	resourceRBACURL := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignments?api-version=2020-04-01-preview&$filter=atScope()", resourceID)

	// Use paginated ARM data collection to handle nextLink properly
	return l.collectPaginatedARMData(accessToken, resourceRBACURL)
}

// getKeyVaultAccessPolicies gets access policies for a single Key Vault
func (l *IAMComprehensiveCollectorLink) getKeyVaultAccessPolicies(accessToken, subscriptionID, kvName string) ([]interface{}, error) {
	// Use paginated ARM data collection to handle nextLink properly
	kvURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01", subscriptionID)

	allVaults, err := l.collectPaginatedARMData(accessToken, kvURL)
	if err != nil {
		return nil, fmt.Errorf("failed to collect Key Vaults for subscription %s: %v", subscriptionID, err)
	}

	// Filter for the specific Key Vault and extract access policies
	var policies []interface{}
	for _, vault := range allVaults {
		vaultMap, ok := vault.(map[string]interface{})
		if !ok {
			continue
		}
		vaultName, ok := vaultMap["name"].(string)
		if !ok || vaultName != kvName {
			continue
		}

		properties, ok := vaultMap["properties"].(map[string]interface{})
		if !ok {
			continue
		}

		accessPolicies, ok := properties["accessPolicies"].([]interface{})
		if ok {
			policies = append(policies, accessPolicies...)
		}
	}

	return policies, nil
}

// processSubscriptionsParallel processes multiple subscriptions in parallel with 5 workers
func (l *IAMComprehensiveCollectorLink) processSubscriptionsParallel(
	subscriptionIDs []string,
	refreshToken, tenantID, proxyURL string,
) map[string]interface{} {

	type subResult struct {
		subscriptionID string
		data           map[string]interface{}
		err            error
	}

	subChan := make(chan string, len(subscriptionIDs))
	resultChan := make(chan subResult, len(subscriptionIDs))

	// Use 1 worker for processing subscriptions - TESTING CONCURRENCY
	var wg sync.WaitGroup
	numWorkers := 1
	if len(subscriptionIDs) < 1 {
		numWorkers = len(subscriptionIDs)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for subID := range subChan {
				l.Logger.Info("Worker processing subscription", "worker", workerID, "subscription", subID)
				message.Info("Collecting AzureRM data for subscription %s...", subID)
				data, err := l.processSubscriptionRM(subID, refreshToken, tenantID, proxyURL)
				resultChan <- subResult{subscriptionID: subID, data: data, err: err}
			}
		}(i)
	}

	// Send work to workers
	for _, subID := range subscriptionIDs {
		subChan <- subID
	}
	close(subChan)

	// Wait for workers and close result channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	allData := make(map[string]interface{})
	for result := range resultChan {
		if result.err != nil {
			l.Logger.Error("Failed to process subscription", "subscription", result.subscriptionID, "error", result.err)
			continue
		}
		allData[result.subscriptionID] = result.data

		// Calculate totals for this subscription
		dataTypeCount := len(result.data)
		message.Info("AzureRM collector completed successfully for subscription %s! Collected %d data types", result.subscriptionID, dataTypeCount)
	}

	return allData
}

// processSubscriptionRM processes a single subscription for Azure RM data only
func (l *IAMComprehensiveCollectorLink) processSubscriptionRM(
	subscriptionID, refreshToken, tenantID, proxyURL string,
) (map[string]interface{}, error) {

	l.Logger.Info("Collecting AzureRM data", "subscription", subscriptionID)

	// Get Azure RM token
	azurermToken, err := helpers.GetAzureRMToken(refreshToken, tenantID, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get AzureRM token: %v", err)
	}

	// Collect ONLY Azure RM data (no Graph/PIM duplication!)
	azurermData, err := l.collectAllAzureRMData(azurermToken.AccessToken, subscriptionID, proxyURL)
	if err != nil {
		l.Logger.Error("Failed to collect AzureRM data", "error", err)
		return nil, err
	}

	return azurermData, nil
}

// collectCompleteGraphPermissions collects comprehensive Graph API permissions from all sources
func (l *IAMComprehensiveCollectorLink) collectCompleteGraphPermissions(accessToken string, azureADData map[string]interface{}) ([]CompleteGraphPermission, error) {
	var allPermissions []CompleteGraphPermission

	l.Logger.Info("Starting comprehensive Microsoft Graph API permissions collection")
	message.Info("Collecting comprehensive Microsoft Graph API permissions...")

	// Extract reference data (already collected)
	servicePrincipals, spOk := azureADData["servicePrincipals"].([]interface{})
	users, usersOk := azureADData["users"].([]interface{})
	groups, groupsOk := azureADData["groups"].([]interface{})

	if !spOk || !usersOk || !groupsOk {
		return nil, fmt.Errorf("missing required reference data (servicePrincipals, users, or groups)")
	}

	// Build reference maps
	spMap := l.buildServicePrincipalsMap(servicePrincipals)
	userMap := l.buildUsersMap(users)
	groupMap := l.buildGroupsMap(groups)

	// Get app roles map for permission name resolution
	appRolesMap, err := l.buildAppRolesMap(accessToken, spMap)
	if err != nil {
		l.Logger.Error("Failed to build app roles map", "error", err)
		appRolesMap = make(map[string]map[string]string)
	}

	// 1. Global OAuth2 Permission Grants (already collected in main flow)
	if oauth2Grants, exists := azureADData["oauth2PermissionGrants"]; exists {
		if oauth2List, ok := oauth2Grants.([]interface{}); ok {
			globalDelegated := l.processGlobalOAuth2Grants(oauth2List, spMap, userMap)
			allPermissions = append(allPermissions, globalDelegated...)
			l.Logger.Info(fmt.Sprintf("Processed %d global OAuth2 grants", len(globalDelegated)))
		}
	}

	// 2. Global App Role Assignments (already collected in main flow)
	if appRoleAssignments, exists := azureADData["appRoleAssignments"]; exists {
		if appRoleList, ok := appRoleAssignments.([]interface{}); ok {
			globalApplication := l.processGlobalAppRoleAssignments(appRoleList, spMap, userMap, groupMap, appRolesMap)
			allPermissions = append(allPermissions, globalApplication...)
			l.Logger.Info(fmt.Sprintf("Processed %d global app role assignments", len(globalApplication)))
		}
	}

	// 3. Service Principal specific permissions
	spPermissions, err := l.collectServicePrincipalPermissions(accessToken, servicePrincipals, spMap, userMap, appRolesMap)
	if err != nil {
		l.Logger.Error("Failed to collect service principal permissions", "error", err)
	} else {
		allPermissions = append(allPermissions, spPermissions...)
	}

	// 4. User specific permissions (limited to first 100 users for performance)
	userPermissions, err := l.collectUserPermissions(accessToken, users, spMap, userMap, appRolesMap)
	if err != nil {
		l.Logger.Error("Failed to collect user permissions", "error", err)
	} else {
		allPermissions = append(allPermissions, userPermissions...)
	}

	// 5. Group specific permissions
	groupPermissions, err := l.collectGroupPermissions(accessToken, groups, spMap, groupMap, appRolesMap)
	if err != nil {
		l.Logger.Error("Failed to collect group permissions", "error", err)
	} else {
		allPermissions = append(allPermissions, groupPermissions...)
	}

	l.Logger.Info(fmt.Sprintf("Collected %d total comprehensive Graph API permissions", len(allPermissions)))
	message.Info("Comprehensive Graph permissions collection completed: %d permissions found", len(allPermissions))

	return allPermissions, nil
}

// buildServicePrincipalsMap creates a map of service principal ID to basic info for name resolution
func (l *IAMComprehensiveCollectorLink) buildServicePrincipalsMap(servicePrincipals []interface{}) map[string]ServicePrincipalInfo {
	spMap := make(map[string]ServicePrincipalInfo)
	for _, spInterface := range servicePrincipals {
		sp, ok := spInterface.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := sp["id"].(string)
		appId, _ := sp["appId"].(string)
		displayName, _ := sp["displayName"].(string)
		if id != "" {
			spMap[id] = ServicePrincipalInfo{
				ID:          id,
				AppID:       appId,
				DisplayName: displayName,
			}
		}
	}
	return spMap
}

// buildUsersMap creates a map of user ID to basic info for name resolution
func (l *IAMComprehensiveCollectorLink) buildUsersMap(users []interface{}) map[string]UserInfo {
	userMap := make(map[string]UserInfo)
	for _, userInterface := range users {
		user, ok := userInterface.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := user["id"].(string)
		displayName, _ := user["displayName"].(string)
		upn, _ := user["userPrincipalName"].(string)
		if id != "" {
			userMap[id] = UserInfo{
				ID:                id,
				DisplayName:       displayName,
				UserPrincipalName: upn,
			}
		}
	}
	return userMap
}

// buildGroupsMap creates a map of group ID to basic info for name resolution
func (l *IAMComprehensiveCollectorLink) buildGroupsMap(groups []interface{}) map[string]GroupInfo {
	groupMap := make(map[string]GroupInfo)
	for _, groupInterface := range groups {
		group, ok := groupInterface.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := group["id"].(string)
		displayName, _ := group["displayName"].(string)
		if id != "" {
			groupMap[id] = GroupInfo{
				ID:          id,
				DisplayName: displayName,
			}
		}
	}
	return groupMap
}

// buildAppRolesMap creates a map of resource ID -> app role ID -> permission name for name resolution
func (l *IAMComprehensiveCollectorLink) buildAppRolesMap(accessToken string, spMap map[string]ServicePrincipalInfo) (map[string]map[string]string, error) {
	appRolesMap := make(map[string]map[string]string)

	// Key resource providers to get detailed app roles for
	keyResourceAppIds := []string{
		"00000003-0000-0000-c000-000000000000", // Microsoft Graph
		"00000002-0000-0000-c000-000000000000", // Azure Active Directory Graph
		"797f4846-ba00-4fd7-ba43-dac1f8f63013", // Azure Service Management
		"00000009-0000-0000-c000-000000000000", // Azure Key Vault
		"c5393580-f805-4401-95e8-94b7a6ef2fc2", // Office 365 Management APIs
		"00000007-0000-0000-c000-000000000000", // Dynamics CRM
	}

	for resourceID, spInfo := range spMap {
		// Process key resources
		shouldProcess := false
		for _, keyAppId := range keyResourceAppIds {
			if spInfo.AppID == keyAppId {
				shouldProcess = true
				break
			}
		}

		if !shouldProcess {
			continue
		}

		// Get both app roles and OAuth2 permission scopes
		appRoles, oauth2Scopes, err := l.getServicePrincipalRoles(accessToken, resourceID)
		if err != nil {
			l.Logger.Error(fmt.Sprintf("Failed to get roles for SP %s", resourceID), "error", err)
			continue
		}

		if len(appRoles) > 0 || len(oauth2Scopes) > 0 {
			roleMap := make(map[string]string)

			// Add application permissions (app roles)
			for roleID, roleName := range appRoles {
				roleMap[roleID] = roleName
			}

			// Add delegated permissions (OAuth2 scopes) with prefix
			for scopeID, scopeName := range oauth2Scopes {
				roleMap["oauth2_"+scopeID] = scopeName
			}

			appRolesMap[resourceID] = roleMap
		}
	}

	return appRolesMap, nil
}

// getServicePrincipalRoles gets app roles and OAuth2 permission scopes for a service principal
func (l *IAMComprehensiveCollectorLink) getServicePrincipalRoles(accessToken, servicePrincipalID string) (map[string]string, map[string]string, error) {
	endpoint := fmt.Sprintf("/servicePrincipals/%s?$select=appRoles,oauth2PermissionScopes", servicePrincipalID)

	req, err := http.NewRequestWithContext(l.Context(), "GET", fmt.Sprintf("https://graph.microsoft.com/v1.0%s", endpoint), nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("API call failed with status %d", resp.StatusCode)
	}

	var result struct {
		AppRoles []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"appRoles"`
		OAuth2PermissionScopes []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"oauth2PermissionScopes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, err
	}

	appRoles := make(map[string]string)
	oauth2Scopes := make(map[string]string)

	for _, role := range result.AppRoles {
		if role.ID != "" && role.Value != "" {
			appRoles[role.ID] = role.Value
		}
	}

	for _, scope := range result.OAuth2PermissionScopes {
		if scope.ID != "" && scope.Value != "" {
			oauth2Scopes[scope.ID] = scope.Value
		}
	}

	return appRoles, oauth2Scopes, nil
}

// processGlobalOAuth2Grants processes the global OAuth2 permission grants
func (l *IAMComprehensiveCollectorLink) processGlobalOAuth2Grants(grants []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	for _, grantInterface := range grants {
		grant, ok := grantInterface.(map[string]interface{})
		if !ok {
			continue
		}

		clientID, _ := grant["clientId"].(string)
		resourceID, _ := grant["resourceId"].(string)
		scope, _ := grant["scope"].(string)
		consentType, _ := grant["consentType"].(string)
		principalID, _ := grant["principalId"].(string)
		startTime, _ := grant["startTime"].(string)
		expiryTime, _ := grant["expiryTime"].(string)
		grantID, _ := grant["id"].(string)

		clientSP, clientExists := spMap[clientID]
		resourceSP, resourceExists := spMap[resourceID]
		if !clientExists || !resourceExists {
			continue
		}

		// Parse individual permissions from scope string
		scopes := strings.Fields(scope)
		for _, individualScope := range scopes {
			if strings.TrimSpace(individualScope) == "" {
				continue
			}

			permission := CompleteGraphPermission{
				ID:                   grantID,
				Type:                 "ServicePrincipalDelegated",
				ServicePrincipalID:   clientID,
				ServicePrincipalName: clientSP.DisplayName,
				ResourceAppID:        resourceSP.AppID,
				ResourceAppName:      resourceSP.DisplayName,
				PermissionType:       "Delegated",
				Permission:           strings.TrimSpace(individualScope),
				ConsentType:          consentType,
				GrantedFor:           principalID,
				CreatedDateTime:      startTime,
				ExpiryDateTime:       expiryTime,
				Scope:                scope,
				Source:               "Global",
			}

			// Add user info if available
			if principalID != "" {
				if user, exists := userMap[principalID]; exists {
					permission.UserID = user.ID
					permission.UserName = user.DisplayName
				}
			}

			permissions = append(permissions, permission)
		}
	}

	return permissions
}

// processGlobalAppRoleAssignments processes the global app role assignments
func (l *IAMComprehensiveCollectorLink) processGlobalAppRoleAssignments(assignments []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, groupMap map[string]GroupInfo, appRolesMap map[string]map[string]string) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	for _, assignmentInterface := range assignments {
		assignment, ok := assignmentInterface.(map[string]interface{})
		if !ok {
			continue
		}

		appRoleID, _ := assignment["appRoleId"].(string)
		resourceID, _ := assignment["resourceId"].(string)
		principalID, _ := assignment["principalId"].(string)
		principalType, _ := assignment["principalType"].(string)
		createdDateTime, _ := assignment["createdDateTime"].(string)
		assignmentID, _ := assignment["id"].(string)

		resourceSP, resourceExists := spMap[resourceID]
		if !resourceExists {
			continue
		}

		// Get permission name
		permissionName := appRoleID
		if resourceRoles, exists := appRolesMap[resourceID]; exists {
			if roleName, roleExists := resourceRoles[appRoleID]; roleExists {
				permissionName = roleName
			}
		}

		permission := CompleteGraphPermission{
			ID:              assignmentID,
			ResourceAppID:   resourceSP.AppID,
			ResourceAppName: resourceSP.DisplayName,
			PermissionType:  "Application",
			Permission:      permissionName,
			ConsentType:     "Admin",
			CreatedDateTime: createdDateTime,
			AppRoleID:       appRoleID,
			Source:          "Global",
		}

		// Set principal info based on type
		switch principalType {
		case "ServicePrincipal":
			if sp, exists := spMap[principalID]; exists {
				permission.Type = "ServicePrincipalApplication"
				permission.ServicePrincipalID = sp.ID
				permission.ServicePrincipalName = sp.DisplayName
			}
		case "User":
			if user, exists := userMap[principalID]; exists {
				permission.Type = "UserApplication"
				permission.UserID = user.ID
				permission.UserName = user.DisplayName
			}
		case "Group":
			if group, exists := groupMap[principalID]; exists {
				permission.Type = "GroupApplication"
				permission.GroupID = group.ID
				permission.GroupName = group.DisplayName
			}
		}

		permissions = append(permissions, permission)
	}

	return permissions
}

// collectServicePrincipalPermissions collects permissions specific to each service principal
func (l *IAMComprehensiveCollectorLink) collectServicePrincipalPermissions(accessToken string, servicePrincipals []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, appRolesMap map[string]map[string]string) ([]CompleteGraphPermission, error) {
	var permissions []CompleteGraphPermission

	l.Logger.Info("Collecting service principal specific permissions")

	batchSize := 5 // Conservative for relationship endpoints to avoid Graph API timeouts
	for i := 0; i < len(servicePrincipals); i += batchSize {
		end := i + batchSize
		if end > len(servicePrincipals) {
			end = len(servicePrincipals)
		}

		batch := servicePrincipals[i:end]
		batchPermissions := l.processServicePrincipalPermissionBatch(accessToken, batch, spMap, userMap, appRolesMap)
		permissions = append(permissions, batchPermissions...)

		l.Logger.Info(fmt.Sprintf("Processed SP permission batch %d-%d: %d permissions", i+1, end, len(batchPermissions)))
		time.Sleep(200 * time.Millisecond) // Respect Graph API throttling for relationship endpoints
	}

	return permissions, nil
}

// processServicePrincipalPermissionBatch processes a batch of service principals for permissions using Graph batch API
func (l *IAMComprehensiveCollectorLink) processServicePrincipalPermissionBatch(accessToken string, servicePrincipals []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, appRolesMap map[string]map[string]string) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	// Build batch requests for all service principals in this batch
	var batchRequests []map[string]interface{}
	spBatchMap := make(map[string]string) // Maps request ID to SP ID

	for _, spInterface := range servicePrincipals {
		sp, ok := spInterface.(map[string]interface{})
		if !ok {
			continue
		}

		spID, _ := sp["id"].(string)
		if spID == "" {
			continue
		}

		// Add app role assignments request
		appRequestID := fmt.Sprintf("sp_app_%s", spID)
		batchRequests = append(batchRequests, map[string]interface{}{
			"id":     appRequestID,
			"method": "GET",
			"url":    fmt.Sprintf("/servicePrincipals/%s/appRoleAssignments", spID),
		})
		spBatchMap[appRequestID] = spID

		// Add OAuth2 permission grants request
		oauth2RequestID := fmt.Sprintf("sp_oauth_%s", spID)
		batchRequests = append(batchRequests, map[string]interface{}{
			"id":     oauth2RequestID,
			"method": "GET",
			"url":    fmt.Sprintf("/servicePrincipals/%s/oauth2PermissionGrants", spID),
		})
		spBatchMap[oauth2RequestID] = spID
	}

	if len(batchRequests) == 0 {
		return permissions
	}

	// Execute batch request using existing batch API
	batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
	if err != nil {
		l.Logger.Error("Failed to execute service principal permissions batch", "error", err)
		return permissions
	}

	// Process batch responses
	if responses, ok := batchResponse["responses"].([]interface{}); ok {
		for _, response := range responses {
			if respMap, ok := response.(map[string]interface{}); ok {
				requestID, _ := respMap["id"].(string)
				_ = spBatchMap[requestID] // SP ID available via spBatchMap if needed

				if body, ok := respMap["body"].(map[string]interface{}); ok {
					if value, ok := body["value"].([]interface{}); ok {
						if strings.HasPrefix(requestID, "sp_app_") {
							// Process app role assignments
							for _, assignmentInterface := range value {
								assignment, ok := assignmentInterface.(map[string]interface{})
								if !ok {
									continue
								}

								permission := l.buildApplicationPermissionFromAssignment(assignment, spMap, appRolesMap, "ServicePrincipal")
								if permission.ID != "" {
									permissions = append(permissions, permission)
								}
							}
						} else if strings.HasPrefix(requestID, "sp_oauth_") {
							// Process OAuth2 grants
							for _, grantInterface := range value {
								grant, ok := grantInterface.(map[string]interface{})
								if !ok {
									continue
								}

								grantPermissions := l.buildDelegatedPermissionsFromGrant(grant, spMap, userMap, "ServicePrincipal")
								permissions = append(permissions, grantPermissions...)
							}
						}
					}
				}
			}
		}
	}

	return permissions
}

// collectUserPermissions collects permissions specific to users
func (l *IAMComprehensiveCollectorLink) collectUserPermissions(accessToken string, users []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, appRolesMap map[string]map[string]string) ([]CompleteGraphPermission, error) {
	var permissions []CompleteGraphPermission

	l.Logger.Info("Collecting user specific permissions")

	// Sample subset of users to avoid overwhelming API (focus on first 100 users)
	maxUsers := 100
	if len(users) > maxUsers {
		users = users[:maxUsers]
		l.Logger.Info(fmt.Sprintf("Limiting user permission collection to %d users", maxUsers))
	}

	batchSize := 5 // Conservative for relationship endpoints to avoid Graph API timeouts
	for i := 0; i < len(users); i += batchSize {
		end := i + batchSize
		if end > len(users) {
			end = len(users)
		}

		batch := users[i:end]
		batchPermissions := l.processUserPermissionBatch(accessToken, batch, spMap, userMap, appRolesMap)
		permissions = append(permissions, batchPermissions...)

		l.Logger.Info(fmt.Sprintf("Processed user permission batch %d-%d: %d permissions", i+1, end, len(batchPermissions)))
		time.Sleep(200 * time.Millisecond) // Respect Graph API throttling for relationship endpoints
	}

	return permissions, nil
}

// processUserPermissionBatch processes a batch of users for permissions using Graph batch API
func (l *IAMComprehensiveCollectorLink) processUserPermissionBatch(accessToken string, users []interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, appRolesMap map[string]map[string]string) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	// Build batch requests for all users in this batch
	var batchRequests []map[string]interface{}
	userBatchMap := make(map[string]string) // Maps request ID to user ID

	for _, userInterface := range users {
		user, ok := userInterface.(map[string]interface{})
		if !ok {
			continue
		}

		userID, _ := user["id"].(string)
		if userID == "" {
			continue
		}

		// Add app role assignments request
		appRequestID := fmt.Sprintf("user_app_%s", userID)
		batchRequests = append(batchRequests, map[string]interface{}{
			"id":     appRequestID,
			"method": "GET",
			"url":    fmt.Sprintf("/users/%s/appRoleAssignments", userID),
		})
		userBatchMap[appRequestID] = userID

		// Add OAuth2 permission grants request
		oauth2RequestID := fmt.Sprintf("user_oauth_%s", userID)
		batchRequests = append(batchRequests, map[string]interface{}{
			"id":     oauth2RequestID,
			"method": "GET",
			"url":    fmt.Sprintf("/users/%s/oauth2PermissionGrants", userID),
		})
		userBatchMap[oauth2RequestID] = userID
	}

	if len(batchRequests) == 0 {
		return permissions
	}

	// Execute batch request using existing batch API
	batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
	if err != nil {
		l.Logger.Error("Failed to execute user permissions batch", "error", err)
		return permissions
	}

	// Process batch responses
	if responses, ok := batchResponse["responses"].([]interface{}); ok {
		for _, response := range responses {
			if respMap, ok := response.(map[string]interface{}); ok {
				requestID, _ := respMap["id"].(string)
				userID := userBatchMap[requestID]

				// Check for successful response (status 200)
				status, _ := respMap["status"].(float64)
				if status != 200 {
					// User may not have permissions, which is normal - continue
					continue
				}

				if body, ok := respMap["body"].(map[string]interface{}); ok {
					if value, ok := body["value"].([]interface{}); ok {
						if strings.HasPrefix(requestID, "user_app_") {
							// Process app role assignments
							for _, assignmentInterface := range value {
								assignment, ok := assignmentInterface.(map[string]interface{})
								if !ok {
									continue
								}

								permission := l.buildApplicationPermissionFromAssignment(assignment, spMap, appRolesMap, "User")
								if permission.ID != "" {
									// Add user details
									if userInfo, exists := userMap[userID]; exists {
										permission.UserID = userInfo.ID
										permission.UserName = userInfo.DisplayName
									}
									permissions = append(permissions, permission)
								}
							}
						} else if strings.HasPrefix(requestID, "user_oauth_") {
							// Process OAuth2 grants
							for _, grantInterface := range value {
								grant, ok := grantInterface.(map[string]interface{})
								if !ok {
									continue
								}

								grantPermissions := l.buildDelegatedPermissionsFromGrant(grant, spMap, userMap, "User")
								permissions = append(permissions, grantPermissions...)
							}
						}
					}
				}
			}
		}
	}

	return permissions
}

// collectGroupPermissions collects permissions specific to groups
func (l *IAMComprehensiveCollectorLink) collectGroupPermissions(accessToken string, groups []interface{}, spMap map[string]ServicePrincipalInfo, groupMap map[string]GroupInfo, appRolesMap map[string]map[string]string) ([]CompleteGraphPermission, error) {
	var permissions []CompleteGraphPermission

	l.Logger.Info("Collecting group specific permissions")

	batchSize := 10 // Conservative for relationship endpoints to avoid Graph API timeouts
	for i := 0; i < len(groups); i += batchSize {
		end := i + batchSize
		if end > len(groups) {
			end = len(groups)
		}

		batch := groups[i:end]
		batchPermissions := l.processGroupPermissionBatch(accessToken, batch, spMap, groupMap, appRolesMap)
		permissions = append(permissions, batchPermissions...)

		l.Logger.Info(fmt.Sprintf("Processed group permission batch %d-%d: %d permissions", i+1, end, len(batchPermissions)))
		time.Sleep(200 * time.Millisecond) // Respect Graph API throttling for relationship endpoints
	}

	return permissions, nil
}

// processGroupPermissionBatch processes a batch of groups for permissions using Graph batch API
func (l *IAMComprehensiveCollectorLink) processGroupPermissionBatch(accessToken string, groups []interface{}, spMap map[string]ServicePrincipalInfo, groupMap map[string]GroupInfo, appRolesMap map[string]map[string]string) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	// Build batch requests for all groups in this batch
	var batchRequests []map[string]interface{}
	groupBatchMap := make(map[string]string) // Maps request ID to group ID

	for _, groupInterface := range groups {
		group, ok := groupInterface.(map[string]interface{})
		if !ok {
			continue
		}

		groupID, _ := group["id"].(string)
		if groupID == "" {
			continue
		}

		// Add app role assignments request (groups don't have OAuth2 grants)
		appRequestID := fmt.Sprintf("group_app_%s", groupID)
		batchRequests = append(batchRequests, map[string]interface{}{
			"id":     appRequestID,
			"method": "GET",
			"url":    fmt.Sprintf("/groups/%s/appRoleAssignments", groupID),
		})
		groupBatchMap[appRequestID] = groupID
	}

	if len(batchRequests) == 0 {
		return permissions
	}

	// Execute batch request using existing batch API
	batchResponse, err := l.callGraphBatchAPI(accessToken, batchRequests)
	if err != nil {
		l.Logger.Error("Failed to execute group permissions batch", "error", err)
		return permissions
	}

	// Process batch responses
	if responses, ok := batchResponse["responses"].([]interface{}); ok {
		for _, response := range responses {
			if respMap, ok := response.(map[string]interface{}); ok {
				requestID, _ := respMap["id"].(string)
				groupID := groupBatchMap[requestID]

				// Check for successful response (status 200)
				status, _ := respMap["status"].(float64)
				if status != 200 {
					// Group may not have permissions, which is normal - continue
					continue
				}

				if body, ok := respMap["body"].(map[string]interface{}); ok {
					if value, ok := body["value"].([]interface{}); ok {
						// Process app role assignments
						for _, assignmentInterface := range value {
							assignment, ok := assignmentInterface.(map[string]interface{})
							if !ok {
								continue
							}

							permission := l.buildApplicationPermissionFromAssignment(assignment, spMap, appRolesMap, "Group")
							if permission.ID != "" {
								// Add group details
								if groupInfo, exists := groupMap[groupID]; exists {
									permission.GroupID = groupInfo.ID
									permission.GroupName = groupInfo.DisplayName
								}
								permissions = append(permissions, permission)
							}
						}
					}
				}
			}
		}
	}

	return permissions
}

// buildApplicationPermissionFromAssignment builds a permission from an app role assignment
func (l *IAMComprehensiveCollectorLink) buildApplicationPermissionFromAssignment(assignment map[string]interface{}, spMap map[string]ServicePrincipalInfo, appRolesMap map[string]map[string]string, principalType string) CompleteGraphPermission {
	appRoleID, _ := assignment["appRoleId"].(string)
	resourceID, _ := assignment["resourceId"].(string)
	createdDateTime, _ := assignment["createdDateTime"].(string)
	assignmentID, _ := assignment["id"].(string)

	resourceSP, resourceExists := spMap[resourceID]
	if !resourceExists {
		return CompleteGraphPermission{}
	}

	// Get permission name
	permissionName := appRoleID
	if resourceRoles, exists := appRolesMap[resourceID]; exists {
		if roleName, roleExists := resourceRoles[appRoleID]; roleExists {
			permissionName = roleName
		}
	}

	permission := CompleteGraphPermission{
		ID:              assignmentID,
		Type:            fmt.Sprintf("%sApplication", principalType),
		ResourceAppID:   resourceSP.AppID,
		ResourceAppName: resourceSP.DisplayName,
		PermissionType:  "Application",
		Permission:      permissionName,
		ConsentType:     "Admin",
		CreatedDateTime: createdDateTime,
		AppRoleID:       appRoleID,
		Source:          principalType,
	}

	return permission
}

// buildDelegatedPermissionsFromGrant builds permissions from an OAuth2 permission grant
func (l *IAMComprehensiveCollectorLink) buildDelegatedPermissionsFromGrant(grant map[string]interface{}, spMap map[string]ServicePrincipalInfo, userMap map[string]UserInfo, principalType string) []CompleteGraphPermission {
	var permissions []CompleteGraphPermission

	clientID, _ := grant["clientId"].(string)
	resourceID, _ := grant["resourceId"].(string)
	scope, _ := grant["scope"].(string)
	consentType, _ := grant["consentType"].(string)
	principalID, _ := grant["principalId"].(string)
	startTime, _ := grant["startTime"].(string)
	expiryTime, _ := grant["expiryTime"].(string)
	grantID, _ := grant["id"].(string)

	clientSP, clientExists := spMap[clientID]
	resourceSP, resourceExists := spMap[resourceID]
	if !clientExists || !resourceExists {
		return permissions
	}

	// Parse individual permissions from scope string
	scopes := strings.Fields(scope)
	for _, individualScope := range scopes {
		if strings.TrimSpace(individualScope) == "" {
			continue
		}

		permission := CompleteGraphPermission{
			ID:                   grantID,
			Type:                 fmt.Sprintf("%sDelegated", principalType),
			ServicePrincipalID:   clientID,
			ServicePrincipalName: clientSP.DisplayName,
			ResourceAppID:        resourceSP.AppID,
			ResourceAppName:      resourceSP.DisplayName,
			PermissionType:       "Delegated",
			Permission:           strings.TrimSpace(individualScope),
			ConsentType:          consentType,
			GrantedFor:           principalID,
			CreatedDateTime:      startTime,
			ExpiryDateTime:       expiryTime,
			Scope:                scope,
			Source:               principalType,
		}

		// Add user info if available
		if principalID != "" && principalType == "User" {
			if user, exists := userMap[principalID]; exists {
				permission.UserID = user.ID
				permission.UserName = user.DisplayName
			}
		}

		permissions = append(permissions, permission)
	}

	return permissions
}

// analyzeComprehensiveGraphPermissions analyzes collected permissions for security risks
func (l *IAMComprehensiveCollectorLink) analyzeComprehensiveGraphPermissions(permissions []CompleteGraphPermission) {
	dangerousPermissions := map[string]string{
		"Directory.ReadWrite.All":                      "Full directory read/write access",
		"Directory.Read.All":                           "Full directory read access",
		"Directory.AccessAsUser.All":                   "Access directory as signed-in user",
		"User.ReadWrite.All":                           "Read/write all user profiles",
		"User.Read.All":                                "Read all user profiles",
		"User.Export.All":                              "Export user data",
		"Application.ReadWrite.All":                    "Manage all applications",
		"Application.Read.All":                         "Read all applications",
		"RoleManagement.ReadWrite.Directory":           "Manage directory roles",
		"RoleManagement.Read.Directory":                "Read directory roles",
		"DeviceManagementConfiguration.ReadWrite.All":  "Manage device configuration",
		"DeviceManagementManagedDevices.ReadWrite.All": "Manage all devices",
		"Policy.ReadWrite.All":                         "Manage all policies",
		"Policy.Read.All":                              "Read all policies",
		"Policy.ReadWrite.ConditionalAccess":           "Manage conditional access policies",
		"PrivilegedAccess.ReadWrite.AzureAD":           "Manage privileged access",
		"Sites.FullControl.All":                        "Full control of all sites",
		"Files.ReadWrite.All":                          "Read/write all files",
		"Mail.ReadWrite":                               "Read/write mail",
		"Calendars.ReadWrite":                          "Read/write calendars",
		"MailboxSettings.ReadWrite":                    "Manage mailbox settings",
		"Group.ReadWrite.All":                          "Manage all groups",
		"GroupMember.ReadWrite.All":                    "Manage group membership",
	}

	dangerousFindings := make(map[string][]string)
	typeStats := make(map[string]int)
	consentStats := make(map[string]int)

	for _, permission := range permissions {
		typeStats[permission.Type]++
		consentStats[permission.ConsentType]++

		if description, isDangerous := dangerousPermissions[permission.Permission]; isDangerous {
			key := fmt.Sprintf("%s (%s)", permission.Permission, description)
			principalName := ""
			if permission.ServicePrincipalName != "" {
				principalName = permission.ServicePrincipalName
			} else if permission.UserName != "" {
				principalName = permission.UserName
			} else if permission.GroupName != "" {
				principalName = permission.GroupName
			}
			dangerousFindings[key] = append(dangerousFindings[key], fmt.Sprintf("%s (%s)", principalName, permission.Type))
		}
	}

	// Log statistics
	l.Logger.Info("Graph Permission Statistics:")
	l.Logger.Info("By Type:")
	for permType, count := range typeStats {
		l.Logger.Info(fmt.Sprintf("  %s: %d", permType, count))
	}
	l.Logger.Info("By Consent:")
	for consent, count := range consentStats {
		l.Logger.Info(fmt.Sprintf("  %s: %d", consent, count))
	}

	if len(dangerousFindings) > 0 {
		l.Logger.Warn(fmt.Sprintf("Found %d types of dangerous Graph API permissions", len(dangerousFindings)))
		message.Info("🚨 Dangerous Graph API permissions detected:")

		for permission, principals := range dangerousFindings {
			l.Logger.Warn(fmt.Sprintf("  %s: %d principals", permission, len(principals)))
			l.Logger.Warn(fmt.Sprintf("  %s: %s", permission, strings.Join(principals, ", ")))
		}
	}
}

func (l *IAMComprehensiveCollectorLink) collectApplicationOwnership(accessToken string) ([]interface{}, error) {
	var applicationOwnerships []interface{}

	applications, err := l.collectPaginatedGraphData(accessToken, "/applications?$expand=owners")
	if err != nil {
		return nil, err
	}

	l.Logger.Info(fmt.Sprintf("Processing application ownership for %d applications", len(applications)))

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

				ownership := map[string]interface{}{
					"applicationId":      appID,
					"applicationName":    appName,
					"ownerId":           ownerID,
					"ownerName":         ownerName,
					"ownerType":         ownerType,
					"role":              "Owner",
					"permissionType":    "ApplicationOwnership",
				}
				applicationOwnerships = append(applicationOwnerships, ownership)
			}
		}
	}

	l.Logger.Info(fmt.Sprintf("Collected %d application ownership records", len(applicationOwnerships)))
	return applicationOwnerships, nil
}

func (l *IAMComprehensiveCollectorLink) collectApplicationCredentialPermissions(accessToken string) ([]interface{}, error) {
	var credentialPermissions []interface{}

	directoryRoles, err := l.collectPaginatedGraphData(accessToken, "/directoryRoles?$expand=members")
	if err != nil {
		return nil, err
	}

	// Roles that can manage application credentials
	credentialRoles := []string{
		"Application Administrator",
		"Cloud Application Administrator",
		"Global Administrator",
	}

	l.Logger.Info(fmt.Sprintf("Processing credential management permissions across %d directory roles", len(directoryRoles)))

	for _, role := range directoryRoles {
		roleMap, ok := role.(map[string]interface{})
		if !ok {
			continue
		}

		roleName, _ := roleMap["displayName"].(string)

		// Check if this role can manage application credentials
		canManageCredentials := false
		for _, credRole := range credentialRoles {
			if roleName == credRole {
				canManageCredentials = true
				break
			}
		}

		if !canManageCredentials {
			continue
		}

		if members, ok := roleMap["members"].([]interface{}); ok {
			for _, member := range members {
				memberMap, ok := member.(map[string]interface{})
				if !ok {
					continue
				}

				memberID, _ := memberMap["id"].(string)
				memberType, _ := memberMap["@odata.type"].(string)
				memberName, _ := memberMap["displayName"].(string)

				permission := map[string]interface{}{
					"principalId":       memberID,
					"principalName":     memberName,
					"principalType":     memberType,
					"role":              roleName,
					"permissionType":    "ApplicationCredentialManagement",
					"capability":        "CanManageApplicationCredentials",
				}
				credentialPermissions = append(credentialPermissions, permission)
			}
		}
	}

	l.Logger.Info(fmt.Sprintf("Collected %d application credential management permissions", len(credentialPermissions)))
	return credentialPermissions, nil
}

func (l *IAMComprehensiveCollectorLink) collectApplicationRBACPermissions(accessToken string) ([]interface{}, error) {
	var rbacPermissions []interface{}

	applications, err := l.collectPaginatedGraphData(accessToken, "/applications")
	if err != nil {
		return nil, err
	}

	l.Logger.Info(fmt.Sprintf("Processing RBAC permissions for %d applications", len(applications)))

	for _, app := range applications {
		appMap, ok := app.(map[string]interface{})
		if !ok {
			continue
		}

		appID, _ := appMap["id"].(string)
		appName, _ := appMap["displayName"].(string)

		// Note: Since applications are not ARM resources, we check for directory role memberships
		// that give implicit RBAC-like permissions over application objects
		directoryRoles := []string{
			"Application Administrator",
			"Cloud Application Administrator",
			"Application Developer",
		}

		for _, roleName := range directoryRoles {
			permission := map[string]interface{}{
				"applicationId":     appID,
				"applicationName":   appName,
				"role":              roleName,
				"permissionType":    "ApplicationRBAC",
				"scope":             "Application",
				"implicitAccess":    true,
			}
			rbacPermissions = append(rbacPermissions, permission)
		}
	}

	l.Logger.Info(fmt.Sprintf("Collected %d application RBAC permission mappings", len(rbacPermissions)))
	return rbacPermissions, nil
}