package iam

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
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

	// STEP 4: Process subscriptions using SDK clients
	l.Logger.Info("Processing %d subscriptions with SDK clients", len(subscriptionIDs))
	allSubscriptionData := l.processSubscriptionsParallelSDK(subscriptionIDs)

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

	l.Logger.Info("Successfully initialized all Azure SDK clients")
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

	l.Logger.Info("Collecting Azure AD objects via Graph SDK")

	// Collection 1: Users (with pagination)
	l.Logger.Info("Collecting users via Graph SDK with pagination")
	message.Info("Collecting users from Graph SDK...")

	users, err := l.collectAllUsersWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect users via paginated SDK", "error", err)
		azureADData["users"] = []interface{}{} // Empty array on error
	} else {
		azureADData["users"] = users
		l.Logger.Info("Collected users via paginated SDK", "count", len(users))
	}

	// Collection 2: Groups (with pagination)
	l.Logger.Info("Collecting groups via Graph SDK with pagination")
	message.Info("Collecting groups from Graph SDK...")

	groups, err := l.collectAllGroupsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect groups via paginated SDK", "error", err)
		azureADData["groups"] = []interface{}{} // Empty array on error
	} else {
		azureADData["groups"] = groups
		l.Logger.Info("Collected groups via paginated SDK", "count", len(groups))
	}

	// Collection 3: Service Principals (with pagination)
	l.Logger.Info("Collecting service principals via Graph SDK with pagination")
	message.Info("Collecting service principals from Graph SDK...")

	servicePrincipals, err := l.collectAllServicePrincipalsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect service principals via paginated SDK", "error", err)
		azureADData["servicePrincipals"] = []interface{}{} // Empty array on error
	} else {
		azureADData["servicePrincipals"] = servicePrincipals
		l.Logger.Info("Collected service principals via paginated SDK", "count", len(servicePrincipals))
	}

	// Collection 4: Applications (with pagination)
	l.Logger.Info("Collecting applications via Graph SDK with pagination")
	message.Info("Collecting applications from Graph SDK...")

	applications, err := l.collectAllApplicationsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect applications via paginated SDK", "error", err)
		azureADData["applications"] = []interface{}{} // Empty array on error
	} else {
		azureADData["applications"] = applications
		l.Logger.Info("Collected applications via paginated SDK", "count", len(applications))
	}

	// Collection 5: Devices (with pagination)
	l.Logger.Info("Collecting devices via Graph SDK with pagination")
	message.Info("Collecting devices from Graph SDK...")

	devices, err := l.collectAllDevicesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect devices via paginated SDK", "error", err)
		azureADData["devices"] = []interface{}{} // Empty array on error
	} else {
		azureADData["devices"] = devices
		l.Logger.Info("Collected devices via paginated SDK", "count", len(devices))
	}

	// Collection 6: Directory Roles (with pagination)
	l.Logger.Info("Collecting directory roles via Graph SDK with pagination")
	message.Info("Collecting directory roles from Graph SDK...")

	directoryRoles, err := l.collectAllDirectoryRolesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory roles via paginated SDK", "error", err)
		azureADData["directoryRoles"] = []interface{}{} // Empty array on error
	} else {
		azureADData["directoryRoles"] = directoryRoles
		l.Logger.Info("Collected directory roles via paginated SDK", "count", len(directoryRoles))
	}

	// Collection 7: Role Definitions (with pagination)
	l.Logger.Info("Collecting role definitions via Graph SDK with pagination")
	message.Info("Collecting role definitions from Graph SDK...")

	roleDefinitions, err := l.collectAllRoleDefinitionsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect role definitions via paginated SDK", "error", err)
		azureADData["roleDefinitions"] = []interface{}{} // Empty array on error
	} else {
		azureADData["roleDefinitions"] = roleDefinitions
		l.Logger.Info("Collected role definitions via paginated SDK", "count", len(roleDefinitions))
	}

	// Collection 8: Conditional Access Policies (with pagination)
	l.Logger.Info("Collecting conditional access policies via Graph SDK with pagination")
	message.Info("Collecting conditional access policies from Graph SDK...")

	conditionalAccessPolicies, err := l.collectAllConditionalAccessPoliciesWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect conditional access policies via paginated SDK", "error", err)
		azureADData["conditionalAccessPolicies"] = []interface{}{} // Empty array on error
	} else {
		azureADData["conditionalAccessPolicies"] = conditionalAccessPolicies
		l.Logger.Info("Collected conditional access policies via paginated SDK", "count", len(conditionalAccessPolicies))
	}

	// Collection 9: Directory Role Assignments (CRITICAL for iam-push compatibility)
	l.Logger.Info("Collecting directory role assignments via Graph SDK with pagination")
	message.Info("Collecting directory role assignments from Graph SDK...")
	directoryRoleAssignments, err := l.collectAllDirectoryRoleAssignmentsWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect directory role assignments via paginated SDK", "error", err)
		azureADData["directoryRoleAssignments"] = []interface{}{} // Empty array on error
	} else {
		azureADData["directoryRoleAssignments"] = directoryRoleAssignments
		l.Logger.Info("Collected directory role assignments via paginated SDK", "count", len(directoryRoleAssignments))
	}

	// TODO: Collect additional relationships (group memberships, oauth2PermissionGrants, appRoleAssignments, etc.)
	// This will require additional SDK calls and will be added next

	return azureADData, nil
}

// collectAllPIMDataSDK collects all PIM data using Graph SDK (official PIM APIs)
// This is a major upgrade from the current HTTP implementation which uses legacy internal APIs
func (l *SDKComprehensiveCollectorLink) collectAllPIMDataSDK() (map[string]interface{}, error) {
	pimData := make(map[string]interface{})
	ctx := l.Context()

	l.Logger.Info("Collecting PIM data via official Graph SDK APIs")

	// Collection 1: Eligible Role Assignments (with pagination)
	l.Logger.Info("Collecting PIM eligible assignments via Graph SDK with pagination")
	message.Info("Collecting PIM eligible assignments from Graph SDK...")

	eligibleAssignments, err := l.collectAllPIMEligibleWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect eligible assignments via paginated SDK", "error", err)
		pimData["eligible_assignments"] = []interface{}{} // Empty array on error
	} else {
		pimData["eligible_assignments"] = eligibleAssignments
		l.Logger.Info("Collected eligible assignments via paginated SDK", "count", len(eligibleAssignments))
	}

	// Collection 2: Active Role Assignments (with pagination)
	l.Logger.Info("Collecting PIM active assignments via Graph SDK with pagination")
	message.Info("Collecting PIM active assignments from Graph SDK...")

	activeAssignments, err := l.collectAllPIMActiveWithPagination(ctx)
	if err != nil {
		l.Logger.Error("Failed to collect active assignments via paginated SDK", "error", err)
		pimData["active_assignments"] = []interface{}{} // Empty array on error
	} else {
		pimData["active_assignments"] = activeAssignments
		l.Logger.Info("Collected active assignments via paginated SDK", "count", len(activeAssignments))
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

	l.Logger.Info("PIM SDK data collection completed", "collections", len(pimData))
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

	// Use single worker for now (can be increased for performance)
	var wg sync.WaitGroup
	numWorkers := 1
	if len(subscriptionIDs) < 1 {
		numWorkers = len(subscriptionIDs)
	}

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
		return nil, nil, nil, fmt.Errorf("failed to create role assignments client for subscription %s: %v", subscriptionID, err)
	}

	// Get all role assignments for the subscription with pagination
	pager := authClient.NewListPager(&armauthorization.RoleAssignmentsClientListOptions{})

	totalCount := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get role assignments page: %v", err)
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

	// Get first page
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

	// Get first page
	response, err := l.graphClient.Groups().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of groups: %v", err)
	}

	for {
		pageCount++
		groups := response.GetValue()
		l.Logger.Info("Processing group page", "page", pageCount, "objects", len(groups))

		// Convert groups from current page
		for _, group := range groups {
			groupMap := map[string]interface{}{
				"id":                    *group.GetId(),
				"displayName":           stringPtrToInterface(group.GetDisplayName()),
				"mail":                  stringPtrToInterface(group.GetMail()),
				"mailEnabled":           boolPtrToInterface(group.GetMailEnabled()),
				"securityEnabled":       boolPtrToInterface(group.GetSecurityEnabled()),
				"groupTypes":            stringSliceToInterface(group.GetGroupTypes()),
				"description":           stringPtrToInterface(group.GetDescription()),
				"createdDateTime":       timeToInterface(group.GetCreatedDateTime()),
				"mailNickname":          stringPtrToInterface(group.GetMailNickname()),
				"visibility":            stringPtrToInterface(group.GetVisibility()),
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

	// Get first page
	response, err := l.graphClient.ServicePrincipals().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get first page of service principals: %v", err)
	}

	for {
		pageCount++
		sps := response.GetValue()
		l.Logger.Info("Processing service principal page", "page", pageCount, "objects", len(sps))

		// Convert service principals from current page
		for _, sp := range sps {
			spMap := map[string]interface{}{
				"id":                         *sp.GetId(),
				"displayName":                stringPtrToInterface(sp.GetDisplayName()),
				"appId":                      stringPtrToInterface(sp.GetAppId()),
				"servicePrincipalType":       stringPtrToInterface(sp.GetServicePrincipalType()),
				"accountEnabled":             boolPtrToInterface(sp.GetAccountEnabled()),
				"appDisplayName":             stringPtrToInterface(sp.GetAppDisplayName()),
				// Note: createdDateTime not available in ServicePrincipal SDK model
				"homepage":                   stringPtrToInterface(sp.GetHomepage()),
				"replyUrls":                  stringSliceToInterface(sp.GetReplyUrls()),
				"servicePrincipalNames":      stringSliceToInterface(sp.GetServicePrincipalNames()),
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

	// Get first page
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

		// Convert devices from current page
		for _, device := range devices {
			deviceMap := map[string]interface{}{
				"id":                    *device.GetId(),
				"displayName":           stringPtrToInterface(device.GetDisplayName()),
				"deviceId":              stringPtrToInterface(device.GetDeviceId()),
				"operatingSystem":       stringPtrToInterface(device.GetOperatingSystem()),
				"operatingSystemVersion": stringPtrToInterface(device.GetOperatingSystemVersion()),
				"accountEnabled":        boolPtrToInterface(device.GetAccountEnabled()),
				// Note: createdDateTime not available in Device SDK model
				"approximateLastSignInDateTime": timeToInterface(device.GetApproximateLastSignInDateTime()),
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

// collectAllDirectoryRoleAssignmentsWithPagination collects all directory role assignments using proper pagination and SDK APIs
func (l *SDKComprehensiveCollectorLink) collectAllDirectoryRoleAssignmentsWithPagination(ctx context.Context) ([]interface{}, error) {
	var allAssignments []interface{}
	totalObjects := 0

	l.Logger.Info("Starting paginated directory role assignments collection")

	// First, get all directory roles
	directoryRolesResponse, err := l.graphClient.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get directory roles: %v", err)
	}

	directoryRoles := directoryRolesResponse.GetValue()
	l.Logger.Info("Processing directory role assignments", "roles", len(directoryRoles))

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

		l.Logger.Debug("Processing role", "roleId", roleId, "roleName", roleName)

		// Get members of this directory role with pagination
		membersResponse, err := l.graphClient.DirectoryRoles().ByDirectoryRoleId(roleId).Members().Get(ctx, nil)
		if err != nil {
			l.Logger.Error("Failed to get members for directory role", "roleId", roleId, "error", err)
			continue
		}

		// Process all pages of members
		for membersResponse != nil {
			members := membersResponse.GetValue()
			l.Logger.Debug("Processing members page", "roleId", roleId, "members", len(members))

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

	l.Logger.Info("Completed paginated directory role assignments collection", "totalAssignments", totalObjects)
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

