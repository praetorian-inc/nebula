package network

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// NetworkTopologyCollectorLink collects network topology with processed security rules
type NetworkTopologyCollectorLink struct {
	*chain.Base

	// Azure SDK clients
	subscriptionClient  *armsubscriptions.Client
	resourceGraphClient *armresourcegraph.Client
	// networkClient is not used in this implementation

	// Service tag resolver
	serviceTagResolver *ServiceTagResolver

	// Credential for all SDK clients
	credential *azidentity.DefaultAzureCredential

	// Configuration
	expandServiceTags bool
	subscription      string // Target subscription(s) - "all" or specific subscription ID
}

// Resource types to collect for network topology
var topologyResourceTypes = []string{
	// Network Infrastructure
	"microsoft.network/virtualnetworks",
	"microsoft.network/networkinterfaces",
	"microsoft.network/publicipaddresses",
	"microsoft.network/networksecuritygroups",
	"microsoft.network/privateendpoints",
	"microsoft.network/loadbalancers",
	"microsoft.network/applicationgateways",
	"microsoft.network/azurefirewalls",

	// Compute Resources
	"microsoft.compute/virtualmachines",
	"microsoft.compute/virtualmachinescalesets",
	"microsoft.containerservice/managedclusters",

	// PaaS with network features
	"microsoft.web/sites",
	"microsoft.sql/servers",
	"microsoft.storage/storageaccounts",
	"microsoft.keyvault/vaults",
}

// NewNetworkTopologyCollectorLink creates a new network topology collector
func NewNetworkTopologyCollectorLink(configs ...cfg.Config) chain.Link {
	l := &NetworkTopologyCollectorLink{
		serviceTagResolver: NewServiceTagResolver(),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

// Params defines the parameters this link accepts
func (l *NetworkTopologyCollectorLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("subscription", "Target subscription ID or 'all' for all subscriptions").
			WithDefault("all").
			WithShortcode("s"),
		cfg.NewParam[bool]("expand-service-tags", "Expand Azure service tags to IP ranges").
			WithDefault(true),
	}
}

// Initialize reads configuration parameters
func (l *NetworkTopologyCollectorLink) Initialize() error {
	// Read configuration parameters
	l.subscription, _ = cfg.As[string](l.Arg("subscription"))
	l.expandServiceTags, _ = cfg.As[bool](l.Arg("expand-service-tags"))

	// Default to all subscriptions if not specified
	if l.subscription == "" {
		l.subscription = "all"
	}

	l.Logger.Info("Network topology collector configuration",
		"subscription", l.subscription,
		"expandServiceTags", l.expandServiceTags)

	return nil
}

// Process handles network topology collection
func (l *NetworkTopologyCollectorLink) Process(input interface{}) error {
	ctx := l.Context()
	// Initialize Azure credential
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}
	l.credential = credential

	// Initialize clients
	l.subscriptionClient, err = armsubscriptions.NewClient(credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create subscription client: %w", err)
	}

	l.resourceGraphClient, err = armresourcegraph.NewClient(credential, nil)
	if err != nil {
		return fmt.Errorf("failed to create resource graph client: %w", err)
	}

	// Update service tags if needed
	if l.expandServiceTags {
		if err := l.serviceTagResolver.UpdateServiceTags(); err != nil {
			// Non-fatal, continue with defaults
			l.Logger.Warn("Failed to update service tags, using defaults", "error", err)
		}
	}

	// Get target subscriptions based on configuration
	var subscriptions []string
	if l.subscription == "all" || l.subscription == "" {
		// Get all subscriptions
		subscriptions, err = l.getAllSubscriptions(ctx)
		if err != nil {
			return fmt.Errorf("failed to get subscriptions: %w", err)
		}
		l.Logger.Info("Collecting from all Azure subscriptions", "count", len(subscriptions))
	} else {
		// Use specific subscription
		subscriptions = []string{l.subscription}
		l.Logger.Info("Collecting from specific subscription", "subscription", l.subscription)
	}

	// Collect resources from subscriptions (batch for better performance)
	allResources := []interface{}{}

	// Process subscriptions in batches of 10 for better performance
	batchSize := 10
	for i := 0; i < len(subscriptions); i += batchSize {
		end := i + batchSize
		if end > len(subscriptions) {
			end = len(subscriptions)
		}
		batch := subscriptions[i:end]

		l.Logger.Info("Collecting resources from subscription batch",
			"batch_start", i+1,
			"batch_end", end,
			"total", len(subscriptions))

		// Query multiple subscriptions at once
		resources, err := l.collectNetworkResourcesBatch(ctx, batch)
		if err != nil {
			// Fall back to individual queries on batch failure
			l.Logger.Warn("Batch query failed, falling back to individual queries", "error", err)
			for j, sub := range batch {
				l.Logger.Debug("Collecting resources from subscription",
					"subscription", sub,
					"progress", fmt.Sprintf("%d/%d", i+j+1, len(subscriptions)))

				subResources, err := l.collectNetworkResources(ctx, sub)
				if err != nil {
					l.Logger.Error("Failed to collect resources from subscription",
						"subscription", sub,
						"error", err)
					continue
				}
				resources = append(resources, subResources...)
			}
		}

		allResources = append(allResources, resources...)
	}

	l.Logger.Info("Collected network resources", "total", len(allResources))

	// Process NSG rules if service tag expansion is enabled
	if l.expandServiceTags {
		l.processNSGRules(allResources)
	}

	// Send each resource to the next link
	for _, resource := range allResources {
		if err := l.Send(resource); err != nil {
			return fmt.Errorf("failed to send resource: %w", err)
		}
	}

	return nil
}

// getAllSubscriptions retrieves all accessible Azure subscriptions
func (l *NetworkTopologyCollectorLink) getAllSubscriptions(ctx context.Context) ([]string, error) {
	var subscriptionIDs []string

	pager := l.subscriptionClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get subscription page: %w", err)
		}

		for _, sub := range page.Value {
			if sub.SubscriptionID != nil && sub.State != nil && *sub.State == armsubscriptions.SubscriptionStateEnabled {
				subscriptionIDs = append(subscriptionIDs, *sub.SubscriptionID)
			}
		}
	}

	return subscriptionIDs, nil
}

// collectNetworkResourcesBatch collects network resources from multiple subscriptions in one query
func (l *NetworkTopologyCollectorLink) collectNetworkResourcesBatch(ctx context.Context, subscriptionIDs []string) ([]interface{}, error) {
	var allResources []interface{}

	// Build resource type filter
	var filterParts []string
	for _, resourceType := range topologyResourceTypes {
		filterParts = append(filterParts, fmt.Sprintf("type =~ '%s'", resourceType))
	}
	resourceTypeFilter := "(" + strings.Join(filterParts, " or ") + ")"

	// Query for network resources across all provided subscriptions
	query := fmt.Sprintf(`
		Resources
		| where %s
		| project id, name, type, location, resourceGroup, subscriptionId, properties, tags
	`, resourceTypeFilter)

	// Convert subscription IDs to pointers
	subPtrs := make([]*string, len(subscriptionIDs))
	for i, sub := range subscriptionIDs {
		s := sub // Create a copy to avoid pointer issues
		subPtrs[i] = &s
	}

	queryRequest := armresourcegraph.QueryRequest{
		Query: &query,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: toPtr(armresourcegraph.ResultFormatObjectArray),
		},
		Subscriptions: subPtrs,
	}

	// Execute query with pagination
	var skipToken *string
	pageNum := 0
	for {
		pageNum++
		if skipToken != nil {
			queryRequest.Options.SkipToken = skipToken
		}

		l.Logger.Debug("Executing batch resource graph query",
			"subscriptions", len(subscriptionIDs),
			"page", pageNum)

		result, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to query resources: %w", err)
		}

		l.Logger.Debug("Batch resource graph query completed",
			"subscriptions", len(subscriptionIDs),
			"page", pageNum)

		// Process resources
		if data, ok := result.Data.([]interface{}); ok {
			for _, item := range data {
				// Process each resource
				resource := l.processResource(item)
				if resource != nil {
					allResources = append(allResources, resource)
				}
			}
		}

		// Check for more pages
		if result.SkipToken == nil || *result.SkipToken == "" {
			break
		}
		skipToken = result.SkipToken
	}

	// Collect VNet ranges for service tag resolution
	for _, res := range allResources {
		if resMap, ok := res.(map[string]interface{}); ok {
			if resType, _ := resMap["type"].(string); strings.EqualFold(resType, "microsoft.network/virtualnetworks") {
				if props, ok := resMap["properties"].(map[string]interface{}); ok {
					if addressSpace, ok := props["addressSpace"].(map[string]interface{}); ok {
						if prefixes, ok := addressSpace["addressPrefixes"].([]interface{}); ok {
							for _, prefix := range prefixes {
								if cidr, ok := prefix.(string); ok {
									l.serviceTagResolver.AddVNetRange(cidr)
								}
							}
						}
					}
				}
			}
		}
	}

	return allResources, nil
}

// collectNetworkResources collects network topology resources from a subscription
func (l *NetworkTopologyCollectorLink) collectNetworkResources(ctx context.Context, subscriptionID string) ([]interface{}, error) {
	var allResources []interface{}

	// Build resource type filter
	var filterParts []string
	for _, resourceType := range topologyResourceTypes {
		filterParts = append(filterParts, fmt.Sprintf("type =~ '%s'", resourceType))
	}
	resourceTypeFilter := "(" + strings.Join(filterParts, " or ") + ")"

	// Query for network resources
	query := fmt.Sprintf(`
		Resources
		| where subscriptionId =~ '%s'
		| where %s
		| project id, name, type, location, resourceGroup, subscriptionId, properties, tags
	`, subscriptionID, resourceTypeFilter)

	queryRequest := armresourcegraph.QueryRequest{
		Query: &query,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: toPtr(armresourcegraph.ResultFormatObjectArray),
		},
		Subscriptions: []*string{&subscriptionID},
	}

	// Execute query with pagination
	var skipToken *string
	pageNum := 0
	for {
		pageNum++
		if skipToken != nil {
			queryRequest.Options.SkipToken = skipToken
		}

		l.Logger.Debug("Executing resource graph query",
			"subscription", subscriptionID,
			"page", pageNum)

		result, err := l.resourceGraphClient.Resources(ctx, queryRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to query resources: %w", err)
		}

		l.Logger.Debug("Resource graph query completed",
			"subscription", subscriptionID,
			"page", pageNum)

		// Process resources
		if data, ok := result.Data.([]interface{}); ok {
			for _, item := range data {
				// Process each resource
				resource := l.processResource(item)
				if resource != nil {
					allResources = append(allResources, resource)
				}
			}
		}

		// Check for more pages
		if result.SkipToken == nil || *result.SkipToken == "" {
			break
		}
		skipToken = result.SkipToken
	}

	// Collect VNet ranges for service tag resolution
	for _, res := range allResources {
		if resMap, ok := res.(map[string]interface{}); ok {
			if resType, _ := resMap["type"].(string); strings.EqualFold(resType, "microsoft.network/virtualnetworks") {
				if props, ok := resMap["properties"].(map[string]interface{}); ok {
					if addressSpace, ok := props["addressSpace"].(map[string]interface{}); ok {
						if prefixes, ok := addressSpace["addressPrefixes"].([]interface{}); ok {
							for _, prefix := range prefixes {
								if cidr, ok := prefix.(string); ok {
									l.serviceTagResolver.AddVNetRange(cidr)
								}
							}
						}
					}
				}
			}
		}
	}

	return allResources, nil
}

// processResource processes a raw resource from Azure Resource Graph
func (l *NetworkTopologyCollectorLink) processResource(raw interface{}) map[string]interface{} {
	resource, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}

	// Ensure required fields exist
	if resource["id"] == nil || resource["type"] == nil {
		return nil
	}

	// Process based on resource type
	resourceType := strings.ToLower(resource["type"].(string))

	switch resourceType {
	case "microsoft.network/networksecuritygroups":
		// Process NSG with rule expansion
		l.processNSGResource(resource)

	case "microsoft.network/virtualnetworks":
		// Extract subnets as separate resources
		l.extractSubnets(resource)

	case "microsoft.network/publicipaddresses":
		// Process Public IP to ensure associations are captured
		l.processPublicIP(resource)

	case "microsoft.network/networkinterfaces":
		// Extract IP configuration and associations
		l.processNIC(resource)

	case "microsoft.compute/virtualmachines":
		// Extract VM network associations
		l.processVM(resource)

	case "microsoft.network/loadbalancers":
		// Process Load Balancer configurations
		l.processLoadBalancer(resource)

	case "microsoft.network/applicationgateways":
		// Process Application Gateway
		l.processApplicationGateway(resource)

	case "microsoft.network/privateendpoints":
		// Process Private Endpoints
		l.processPrivateEndpoint(resource)

	case "microsoft.compute/virtualmachinescalesets":
		// Process VM Scale Sets
		l.processVMScaleSet(resource)
	}

	return resource
}

// processNSGResource processes NSG rules with service tag expansion
func (l *NetworkTopologyCollectorLink) processNSGResource(resource map[string]interface{}) {
	if !l.expandServiceTags {
		return
	}

	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Process security rules
	if rules, ok := props["securityRules"].([]interface{}); ok {
		processedRules := l.processSecurityRules(rules, "Custom")
		props["processedRules"] = processedRules
	}

	// Add default rules
	defaultInbound := GetDefaultInboundRules()
	defaultOutbound := GetDefaultOutboundRules()

	// Combine with custom rules
	allRules := []ProcessedRule{}
	if processed, ok := props["processedRules"].([]ProcessedRule); ok {
		allRules = append(allRules, processed...)
	}
	allRules = append(allRules, defaultInbound...)
	allRules = append(allRules, defaultOutbound...)

	// Sort by priority
	sort.Slice(allRules, func(i, j int) bool {
		return allRules[i].Priority < allRules[j].Priority
	})

	props["processedRules"] = allRules
}

// processSecurityRules processes raw NSG rules into normalized format
func (l *NetworkTopologyCollectorLink) processSecurityRules(rules []interface{}, ruleType string) []ProcessedRule {
	processed := []ProcessedRule{}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract rule properties
		props, ok := ruleMap["properties"].(map[string]interface{})
		if !ok {
			props = ruleMap
		}

		p := ProcessedRule{
			Name:      getStringField(ruleMap, "name"),
			Priority:  getIntField(props, "priority"),
			Direction: getStringField(props, "direction"),
			Access:    getStringField(props, "access"),
			Protocol:  NormalizeProtocol(getStringField(props, "protocol")),
		}

		// Process source addresses
		sourcePrefix := getStringField(props, "sourceAddressPrefix")
		if sourcePrefix == "" {
			sourcePrefixes := getStringArrayField(props, "sourceAddressPrefixes")
			for _, prefix := range sourcePrefixes {
				p.SourceIPRanges = append(p.SourceIPRanges, l.serviceTagResolver.Resolve(prefix)...)
			}
		} else {
			p.SourceIPRanges = l.serviceTagResolver.Resolve(sourcePrefix)
		}

		// Process destination addresses
		destPrefix := getStringField(props, "destinationAddressPrefix")
		if destPrefix == "" {
			destPrefixes := getStringArrayField(props, "destinationAddressPrefixes")
			for _, prefix := range destPrefixes {
				p.DestIPRanges = append(p.DestIPRanges, l.serviceTagResolver.Resolve(prefix)...)
			}
		} else {
			p.DestIPRanges = l.serviceTagResolver.Resolve(destPrefix)
		}

		// Process port ranges
		destPortRange := getStringField(props, "destinationPortRange")
		if destPortRange == "" {
			destPortRanges := getStringArrayField(props, "destinationPortRanges")
			for _, portRange := range destPortRanges {
				p.PortRanges = append(p.PortRanges, ParsePortRanges(portRange)...)
			}
		} else {
			p.PortRanges = ParsePortRanges(destPortRange)
		}

		processed = append(processed, p)
	}

	return processed
}

// extractSubnets extracts subnet information from VNet resource
func (l *NetworkTopologyCollectorLink) extractSubnets(vnetResource map[string]interface{}) {
	props, ok := vnetResource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract VNet peerings
	if peerings, ok := props["virtualNetworkPeerings"].([]interface{}); ok {
		var peeringIds []string
		for _, peering := range peerings {
			if peerMap, ok := peering.(map[string]interface{}); ok {
				if peerProps, ok := peerMap["properties"].(map[string]interface{}); ok {
					if remoteVnet, ok := peerProps["remoteVirtualNetwork"].(map[string]interface{}); ok {
						if id, ok := remoteVnet["id"].(string); ok {
							peeringIds = append(peeringIds, id)
						}
					}
				}
			}
		}
		if len(peeringIds) > 0 {
			vnetResource["peeringIds"] = peeringIds
		}
	}

	// Extract DDoS protection status
	if ddos, ok := props["enableDdosProtection"].(bool); ok {
		vnetResource["ddosProtection"] = ddos
	}

	subnets, ok := props["subnets"].([]interface{})
	if !ok {
		return
	}

	// Store extracted subnets in VNet resource
	extractedSubnets := []map[string]interface{}{}
	for _, subnet := range subnets {
		subnetMap, ok := subnet.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract subnet properties
		subnetData := map[string]interface{}{
			"id":   subnetMap["id"],
			"name": subnetMap["name"],
			"type": "Microsoft.Network/virtualNetworks/subnets",
		}

		if subnetProps, ok := subnetMap["properties"].(map[string]interface{}); ok {
			subnetData["properties"] = subnetProps

			// Extract NSG association
			if nsg, ok := subnetProps["networkSecurityGroup"].(map[string]interface{}); ok {
				if nsgID, ok := nsg["id"].(string); ok {
					subnetData["nsgId"] = nsgID
				}
			}

			// Extract Route Table association
			if routeTable, ok := subnetProps["routeTable"].(map[string]interface{}); ok {
				if rtID, ok := routeTable["id"].(string); ok {
					subnetData["routeTableId"] = rtID
				}
			}

			// Extract Service Endpoints
			if serviceEndpoints, ok := subnetProps["serviceEndpoints"].([]interface{}); ok {
				var endpoints []string
				for _, ep := range serviceEndpoints {
					if epMap, ok := ep.(map[string]interface{}); ok {
						if service, ok := epMap["service"].(string); ok {
							endpoints = append(endpoints, service)
						}
					}
				}
				if len(endpoints) > 0 {
					subnetData["serviceEndpoints"] = endpoints
				}
			}

			// Pre-compute address range
			if addressPrefix, ok := subnetProps["addressPrefix"].(string); ok {
				subnetData["addressPrefix"] = addressPrefix
				// Store as range for fast queries
				if _, ipnet, err := net.ParseCIDR(addressPrefix); err == nil {
					ipRange := cidrToRange(ipnet)
					subnetData["addressRange"] = fmt.Sprintf("%s-%s", ipRange.Start, ipRange.End)
				}
			}
		}

		extractedSubnets = append(extractedSubnets, subnetData)
	}

	vnetResource["extractedSubnets"] = extractedSubnets
}

// processNIC processes network interface to extract IP configurations and associations
func (l *NetworkTopologyCollectorLink) processNIC(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract NSG association
	if nsg, ok := props["networkSecurityGroup"].(map[string]interface{}); ok {
		if nsgID, ok := nsg["id"].(string); ok {
			resource["nsgId"] = nsgID
		}
	}

	// Extract VM association
	if vm, ok := props["virtualMachine"].(map[string]interface{}); ok {
		if vmID, ok := vm["id"].(string); ok {
			resource["vmId"] = vmID
		}
	}

	// Extract Application Security Groups
	if asgList, ok := props["applicationSecurityGroups"].([]interface{}); ok {
		var asgIds []string
		for _, asg := range asgList {
			if asgMap, ok := asg.(map[string]interface{}); ok {
				if id, ok := asgMap["id"].(string); ok {
					asgIds = append(asgIds, id)
				}
			}
		}
		if len(asgIds) > 0 {
			resource["applicationSecurityGroups"] = asgIds
		}
	}

	// Extract IP configurations
	if ipConfigs, ok := props["ipConfigurations"].([]interface{}); ok && len(ipConfigs) > 0 {
		if ipConfig, ok := ipConfigs[0].(map[string]interface{}); ok {
			if ipProps, ok := ipConfig["properties"].(map[string]interface{}); ok {
				// Get private IP
				if privateIP, ok := ipProps["privateIPAddress"].(string); ok {
					resource["privateIPAddress"] = privateIP
				}

				// Get subnet reference
				if subnet, ok := ipProps["subnet"].(map[string]interface{}); ok {
					if subnetID, ok := subnet["id"].(string); ok {
						resource["subnetId"] = subnetID
					}
				}

				// Get public IP reference
				if publicIP, ok := ipProps["publicIPAddress"].(map[string]interface{}); ok {
					if publicIPID, ok := publicIP["id"].(string); ok {
						resource["publicIPId"] = publicIPID
					}
				}
			}
		}
	}
}

// processVM extracts VM network associations
func (l *NetworkTopologyCollectorLink) processVM(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract NIC associations
	if netProfile, ok := props["networkProfile"].(map[string]interface{}); ok {
		if nics, ok := netProfile["networkInterfaces"].([]interface{}); ok {
			var nicIds []string
			var primaryNicId string
			for _, nic := range nics {
				if nicMap, ok := nic.(map[string]interface{}); ok {
					if id, ok := nicMap["id"].(string); ok {
						nicIds = append(nicIds, id)
						// Check if this is the primary NIC
						if nicProps, ok := nicMap["properties"].(map[string]interface{}); ok {
							if primary, ok := nicProps["primary"].(bool); ok && primary {
								primaryNicId = id
							}
						}
					}
				}
			}
			if len(nicIds) > 0 {
				resource["nicIds"] = nicIds
				if primaryNicId != "" {
					resource["primaryNicId"] = primaryNicId
				}
			}
		}
	}

	// Extract availability zone
	if zones, ok := props["zones"].([]interface{}); ok && len(zones) > 0 {
		resource["availabilityZone"] = zones[0]
	}
}

// processPublicIP processes public IP to capture associations
func (l *NetworkTopologyCollectorLink) processPublicIP(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract IP address
	if ipAddr, ok := props["ipAddress"].(string); ok {
		resource["ipAddress"] = ipAddr
	}

	// Extract associated resource (NIC or LB Frontend)
	if ipConfig, ok := props["ipConfiguration"].(map[string]interface{}); ok {
		if id, ok := ipConfig["id"].(string); ok {
			// Determine if it's associated with a NIC or Load Balancer
			if strings.Contains(id, "/networkInterfaces/") {
				resource["associatedNicId"] = extractResourceIDFromConfigID(id, "networkInterfaces")
			} else if strings.Contains(id, "/loadBalancers/") {
				resource["associatedLBId"] = extractResourceIDFromConfigID(id, "loadBalancers")
			}
		}
	}

	// Extract SKU (Basic/Standard)
	if sku, ok := props["publicIPAllocationMethod"].(string); ok {
		resource["allocationMethod"] = sku
	}
}

// processLoadBalancer extracts load balancer configurations
func (l *NetworkTopologyCollectorLink) processLoadBalancer(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract frontend IP configurations
	if frontends, ok := props["frontendIPConfigurations"].([]interface{}); ok {
		var publicIPs []string
		var privateIPs []string
		for _, fe := range frontends {
			if feMap, ok := fe.(map[string]interface{}); ok {
				if feProps, ok := feMap["properties"].(map[string]interface{}); ok {
					// Public IP
					if pubIP, ok := feProps["publicIPAddress"].(map[string]interface{}); ok {
						if id, ok := pubIP["id"].(string); ok {
							publicIPs = append(publicIPs, id)
						}
					}
					// Private IP
					if privIP, ok := feProps["privateIPAddress"].(string); ok {
						privateIPs = append(privateIPs, privIP)
					}
				}
			}
		}
		if len(publicIPs) > 0 {
			resource["frontendPublicIPs"] = publicIPs
		}
		if len(privateIPs) > 0 {
			resource["frontendPrivateIPs"] = privateIPs
		}
	}

	// Extract backend pools
	if backends, ok := props["backendAddressPools"].([]interface{}); ok {
		var backendNICs []string
		for _, be := range backends {
			if beMap, ok := be.(map[string]interface{}); ok {
				if beProps, ok := beMap["properties"].(map[string]interface{}); ok {
					if ipConfigs, ok := beProps["backendIPConfigurations"].([]interface{}); ok {
						for _, ipConfig := range ipConfigs {
							if configMap, ok := ipConfig.(map[string]interface{}); ok {
								if id, ok := configMap["id"].(string); ok {
									if nicID := extractResourceIDFromConfigID(id, "networkInterfaces"); nicID != "" {
										backendNICs = append(backendNICs, nicID)
									}
								}
							}
						}
					}
				}
			}
		}
		if len(backendNICs) > 0 {
			resource["backendNICs"] = backendNICs
		}
	}
}

// processApplicationGateway extracts app gateway configurations
func (l *NetworkTopologyCollectorLink) processApplicationGateway(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract frontend IPs
	if frontends, ok := props["frontendIPConfigurations"].([]interface{}); ok {
		var publicIPs []string
		for _, fe := range frontends {
			if feMap, ok := fe.(map[string]interface{}); ok {
				if feProps, ok := feMap["properties"].(map[string]interface{}); ok {
					if pubIP, ok := feProps["publicIPAddress"].(map[string]interface{}); ok {
						if id, ok := pubIP["id"].(string); ok {
							publicIPs = append(publicIPs, id)
						}
					}
				}
			}
		}
		if len(publicIPs) > 0 {
			resource["frontendPublicIPs"] = publicIPs
		}
	}

	// Extract backend pools
	if backends, ok := props["backendAddressPools"].([]interface{}); ok {
		var backendIPs []string
		for _, be := range backends {
			if beMap, ok := be.(map[string]interface{}); ok {
				if beProps, ok := beMap["properties"].(map[string]interface{}); ok {
					if addresses, ok := beProps["backendAddresses"].([]interface{}); ok {
						for _, addr := range addresses {
							if addrMap, ok := addr.(map[string]interface{}); ok {
								if ipAddr, ok := addrMap["ipAddress"].(string); ok {
									backendIPs = append(backendIPs, ipAddr)
								}
							}
						}
					}
				}
			}
		}
		if len(backendIPs) > 0 {
			resource["backendAddresses"] = backendIPs
		}
	}
}

// processPrivateEndpoint extracts private endpoint configurations
func (l *NetworkTopologyCollectorLink) processPrivateEndpoint(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract subnet information
	if subnet, ok := props["subnet"].(map[string]interface{}); ok {
		if subnetID, ok := subnet["id"].(string); ok {
			resource["subnetId"] = subnetID
		}
	}

	// Extract network interfaces
	if nics, ok := props["networkInterfaces"].([]interface{}); ok {
		var nicIDs []string
		for _, nic := range nics {
			if nicMap, ok := nic.(map[string]interface{}); ok {
				if nicID, ok := nicMap["id"].(string); ok {
					nicIDs = append(nicIDs, nicID)
				}
			}
		}
		if len(nicIDs) > 0 {
			resource["nicIds"] = nicIDs
		}
	}

	// Extract private link service connections
	if connections, ok := props["privateLinkServiceConnections"].([]interface{}); ok {
		var targetResourceIDs []string
		for _, conn := range connections {
			if connMap, ok := conn.(map[string]interface{}); ok {
				if connProps, ok := connMap["properties"].(map[string]interface{}); ok {
					if targetID, ok := connProps["privateLinkServiceId"].(string); ok {
						targetResourceIDs = append(targetResourceIDs, targetID)
					}
				}
			}
		}
		if len(targetResourceIDs) > 0 {
			resource["targetResourceIds"] = targetResourceIDs
		}
	}

	// Also check manual connections
	if manualConnections, ok := props["manualPrivateLinkServiceConnections"].([]interface{}); ok {
		var manualTargets []string
		for _, conn := range manualConnections {
			if connMap, ok := conn.(map[string]interface{}); ok {
				if connProps, ok := connMap["properties"].(map[string]interface{}); ok {
					if targetID, ok := connProps["privateLinkServiceId"].(string); ok {
						manualTargets = append(manualTargets, targetID)
					}
				}
			}
		}
		if len(manualTargets) > 0 {
			existing, _ := resource["targetResourceIds"].([]string)
			resource["targetResourceIds"] = append(existing, manualTargets...)
		}
	}
}

// processVMScaleSet extracts VM Scale Set configurations
func (l *NetworkTopologyCollectorLink) processVMScaleSet(resource map[string]interface{}) {
	props, ok := resource["properties"].(map[string]interface{})
	if !ok {
		return
	}

	// Extract virtual machine profile
	if vmProfile, ok := props["virtualMachineProfile"].(map[string]interface{}); ok {
		// Get network profile
		if netProfile, ok := vmProfile["networkProfile"].(map[string]interface{}); ok {
			// Get network interface configurations
			if nicConfigs, ok := netProfile["networkInterfaceConfigurations"].([]interface{}); ok {
				var subnetIDs []string
				var nsgIDs []string

				for _, nicConfig := range nicConfigs {
					if configMap, ok := nicConfig.(map[string]interface{}); ok {
						if configProps, ok := configMap["properties"].(map[string]interface{}); ok {
							// Get NSG
							if nsg, ok := configProps["networkSecurityGroup"].(map[string]interface{}); ok {
								if nsgID, ok := nsg["id"].(string); ok {
									nsgIDs = append(nsgIDs, nsgID)
								}
							}

							// Get IP configurations
							if ipConfigs, ok := configProps["ipConfigurations"].([]interface{}); ok {
								for _, ipConfig := range ipConfigs {
									if ipMap, ok := ipConfig.(map[string]interface{}); ok {
										if ipProps, ok := ipMap["properties"].(map[string]interface{}); ok {
											// Get subnet
											if subnet, ok := ipProps["subnet"].(map[string]interface{}); ok {
												if subnetID, ok := subnet["id"].(string); ok {
													subnetIDs = append(subnetIDs, subnetID)
												}
											}

											// Get load balancer backend address pools
											if bePoolRefs, ok := ipProps["loadBalancerBackendAddressPools"].([]interface{}); ok {
												var lbPoolIDs []string
												for _, poolRef := range bePoolRefs {
													if poolMap, ok := poolRef.(map[string]interface{}); ok {
														if poolID, ok := poolMap["id"].(string); ok {
															lbPoolIDs = append(lbPoolIDs, poolID)
														}
													}
												}
												if len(lbPoolIDs) > 0 {
													resource["loadBalancerBackendPools"] = lbPoolIDs
												}
											}
										}
									}
								}
							}
						}
					}
				}

				if len(subnetIDs) > 0 {
					resource["subnetIds"] = subnetIDs
				}
				if len(nsgIDs) > 0 {
					resource["nsgIds"] = nsgIDs
				}
			}
		}
	}

	// Store instance count
	if sku, ok := props["sku"].(map[string]interface{}); ok {
		if capacity, ok := sku["capacity"].(float64); ok {
			resource["instanceCount"] = int(capacity)
		}
	}
}

// extractResourceIDFromConfigID extracts the resource ID from an IP configuration ID
func extractResourceIDFromConfigID(configID string, resourceType string) string {
	parts := strings.Split(configID, "/")
	for i, part := range parts {
		if part == resourceType && i+1 < len(parts) {
			// Reconstruct the resource ID up to the resource name
			endIdx := i + 2
			if endIdx > len(parts) {
				endIdx = len(parts)
			}
			return "/" + strings.Join(parts[1:endIdx], "/")
		}
	}
	return ""
}

// processNSGRules processes all NSG rules in collected resources
func (l *NetworkTopologyCollectorLink) processNSGRules(resources []interface{}) {
	for _, res := range resources {
		if resMap, ok := res.(map[string]interface{}); ok {
			if resType, _ := resMap["type"].(string); strings.EqualFold(resType, "microsoft.network/networksecuritygroups") {
				l.processNSGResource(resMap)
			}
		}
	}
}

// Helper functions to extract fields
func getStringField(m map[string]interface{}, field string) string {
	if val, ok := m[field].(string); ok {
		return val
	}
	return ""
}

func getIntField(m map[string]interface{}, field string) int {
	if val, ok := m[field].(float64); ok {
		return int(val)
	}
	if val, ok := m[field].(int); ok {
		return val
	}
	return 0
}

func getStringArrayField(m map[string]interface{}, field string) []string {
	result := []string{}
	if arr, ok := m[field].([]interface{}); ok {
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

// GetLinkName returns the name of the link
func (l *NetworkTopologyCollectorLink) GetLinkName() string {
	return "NetworkTopologyCollectorLink"
}

// GetLinkID returns the ID of the link
func (l *NetworkTopologyCollectorLink) GetLinkID() string {
	return "network-topology-collector"
}

// toPtr is a helper function to get a pointer to a value
func toPtr[T any](v T) *T {
	return &v
}