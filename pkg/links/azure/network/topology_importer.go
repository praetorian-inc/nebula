package network

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)


// NetworkTopologyImporterLink imports network topology into Neo4j
type NetworkTopologyImporterLink struct {
	*chain.Base

	// Neo4j driver
	driver neo4j.DriverWithContext

	// Configuration
	neo4jURL      string
	neo4jUser     string
	neo4jPassword string
	clearDB       bool
	batchSize     int  // Batch size for bulk operations

	// Collected resources for batch processing
	resources []map[string]interface{}

	// Performance metrics
	nodeCount         int
	relationshipCount int

	// Cache for faster lookups
	nodeCache map[string]bool  // Track created nodes to avoid duplicates

	// Pending relationships to create in Complete()
	pendingRelationships []map[string]string
}

// NewNetworkTopologyImporterLink creates a new network topology importer
func NewNetworkTopologyImporterLink(configs ...cfg.Config) chain.Link {
	l := &NetworkTopologyImporterLink{
		resources:            []map[string]interface{}{},
		batchSize:            500, // Optimal batch size for Neo4j
		nodeCache:            make(map[string]bool),
		pendingRelationships: []map[string]string{},
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

// Params defines the parameters this link accepts
func (l *NetworkTopologyImporterLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("neo4j-url", "Neo4j connection URL"),
		cfg.NewParam[string]("neo4j-user", "Neo4j username"),
		cfg.NewParam[string]("neo4j-password", "Neo4j password"),
		cfg.NewParam[bool]("clear-db", "Clear database before import").WithDefault(false),
	}
}

// Initialize reads configuration parameters and sets up the link
func (l *NetworkTopologyImporterLink) Initialize() error {
	// Get configuration parameters - these will now include command-line overrides
	l.neo4jURL, _ = cfg.As[string](l.Arg("neo4j-url"))
	l.neo4jUser, _ = cfg.As[string](l.Arg("neo4j-user"))
	l.neo4jPassword, _ = cfg.As[string](l.Arg("neo4j-password"))
	l.clearDB, _ = cfg.As[bool](l.Arg("clear-db"))

	// Check required parameters
	if l.neo4jURL == "" {
		return fmt.Errorf("neo4j-url parameter is required")
	}
	if l.neo4jUser == "" {
		return fmt.Errorf("neo4j-user parameter is required")
	}
	if l.neo4jPassword == "" {
		return fmt.Errorf("neo4j-password parameter is required - please provide --neo4j-password")
	}

	// Log configuration (without exposing password)
	l.Logger.Info("Neo4j configuration", "url", l.neo4jURL, "user", l.neo4jUser, "clearDB", l.clearDB)
	return nil
}

// Process handles the import of network topology data into Neo4j
func (l *NetworkTopologyImporterLink) Process(input interface{}) error {
	ctx := l.Context()

	// No need for runtime parameter reading since we're hardcoding for now

	// Accept either a single resource or a slice of resources
	switch data := input.(type) {
	case []interface{}:
		for _, item := range data {
			if resource, ok := item.(map[string]interface{}); ok {
				l.resources = append(l.resources, resource)
			}
		}
	case map[string]interface{}:
		l.resources = append(l.resources, data)
	case []map[string]interface{}:
		l.resources = append(l.resources, data...)
	}

	// Perform the import
	return l.performImport(ctx)
}

// performImport performs the actual import after all resources are collected
func (l *NetworkTopologyImporterLink) performImport(ctx context.Context) error {
	if len(l.resources) == 0 {
		l.Logger.Info("No resources to import")
		return nil
	}

	l.Logger.Info("Starting Neo4j import", "resources", len(l.resources))
	l.Logger.Debug("Neo4j connection details", "url", l.neo4jURL, "user", l.neo4jUser, "hasPassword", l.neo4jPassword != "")

	// Initialize Neo4j driver
	auth := neo4j.BasicAuth(l.neo4jUser, l.neo4jPassword, "")
	driver, err := neo4j.NewDriverWithContext(l.neo4jURL, auth)
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}
	defer driver.Close(ctx)
	l.driver = driver

	// Verify connectivity
	if err := driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	// Clear database if requested
	if l.clearDB {
		if err := l.clearDatabase(ctx); err != nil {
			return fmt.Errorf("failed to clear database: %w", err)
		}
	}

	// Create constraints and indexes
	if err := l.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Import nodes
	if err := l.importNodes(ctx); err != nil {
		return fmt.Errorf("failed to import nodes: %w", err)
	}

	// Import relationships
	if err := l.importRelationships(ctx); err != nil {
		return fmt.Errorf("failed to import relationships: %w", err)
	}

	l.Logger.Info("Successfully imported network topology to Neo4j")
	return nil
}

// clearDatabase clears the Neo4j database
func (l *NetworkTopologyImporterLink) clearDatabase(ctx context.Context) error {
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to clear database: %w", err)
	}

	l.Logger.Info("Cleared Neo4j database")
	return nil
}

// createIndexes creates necessary indexes in Neo4j
func (l *NetworkTopologyImporterLink) createIndexes(ctx context.Context) error {
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	indexes := []string{
		"CREATE CONSTRAINT resource_unique_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
		"CREATE INDEX resource_type_idx IF NOT EXISTS FOR (r:Resource) ON (r.resourceType)",
		"CREATE INDEX resource_name_idx IF NOT EXISTS FOR (r:Resource) ON (r.name)",
		"CREATE INDEX resource_location_idx IF NOT EXISTS FOR (r:Resource) ON (r.location)",
	}

	for _, index := range indexes {
		_, err := session.Run(ctx, index, nil)
		if err != nil {
			// Index creation errors are non-fatal
			l.Logger.Warn("Failed to create index", "error", err)
		}
	}

	// Create Internet node for security analysis
	internetQuery := `
		MERGE (i:Resource {id: "internet"})
		SET i.name = "Internet",
		    i.resourceType = "Internet",
		    i.description = "External Internet connectivity"
	`
	_, err := session.Run(ctx, internetQuery, nil)
	if err != nil {
		l.Logger.Warn("Failed to create Internet node", "error", err)
	}

	return nil
}

// importNodes imports all nodes into Neo4j using batch processing
func (l *NetworkTopologyImporterLink) importNodes(ctx context.Context) error {
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Process all resources as Resource nodes in batches
	for i := 0; i < len(l.resources); i += l.batchSize {
		end := i + l.batchSize
		if end > len(l.resources) {
			end = len(l.resources)
		}
		batch := l.resources[i:end]

		if err := l.createResourceNodesBatch(ctx, session, batch); err != nil {
			return fmt.Errorf("failed to create Resource nodes batch: %w", err)
		}
	}

	// Store the session for use in Complete()
	l.Send(map[string]interface{}{"import_summary": map[string]interface{}{
		"nodes_created": len(l.resources),
		"status": "nodes_imported",
	}})

	return nil
}

// Complete is called after all resources have been processed
func (l *NetworkTopologyImporterLink) Complete() error {
	ctx := l.Context()

	// Connect to Neo4j to create relationships
	auth := neo4j.BasicAuth(l.neo4jUser, l.neo4jPassword, "")
	driver, err := neo4j.NewDriverWithContext(l.neo4jURL, auth)
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	l.Logger.Info("Creating relationships after all nodes have been imported",
		"nodes", l.nodeCount)

	// Create all relationships
	if err := l.createRelationships(ctx, session); err != nil {
		return fmt.Errorf("failed to create relationships: %w", err)
	}

	// Log import metrics
	l.Logger.Info("Import complete - Summary",
		"nodes_created", l.nodeCount,
		"relationships_created", l.relationshipCount,
		"batch_size", l.batchSize)

	// Send final summary
	l.Send(map[string]interface{}{
		"import_summary": map[string]interface{}{
			"nodes_created":         l.nodeCount,
			"relationships_created": l.relationshipCount,
			"batch_size":           l.batchSize,
			"status":               "complete",
		},
	})

	return nil
}

// createResourceNodesBatch creates Resource nodes in batch
func (l *NetworkTopologyImporterLink) createResourceNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources as resource
		MERGE (r:Resource {id: resource.id})
		SET r.name = resource.name,
		    r.resourceType = resource.resourceType,
		    r.location = resource.location,
		    r.subscriptionId = resource.subscriptionId,
		    r.resourceGroup = resource.resourceGroup,
		    r.properties = resource.properties
		WITH r, resource
		FOREACH (dummy IN CASE WHEN resource.subnetId IS NOT NULL THEN [1] ELSE [] END |
		    SET r.subnetId = resource.subnetId
		)
		FOREACH (dummy IN CASE WHEN resource.privateIPAddress IS NOT NULL THEN [1] ELSE [] END |
		    SET r.privateIPAddress = resource.privateIPAddress
		)
		FOREACH (dummy IN CASE WHEN resource.primary IS NOT NULL THEN [1] ELSE [] END |
		    SET r.primary = resource.primary
		)
		RETURN r
	`

	resourceList := make([]map[string]interface{}, 0, len(resources))
	for _, resource := range resources {
		resourceData := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"resourceType":   getStringFromResource(resource, "type"),
			"location":       getStringFromResource(resource, "location"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
		}

		// Handle properties as JSON string
		if props, ok := resource["properties"]; ok {
			if propsBytes, err := json.Marshal(props); err == nil {
				resourceData["properties"] = string(propsBytes)
			} else {
				resourceData["properties"] = "{}"
			}
		} else {
			resourceData["properties"] = "{}"
		}

		// Extract resource-specific properties from JSON
		resourceType := strings.ToLower(getStringFromResource(resource, "type"))
		if propsStr, ok := resourceData["properties"].(string); ok {
			var props map[string]interface{}
			if err := json.Unmarshal([]byte(propsStr), &props); err == nil {

				// Extract NIC-specific properties for subnet relationships
				if strings.Contains(resourceType, "networkinterfaces") {
					if ipConfigs, ok := props["ipConfigurations"].([]interface{}); ok && len(ipConfigs) > 0 {
						if ipConfig, ok := ipConfigs[0].(map[string]interface{}); ok {
							if ipProps, ok := ipConfig["properties"].(map[string]interface{}); ok {
								if subnet, ok := ipProps["subnet"].(map[string]interface{}); ok {
									if subnetId, ok := subnet["id"].(string); ok {
										resourceData["subnetId"] = subnetId
									}
								}
								if privateIP, ok := ipProps["privateIPAddress"].(string); ok {
									resourceData["privateIPAddress"] = privateIP
								}
								if primary, ok := ipProps["primary"].(bool); ok {
									resourceData["primary"] = primary
								}
							}
						}
					}
				}

				// Extract PublicIP address
				if strings.Contains(resourceType, "publicipaddresses") {
					if ipAddr, ok := props["ipAddress"].(string); ok && ipAddr != "" {
						resourceData["ipAddress"] = ipAddr
					}
					if allocMethod, ok := props["publicIPAllocationMethod"].(string); ok {
						resourceData["allocationMethod"] = allocMethod
					}
					if version, ok := props["publicIPAddressVersion"].(string); ok {
						resourceData["ipVersion"] = version
					}
				}

				// Extract VNet address space
				if strings.Contains(resourceType, "virtualnetworks") {
					if addrSpace, ok := props["addressSpace"].(map[string]interface{}); ok {
						if prefixes, ok := addrSpace["addressPrefixes"].([]interface{}); ok && len(prefixes) > 0 {
							if prefix, ok := prefixes[0].(string); ok {
								resourceData["addressSpace"] = prefix
							}
						}
					}
				}

				// Extract NSG location for better querying
				if strings.Contains(resourceType, "networksecuritygroups") {
					if resourceGuid, ok := props["resourceGuid"].(string); ok {
						resourceData["resourceGuid"] = resourceGuid
					}
				}
			}
		}

		resourceList = append(resourceList, resourceData)
	}

	params := map[string]interface{}{
		"resources": resourceList,
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		// Count created nodes
		for result.Next(ctx) {
			l.nodeCount++
		}

		return result.Consume(ctx)
	})

	if err != nil {
		return fmt.Errorf("failed to create Resource nodes: %w", err)
	}

	// Post-process special resource types
	for _, resource := range resources {
		resourceType := strings.ToLower(getStringFromResource(resource, "type"))

		// Create NSG security rules
		if strings.Contains(resourceType, "networksecuritygroups") {
			nsgID := getStringFromResource(resource, "id")

			// Try both string and direct map access for properties
			var props map[string]interface{}
			if propsStr, ok := resource["properties"].(string); ok {
				if err := json.Unmarshal([]byte(propsStr), &props); err != nil {
					l.Logger.Debug("Failed to parse properties JSON for NSG", "nsgId", nsgID, "error", err)
					continue
				}
			} else if propsMap, ok := resource["properties"].(map[string]interface{}); ok {
				props = propsMap
			} else {
				l.Logger.Debug("No properties found for NSG", "nsgId", nsgID)
				continue
			}

			if processedRules, ok := props["processedRules"].([]interface{}); ok && len(processedRules) > 0 {
				l.Logger.Info("Creating NSG security rules", "nsgId", nsgID, "ruleCount", len(processedRules))
				for idx, rule := range processedRules {
					if ruleMap, ok := rule.(map[string]interface{}); ok {
						if err := l.createNSGRuleNode(ctx, session, ruleMap, nsgID, idx); err != nil {
							l.Logger.Error("Failed to create NSG rule node", "error", err, "nsg", nsgID, "rule", ruleMap["name"])
						} else {
							l.Logger.Debug("Successfully created NSG rule", "nsg", nsgID, "rule", ruleMap["name"])
						}
					}
				}
			} else {
				l.Logger.Debug("No processedRules found for NSG", "nsgId", nsgID, "propsKeys", getMapKeys(props))
			}
		}

		// Create subnet nodes from VNets
		if strings.Contains(resourceType, "virtualnetworks") {
			vnetID := getStringFromResource(resource, "id")

			// Try both string and direct map access for properties
			var props map[string]interface{}
			if propsStr, ok := resource["properties"].(string); ok {
				if err := json.Unmarshal([]byte(propsStr), &props); err != nil {
					l.Logger.Debug("Failed to parse properties JSON for VNet", "vnetId", vnetID, "error", err)
					continue
				}
			} else if propsMap, ok := resource["properties"].(map[string]interface{}); ok {
				props = propsMap
			} else {
				l.Logger.Debug("No properties found for VNet", "vnetId", vnetID)
				continue
			}

			if subnetsArray, ok := props["subnets"].([]interface{}); ok && len(subnetsArray) > 0 {
				l.Logger.Info("Creating subnets for VNet", "vnetId", vnetID, "subnetCount", len(subnetsArray))
				for _, subnet := range subnetsArray {
					if subnetMap, ok := subnet.(map[string]interface{}); ok {
						if err := l.createSubnetNodeFromVNet(ctx, session, subnetMap, vnetID); err != nil {
							l.Logger.Error("Failed to create subnet node", "error", err, "vnet", vnetID, "subnet", getStringFromMap(subnetMap, "name"))
						} else {
							l.Logger.Debug("Successfully created subnet node", "vnet", vnetID, "subnet", getStringFromMap(subnetMap, "name"))
						}
					}
				}
			} else {
				l.Logger.Debug("No subnets found for VNet", "vnetId", vnetID, "propsKeys", getMapKeys(props))
			}
		}
	}

	l.Logger.Debug("Created Resource nodes batch", "count", len(resources))
	return nil
}

// createVNetNode creates VNet and Subnet nodes
func (l *NetworkTopologyImporterLink) createVNetNode(ctx context.Context, session neo4j.SessionWithContext, resource map[string]interface{}) error {
	// Create VNet node
	vnetQuery := `
		MERGE (v:Resource {id: $id})
		SET v.name = $name,
		    v.resourceType = "microsoft.network/virtualnetworks",
		    v.subscriptionId = $subscriptionId,
		    v.resourceGroup = $resourceGroup,
		    v.location = $location,
		    v.addressSpace = $addressSpace
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(resource, "id")
	params["name"] = getStringFromResource(resource, "name")
	params["subscriptionId"] = getStringFromResource(resource, "subscriptionId")
	params["resourceGroup"] = getStringFromResource(resource, "resourceGroup")
	params["location"] = getStringFromResource(resource, "location")

	// Extract address space
	if props, ok := resource["properties"].(map[string]interface{}); ok {
		if addressSpace, ok := props["addressSpace"].(map[string]interface{}); ok {
			if prefixes, ok := addressSpace["addressPrefixes"].([]interface{}); ok {
				addressSpaceList := []string{}
				for _, prefix := range prefixes {
					if str, ok := prefix.(string); ok {
						addressSpaceList = append(addressSpaceList, str)
					}
				}
				params["addressSpace"] = addressSpaceList
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, vnetQuery, params)
		return nil, err
	})

	if err != nil {
		return err
	}

	// Create Subnet nodes
	if subnetsRaw, ok := resource["extractedSubnets"]; ok {
		l.Logger.Debug("Found extractedSubnets", "vnet", getStringFromResource(resource, "name"), "type", fmt.Sprintf("%T", subnetsRaw))

		// Handle both []interface{} and []map[string]interface{}
		switch subnets := subnetsRaw.(type) {
		case []interface{}:
			for _, subnetRaw := range subnets {
				if subnet, ok := subnetRaw.(map[string]interface{}); ok {
					if err := l.createSubnetNode(ctx, session, subnet, getStringFromResource(resource, "id")); err != nil {
						l.Logger.Error("Failed to create subnet node", "error", err)
					}
				}
			}
		case []map[string]interface{}:
			for _, subnet := range subnets {
				if err := l.createSubnetNode(ctx, session, subnet, getStringFromResource(resource, "id")); err != nil {
					l.Logger.Error("Failed to create subnet node", "error", err)
				}
			}
		default:
			l.Logger.Warn("Unexpected extractedSubnets type", "type", fmt.Sprintf("%T", subnetsRaw))
		}
	} else {
		l.Logger.Debug("No extractedSubnets found", "vnet", getStringFromResource(resource, "name"))
	}

	return nil
}

// createSubnetNode creates a Subnet node
func (l *NetworkTopologyImporterLink) createSubnetNode(ctx context.Context, session neo4j.SessionWithContext, subnet map[string]interface{}, vnetId string) error {
	query := `
		MERGE (s:Resource {id: $id})
		SET s.name = $name,
		    s.resourceType = "microsoft.network/subnets",
		    s.vnetId = $vnetId,
		    s.addressPrefix = $addressPrefix,
		    s.addressRange = $addressRange
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(subnet, "id")
	params["name"] = getStringFromResource(subnet, "name")
	params["vnetId"] = vnetId
	params["addressPrefix"] = getStringFromResource(subnet, "addressPrefix")
	params["addressRange"] = getStringFromResource(subnet, "addressRange")

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// createNSGNode creates an NSG node and individual rule nodes
func (l *NetworkTopologyImporterLink) createNSGNode(ctx context.Context, session neo4j.SessionWithContext, resource map[string]interface{}) error {
	query := `
		MERGE (n:Resource {id: $id})
		SET n.name = $name,
		    n.resourceType = "microsoft.network/networksecuritygroups",
		    n.location = $location,
		    n.processedRules = $processedRules,
		    n.resourceGroup = $resourceGroup,
		    n.subscriptionId = $subscriptionId
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(resource, "id")
	params["name"] = getStringFromResource(resource, "name")
	params["location"] = getStringFromResource(resource, "location")
	params["resourceGroup"] = getStringFromResource(resource, "resourceGroup")
	params["subscriptionId"] = getStringFromResource(resource, "subscriptionId")

	// Store processed rules as JSON (default to empty if not present)
	params["processedRules"] = "[]"
	if props, ok := resource["properties"].(map[string]interface{}); ok {
		if rules, ok := props["processedRules"]; ok {
			if rulesJSON, err := json.Marshal(rules); err == nil {
				params["processedRules"] = string(rulesJSON)
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	if err != nil {
		return err
	}

	// Create individual NSG rule nodes for better security analysis
	nsgID := getStringFromResource(resource, "id")
	if props, ok := resource["properties"].(map[string]interface{}); ok {
		if processedRules, ok := props["processedRules"].([]interface{}); ok {
			for idx, rule := range processedRules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if err := l.createNSGRuleNode(ctx, session, ruleMap, nsgID, idx); err != nil {
						l.Logger.Error("Failed to create NSG rule node", "error", err, "nsg", params["name"])
					}
				}
			}
		}
	}

	return nil
}

// createNSGRuleNode creates an individual NSG rule node for security analysis
func (l *NetworkTopologyImporterLink) createNSGRuleNode(ctx context.Context, session neo4j.SessionWithContext, rule map[string]interface{}, nsgID string, index int) error {
	ruleName := getStringFromResource(rule, "name")
	if ruleName == "" {
		ruleName = fmt.Sprintf("rule_%d", index)
	}

	ruleID := fmt.Sprintf("%s/rule/%s", nsgID, ruleName)

	// Determine if rule is risky
	isRisky := false
	riskReasons := []string{}

	// Check for overly permissive sources
	if sourceRanges, ok := rule["sourceIPRanges"].([]interface{}); ok {
		for _, srcRange := range sourceRanges {
			if rangeMap, ok := srcRange.(map[string]interface{}); ok {
				if start, _ := rangeMap["start"].(string); start == "0.0.0.0" {
					if end, _ := rangeMap["end"].(string); end == "255.255.255.255" {
						isRisky = true
						riskReasons = append(riskReasons, "Source: Internet (0.0.0.0/0)")
					}
				}
			}
		}
	}

	// Check for dangerous ports
	access := getStringFromResource(rule, "access")
	direction := getStringFromResource(rule, "direction")
	if access == "Allow" && direction == "Inbound" {
		if portRanges, ok := rule["portRanges"].([]interface{}); ok {
			for _, portRange := range portRanges {
				if rangeMap, ok := portRange.(map[string]interface{}); ok {
					start, _ := rangeMap["start"].(float64)
					end, _ := rangeMap["end"].(float64)

					// Check for common risky ports
					dangerousPorts := map[float64]string{
						22:   "SSH",
						3389: "RDP",
						445:  "SMB",
						1433: "SQL Server",
						3306: "MySQL",
						5432: "PostgreSQL",
					}

					for port, service := range dangerousPorts {
						if start <= port && port <= end && isRisky {
							riskReasons = append(riskReasons, fmt.Sprintf("Port %d (%s) exposed", int(port), service))
						}
					}

					// Check for all ports open
					if start == 0 && end == 65535 && isRisky {
						riskReasons = append(riskReasons, "All ports open")
					}
				}
			}
		}
	}

	// Extract port information
	var ports []string
	var sourceAddresses []string
	var destAddresses []string

	if portRanges, ok := rule["portRanges"].([]interface{}); ok {
		for _, portRange := range portRanges {
			if rangeMap, ok := portRange.(map[string]interface{}); ok {
				start, _ := rangeMap["start"].(float64)
				end, _ := rangeMap["end"].(float64)
				if start == end {
					ports = append(ports, fmt.Sprintf("%.0f", start))
				} else if start == 0 && end == 65535 {
					ports = append(ports, "*")
				} else {
					ports = append(ports, fmt.Sprintf("%.0f-%.0f", start, end))
				}
			}
		}
	}

	// Extract source addresses
	if sourceRanges, ok := rule["sourceIPRanges"].([]interface{}); ok {
		for _, srcRange := range sourceRanges {
			if rangeMap, ok := srcRange.(map[string]interface{}); ok {
				start, _ := rangeMap["start"].(string)
				end, _ := rangeMap["end"].(string)
				if start == "0.0.0.0" && end == "255.255.255.255" {
					sourceAddresses = append(sourceAddresses, "Internet")
				} else if start == end {
					sourceAddresses = append(sourceAddresses, start)
				} else {
					sourceAddresses = append(sourceAddresses, fmt.Sprintf("%s-%s", start, end))
				}
			}
		}
	}

	// Extract destination addresses
	if destRanges, ok := rule["destIPRanges"].([]interface{}); ok {
		for _, destRange := range destRanges {
			if rangeMap, ok := destRange.(map[string]interface{}); ok {
				start, _ := rangeMap["start"].(string)
				end, _ := rangeMap["end"].(string)
				if start == "0.0.0.0" && end == "255.255.255.255" {
					destAddresses = append(destAddresses, "Any")
				} else if start == end {
					destAddresses = append(destAddresses, start)
				} else {
					destAddresses = append(destAddresses, fmt.Sprintf("%s-%s", start, end))
				}
			}
		}
	}

	query := `
		MERGE (r:Resource {id: $id})
		SET r.name = $name,
		    r.resourceType = "microsoft.network/networksecuritygroups/securityrules",
		    r.nsgId = $nsgId,
		    r.direction = $direction,
		    r.access = $access,
		    r.priority = $priority,
		    r.protocol = $protocol,
		    r.isRisky = $isRisky,
		    r.riskReasons = $riskReasons,
		    r.ports = $ports,
		    r.sourceAddresses = $sourceAddresses,
		    r.destAddresses = $destAddresses
	`

	params := map[string]interface{}{}
	params["id"] = ruleID
	params["name"] = ruleName
	params["nsgId"] = nsgID
	params["direction"] = direction
	params["access"] = access
	params["priority"] = rule["priority"]
	params["protocol"] = getStringFromResource(rule, "protocol")
	params["isRisky"] = isRisky
	params["riskReasons"] = riskReasons
	params["ports"] = ports
	params["sourceAddresses"] = sourceAddresses
	params["destAddresses"] = destAddresses

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// createNICNode creates a NIC node
func (l *NetworkTopologyImporterLink) createNICNode(ctx context.Context, session neo4j.SessionWithContext, resource map[string]interface{}) error {
	query := `
		MERGE (n:Resource {id: $id})
		SET n.name = $name,
		    n.resourceType = "microsoft.network/networkinterfaces",
		    n.privateIPAddress = $privateIPAddress,
		    n.macAddress = $macAddress,
		    n.primary = $primary
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(resource, "id")
	params["name"] = getStringFromResource(resource, "name")
	params["privateIPAddress"] = getStringFromResource(resource, "privateIPAddress")
	params["primary"] = true // Default to true

	// Extract MAC address if available
	if props, ok := resource["properties"].(map[string]interface{}); ok {
		params["macAddress"] = getStringFromResource(props, "macAddress")
		if primary, ok := props["primary"].(bool); ok {
			params["primary"] = primary
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// createPublicIPNode creates a PublicIP node
func (l *NetworkTopologyImporterLink) createPublicIPNode(ctx context.Context, session neo4j.SessionWithContext, resource map[string]interface{}) error {
	query := `
		MERGE (p:Resource {id: $id})
		SET p.name = $name,
		    p.resourceType = "microsoft.network/publicipaddresses",
		    p.ipAddress = $ipAddress,
		    p.allocationMethod = $allocationMethod,
		    p.sku = $sku
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(resource, "id")
	params["name"] = getStringFromResource(resource, "name")
	params["ipAddress"] = getStringFromResource(resource, "ipAddress")
	params["allocationMethod"] = "" // Default
	params["sku"] = "" // Default

	// Extract additional properties
	if props, ok := resource["properties"].(map[string]interface{}); ok {
		if allocation := getStringFromResource(props, "publicIPAllocationMethod"); allocation != "" {
			params["allocationMethod"] = allocation
		}

		if sku, ok := props["sku"].(map[string]interface{}); ok {
			if skuName := getStringFromResource(sku, "name"); skuName != "" {
				params["sku"] = skuName
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// createResourceNode creates a generic Resource node
func (l *NetworkTopologyImporterLink) createResourceNode(ctx context.Context, session neo4j.SessionWithContext, resource map[string]interface{}) error {
	query := `
		MERGE (r:Resource {id: $id})
		SET r.name = $name,
		    r.type = $type,
		    r.location = $location,
		    r.subscriptionId = $subscriptionId,
		    r.resourceGroup = $resourceGroup
	`

	params := map[string]interface{}{}
	params["id"] = getStringFromResource(resource, "id")
	params["name"] = getStringFromResource(resource, "name")
	params["type"] = getStringFromResource(resource, "type")
	params["location"] = getStringFromResource(resource, "location")
	params["subscriptionId"] = getStringFromResource(resource, "subscriptionId")
	params["resourceGroup"] = getStringFromResource(resource, "resourceGroup")

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	return err
}

// importRelationships imports all relationships
func (l *NetworkTopologyImporterLink) importRelationships(ctx context.Context) error {
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Create VNet->Subnet CONTAINS relationships
	if err := l.createVNetSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create VNet-Subnet relationships", "error", err)
	}

	// Create NIC->Subnet IN relationships
	if err := l.createNICSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NIC-Subnet relationships", "error", err)
	}

	// NSG relationships are handled via PROTECTED_BY in other functions

	return nil
}

// createVNetSubnetRelationships creates CONTAINS relationships between VNets and Subnets
func (l *NetworkTopologyImporterLink) createVNetSubnetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Match based on vnetId property
	query := `
		MATCH (v:Resource {resourceType: "microsoft.network/virtualnetworks"})
		MATCH (s:Resource {resourceType: "microsoft.network/subnets"})
		WHERE s.vnetId = v.id
		MERGE (v)-[:CONTAINS]->(s)
		RETURN count(*) as relCount
	`

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		// Get the count
		if result.Next(ctx) {
			record := result.Record()
			if count, ok := record.Get("relCount"); ok {
				if relCount, ok := count.(int64); ok {
					l.relationshipCount += int(relCount)
					l.Logger.Info("Created VNet-Subnet relationships", "count", relCount)
				}
			}
		}

		return result.Consume(ctx)
	})

	return err
}

// Removed createProtectsRelationship - using only PROTECTED_BY instead

// createResourceUsageRelationships creates USES relationships between Resources and NICs/PublicIPs
func (l *NetworkTopologyImporterLink) createResourceUsageRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Process compute resources
	for _, resource := range l.resources {
		resourceType := strings.ToLower(getStringFromResource(resource, "type"))

		// Skip network infrastructure resources
		if strings.HasPrefix(resourceType, "microsoft.network/") {
			continue
		}

		resourceId := getStringFromResource(resource, "id")
		if resourceId == "" {
			continue
		}

		// Find associated NICs
		if props, ok := resource["properties"].(map[string]interface{}); ok {
			if netProfile, ok := props["networkProfile"].(map[string]interface{}); ok {
				if nics, ok := netProfile["networkInterfaces"].([]interface{}); ok {
					for _, nic := range nics {
						if nicMap, ok := nic.(map[string]interface{}); ok {
							nicId := getStringFromResource(nicMap, "id")
							if nicId != "" {
								l.createUsesRelationship(ctx, session, resourceId, nicId, "NIC")
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// createUsesRelationship creates a single USES relationship
func (l *NetworkTopologyImporterLink) createUsesRelationship(ctx context.Context, session neo4j.SessionWithContext, resourceId, targetId, targetType string) {
	query := fmt.Sprintf(`
		MATCH (r:Resource {id: $resourceId})
		MATCH (t:%s {id: $targetId})
		MERGE (r)-[:USES]->(t)
	`, targetType)

	params := map[string]interface{}{}
	params["resourceId"] = resourceId
	params["targetId"] = targetId

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	if err != nil {
		l.Logger.Error("Failed to create USES relationship", "error", err)
	}
}

// createPublicIPConnections creates CONNECTED relationships for PublicIPs
func (l *NetworkTopologyImporterLink) createPublicIPConnections(ctx context.Context, session neo4j.SessionWithContext) error {
	query := `
		MATCH (p:Resource {resourceType: "microsoft.network/publicipaddresses"})
		MATCH (i:Resource {id: 'internet'})
		WHERE p.ipAddress IS NOT NULL AND p.ipAddress <> ''
		MERGE (p)-[:CONNECTED]->(i)
	`

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		return result.Consume(ctx)
	})

	// Also connect NICs to their public IPs
	for _, resource := range l.resources {
		if strings.EqualFold(getStringFromResource(resource, "type"), "microsoft.network/networkinterfaces") {
			nicId := getStringFromResource(resource, "id")
			publicIPId := getStringFromResource(resource, "publicIPId")

			if nicId != "" && publicIPId != "" {
				connectQuery := `
					MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
					MATCH (p:Resource {id: $publicIPId, resourceType: "microsoft.network/publicipaddresses"})
					MERGE (n)-[:USES]->(p)
				`

				params := map[string]interface{}{}
				params["nicId"] = nicId
				params["publicIPId"] = publicIPId

				session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
					_, err := tx.Run(ctx, connectQuery, params)
					return nil, err
				})
			}
		}
	}

	return err
}

// createVNetPeeringRelationships creates CONNECTED relationships for VNet peerings
func (l *NetworkTopologyImporterLink) createRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// 1. VNet -> Subnet (CONTAINS relationship) - Do this first
	if err := l.createVNetSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create VNet-Subnet relationships", "error", err)
	}

	// 2. NIC -> Subnet (IN relationship)
	if err := l.createNICSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NIC-Subnet relationships", "error", err)
	}

	// 3. NSG -> NIC (PROTECTS relationship)
	if err := l.createNSGNICRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NSG-NIC relationships", "error", err)
	}

	// 4. NSG -> Subnet (PROTECTS relationship)
	if err := l.createNSGSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NSG-Subnet relationships", "error", err)
	}

	// 5. VM -> NIC (USES relationship)
	if err := l.createVMNICRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create VM-NIC relationships", "error", err)
	}

	// 6. PublicIP -> NIC (CONNECTED relationship)
	if err := l.createPublicIPNICRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create PublicIP-NIC relationships", "error", err)
	}

	// 7. PublicIP -> LoadBalancer (CONNECTED relationship)
	// PublicIP->LoadBalancer relationships handled via FRONTEND_IP in processPendingRelationships

	// 8. Internet -> PublicIP (CONNECTED relationship)
	if err := l.createInternetPublicIPRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create Internet-PublicIP relationships", "error", err)
	}

	// 9. VNet Peering relationships
	if err := l.createVNetPeeringRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create VNet peering relationships", "error", err)
	}

	// 10. LoadBalancer backend relationships handled via BACKEND_POOL in processPendingRelationships

	// 11. NSG -> NSGRule (HAS_RULE relationship)
	if err := l.createNSGRuleRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NSG-Rule relationships", "error", err)
	}

	// 12. LoadBalancer -> PublicIP (FRONTEND_IP relationship)
	if err := l.createLoadBalancerPublicIPRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create LoadBalancer-PublicIP relationships", "error", err)
	}

	// 13. LoadBalancer -> NIC (BACKEND_POOL relationship)
	if err := l.createLoadBalancerNICRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create LoadBalancer-NIC relationships", "error", err)
	}

	// 14. PrivateEndpoint -> Subnet (IN relationship)
	if err := l.createPrivateEndpointSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create PrivateEndpoint-Subnet relationships", "error", err)
	}

	// 15. PrivateEndpoint -> Resource (CONNECTS_TO relationship)
	if err := l.createPrivateEndpointResourceRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create PrivateEndpoint-Resource relationships", "error", err)
	}

	// 16. VMScaleSet -> Subnet (DEPLOYED_IN relationship)
	if err := l.createVMScaleSetSubnetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create VMScaleSet-Subnet relationships", "error", err)
	}

	// 17. NSG -> VMScaleSet (PROTECTS relationship)
	if err := l.createNSGVMScaleSetRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create NSG-VMScaleSet relationships", "error", err)
	}

	// 18. ApplicationGateway -> PublicIP (FRONTEND_IP relationship)
	if err := l.createApplicationGatewayPublicIPRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create ApplicationGateway-PublicIP relationships", "error", err)
	}

	// 19. Process all pending relationships collected during node creation
	if err := l.processPendingRelationships(ctx, session); err != nil {
		l.Logger.Error("Failed to create pending relationships", "error", err)
	}

	return nil
}

func (l *NetworkTopologyImporterLink) createNICSubnetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Build map from resources
	nicSubnetMap := make(map[string]string)
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/networkinterfaces") {
			if nicID, _ := resource["id"].(string); nicID != "" {
				if subnetID, _ := resource["subnetId"].(string); subnetID != "" {
					nicSubnetMap[nicID] = subnetID
				}
			}
		}
	}

	for nicId, subnetId := range nicSubnetMap {
		query := `
			MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
			MATCH (s:Resource {id: $subnetId, resourceType: "microsoft.network/subnets"})
			MERGE (n)-[:IN]->(s)
		`
		params := map[string]interface{}{
			"nicId":    nicId,
			"subnetId": subnetId,
		}

		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, query, params)
			return nil, err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *NetworkTopologyImporterLink) createNSGNICRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Build a map of NSG to NICs
	nsgToNICs := make(map[string][]string)
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/networkinterfaces") {
			if nicID, _ := resource["id"].(string); nicID != "" {
				if nsgID, _ := resource["nsgId"].(string); nsgID != "" {
					nsgToNICs[nsgID] = append(nsgToNICs[nsgID], nicID)
				}
			}
		}
	}

	// Create relationships with NSG as source
	for nsgID, nicIDs := range nsgToNICs {
		for _, nicID := range nicIDs {
			query := `
				MATCH (nsg:Resource {id: $nsgId, resourceType: "microsoft.network/networksecuritygroups"})
				MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
				MERGE (nsg)-[:PROTECTS]->(n)
			`
			params := map[string]interface{}{
				"nsgId": nsgID,
				"nicId": nicID,
			}

			_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
				_, err := tx.Run(ctx, query, params)
				return nil, err
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *NetworkTopologyImporterLink) createNSGSubnetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Build a map of NSG to Subnets
	nsgToSubnets := make(map[string][]string)
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/virtualnetworks") {
			if subnets, ok := resource["extractedSubnets"].([]map[string]interface{}); ok {
				for _, subnet := range subnets {
					if subnetID, _ := subnet["id"].(string); subnetID != "" {
						if nsgID, _ := subnet["nsgId"].(string); nsgID != "" {
							nsgToSubnets[nsgID] = append(nsgToSubnets[nsgID], subnetID)
						}
					}
				}
			}
		}
	}

	// Create relationships with NSG as source
	for nsgID, subnetIDs := range nsgToSubnets {
		for _, subnetID := range subnetIDs {
			query := `
				MATCH (nsg:Resource {id: $nsgId, resourceType: "microsoft.network/networksecuritygroups"})
				MATCH (s:Resource {id: $subnetId, resourceType: "microsoft.network/subnets"})
				MERGE (nsg)-[:PROTECTS]->(s)
			`
			params := map[string]interface{}{
				"nsgId":    nsgID,
				"subnetId": subnetID,
			}

			_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
				_, err := tx.Run(ctx, query, params)
				return nil, err
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *NetworkTopologyImporterLink) createVMNICRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	vmCount := 0
	relationshipCount := 0

	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.compute/virtualmachines") {
			if vmID, _ := resource["id"].(string); vmID != "" {
				vmCount++

				// Handle both []string and []interface{} types
				var nicIds []string
				if ids, ok := resource["nicIds"].([]string); ok {
					nicIds = ids
				} else if idsInterface, ok := resource["nicIds"].([]interface{}); ok {
					for _, id := range idsInterface {
						if nicID, ok := id.(string); ok {
							nicIds = append(nicIds, nicID)
						}
					}
				}

				for _, nicID := range nicIds {
					query := `
						MATCH (vm:Resource {id: $vmId})
						MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
						MERGE (vm)-[:USES]->(n)
						RETURN vm, n
					`
					params := map[string]interface{}{
						"vmId":  vmID,
						"nicId": nicID,
					}

					result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
						result, err := tx.Run(ctx, query, params)
						if err != nil {
							return nil, err
						}
						if result.Next(ctx) {
							return true, nil
						}
						return false, nil
					})

					if err != nil {
						l.Logger.Error("Failed to create VM-NIC relationship", "vmId", vmID, "nicId", nicID, "error", err)
					} else if result.(bool) {
						relationshipCount++
						l.Logger.Debug("Created VM-NIC relationship", "vmId", vmID, "nicId", nicID)
					}
				}
			}
		}
	}

	l.Logger.Info("Created VM-NIC relationships", "vms", vmCount, "relationships", relationshipCount)
	return nil
}

func (l *NetworkTopologyImporterLink) createPublicIPNICRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/publicipaddresses") {
			if pubIPID, _ := resource["id"].(string); pubIPID != "" {
				if nicID, _ := resource["associatedNicId"].(string); nicID != "" {
					query := `
						MATCH (p:Resource {id: $pubIPId, resourceType: "microsoft.network/publicipaddresses"})
						MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
						MERGE (p)-[:EXPOSES]->(n)
					`
					params := map[string]interface{}{
						"pubIPId": pubIPID,
						"nicId":   nicID,
					}

					_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
						_, err := tx.Run(ctx, query, params)
						return nil, err
					})
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Removed createPublicIPLBRelationships - handled via FRONTEND_IP in pending relationships

func (l *NetworkTopologyImporterLink) createInternetPublicIPRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Connect all public IPs to Internet node using EXPOSES
	query := `
		MATCH (i:Resource {id: "internet"})
		MATCH (p:Resource {resourceType: "microsoft.network/publicipaddresses"})
		MERGE (i)-[:EXPOSES]->(p)
	`

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, nil)
		return nil, err
	})
	return err
}

// createNSGRuleRelationships creates HAS_RULE relationships between NSGs and their rules
func (l *NetworkTopologyImporterLink) createNSGRuleRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	query := `
		MATCH (nsg:Resource {resourceType: "microsoft.network/networksecuritygroups"})
		MATCH (r:Resource {resourceType: "microsoft.network/networksecuritygroups/securityrules"})
		WHERE r.nsgId = nsg.id
		MERGE (nsg)-[:HAS_RULE]->(r)
	`

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		return result.Consume(ctx)
	})

	return err
}

func (l *NetworkTopologyImporterLink) createVNetPeeringRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/virtualnetworks") {
			if vnetID, _ := resource["id"].(string); vnetID != "" {
				if peeringIds, ok := resource["peeringIds"].([]string); ok {
					for _, peerID := range peeringIds {
						query := `
							MATCH (v1:Resource {id: $vnetId, resourceType: "microsoft.network/virtualnetworks"})
							MATCH (v2:Resource {id: $peerId, resourceType: "microsoft.network/virtualnetworks"})
							MERGE (v1)-[:PEERED_WITH]-(v2)
						`
						params := map[string]interface{}{
							"vnetId": vnetID,
							"peerId": peerID,
						}

						_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
							_, err := tx.Run(ctx, query, params)
							return nil, err
						})
						if err != nil {
							// Log but don't fail - peer might be in different subscription
							l.Logger.Warn("Failed to create VNet peering", "error", err)
						}
					}
				}
			}
		}
	}
	return nil
}

func (l *NetworkTopologyImporterLink) createLBBackendRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	for _, resource := range l.resources {
		if resType, _ := resource["type"].(string); strings.EqualFold(resType, "microsoft.network/loadbalancers") {
			if lbID, _ := resource["id"].(string); lbID != "" {
				if backendNICs, ok := resource["backendNICs"].([]string); ok {
					for _, nicID := range backendNICs {
						query := `
							MATCH (lb:Resource {id: $lbId})
							MATCH (n:Resource {id: $nicId, resourceType: "microsoft.network/networkinterfaces"})
							MERGE (lb)-[:ROUTES_TO]->(n)
						`
						params := map[string]interface{}{
							"lbId":  lbID,
							"nicId": nicID,
						}

						_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
							_, err := tx.Run(ctx, query, params)
							return nil, err
						})
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

// Batch creation methods for performance optimization

// createVNetNodesBatch creates multiple VNet nodes in a single transaction
func (l *NetworkTopologyImporterLink) createVNetNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources AS resource
		MERGE (v:Resource {id: resource.id})
		SET v.name = resource.name,
		    v.resourceType = "microsoft.network/virtualnetworks",
		    v.addressSpace = resource.addressSpace,
		    v.subscriptionId = resource.subscriptionId,
		    v.resourceGroup = resource.resourceGroup,
		    v.location = resource.location
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"addressSpace":   getStringFromResource(resource, "addressSpace"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"location":       getStringFromResource(resource, "location"),
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Extract and process subnets from VNet properties
		var subnetsToCreate []interface{}

		// First try extractedSubnets (if network-pull provides them)
		if extractedSubnets, ok := resource["extractedSubnets"].([]interface{}); ok && len(extractedSubnets) > 0 {
			subnetsToCreate = extractedSubnets
		} else {
			// Extract from JSON properties if not pre-extracted
			if propsStr, ok := resource["properties"].(string); ok {
				var props map[string]interface{}
				if err := json.Unmarshal([]byte(propsStr), &props); err == nil {
					if subnetsArray, ok := props["subnets"].([]interface{}); ok {
						for _, subnet := range subnetsArray {
							if subnetMap, ok := subnet.(map[string]interface{}); ok {
								// Extract essential subnet properties
								subnetData := map[string]interface{}{
									"id":   getStringFromMap(subnetMap, "id"),
									"name": getStringFromMap(subnetMap, "name"),
									"type": getStringFromMap(subnetMap, "type"),
								}
								if props, ok := subnetMap["properties"].(map[string]interface{}); ok {
									if addressPrefixes, ok := props["addressPrefixes"].([]interface{}); ok && len(addressPrefixes) > 0 {
										if prefix, ok := addressPrefixes[0].(string); ok {
											subnetData["addressPrefix"] = prefix
										}
									}
									subnetData["addressRange"] = subnetData["addressPrefix"]
								}
								subnetsToCreate = append(subnetsToCreate, subnetData)
							}
						}
					}
				}
			}
		}

		if len(subnetsToCreate) > 0 {
			l.Logger.Debug("Processing subnets for VNet", "vnet", params["name"], "subnetCount", len(subnetsToCreate))
			if err := l.createSubnetNodesBatch(ctx, session, subnetsToCreate, params["id"].(string)); err != nil {
				l.Logger.Error("Failed to create subnet nodes", "error", err, "vnet", params["name"])
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})
	return err
}

// createSubnetNodesBatch creates multiple Subnet nodes
func (l *NetworkTopologyImporterLink) createSubnetNodesBatch(ctx context.Context, session neo4j.SessionWithContext, subnets []interface{}, vnetID string) error {
	// Create Subnet nodes only (relationships will be created in Complete())
	query := `
		UNWIND $subnets AS subnet
		MERGE (s:Resource {id: subnet.id})
		SET s.name = subnet.name,
		    s.resourceType = "microsoft.network/subnets",
		    s.addressPrefix = subnet.addressPrefix,
		    s.nsgId = subnet.nsgId,
		    s.vnetId = $vnetId
	`

	var batchParams []map[string]interface{}
	for _, subnet := range subnets {
		if subnetMap, ok := subnet.(map[string]interface{}); ok {
			params := map[string]interface{}{
				"id":            getStringFromResource(subnetMap, "id"),
				"name":          getStringFromResource(subnetMap, "name"),
				"addressPrefix": getStringFromResource(subnetMap, "addressPrefix"),
				"nsgId":         getStringFromResource(subnetMap, "nsgId"),
			}
			batchParams = append(batchParams, params)
			l.nodeCount++
		}
	}

	if len(batchParams) == 0 {
		return nil
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{
			"subnets": batchParams,
			"vnetId":  vnetID,
		})
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create subnet nodes: %w", err)
	}

	l.Logger.Debug("Created subnet nodes and relationships", "count", len(batchParams), "vnet", vnetID)
	return nil
}

// createNSGNodesBatch creates multiple NSG nodes in a single transaction
func (l *NetworkTopologyImporterLink) createNSGNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	l.Logger.Info("Creating NSG nodes batch", "count", len(resources))

	// Create NSG nodes - temporarily without rules due to Neo4j complex object issues
	query := `
		UNWIND $resources AS resource
		MERGE (nsg:Resource {id: resource.id})
		SET nsg.name = resource.name,
		    nsg.resourceType = "microsoft.network/networksecuritygroups",
		    nsg.location = resource.location,
		    nsg.resourceGroup = resource.resourceGroup,
		    nsg.subscriptionId = resource.subscriptionId
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		// Debug first resource
		if len(batchParams) == 0 {
			if props, ok := resource["properties"].(map[string]interface{}); ok {
				if _, hasProcessed := props["processedRules"]; hasProcessed {
					l.Logger.Warn("Resource has processedRules!", "id", getStringFromResource(resource, "id"))
				}
			}
		}

		// Simple params without rules for now
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"location":       getStringFromResource(resource, "location"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
		}

		batchParams = append(batchParams, params)
		l.nodeCount++
	}

	l.Logger.Info("Prepared NSG batch params", "count", len(batchParams))

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})

	// Create individual NSG rule nodes for security analysis
	for _, resource := range resources {
		nsgID := getStringFromResource(resource, "id")

		// Parse properties JSON string
		var props map[string]interface{}
		if propsStr, ok := resource["properties"].(string); ok {
			if err := json.Unmarshal([]byte(propsStr), &props); err != nil {
				l.Logger.Warn("Failed to parse NSG properties JSON", "nsgId", nsgID, "error", err)
				continue
			}
		} else if propsMap, ok := resource["properties"].(map[string]interface{}); ok {
			props = propsMap
		} else {
			continue
		}

		// Extract processedRules
		if processedRules, ok := props["processedRules"].([]interface{}); ok {
			l.Logger.Debug("Creating NSG rules", "nsgId", nsgID, "ruleCount", len(processedRules))
			for idx, rule := range processedRules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if err := l.createNSGRuleNode(ctx, session, ruleMap, nsgID, idx); err != nil {
						l.Logger.Error("Failed to create NSG rule node", "error", err, "nsg", nsgID, "rule", ruleMap["name"])
					}
				}
			}
		} else {
			l.Logger.Debug("No processedRules found in NSG", "nsgId", nsgID)
		}
	}

	return err
}

// createNICNodesBatch creates multiple NIC nodes in a single transaction
func (l *NetworkTopologyImporterLink) createNICNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	// Create NIC nodes first
	query := `
		UNWIND $resources AS resource
		MERGE (n:Resource {id: resource.id})
		SET n.name = resource.name,
		    n.resourceType = "microsoft.network/networkinterfaces",
		    n.privateIPAddress = resource.privateIPAddress,
		    n.macAddress = resource.macAddress,
		    n.primary = resource.primary,
		    n.subnetId = resource.subnetId
	`

	var batchParams []map[string]interface{}
	var nicSubnetPairs []map[string]interface{}

	for _, resource := range resources {
		params := map[string]interface{}{
			"id":                getStringFromResource(resource, "id"),
			"name":              getStringFromResource(resource, "name"),
			"privateIPAddress":  getStringFromResource(resource, "privateIPAddress"),
			"primary":           true,
			"macAddress":        "",
			"subnetId":          getStringFromResource(resource, "subnetId"),
		}

		if props, ok := resource["properties"].(map[string]interface{}); ok {
			params["macAddress"] = getStringFromResource(props, "macAddress")
			if primary, ok := props["primary"].(bool); ok {
				params["primary"] = primary
			}
		}

		batchParams = append(batchParams, params)
		l.nodeCount++

		// Collect NIC-Subnet pairs for relationship creation
		if subnetId := getStringFromResource(resource, "subnetId"); subnetId != "" {
			nicSubnetPairs = append(nicSubnetPairs, map[string]interface{}{
				"nicId":    params["id"],
				"subnetId": subnetId,
			})
		}
	}

	// Create NIC nodes
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create NIC nodes: %w", err)
	}

	// Create NIC-Subnet relationships if any
	if len(nicSubnetPairs) > 0 {
		relationshipQuery := `
			UNWIND $pairs AS pair
			MATCH (n:Resource {id: pair.nicId, resourceType: "microsoft.network/networkinterfaces"})
			MATCH (s:Resource {id: pair.subnetId, resourceType: "microsoft.network/subnets"})
			MERGE (n)-[:IN]->(s)
		`

		_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, relationshipQuery, map[string]interface{}{"pairs": nicSubnetPairs})
			return nil, err
		})

		if err != nil {
			l.Logger.Warn("Failed to create some NIC-Subnet relationships", "error", err)
			// Don't fail the whole operation, just log the warning
		} else {
			l.relationshipCount += len(nicSubnetPairs)
			l.Logger.Debug("Created NIC-Subnet relationships", "count", len(nicSubnetPairs))
		}
	}

	return nil
}

// createPublicIPNodesBatch creates multiple PublicIP nodes in a single transaction
func (l *NetworkTopologyImporterLink) createPublicIPNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	// Create PublicIP nodes first
	query := `
		UNWIND $resources AS resource
		MERGE (p:Resource {id: resource.id})
		SET p.name = resource.name,
		    p.resourceType = "microsoft.network/publicipaddresses",
		    p.ipAddress = resource.ipAddress,
		    p.allocationMethod = resource.allocationMethod,
		    p.sku = resource.sku,
		    p.location = resource.location,
		    p.associatedNicId = resource.associatedNicId
	`

	var batchParams []map[string]interface{}
	var publicIPNicPairs []map[string]interface{}

	for _, resource := range resources {
		params := map[string]interface{}{
			"id":               getStringFromResource(resource, "id"),
			"name":             getStringFromResource(resource, "name"),
			"ipAddress":        getStringFromResource(resource, "ipAddress"),
			"allocationMethod": getStringFromResource(resource, "allocationMethod"),
			"sku":              getStringFromResource(resource, "sku"),
			"location":         getStringFromResource(resource, "location"),
			"associatedNicId":  getStringFromResource(resource, "associatedNicId"),
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Collect PublicIP-NIC pairs for relationship creation
		if associatedNicId := getStringFromResource(resource, "associatedNicId"); associatedNicId != "" {
			publicIPNicPairs = append(publicIPNicPairs, map[string]interface{}{
				"publicIPId": params["id"],
				"nicId":      associatedNicId,
			})
		}
	}

	// Create PublicIP nodes
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})

	if err != nil {
		return fmt.Errorf("failed to create PublicIP nodes: %w", err)
	}

	// Create PublicIP-NIC relationships if any
	if len(publicIPNicPairs) > 0 {
		relationshipQuery := `
			UNWIND $pairs AS pair
			MATCH (p:Resource {id: pair.publicIPId, resourceType: "microsoft.network/publicipaddresses"})
			MATCH (n:Resource {id: pair.nicId, resourceType: "microsoft.network/networkinterfaces"})
			MERGE (p)-[:EXPOSES]->(n)
		`

		_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, relationshipQuery, map[string]interface{}{"pairs": publicIPNicPairs})
			return nil, err
		})

		if err != nil {
			l.Logger.Warn("Failed to create some PublicIP-NIC relationships", "error", err)
			// Don't fail the whole operation, just log the warning
		} else {
			l.relationshipCount += len(publicIPNicPairs)
			l.Logger.Debug("Created PublicIP-NIC relationships", "count", len(publicIPNicPairs))
		}
	}

	return nil
}

// createLoadBalancerNodesBatch creates multiple LoadBalancer nodes in a single transaction
func (l *NetworkTopologyImporterLink) createLoadBalancerNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources AS resource
		MERGE (lb:Resource {id: resource.id})
		SET lb.name = resource.name,
		    lb.resourceType = "microsoft.network/loadbalancers",
		    lb.location = resource.location,
		    lb.resourceGroup = resource.resourceGroup,
		    lb.subscriptionId = resource.subscriptionId
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"location":       getStringFromResource(resource, "location"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Store frontend public IP relationships for later processing
		if frontendIPs, ok := resource["frontendPublicIPs"].([]interface{}); ok {
			for _, pip := range frontendIPs {
				if pipID, ok := pip.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   pipID,
						"targetId":   params["id"].(string),
						"type":       "FRONTEND_IP",
						"sourceType": "PublicIP",
						"targetType": "LoadBalancer",
					})
					l.Logger.Debug("Added pending LoadBalancer frontend relationship",
						"pipID", pipID, "lbID", params["id"])
				}
			}
		}

		// Store backend NIC relationships for later processing
		if backendNICs, ok := resource["backendNICs"].([]interface{}); ok {
			for _, nic := range backendNICs {
				if nicID, ok := nic.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   params["id"].(string),
						"targetId":   nicID,
						"type":       "BACKEND_POOL",
						"sourceType": "LoadBalancer",
						"targetType": "NIC",
					})
				}
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})
	return err
}

// createPrivateEndpointNodesBatch creates multiple PrivateEndpoint nodes in a single transaction
func (l *NetworkTopologyImporterLink) createPrivateEndpointNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources AS resource
		MERGE (pe:Resource {id: resource.id})
		SET pe.name = resource.name,
		    pe.resourceType = "microsoft.network/privateendpoints",
		    pe.location = resource.location,
		    pe.resourceGroup = resource.resourceGroup,
		    pe.subscriptionId = resource.subscriptionId,
		    pe.subnetId = resource.subnetId
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"location":       getStringFromResource(resource, "location"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
			"subnetId":       getStringFromResource(resource, "subnetId"),
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Store target resource relationships
		if targetIDs, ok := resource["targetResourceIds"].([]interface{}); ok {
			for _, target := range targetIDs {
				if targetID, ok := target.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   params["id"].(string),
						"targetId":   targetID,
						"type":       "CONNECTS_TO",
						"sourceType": "PrivateEndpoint",
						"targetType": "Resource",
					})
				}
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})
	return err
}

// createVMScaleSetNodesBatch creates multiple VMScaleSet nodes in a single transaction
func (l *NetworkTopologyImporterLink) createVMScaleSetNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources AS resource
		MERGE (vmss:Resource {id: resource.id})
		SET vmss.name = resource.name,
		    vmss.resourceType = "microsoft.compute/virtualmachinescalesets",
		    vmss.location = resource.location,
		    vmss.resourceGroup = resource.resourceGroup,
		    vmss.subscriptionId = resource.subscriptionId,
		    vmss.instanceCount = resource.instanceCount
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"location":       getStringFromResource(resource, "location"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
			"instanceCount":  resource["instanceCount"],
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Store subnet relationships
		if subnetIDs, ok := resource["subnetIds"].([]interface{}); ok {
			for _, subnet := range subnetIDs {
				if subnetID, ok := subnet.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   params["id"].(string),
						"targetId":   subnetID,
						"type":       "IN",
						"sourceType": "VMScaleSet",
						"targetType": "Subnet",
					})
				}
			}
		}

		// Store NSG relationships
		if nsgIDs, ok := resource["nsgIds"].([]interface{}); ok {
			for _, nsg := range nsgIDs {
				if nsgID, ok := nsg.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   nsgID,
						"targetId":   params["id"].(string),
						"type":       "PROTECTS",
						"sourceType": "NSG",
						"targetType": "VMScaleSet",
					})
				}
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})
	return err
}

// createApplicationGatewayNodesBatch creates multiple ApplicationGateway nodes in a single transaction
func (l *NetworkTopologyImporterLink) createApplicationGatewayNodesBatch(ctx context.Context, session neo4j.SessionWithContext, resources []map[string]interface{}) error {
	query := `
		UNWIND $resources AS resource
		MERGE (ag:Resource {id: resource.id})
		SET ag.name = resource.name,
		    ag.resourceType = "microsoft.network/applicationgateways",
		    ag.location = resource.location,
		    ag.resourceGroup = resource.resourceGroup,
		    ag.subscriptionId = resource.subscriptionId
	`

	var batchParams []map[string]interface{}
	for _, resource := range resources {
		params := map[string]interface{}{
			"id":             getStringFromResource(resource, "id"),
			"name":           getStringFromResource(resource, "name"),
			"location":       getStringFromResource(resource, "location"),
			"resourceGroup":  getStringFromResource(resource, "resourceGroup"),
			"subscriptionId": getStringFromResource(resource, "subscriptionId"),
		}
		batchParams = append(batchParams, params)
		l.nodeCount++

		// Store frontend public IP relationships
		if frontendIPs, ok := resource["frontendPublicIPs"].([]interface{}); ok {
			for _, pip := range frontendIPs {
				if pipID, ok := pip.(string); ok {
					l.pendingRelationships = append(l.pendingRelationships, map[string]string{
						"sourceId":   pipID,
						"targetId":   params["id"].(string),
						"type":       "FRONTEND_IP",
						"sourceType": "PublicIP",
						"targetType": "ApplicationGateway",
					})
				}
			}
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, map[string]interface{}{"resources": batchParams})
		return nil, err
	})
	return err
}

// Helper function to extract string from resource map
// processPendingRelationships creates all relationships that were deferred during node creation
func (l *NetworkTopologyImporterLink) processPendingRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	if len(l.pendingRelationships) == 0 {
		l.Logger.Info("No pending relationships to process")
		return nil
	}

	l.Logger.Info("Processing pending relationships", "count", len(l.pendingRelationships))

	// Group relationships by type for batch processing
	relationshipGroups := make(map[string][]map[string]string)
	for _, rel := range l.pendingRelationships {
		key := fmt.Sprintf("%s_%s_%s", rel["sourceType"], rel["type"], rel["targetType"])
		relationshipGroups[key] = append(relationshipGroups[key], rel)
	}

	// Process each group
	for groupKey, rels := range relationshipGroups {
		if len(rels) == 0 {
			continue
		}

		// Build query based on first relationship in group (all should be same type)
		rel := rels[0]
		query := fmt.Sprintf(`
			UNWIND $rels AS rel
			MATCH (s:%s {id: rel.sourceId})
			MATCH (t:%s {id: rel.targetId})
			MERGE (s)-[:%s]->(t)
			RETURN count(*) as created
		`, rel["sourceType"], rel["targetType"], rel["type"])

		// Execute batch
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, query, map[string]interface{}{"rels": rels})
			if err != nil {
				return nil, err
			}

			if result.Next(ctx) {
				record := result.Record()
				if count, ok := record.Get("created"); ok {
					if created, ok := count.(int64); ok {
						l.relationshipCount += int(created)
						l.Logger.Debug("Created pending relationships", "type", groupKey, "count", created)
					}
				}
			}

			return result.Consume(ctx)
		})

		if err != nil {
			l.Logger.Warn("Failed to create some pending relationships",
				"type", groupKey,
				"error", err,
				"count", len(rels))
		}
	}

	return nil
}

// Stub functions for new relationship types - these will use the pending relationships
func (l *NetworkTopologyImporterLink) createLoadBalancerPublicIPRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships
	return nil
}

func (l *NetworkTopologyImporterLink) createLoadBalancerNICRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships
	return nil
}

func (l *NetworkTopologyImporterLink) createPrivateEndpointSubnetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	query := `
		MATCH (pe:Resource {resourceType: "microsoft.network/privateendpoints"})
		WHERE pe.subnetId IS NOT NULL
		MATCH (s:Resource {id: pe.subnetId, resourceType: "microsoft.network/subnets"})
		MERGE (pe)-[:IN]->(s)
		RETURN count(*) as created
	`

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}

		if result.Next(ctx) {
			record := result.Record()
			if count, ok := record.Get("created"); ok {
				if created, ok := count.(int64); ok {
					l.relationshipCount += int(created)
					l.Logger.Debug("Created PrivateEndpoint-Subnet relationships", "count", created)
				}
			}
		}

		return result.Consume(ctx)
	})

	return err
}

func (l *NetworkTopologyImporterLink) createPrivateEndpointResourceRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships
	return nil
}

func (l *NetworkTopologyImporterLink) createVMScaleSetSubnetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships
	return nil
}

func (l *NetworkTopologyImporterLink) createNSGVMScaleSetRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships via PROTECTS
	return nil
}

func (l *NetworkTopologyImporterLink) createApplicationGatewayPublicIPRelationships(ctx context.Context, session neo4j.SessionWithContext) error {
	// Already handled in processPendingRelationships
	return nil
}

func getStringFromResource(resource map[string]interface{}, field string) string {
	if val, ok := resource[field].(string); ok {
		return val
	}
	return ""
}

func getStringFromMap(m map[string]interface{}, field string) string {
	if val, ok := m[field].(string); ok {
		return val
	}
	return ""
}

// getMapKeys returns the keys of a map for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// createSubnetNodeFromVNet creates a subnet node from VNet subnet data
func (l *NetworkTopologyImporterLink) createSubnetNodeFromVNet(ctx context.Context, session neo4j.SessionWithContext, subnetMap map[string]interface{}, vnetID string) error {
	query := `
		MERGE (s:Resource {id: $id})
		SET s.name = $name,
		    s.resourceType = "microsoft.network/subnets",
		    s.vnetId = $vnetId,
		    s.addressPrefix = $addressPrefix,
		    s.type = $type
	`

	subnetID := getStringFromMap(subnetMap, "id")
	if subnetID == "" {
		return fmt.Errorf("subnet missing ID, available keys: %v", getMapKeys(subnetMap))
	}

	params := map[string]interface{}{
		"id":            subnetID,
		"name":          getStringFromMap(subnetMap, "name"),
		"vnetId":        vnetID,
		"type":          getStringFromMap(subnetMap, "type"),
		"addressPrefix": "",
	}

	// Extract address prefix from subnet properties
	if props, ok := subnetMap["properties"].(map[string]interface{}); ok {
		// Try addressPrefixes first (array format)
		if addressPrefixes, ok := props["addressPrefixes"].([]interface{}); ok && len(addressPrefixes) > 0 {
			if prefix, ok := addressPrefixes[0].(string); ok {
				params["addressPrefix"] = prefix
			}
		} else if prefix, ok := props["addressPrefix"].(string); ok {
			// Try single addressPrefix field
			params["addressPrefix"] = prefix
		}
	}

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		_, err := tx.Run(ctx, query, params)
		return nil, err
	})

	if err == nil {
		l.nodeCount++
		l.Logger.Debug("Created subnet node", "subnetId", subnetID, "name", params["name"], "addressPrefix", params["addressPrefix"])
	}

	return err
}

// GetLinkName returns the name of the link
func (l *NetworkTopologyImporterLink) GetLinkName() string {
	return "NetworkTopologyImporterLink"
}

// GetLinkID returns the ID of the link
func (l *NetworkTopologyImporterLink) GetLinkID() string {
	return "network-topology-importer"
}

// Threat Analysis Methods

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}