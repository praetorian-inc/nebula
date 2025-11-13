package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// Neo4jImporterLink imports consolidated Azure security data into Neo4j using simplified graph model
// Implements two-edge architecture: CONTAINS (hierarchy) and HAS_PERMISSION (permissions)
type Neo4jImporterLink struct {
	*chain.Base
	consolidatedData   map[string]interface{}
	nodeCounts         map[string]int
	edgeCounts         map[string]int
	driver             neo4j.DriverWithContext
	neo4jURL           string
	neo4jUser          string
	neo4jPassword      string
	roleDefinitionsMap map[string]interface{} // Cache role definitions for permission expansion
}

func NewNeo4jImporterLink(configs ...cfg.Config) chain.Link {
	l := &Neo4jImporterLink{}
	l.Base = chain.NewBase(l, configs...)
	l.nodeCounts = make(map[string]int)
	l.edgeCounts = make(map[string]int)
	l.roleDefinitionsMap = make(map[string]interface{})
	return l
}

func (l *Neo4jImporterLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureNeo4jURL(),
		options.AzureNeo4jUser(),
		options.AzureNeo4jPassword(),
		options.AzureDataFile(),
		options.AzureClearDB(),
	}
}

func (l *Neo4jImporterLink) Process(input interface{}) error {
	l.neo4jURL, _ = cfg.As[string](l.Arg("neo4j-url"))
	l.neo4jUser, _ = cfg.As[string](l.Arg("neo4j-user"))
	l.neo4jPassword, _ = cfg.As[string](l.Arg("neo4j-password"))
	dataFile, _ := cfg.As[string](l.Arg("data-file"))
	clearDB, _ := cfg.As[bool](l.Arg("clear-db"))

	l.Logger.Info("Starting real Neo4j import", "neo4j_url", l.neo4jURL, "data_file", dataFile)
	message.Info("📊 Azure Security Graph - Neo4j Import Tool")
	message.Info("🔍 Phase 1: Creating simplified security graph model")
	message.Info("🏗️  Architecture: Single Resource nodes + Two edge types (CONTAINS + HAS_PERMISSION)")

	// Step 1: Load consolidated JSON data
	if err := l.loadConsolidatedData(dataFile); err != nil {
		return fmt.Errorf("failed to load data: %v", err)
	}

	// Step 2: Connect to Neo4j with real driver
	if err := l.connectToNeo4j(); err != nil {
		return fmt.Errorf("failed to connect to Neo4j: %v", err)
	}
	defer l.driver.Close(context.Background())

	// Step 3: Clear database if requested
	if clearDB {
		if err := l.clearDatabase(); err != nil {
			return fmt.Errorf("failed to clear database: %v", err)
		}
	}

	// Step 4: Create constraints
	if err := l.createConstraints(); err != nil {
		return fmt.Errorf("failed to create constraints: %v", err)
	}

	// Step 5: Build roleDefinitions cache for permission expansion
	if err := l.buildRoleDefinitionsCache(); err != nil {
		return fmt.Errorf("failed to build roleDefinitions cache: %v", err)
	}

	// Step 6: Create all Resource nodes
	if err := l.createAllResourceNodes(); err != nil {
		return fmt.Errorf("failed to create nodes: %v", err)
	}

	// Step 9: Create CONTAINS edges (hierarchy)
	message.Info("🔗 Phase 2a: Creating CONTAINS edges (hierarchy)")
	if err := l.createContainsEdges(); err != nil {
		return fmt.Errorf("failed to create CONTAINS edges: %v", err)
	}

	// Step 10: Create HAS_PERMISSION edges (permissions)
	message.Info("🔐 Phase 2b: Creating HAS_PERMISSION edges (permissions)")
	if !l.createPermissionEdges() {
		l.Logger.Warn("No HAS_PERMISSION edges were created")
	}

	// Step 11: Generate summary
	summary := l.generateImportSummary()
	message.Info("🎉 Security graph creation completed successfully!")
	message.Info("📈 Ready for Azure security analysis and attack path discovery")

	l.Send(summary)
	return nil
}

// connectToNeo4j establishes real connection to Neo4j - exactly like AzureDumperConsolidated
func (l *Neo4jImporterLink) connectToNeo4j() error {
	message.Info("Connecting to Neo4j at: %s", l.neo4jURL)

	driver, err := neo4j.NewDriverWithContext(
		l.neo4jURL,
		neo4j.BasicAuth(l.neo4jUser, l.neo4jPassword, ""),
	)
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %v", err)
	}

	l.driver = driver

	// Test connection with real query
	ctx := context.Background()
	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, "RETURN 1 AS test", nil)
		if err != nil {
			return nil, err
		}

		if result.Next(ctx) {
			return result.Record().Values[0], nil
		}
		return nil, fmt.Errorf("no result returned")
	})

	if err != nil {
		return fmt.Errorf("failed to test Neo4j connection: %v", err)
	}

	if testValue, ok := result.(int64); ok && testValue == 1 {
		message.Info("✅ Neo4j connection successful")
		return nil
	}

	return fmt.Errorf("unexpected test result: %v", result)
}

// clearDatabase clears the Neo4j database - exactly like AzureDumperConsolidated
func (l *Neo4jImporterLink) clearDatabase() error {
	message.Info("🗑️  Clearing Neo4j database...")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	queries := []string{
		"MATCH (n) DETACH DELETE n",                                              // Delete all nodes and relationships
		"CALL apoc.schema.assert({},{},true) YIELD label, key RETURN *",          // Drop all constraints and indexes
	}

	for _, query := range queries {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, query, nil)
			return nil, err
		})

		if err != nil {
			if strings.Contains(err.Error(), "apoc") {
				// APOC not available, try manual constraint dropping
				l.Logger.Warn("APOC not available, using manual cleanup")
			} else {
				return fmt.Errorf("database clear error: %v", err)
			}
		}
	}

	message.Info("✅ Database cleared successfully")
	return nil
}

func (l *Neo4jImporterLink) createConstraints() error {
	message.Info("=== Creating Neo4j Constraints (Simplified Model) ===")

	// Single constraint for unified Resource node type
	constraints := []string{
		"CREATE CONSTRAINT resource_unique_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
	}

	// Optional performance indexes for common queries
	indexes := []string{
		"CREATE INDEX resource_type_idx IF NOT EXISTS FOR (r:Resource) ON (r.resourceType)",
		"CREATE INDEX resource_display_name_idx IF NOT EXISTS FOR (r:Resource) ON (r.displayName)",
	}

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Create constraints
	for _, constraint := range constraints {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, constraint, nil)
			return nil, err
		})

		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				message.Info("Constraint already exists: %s", constraint)
			} else {
				l.Logger.Error("Error creating constraint", "constraint", constraint, "error", err)
				return err
			}
		} else {
			message.Info("Created constraint: %s", constraint)
		}
	}

	// Create performance indexes
	message.Info("Creating performance indexes...")
	for _, index := range indexes {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, index, nil)
			return nil, err
		})

		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				message.Info("Index already exists: %s", index)
			} else {
				l.Logger.Warn("Error creating index (non-critical)", "index", index, "error", err)
			}
		} else {
			message.Info("Created index: %s", index)
		}
	}

	return nil
}

// loadConsolidatedData loads the consolidated JSON file - handles both array and object formats
func (l *Neo4jImporterLink) loadConsolidatedData(dataFile string) error {
	message.Info("Loading Azure IAM data from: %s", dataFile)

	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return fmt.Errorf("Azure IAM data file not found: %s", dataFile)
	}

	fileData, err := os.ReadFile(dataFile)
	if err != nil {
		return fmt.Errorf("failed to read data file: %v", err)
	}

	// Handle both array format (from Nebula's RuntimeJSONOutputter) and object format
	var tempData interface{}
	if err := json.Unmarshal(fileData, &tempData); err != nil {
		return fmt.Errorf("failed to parse JSON data: %v", err)
	}

	// If it's an array (from Nebula), extract the first element
	if dataArray, ok := tempData.([]interface{}); ok {
		if len(dataArray) > 0 {
			if firstElement, ok := dataArray[0].(map[string]interface{}); ok {
				l.consolidatedData = firstElement
			} else {
				return fmt.Errorf("invalid JSON structure: array element is not an object")
			}
		} else {
			return fmt.Errorf("empty JSON array")
		}
	} else if dataObject, ok := tempData.(map[string]interface{}); ok {
		// If it's already an object (direct format), use it directly
		l.consolidatedData = dataObject
	} else {
		return fmt.Errorf("invalid JSON structure: expected object or array")
	}

	message.Info("Successfully loaded consolidated Azure IAM data")

	// Show data summary
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	message.Info("Tenant ID: %s", l.getStringValue(metadata, "tenant_id"))
	message.Info("Collection timestamp: %s", l.getStringValue(metadata, "collection_timestamp"))

	return nil
}

// createAllResourceNodes creates all resources as unified Resource nodes
func (l *Neo4jImporterLink) createAllResourceNodes() error {
	message.Info("=== Creating All Resource Nodes (Unified Model) ===")

	totalNodes := 0

	// Create Identity Resources (from Azure AD)
	identityCount := l.createIdentityResources()
	totalNodes += identityCount

	// Create Hierarchy Resources (Tenant, Management Groups, Subscriptions, Resource Groups)
	hierarchyCount := l.createHierarchyResources()
	totalNodes += hierarchyCount

	// Create Azure Resources (VMs, Storage, etc. - filtered to security-relevant only)
	azureResourceCount := l.createAzureResourceNodes()
	totalNodes += azureResourceCount

	message.Info("Resource node creation summary:", "identity_nodes", identityCount, "hierarchy_nodes", hierarchyCount, "azure_resource_nodes", azureResourceCount, "total_nodes", totalNodes)

	if totalNodes > 0 {
		message.Info("🎉 Resource node creation completed successfully!", "total", totalNodes)
		l.nodeCounts["Resource"] = totalNodes
		return nil
	}

	return fmt.Errorf("no resource nodes created")
}

func (l *Neo4jImporterLink) generateImportSummary() map[string]interface{} {
	message.Info("=== AzureDumper Import Summary ===")

	totalNodes := 0
	for _, count := range l.nodeCounts {
		totalNodes += count
	}

	totalEdges := 0
	for _, count := range l.edgeCounts {
		totalEdges += count
	}

	message.Info("Total nodes created: %d", totalNodes)
	message.Info("Total edges created: %d", totalEdges)

	message.Info("=== Node Summary ===")
	for nodeType, count := range l.nodeCounts {
		message.Info("%s: %d nodes", nodeType, count)
	}

	message.Info("=== Edge Summary ===")
	for edgeType, count := range l.edgeCounts {
		message.Info("%s: %d edges", edgeType, count)
	}

	return map[string]interface{}{
		"neo4j_import_summary": map[string]interface{}{
			"total_nodes":         totalNodes,
			"total_edges":         totalEdges,
			"nodes_by_type":       l.nodeCounts,
			"edges_by_type":       l.edgeCounts,
			"import_timestamp":    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"status":              "real_success",
			"database_url":        l.neo4jURL,
		},
	}
}

// createIdentityResources creates all identity-related Resource nodes
func (l *Neo4jImporterLink) createIdentityResources() int {
	message.Info("=== Creating Identity Resource Nodes ===")

	totalCreated := 0
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Create Users as Resource nodes
	users := l.getArrayValue(azureAD, "users")
	if len(users) > 0 {
		userNodes := make([]map[string]interface{}, 0)
		for _, user := range users {
			if userMap, ok := user.(map[string]interface{}); ok {
				resourceNode := map[string]interface{}{
					"id": l.getStringValue(userMap, "id"),
					"resourceType": "Microsoft.DirectoryServices/users",
					"displayName": l.getStringValue(userMap, "displayName"),
					"userPrincipalName": l.getStringValue(userMap, "userPrincipalName"),
					"mail": l.getStringValue(userMap, "mail"),
					"userType": l.getStringValue(userMap, "userType"),
				}
				if accountEnabled, ok := userMap["accountEnabled"].(bool); ok {
					resourceNode["accountEnabled"] = accountEnabled
				}

				// Add metadata with user attributes
				metadata := map[string]interface{}{
					"email": l.getStringValue(userMap, "mail"),
					"userPrincipalName": l.getStringValue(userMap, "userPrincipalName"),
					"userType": l.getStringValue(userMap, "userType"),
				}
				if accountEnabled, ok := userMap["accountEnabled"].(bool); ok {
					metadata["accountEnabled"] = accountEnabled
				}
				resourceNode["metadata"] = l.toJSONString(metadata)
				userNodes = append(userNodes, resourceNode)
			}
		}

		if created := l.createResourceNodesBatch(session, ctx, userNodes, []string{"Resource", "Identity", "Principal"}); created > 0 {
			totalCreated += created
			message.Info("Created User resource nodes", "count", created)
		}
	}

	// Create Groups as Resource nodes
	groups := l.getArrayValue(azureAD, "groups")
	if len(groups) > 0 {
		groupNodes := make([]map[string]interface{}, 0)
		for _, group := range groups {
			if groupMap, ok := group.(map[string]interface{}); ok {
				resourceNode := map[string]interface{}{
					"id": l.getStringValue(groupMap, "id"),
					"resourceType": "Microsoft.DirectoryServices/groups",
					"displayName": l.getStringValue(groupMap, "displayName"),
					"description": l.getStringValue(groupMap, "description"),
				}
				if securityEnabled, ok := groupMap["securityEnabled"].(bool); ok {
					resourceNode["securityEnabled"] = securityEnabled
				}
				if mailEnabled, ok := groupMap["mailEnabled"].(bool); ok {
					resourceNode["mailEnabled"] = mailEnabled
				}

				// Add metadata with group attributes
				groupMetadata := map[string]interface{}{
					"description": l.getStringValue(groupMap, "description"),
				}
				if securityEnabled, ok := groupMap["securityEnabled"].(bool); ok {
					groupMetadata["securityEnabled"] = securityEnabled
				}
				if mailEnabled, ok := groupMap["mailEnabled"].(bool); ok {
					groupMetadata["mailEnabled"] = mailEnabled
				}
				// Handle groupTypes array if present
				if groupTypes, ok := groupMap["groupTypes"].([]interface{}); ok && len(groupTypes) > 0 {
					types := make([]string, 0, len(groupTypes))
					for _, gt := range groupTypes {
						if gtStr, ok := gt.(string); ok {
							types = append(types, gtStr)
						}
					}
					if len(types) > 0 {
						groupMetadata["groupTypes"] = types
					}
				}
				resourceNode["metadata"] = l.toJSONString(groupMetadata)
				groupNodes = append(groupNodes, resourceNode)
			}
		}

		if created := l.createResourceNodesBatch(session, ctx, groupNodes, []string{"Resource", "Identity", "Principal"}); created > 0 {
			totalCreated += created
			message.Info("Created Group resource nodes", "count", created)
		}
	}

	// Create Service Principals as Resource nodes
	servicePrincipals := l.getArrayValue(azureAD, "servicePrincipals")
	if len(servicePrincipals) > 0 {
		spNodes := make([]map[string]interface{}, 0)
		for _, sp := range servicePrincipals {
			if spMap, ok := sp.(map[string]interface{}); ok {
				resourceNode := map[string]interface{}{
					"id": l.getStringValue(spMap, "id"),
					"resourceType": "Microsoft.DirectoryServices/servicePrincipals",
					"displayName": l.getStringValue(spMap, "displayName"),
					"appId": l.getStringValue(spMap, "appId"),
					"servicePrincipalType": l.getStringValue(spMap, "servicePrincipalType"),
				}
				if accountEnabled, ok := spMap["accountEnabled"].(bool); ok {
					resourceNode["accountEnabled"] = accountEnabled
				}

				// Add metadata with service principal attributes
				spMetadata := map[string]interface{}{
					"appId": l.getStringValue(spMap, "appId"),
					"servicePrincipalType": l.getStringValue(spMap, "servicePrincipalType"),
				}
				if accountEnabled, ok := spMap["accountEnabled"].(bool); ok {
					spMetadata["accountEnabled"] = accountEnabled
				}
				resourceNode["metadata"] = l.toJSONString(spMetadata)
				spNodes = append(spNodes, resourceNode)
			}
		}

		if created := l.createResourceNodesBatch(session, ctx, spNodes, []string{"Resource", "Identity", "Principal"}); created > 0 {
			totalCreated += created
			message.Info("Created Service Principal resource nodes", "count", created)
		}
	}

	// Create Applications as Resource nodes
	applications := l.getArrayValue(azureAD, "applications")
	if len(applications) > 0 {
		appNodes := make([]map[string]interface{}, 0)
		for _, app := range applications {
			if appMap, ok := app.(map[string]interface{}); ok {
				resourceNode := map[string]interface{}{
					"id": l.getStringValue(appMap, "id"),
					"resourceType": "Microsoft.DirectoryServices/applications",
					"displayName": l.getStringValue(appMap, "displayName"),
					"appId": l.getStringValue(appMap, "appId"),
					"signInAudience": l.getStringValue(appMap, "signInAudience"),
				}

				// Add metadata with application attributes
				appMetadata := map[string]interface{}{
					"appId": l.getStringValue(appMap, "appId"),
					"signInAudience": l.getStringValue(appMap, "signInAudience"),
				}
				resourceNode["metadata"] = l.toJSONString(appMetadata)
				appNodes = append(appNodes, resourceNode)
			}
		}

		if created := l.createResourceNodesBatch(session, ctx, appNodes, []string{"Resource", "Identity"}); created > 0 {
			totalCreated += created
			message.Info("Created Application resource nodes", "count", created)
		}
	}

	return totalCreated
}

// createHierarchyResources creates hierarchy Resource nodes (Tenant, Management Groups, Subscriptions, Resource Groups)
func (l *Neo4jImporterLink) createHierarchyResources() int {
	message.Info("=== Creating Hierarchy Resource Nodes ===")

	totalCreated := 0
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Create Tenant resource node
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	tenantID := l.getStringValue(metadata, "tenant_id")
	if tenantID != "" {
		// Create tenant metadata with domain and collection info
		tenantMetadata := map[string]interface{}{
			"tenantId": tenantID,
		}
		if domain := l.getStringValue(metadata, "domain"); domain != "" {
			tenantMetadata["domain"] = domain
		}
		if displayName := l.getStringValue(metadata, "display_name"); displayName != "" {
			tenantMetadata["displayName"] = displayName
		}
		if country := l.getStringValue(metadata, "country"); country != "" {
			tenantMetadata["country"] = country
		}

		tenantNodes := []map[string]interface{}{
			{
				"id": tenantID,
				"resourceType": "Microsoft.DirectoryServices/tenant",
				"displayName": "Azure AD Tenant",
				"tenantId": tenantID,
				"metadata": l.toJSONString(tenantMetadata),
			},
		}

		if created := l.createResourceNodesBatch(session, ctx, tenantNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Tenant resource node", "tenantId", tenantID)
		}

		// Create Root Management Group (always exists in Azure with tenant ID)
		rootMgId := "/providers/Microsoft.Management/managementGroups/" + tenantID
		rootMgMetadata := map[string]interface{}{
			"managementGroupId": tenantID,
			"tenantId":          tenantID,
			"isRoot":            true,
		}

		rootMgNodes := []map[string]interface{}{
			{
				"id":                 rootMgId,
				"resourceType":       "Microsoft.Management/managementGroups",
				"displayName":        "Tenant Root Group",
				"managementGroupId":  tenantID,
				"tenantId":           tenantID,
				"isRoot":             true,
				"metadata":           l.toJSONString(rootMgMetadata),
			},
		}

		if created := l.createResourceNodesBatch(session, ctx, rootMgNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Root Management Group resource node", "managementGroupId", tenantID)
		}
	}

	// Create Management Groups
	managementGroups := l.getArrayValue(l.consolidatedData, "management_groups")
	if len(managementGroups) > 0 {
		managementGroupNodes := make([]map[string]interface{}, 0)

		for _, mgData := range managementGroups {
			if mgMap, ok := mgData.(map[string]interface{}); ok {
				// Only process actual management groups, skip subscriptions
				itemType := l.getStringValue(mgMap, "type")
				if itemType != "microsoft.management/managementgroups" {
					continue
				}

				mgID := l.getStringValue(mgMap, "name")  // Management Group ID

				if mgID != "" {
					// Extract properties if they exist
					properties := l.getMapValue(mgMap, "properties")
					var parentID string
					var children []interface{}
					var mgDisplayName string

					if properties != nil {
						mgDisplayName = l.getStringValue(properties, "displayName")
						if parentMap := l.getMapValue(properties, "parent"); parentMap != nil {
							parentID = l.getStringValue(parentMap, "name")
						}
						children = l.getArrayValue(properties, "children")
					}

					// Add metadata for management group
					mgMetadata := map[string]interface{}{
						"managementGroupId": mgID,
						"parentId":          parentID,
						"childrenCount":     len(children),
					}

					managementGroupNode := map[string]interface{}{
						"id":           "/providers/Microsoft.Management/managementGroups/" + mgID,
						"resourceType": "Microsoft.Management/managementGroups",
						"displayName":  mgDisplayName,
						"tenantId":      tenantID,
						"managementGroupId": mgID,
						"parentId":      parentID,
						"childrenCount": len(children),
						"metadata":     l.toJSONString(mgMetadata),
					}
					managementGroupNodes = append(managementGroupNodes, managementGroupNode)
				}
			}
		}

		if created := l.createResourceNodesBatch(session, ctx, managementGroupNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Management Group resource nodes", "count", created)
		}
	}

	// Create Subscriptions and Resource Groups
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources != nil {
		subscriptionNodes := make([]map[string]interface{}, 0)
		resourceGroupNodes := make([]map[string]interface{}, 0)

		for subscriptionId, subscriptionData := range azureResources {
			// Create subscription node with metadata
			subscriptionMetadata := map[string]interface{}{
				"subscriptionId": subscriptionId,
			}
			subscriptionNodes = append(subscriptionNodes, map[string]interface{}{
				"id": "/subscriptions/" + subscriptionId,
				"resourceType": "Microsoft.Resources/subscriptions",
				"displayName": "Subscription " + subscriptionId,
				"subscriptionId": subscriptionId,
				"metadata": l.toJSONString(subscriptionMetadata),
			})

			// Create resource groups from azureResourceGroups collection
			if subData, ok := subscriptionData.(map[string]interface{}); ok {
				azureResourceGroupsList := l.getArrayValue(subData, "azureResourceGroups")
				seenResourceGroups := make(map[string]bool) // Use case-insensitive key

				for _, resourceGroup := range azureResourceGroupsList {
					if rgMap, ok := resourceGroup.(map[string]interface{}); ok {
						rgId := l.getStringValue(rgMap, "id")
						rgName := l.getStringValue(rgMap, "name")

						if rgId != "" && rgName != "" {
							// Normalize resource group name to lowercase for consistency
							normalizedRgName := strings.ToLower(rgName)
							normalizedRgId := "/subscriptions/" + subscriptionId + "/resourceGroups/" + normalizedRgName

							// Use normalized ID for deduplication
							if !seenResourceGroups[normalizedRgId] {
								// Create resource group metadata
								rgMetadata := map[string]interface{}{
									"resourceGroupName": normalizedRgName,
									"subscriptionId":    subscriptionId,
									"location":          l.getStringValue(rgMap, "location"),
								}

								resourceGroupNodes = append(resourceGroupNodes, map[string]interface{}{
									"id":                normalizedRgId,
									"resourceType":      "Microsoft.Resources/resourceGroups",
									"displayName":       normalizedRgName,
									"resourceGroupName": normalizedRgName,
									"subscriptionId":    subscriptionId,
									"location":          l.getStringValue(rgMap, "location"),
									"metadata":          l.toJSONString(rgMetadata),
								})
								seenResourceGroups[normalizedRgId] = true
							}
						}
					}
				}
			}
		}

		// Create subscription nodes
		if created := l.createResourceNodesBatch(session, ctx, subscriptionNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Subscription resource nodes", "count", created)
		}

		// Create resource group nodes
		if created := l.createResourceNodesBatch(session, ctx, resourceGroupNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Resource Group resource nodes", "count", created)
		}
	}

	return totalCreated
}

// createAzureResourceNodes creates security-relevant Azure Resource nodes
func (l *Neo4jImporterLink) createAzureResourceNodes() int {
	message.Info("=== Creating Azure Resource Nodes (Security-Relevant Only) ===")

	totalCreated := 0
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Define security-relevant resource types
	securityRelevantTypes := map[string]bool{
		"microsoft.compute/virtualmachines": true,
		"microsoft.containerservice/managedclusters": true,
		"microsoft.storage/storageaccounts": true,
		"microsoft.keyvault/vaults": true,
		"microsoft.sql/servers": true,
		"microsoft.dbforpostgresql/flexibleservers": true,
		"microsoft.dbformysql/flexibleservers": true,
		"microsoft.documentdb/databaseaccounts": true,
		"microsoft.web/sites": true,
		"microsoft.logic/workflows": true,
		"microsoft.cognitiveservices/accounts": true,
		"microsoft.automation/automationaccounts": true,
		"microsoft.recoveryservices/vaults": true,
		"microsoft.managedidentity/userassignedidentities": true,
		"microsoft.network/virtualnetworkgateways": true,
		"microsoft.network/applicationgateways": true,
		"microsoft.network/azurefirewalls": true,
	}

	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources == nil {
		l.Logger.Warn("No azure_resources data found for Azure resource node creation")
		return 0
	}

	resourceNodes := make([]map[string]interface{}, 0)

	for subscriptionId, subscriptionData := range azureResources {
		if subData, ok := subscriptionData.(map[string]interface{}); ok {
			azureResourcesList := l.getArrayValue(subData, "azureResources")

			for _, resource := range azureResourcesList {
				if resourceMap, ok := resource.(map[string]interface{}); ok {
					resourceType := strings.ToLower(l.getStringValue(resourceMap, "type"))

					// Only include security-relevant resources
					if securityRelevantTypes[resourceType] {
						// Process identity data for managed identities
						l.processIdentityData(resourceMap)

						resourceNode := map[string]interface{}{
							"id": l.getStringValue(resourceMap, "id"),
							"resourceType": l.getStringValue(resourceMap, "type"),
							"displayName": l.getStringValue(resourceMap, "name"),
						}

						// Add additional fields for query optimization
						if location := l.getStringValue(resourceMap, "location"); location != "" {
							resourceNode["location"] = location
						}
						if subscriptionId != "" {
							resourceNode["subscriptionId"] = subscriptionId
						}
						if resourceGroup := l.getStringValue(resourceMap, "resourceGroup"); resourceGroup != "" {
							resourceNode["resourceGroup"] = resourceGroup
						}

						// For managed identities, preserve the principalId for linking to service principals
						if strings.Contains(strings.ToLower(resourceType), "managedidentity") {
							if properties := l.getMapValue(resourceMap, "properties"); properties != nil {
								if principalId := l.getStringValue(properties, "principalId"); principalId != "" {
									resourceNode["principalId"] = principalId
									l.Logger.Debug("Extracted principalId from managed identity", "resourceName", l.getStringValue(resourceMap, "name"), "principalId", principalId)
								} else {
									l.Logger.Warn("No principalId found in managed identity properties", "resourceName", l.getStringValue(resourceMap, "name"), "properties", properties)
								}
							} else {
								l.Logger.Warn("No properties found for managed identity", "resourceName", l.getStringValue(resourceMap, "name"))
							}
						}

						resourceNodes = append(resourceNodes, resourceNode)
					}
				}
			}

			l.Logger.Debug("Processed Azure resources for subscription", "subscription", subscriptionId, "total_resources", len(azureResourcesList), "security_relevant", "filtered")
		}
	}

	// Create Azure resource nodes in batches
	if len(resourceNodes) > 0 {
		if created := l.createResourceNodesBatch(session, ctx, resourceNodes, []string{"Resource", "AzureResource"}); created > 0 {
			totalCreated += created
			message.Info("Created security-relevant Azure resource nodes", "count", created)
		}
	} else {
		l.Logger.Warn("No security-relevant Azure resources found to create nodes for")
	}

	return totalCreated
}

// createResourceNodesBatch creates a batch of Resource nodes with the given labels
func (l *Neo4jImporterLink) createResourceNodesBatch(session neo4j.SessionWithContext, ctx context.Context, resourceNodes []map[string]interface{}, labels []string) int {
	if len(resourceNodes) == 0 {
		return 0
	}

	// Create Cypher query with dynamic labels
	labelString := strings.Join(labels, ":")
	cypher := fmt.Sprintf(`
		UNWIND $resources AS resource
		CREATE (r:%s {
			id: resource.id,
			resourceType: resource.resourceType,
			displayName: resource.displayName,
			metadata: COALESCE(resource.metadata, '{}'),
			location: resource.location,
			subscriptionId: resource.subscriptionId,
			resourceGroup: resource.resourceGroup,
			principalId: resource.principalId
		})
	`, labelString)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"resources": resourceNodes})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().NodesCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating resource nodes batch", "error", err, "labels", labels)
		return 0
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		return int(nodesCreated)
	}

	l.Logger.Error("Unexpected result type from resource node creation", "result", result, "type", fmt.Sprintf("%T", result))
	return 0
}

// createContainsEdges creates all CONTAINS relationships for the hierarchy
func (l *Neo4jImporterLink) createContainsEdges() error {
	message.Info("=== Creating CONTAINS Edges (Hierarchy) ===")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	totalEdgesCreated := 0

	// 1. Create Tenant → Root Management Group CONTAINS edges
	if edgesCreated := l.createTenantToRootManagementGroupContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Tenant → Root Management Group CONTAINS edges", "count", edgesCreated)
	}

	// 1.5. Create Management Group → Management Group CONTAINS edges (for nested hierarchy)
	if edgesCreated := l.createManagementGroupToManagementGroupContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Management Group → Management Group CONTAINS edges", "count", edgesCreated)
	}

	// 1.7. Create Management Group → Subscription CONTAINS edges
	if edgesCreated := l.createManagementGroupToSubscriptionContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Management Group → Subscription CONTAINS edges", "count", edgesCreated)
	}

	// 1.9. Create Root MG → Subscription CONTAINS edges for subscriptions not in child Management Groups
	if edgesCreated := l.createTenantToOrphanSubscriptionContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Root MG → Subscription CONTAINS edges", "count", edgesCreated)
	}

	// 2. Create Subscription → Resource Group CONTAINS edges
	if edgesCreated := l.createSubscriptionToResourceGroupContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Subscription → Resource Group CONTAINS edges", "count", edgesCreated)
	}

	// 3. Create Resource Group → Resource CONTAINS edges
	if edgesCreated := l.createResourceGroupToResourceContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Resource Group → Resource CONTAINS edges", "count", edgesCreated)
	}

	// 3.5. Create Managed Identity → Service Principal CONTAINS edges
	if edgesCreated := l.createManagedIdentityToServicePrincipalContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Managed Identity → Service Principal CONTAINS edges", "count", edgesCreated)
	}

	// 4. Create Group → Member CONTAINS edges (group memberships)
	if edgesCreated := l.createGroupMemberContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Group → Member CONTAINS edges", "count", edgesCreated)
	}

	// 5. Create Application → Service Principal CONTAINS edges
	if edgesCreated := l.createApplicationToServicePrincipalContains(session, ctx); edgesCreated > 0 {
		totalEdgesCreated += edgesCreated
		message.Info("Created Application → Service Principal CONTAINS edges", "count", edgesCreated)
	}

	l.edgeCounts["CONTAINS"] = totalEdgesCreated
	message.Info("Created total CONTAINS edges", "count", totalEdgesCreated)

	return nil
}

// createTenantToSubscriptionContains creates CONTAINS edges from Tenant to Subscriptions
func (l *Neo4jImporterLink) createTenantToSubscriptionContains(session neo4j.SessionWithContext, ctx context.Context) int {
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	tenantID := l.getStringValue(metadata, "tenant_id")

	if tenantID == "" {
		l.Logger.Warn("No tenant ID found for tenant-subscription relationships")
		return 0
	}

	cypher := `
		MATCH (tenant:Resource {id: $tenantId})
		MATCH (subscription:Resource)
		WHERE subscription.resourceType = "Microsoft.Resources/subscriptions"
		MERGE (tenant)-[:CONTAINS]->(subscription)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"tenantId": tenantID})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating tenant-subscription CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createTenantToRootManagementGroupContains creates CONTAINS edges from Tenant to Root Management Groups
func (l *Neo4jImporterLink) createTenantToRootManagementGroupContains(session neo4j.SessionWithContext, ctx context.Context) int {
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	tenantID := l.getStringValue(metadata, "tenant_id")

	if tenantID == "" {
		l.Logger.Warn("No tenant ID found for tenant-management group relationships")
		return 0
	}

	// Connect tenant to root management group (which has tenant ID)
	cypher := `
		MATCH (tenant:Resource {id: $tenantId})
		MATCH (rootMg:Resource)
		WHERE rootMg.resourceType = "Microsoft.Management/managementGroups"
		AND rootMg.id = "/providers/Microsoft.Management/managementGroups/" + $tenantId
		MERGE (tenant)-[:CONTAINS]->(rootMg)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"tenantId": tenantID})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating tenant-management group CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createManagementGroupToManagementGroupContains creates CONTAINS edges between Management Groups (parent -> child)
func (l *Neo4jImporterLink) createManagementGroupToManagementGroupContains(session neo4j.SessionWithContext, ctx context.Context) int {
	// Extract management groups and their parent relationships from the consolidated data
	managementGroupHierarchy := []map[string]interface{}{}

	managementGroups := l.getArrayValue(l.consolidatedData, "management_groups")
	for _, mgData := range managementGroups {
		if mgMap, ok := mgData.(map[string]interface{}); ok {
			// Only process actual management groups (not subscriptions mixed in the array)
			if resourceType := l.getStringValue(mgMap, "ResourceType"); resourceType == "ManagementGroup" {
				parentId := l.getStringValue(mgMap, "ParentId")
				mgId := l.getStringValue(mgMap, "id")

				if parentId != "" && mgId != "" {
					// Convert parent ID to full path format for consistency
					var fullParentId string
					if strings.HasPrefix(parentId, "/providers/Microsoft.Management/managementGroups/") {
						fullParentId = parentId
					} else {
						fullParentId = "/providers/Microsoft.Management/managementGroups/" + parentId
					}

					managementGroupHierarchy = append(managementGroupHierarchy, map[string]interface{}{
						"childMgId":  mgId,
						"parentMgId": fullParentId,
					})
				}
			}
		}
	}

	if len(managementGroupHierarchy) == 0 {
		message.Info("No management group hierarchy relationships found")
		return 0
	}

	// Create the CONTAINS edges from parent management groups to child management groups
	cypher := `
		UNWIND $relationships as rel
		MATCH (parentMg:Resource)
		WHERE parentMg.resourceType = "Microsoft.Management/managementGroups"
		AND parentMg.id = rel.parentMgId
		MATCH (childMg:Resource)
		WHERE childMg.resourceType = "Microsoft.Management/managementGroups"
		AND childMg.id = rel.childMgId
		MERGE (parentMg)-[:CONTAINS]->(childMg)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{
			"relationships": managementGroupHierarchy,
		})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating management group hierarchy CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		message.Info("Created management group hierarchy CONTAINS edges", "count", int(edgesCreated))
		return int(edgesCreated)
	}

	return 0
}

// createManagementGroupToSubscriptionContains creates CONTAINS edges from Management Groups to Subscriptions
func (l *Neo4jImporterLink) createManagementGroupToSubscriptionContains(session neo4j.SessionWithContext, ctx context.Context) int {
	// The management_groups array contains both management groups AND subscriptions
	// Subscriptions in this array have a ParentId pointing to their management group
	managementGroups := l.getArrayValue(l.consolidatedData, "management_groups")
	if len(managementGroups) == 0 {
		return 0
	}

	totalEdges := 0

	for _, item := range managementGroups {
		if itemMap, ok := item.(map[string]interface{}); ok {
			itemType := l.getStringValue(itemMap, "type")
			itemName := l.getStringValue(itemMap, "name")
			parentId := l.getStringValue(itemMap, "ParentId")

			// Look for subscriptions that have a management group as parent
			if itemType == "microsoft.resources/subscriptions" && itemName != "" && parentId != "" {
				// Extract management group ID from parent path
				// ParentId format: "/providers/Microsoft.Management/managementGroups/{mgId}" OR just "{mgId}"
				var parentMgId string
				if strings.Contains(parentId, "/providers/Microsoft.Management/managementGroups/") {
					parts := strings.Split(parentId, "/")
					if len(parts) > 0 {
						parentMgId = parts[len(parts)-1]
					}
				} else {
					parentMgId = parentId
				}

				if parentMgId != "" {
					cypher := `
						MATCH (mg:Resource)
						WHERE mg.resourceType = "Microsoft.Management/managementGroups"
						AND mg.id = "/providers/Microsoft.Management/managementGroups/" + $mgId
						MATCH (subscription:Resource {id: "/subscriptions/" + $subscriptionId})
						WHERE subscription.resourceType = "Microsoft.Resources/subscriptions"
						MERGE (mg)-[:CONTAINS]->(subscription)
					`

					result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
						result, err := tx.Run(ctx, cypher, map[string]interface{}{
							"mgId":          parentMgId,
							"subscriptionId": itemName,
						})
						if err != nil {
							return nil, err
						}

						summary, err := result.Consume(ctx)
						if err != nil {
							return nil, err
						}

						return summary.Counters().RelationshipsCreated(), nil
					})

					if err != nil {
						l.Logger.Warn("Error creating management group-subscription CONTAINS edge", "mgId", parentMgId, "subscriptionId", itemName, "error", err)
					} else if edgesCreated, ok := l.convertToInt64(result); ok {
						totalEdges += int(edgesCreated)
					}
				}
			}
		}
	}

	return totalEdges
}

// createTenantToOrphanSubscriptionContains creates CONTAINS edges from Tenant to subscriptions not in Management Groups
func (l *Neo4jImporterLink) createTenantToOrphanSubscriptionContains(session neo4j.SessionWithContext, ctx context.Context) int {
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	tenantID := l.getStringValue(metadata, "tenant_id")

	if tenantID == "" {
		l.Logger.Warn("No tenant ID found for tenant-orphan subscription relationships")
		return 0
	}

	// Get list of subscriptions that are in management groups
	managementGroups := l.getArrayValue(l.consolidatedData, "management_groups")
	subscriptionsInMGs := make(map[string]bool)

	for _, item := range managementGroups {
		if itemMap, ok := item.(map[string]interface{}); ok {
			itemType := l.getStringValue(itemMap, "type")
			itemName := l.getStringValue(itemMap, "name")
			parentId := l.getStringValue(itemMap, "ParentId")

			// If it's a subscription with a management group parent, mark it as "in MG"
			if itemType == "microsoft.resources/subscriptions" && itemName != "" && parentId != "" {
				// Check if parent is a management group (not the tenant root)
				if strings.Contains(parentId, "/providers/Microsoft.Management/managementGroups/") {
					subscriptionsInMGs[itemName] = true
				}
			}
		}
	}

	// Connect root management group to subscriptions that are NOT in any child management group
	cypher := `
		MATCH (rootMg:Resource)
		WHERE rootMg.resourceType = "Microsoft.Management/managementGroups"
		AND rootMg.id = "/providers/Microsoft.Management/managementGroups/" + $tenantId
		MATCH (subscription:Resource)
		WHERE subscription.resourceType = "Microsoft.Resources/subscriptions"
		AND LAST(SPLIT(subscription.id, "/")) IN $orphanSubscriptions
		MERGE (rootMg)-[:CONTAINS]->(subscription)
	`

	// Get all subscriptions and filter out those in management groups
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	orphanSubscriptions := make([]string, 0)

	if azureResources != nil {
		for subscriptionId := range azureResources {
			if !subscriptionsInMGs[subscriptionId] {
				orphanSubscriptions = append(orphanSubscriptions, subscriptionId)
			}
		}
	}

	if len(orphanSubscriptions) == 0 {
		return 0
	}

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{
			"tenantId":           tenantID,
			"orphanSubscriptions": orphanSubscriptions,
		})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating tenant-orphan subscription CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createSubscriptionToResourceGroupContains creates CONTAINS edges from Subscriptions to Resource Groups
func (l *Neo4jImporterLink) createSubscriptionToResourceGroupContains(session neo4j.SessionWithContext, ctx context.Context) int {
	cypher := `
		MATCH (subscription:Resource)
		WHERE subscription.resourceType = "Microsoft.Resources/subscriptions"
		MATCH (rg:Resource)
		WHERE rg.resourceType = "Microsoft.Resources/resourceGroups"
		AND rg.id STARTS WITH subscription.id + "/resourceGroups/"
		MERGE (subscription)-[:CONTAINS]->(rg)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating subscription-resource group CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createResourceGroupToResourceContains creates CONTAINS edges from Resource Groups to Resources
func (l *Neo4jImporterLink) createResourceGroupToResourceContains(session neo4j.SessionWithContext, ctx context.Context) int {
	cypher := `
		MATCH (rg:Resource)
		WHERE rg.resourceType = "Microsoft.Resources/resourceGroups"
		MATCH (resource:Resource)
		WHERE toLower(resource.resourceType) STARTS WITH "microsoft."
		AND resource.resourceType <> "Microsoft.Resources/subscriptions"
		AND resource.resourceType <> "Microsoft.Resources/resourceGroups"
		AND resource.resourceType <> "Microsoft.DirectoryServices/tenant"
		AND resource.resourceGroup IS NOT NULL
		AND toLower(resource.resourceGroup) = toLower(rg.displayName)
		MERGE (rg)-[:CONTAINS]->(resource)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating resource group-resource CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createManagedIdentityToServicePrincipalContains creates CONTAINS edges from Managed Identity resources to their Service Principals
func (l *Neo4jImporterLink) createManagedIdentityToServicePrincipalContains(session neo4j.SessionWithContext, ctx context.Context) int {
	// Debug: Check what managed identity resources exist
	debugCypher := `
		MATCH (mi:Resource)
		WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
		RETURN mi.displayName, mi.principalId, mi.resourceType
	`

	debugResult, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, debugCypher, nil)
		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)
		if err != nil {
			return nil, err
		}

		return records, nil
	})

	if err == nil {
		if records, ok := debugResult.([]*neo4j.Record); ok {
			l.Logger.Debug("Found managed identity resources", "count", len(records))
			for _, record := range records {
				displayName, _ := record.Get("mi.displayName")
				principalId, _ := record.Get("mi.principalId")
				resourceType, _ := record.Get("mi.resourceType")
				l.Logger.Debug("Managed identity details", "displayName", displayName, "principalId", principalId, "resourceType", resourceType)
			}
		}
	}

	cypher := `
		MATCH (mi:Resource)
		WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
		AND mi.principalId IS NOT NULL
		MATCH (sp:Resource {id: mi.principalId})
		WHERE sp.resourceType = "Microsoft.DirectoryServices/servicePrincipals"
		MERGE (mi)-[:CONTAINS]->(sp)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating managed identity-service principal CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createGroupMemberContains creates CONTAINS edges from Groups to their Members
func (l *Neo4jImporterLink) createGroupMemberContains(session neo4j.SessionWithContext, ctx context.Context) int {
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	groupMemberships := l.getArrayValue(azureAD, "groupMemberships")

	if len(groupMemberships) == 0 {
		l.Logger.Info("No group memberships found")
		return 0
	}

	// Build relationships data
	relationships := make([]map[string]interface{}, 0)
	for _, membership := range groupMemberships {
		if membershipMap, ok := membership.(map[string]interface{}); ok {
			groupId := l.getStringValue(membershipMap, "groupId")
			memberId := l.getStringValue(membershipMap, "memberId")

			if groupId != "" && memberId != "" {
				relationships = append(relationships, map[string]interface{}{
					"groupId":  groupId,
					"memberId": memberId,
				})
			}
		}
	}

	if len(relationships) == 0 {
		return 0
	}

	cypher := `
		UNWIND $relationships AS rel
		MATCH (group:Resource {id: rel.groupId})
		MATCH (member:Resource {id: rel.memberId})
		MERGE (group)-[:CONTAINS]->(member)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"relationships": relationships})
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating group membership CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createApplicationToServicePrincipalContains creates CONTAINS edges from Applications to Service Principals
func (l *Neo4jImporterLink) createApplicationToServicePrincipalContains(session neo4j.SessionWithContext, ctx context.Context) int {
	cypher := `
		MATCH (app:Resource)
		WHERE app.resourceType = "Microsoft.DirectoryServices/applications"
		MATCH (sp:Resource)
		WHERE sp.resourceType = "Microsoft.DirectoryServices/servicePrincipals"
		AND app.appId = sp.appId
		MERGE (app)-[:CONTAINS]->(sp)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}

		return summary.Counters().RelationshipsCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating application-service principal CONTAINS edges", "error", err)
		return 0
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		return int(edgesCreated)
	}

	return 0
}

// createPermissionEdges creates HAS_PERMISSION edges for Entra ID directory role assignments
func (l *Neo4jImporterLink) createPermissionEdges() bool {
	message.Info("Creating HAS_PERMISSION edges for both Entra ID and Azure RBAC permissions...")

	// Store initial edge count
	initialEdgeCount := l.edgeCounts["HAS_PERMISSION"]

	// Process Entra ID permissions (existing logic)
	entraIDEdgesCreated := l.createEntraIDPermissionEdges()
	entraIDEdgeCount := 0
	if entraIDEdgesCreated {
		entraIDEdgeCount = l.edgeCounts["HAS_PERMISSION"] - initialEdgeCount
	}

	// Process Azure RBAC permissions (new logic)
	rbacEdgesCreated := l.createRBACPermissionEdges()
	rbacEdgeCount := 0
	if rbacEdgesCreated {
		rbacEdgeCount = l.edgeCounts["HAS_PERMISSION"] - initialEdgeCount - entraIDEdgeCount
	}

	// Update final total edge count
	totalEdgesCreated := entraIDEdgeCount + rbacEdgeCount
	l.edgeCounts["HAS_PERMISSION"] = initialEdgeCount + totalEdgesCreated

	success := entraIDEdgesCreated || rbacEdgesCreated
	if success {
		message.Info("✅ Permission edge creation completed successfully!")
		message.Info("📊 Summary: %d Entra ID edges + %d RBAC edges = %d total HAS_PERMISSION edges", entraIDEdgeCount, rbacEdgeCount, totalEdgesCreated)
	} else {
		message.Info("⚠️  No permission edges were created")
	}

	return success
}

// createEntraIDPermissionEdges creates HAS_PERMISSION edges for Entra ID directory role assignments
func (l *Neo4jImporterLink) createEntraIDPermissionEdges() bool {
	message.Info("Creating HAS_PERMISSION edges for Entra ID roles...")

	// Get Azure AD data
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	if azureAD == nil {
		message.Info("No azure_ad data found")
		return false
	}

	// Get directory role assignments from Entra ID
	directoryRoleAssignments := l.getArrayValue(azureAD, "directoryRoleAssignments")

	if len(directoryRoleAssignments) == 0 {
		message.Info("No Entra ID directory role assignments found")
		return false
	}

	message.Info("Processing %d Entra ID directory role assignments", len(directoryRoleAssignments))

	// Process directory role assignments
	var permissions []map[string]interface{}

	for _, assignment := range directoryRoleAssignments {
		assignmentMap, ok := assignment.(map[string]interface{})
		if !ok {
			continue
		}

		principalId := l.getStringValue(assignmentMap, "principalId")
		roleId := l.getStringValue(assignmentMap, "roleId")
		roleName := l.getStringValue(assignmentMap, "roleName")
		roleTemplateId := l.getStringValue(assignmentMap, "roleTemplateId")
		principalType := l.getStringValue(assignmentMap, "principalType")

		if principalId == "" || roleId == "" || roleName == "" {
			continue
		}

		// Expand role to individual permissions using roleTemplateId
		expandedPermissions := l.expandRoleToPermissions(roleTemplateId)

		// Only process if we have expanded permissions (requires roleDefinitions data)
		if len(expandedPermissions) > 0 {
			l.Logger.Debug("Found expanded permissions", "roleName", roleName, "permissionCount", len(expandedPermissions))
			// Create edges for each dangerous permission
			for _, permission := range expandedPermissions {
				if l.isDangerousEntraPermission(permission) {
					l.Logger.Debug("Found dangerous Entra permission", "roleName", roleName, "permission", permission, "principalId", principalId)
					permissions = append(permissions, map[string]interface{}{
						"principalId":   principalId,
						"permission":    permission,
						"scope":         "/",  // Entra ID roles are tenant-scoped
						"roleId":        roleId,
						"roleName":      roleName,
						"principalType": principalType,
						"source":        "Entra ID",
					})
				}
			}
		} else {
			l.Logger.Debug("No expanded permissions found - skipping role assignment", "roleName", roleName, "roleTemplateId", roleTemplateId)
		}
	}

	if len(permissions) == 0 {
		message.Info("No dangerous Entra ID permissions found")
		return false
	}

	message.Info("Found %d dangerous Entra ID permissions", len(permissions))

	// Process in batches
	batchSize := 10000
	totalEdgesCreated := 0

	for i := 0; i < len(permissions); i += batchSize {
		end := i + batchSize
		if end > len(permissions) {
			end = len(permissions)
		}

		batch := permissions[i:end]

		cypher := `
		UNWIND $permissions AS perm
		WITH perm
		WHERE perm.principalId IS NOT NULL AND perm.permission IS NOT NULL
		MATCH (principal:Resource {id: perm.principalId})
		MATCH (tenant:Resource {resourceType: "Microsoft.DirectoryServices/tenant"})
		CREATE (principal)-[r:HAS_PERMISSION]->(tenant)
		SET r.roleId = perm.roleId,
			r.permission = perm.permission,
			r.roleName = perm.roleName,
			r.principalType = perm.principalType,
			r.source = perm.source,
			r.createdAt = datetime()
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"permissions": batch})
			if err != nil {
				return nil, err
			}

			summary, err := result.Consume(ctx)
			if err != nil {
				return nil, err
			}

			return summary.Counters().RelationshipsCreated(), nil
		})

		session.Close(ctx)

		if err != nil {
			l.Logger.Error("Error creating Entra ID HAS_PERMISSION edges for batch", "error", err, "batch", i/batchSize+1)
			continue
		}

		if edgesCreated, ok := l.convertToInt64(result); ok {
			totalEdgesCreated += int(edgesCreated)
			message.Info("Batch %d/%d: Created %d Entra ID HAS_PERMISSION edges", i/batchSize+1, (len(permissions)+batchSize-1)/batchSize, edgesCreated)
		}
	}

	l.edgeCounts["HAS_PERMISSION"] = totalEdgesCreated
	message.Info("Created %d total Entra ID HAS_PERMISSION edges", totalEdgesCreated)

	return totalEdgesCreated > 0
}

// createRBACPermissionEdges creates HAS_PERMISSION edges for Azure RBAC role assignments
func (l *Neo4jImporterLink) createRBACPermissionEdges() bool {
	message.Info("Creating HAS_PERMISSION edges for Azure RBAC roles...")

	// Get Azure resources data
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources == nil {
		message.Info("No azure_resources data found")
		return false
	}

	// Process RBAC assignments by scope (no flattening - maintain hierarchy)
	var permissions []map[string]interface{}
	totalAssignments := 0

	for subscriptionId, subscriptionData := range azureResources {
		if subData, ok := subscriptionData.(map[string]interface{}); ok {
			// Process each scope type separately to create edges only at granted level

			// Process subscription-level RBAC assignments
			if subRBACAssignments := l.getArrayValue(subData, "subscriptionRoleAssignments"); len(subRBACAssignments) > 0 {
				scopePermissions := l.processScopedRBACAssignments(subRBACAssignments, "subscription")
				permissions = append(permissions, scopePermissions...)
				totalAssignments += len(subRBACAssignments)
				l.Logger.Debug("Found subscription RBAC assignments", "subscriptionId", subscriptionId, "count", len(subRBACAssignments))
			}

			// Process resource group-level RBAC assignments
			if rgRBACAssignments := l.getArrayValue(subData, "resourceGroupRoleAssignments"); len(rgRBACAssignments) > 0 {
				scopePermissions := l.processScopedRBACAssignments(rgRBACAssignments, "resourceGroup")
				permissions = append(permissions, scopePermissions...)
				totalAssignments += len(rgRBACAssignments)
				l.Logger.Debug("Found resource group RBAC assignments", "subscriptionId", subscriptionId, "count", len(rgRBACAssignments))
			}

			// Process resource-level RBAC assignments
			if resourceRBACAssignments := l.getArrayValue(subData, "resourceLevelRoleAssignments"); len(resourceRBACAssignments) > 0 {
				scopePermissions := l.processScopedRBACAssignments(resourceRBACAssignments, "resource")
				permissions = append(permissions, scopePermissions...)
				totalAssignments += len(resourceRBACAssignments)
				l.Logger.Debug("Found resource-level RBAC assignments", "subscriptionId", subscriptionId, "count", len(resourceRBACAssignments))
			}

			// Process management group-level RBAC assignments
			if mgRBACAssignments := l.getArrayValue(subData, "managementGroupRoleAssignments"); len(mgRBACAssignments) > 0 {
				scopePermissions := l.processScopedRBACAssignments(mgRBACAssignments, "managementGroup")
				permissions = append(permissions, scopePermissions...)
				totalAssignments += len(mgRBACAssignments)
				l.Logger.Debug("Found management group RBAC assignments", "subscriptionId", subscriptionId, "count", len(mgRBACAssignments))
			}

			// Process tenant-level RBAC assignments
			if tenantRBACAssignments := l.getArrayValue(subData, "tenantRoleAssignments"); len(tenantRBACAssignments) > 0 {
				scopePermissions := l.processScopedRBACAssignments(tenantRBACAssignments, "tenant")
				permissions = append(permissions, scopePermissions...)
				totalAssignments += len(tenantRBACAssignments)
				l.Logger.Debug("Found tenant-level RBAC assignments", "subscriptionId", subscriptionId, "count", len(tenantRBACAssignments))
			}
		}
	}

	if totalAssignments == 0 {
		message.Info("No Azure RBAC role assignments found")
		return false
	}

	message.Info("Found %d dangerous Azure RBAC permissions", len(permissions))

	if len(permissions) == 0 {
		message.Info("No dangerous Azure RBAC permissions found")
		return false
	}

	message.Info("Found %d dangerous Azure RBAC permissions", len(permissions))

	// Process in batches (same as Entra ID)
	batchSize := 10000
	totalEdgesCreated := 0

	for i := 0; i < len(permissions); i += batchSize {
		end := i + batchSize
		if end > len(permissions) {
			end = len(permissions)
		}

		batch := permissions[i:end]

		cypher := `
		UNWIND $permissions AS perm
		WITH perm
		WHERE perm.principalId IS NOT NULL AND perm.permission IS NOT NULL AND perm.targetResourceId IS NOT NULL
		MATCH (principal:Resource {id: perm.principalId})
		MATCH (target:Resource {id: perm.targetResourceId})
		CREATE (principal)-[r:HAS_PERMISSION]->(target)
		SET r.roleDefinitionId = perm.roleDefinitionId,
			r.permission = perm.permission,
			r.principalType = perm.principalType,
			r.source = perm.source,
			r.grantedAt = perm.grantedAt,
			r.targetResourceType = perm.targetResourceType,
			r.createdAt = datetime()
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"permissions": batch})
			if err != nil {
				return nil, err
			}

			summary, err := result.Consume(ctx)
			if err != nil {
				return nil, err
			}

			return summary.Counters().RelationshipsCreated(), nil
		})

		session.Close(ctx)

		if err != nil {
			l.Logger.Error("Error creating RBAC HAS_PERMISSION edges for batch", "error", err, "batch", i/batchSize+1)
			continue
		}

		if edgesCreated, ok := l.convertToInt64(result); ok {
			totalEdgesCreated += int(edgesCreated)
			message.Info("Batch %d/%d: Created %d RBAC HAS_PERMISSION edges", i/batchSize+1, (len(permissions)+batchSize-1)/batchSize, edgesCreated)
		}
	}

	// Add RBAC edges to the existing HAS_PERMISSION count
	currentCount := l.edgeCounts["HAS_PERMISSION"]
	l.edgeCounts["HAS_PERMISSION"] = currentCount + totalEdgesCreated

	message.Info("Created %d total RBAC HAS_PERMISSION edges", totalEdgesCreated)
	return totalEdgesCreated > 0
}

// buildRoleDefinitionsCache builds a cache of role definitions mapped by templateId/roleDefinitionId for permission expansion
func (l *Neo4jImporterLink) buildRoleDefinitionsCache() error {
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	if azureAD == nil {
		l.Logger.Error("No azure_ad data found for roleDefinitions cache")
		return fmt.Errorf("❌ No azure_ad section found - cannot perform permission analysis\n💡 Run 'iam-pull' to collect Azure AD data including roleDefinitions")
	}

	// Cache Entra ID role definitions (existing logic)
	entaaRoleDefinitions := l.getArrayValue(azureAD, "roleDefinitions")
	if len(entaaRoleDefinitions) == 0 {
		l.Logger.Error("No roleDefinitions found in data")
		return fmt.Errorf("❌ No roleDefinitions found in azure_ad data - permission analysis requires roleDefinitions\n💡 Run 'iam-pull' again to collect roleDefinitions with the updated collector")
	}

	for _, roleDef := range entaaRoleDefinitions {
		if roleDefMap, ok := roleDef.(map[string]interface{}); ok {
			templateId := l.getStringValue(roleDefMap, "templateId")
			if templateId != "" {
				l.roleDefinitionsMap[templateId] = roleDefMap
			}
		}
	}

	// Cache Azure RBAC role definitions (new)
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources != nil {
		rbacRoleCount := 0
		for _, subscriptionData := range azureResources {
			if subData, ok := subscriptionData.(map[string]interface{}); ok {
				rbacRoleDefinitions := l.getArrayValue(subData, "azureRoleDefinitions")
				for _, roleDef := range rbacRoleDefinitions {
					if roleDefMap, ok := roleDef.(map[string]interface{}); ok {
						roleDefinitionId := l.getStringValue(roleDefMap, "id") // RBAC uses "id" field as full path ID
						if roleDefinitionId != "" {
							l.roleDefinitionsMap[roleDefinitionId] = roleDefMap
							rbacRoleCount++
						}
					}
				}
			}
		}
		l.Logger.Info("Cached %d Azure RBAC role definitions", rbacRoleCount)
	}

	message.Info("Built roleDefinitions cache with %d total role definitions", len(l.roleDefinitionsMap))
	return nil
}

// expandRoleToPermissions expands a role definition to its individual permissions
func (l *Neo4jImporterLink) expandRoleToPermissions(roleTemplateId string) []string {
	var permissions []string

	// Look up role definition by templateId
	roleDef, exists := l.roleDefinitionsMap[roleTemplateId]
	if !exists {
		l.Logger.Debug("Role definition not found", "templateId", roleTemplateId)
		return permissions
	}

	roleDefMap, ok := roleDef.(map[string]interface{})
	if !ok {
		l.Logger.Debug("Invalid role definition format", "templateId", roleTemplateId)
		return permissions
	}

	// Extract rolePermissions array
	rolePermissions := l.getArrayValue(roleDefMap, "rolePermissions")
	for _, permSet := range rolePermissions {
		if permSetMap, ok := permSet.(map[string]interface{}); ok {
			// Get allowedResourceActions array
			actions := l.getArrayValue(permSetMap, "allowedResourceActions")
			for _, action := range actions {
				if actionStr, ok := action.(string); ok {
					permissions = append(permissions, actionStr)
				}
			}
		}
	}

	l.Logger.Debug("Expanded role to permissions", "templateId", roleTemplateId, "permissionCount", len(permissions))
	return permissions
}

// expandRBACRoleToPermissions expands an RBAC role definition to its individual permissions
func (l *Neo4jImporterLink) expandRBACRoleToPermissions(roleDefinitionId string) []string {
	var permissions []string

	l.Logger.Debug("Attempting to expand RBAC role", "roleDefinitionId", roleDefinitionId)

	// Look up role definition by roleDefinitionId
	roleDef, exists := l.roleDefinitionsMap[roleDefinitionId]
	if !exists {
		l.Logger.Debug("RBAC role definition not found", "roleDefinitionId", roleDefinitionId)
		return permissions
	}

	l.Logger.Debug("Found RBAC role definition", "roleDefinitionId", roleDefinitionId)

	roleDefMap, ok := roleDef.(map[string]interface{})
	if !ok {
		l.Logger.Debug("Invalid RBAC role definition format", "roleDefinitionId", roleDefinitionId)
		return permissions
	}

	// Handle both SDK collector format (direct permissions array) and legacy Azure REST API format (properties.permissions)
	var rbacPermissions []interface{}

	// Try SDK collector format first: permissions[] directly on role definition
	if directPermissions := l.getArrayValue(roleDefMap, "permissions"); len(directPermissions) > 0 {
		l.Logger.Debug("Using SDK collector format for RBAC permissions", "roleDefinitionId", roleDefinitionId)
		rbacPermissions = directPermissions
	} else {
		// Fallback to Azure REST API format: properties.permissions[]
		l.Logger.Debug("Using Azure REST API format for RBAC permissions", "roleDefinitionId", roleDefinitionId)
		properties := l.getMapValue(roleDefMap, "properties")
		if properties == nil {
			l.Logger.Debug("No properties found in RBAC role definition", "roleDefinitionId", roleDefinitionId)
			return permissions
		}
		rbacPermissions = l.getArrayValue(properties, "permissions")
	}

	// Process permissions array
	for _, permSet := range rbacPermissions {
		if permSetMap, ok := permSet.(map[string]interface{}); ok {
			// Get actions array (RBAC uses "actions" for both formats)
			actions := l.getArrayValue(permSetMap, "actions")
			l.Logger.Debug("Processing RBAC permission set", "roleDefinitionId", roleDefinitionId, "actionCount", len(actions))
			for _, action := range actions {
				if actionStr, ok := action.(string); ok {
					permissions = append(permissions, actionStr)
					l.Logger.Debug("Found RBAC action", "roleDefinitionId", roleDefinitionId, "action", actionStr)
				}
			}
		}
	}

	l.Logger.Debug("Expanded RBAC role to permissions", "roleDefinitionId", roleDefinitionId, "permissionCount", len(permissions))
	if len(permissions) > 0 {
		l.Logger.Debug("Sample RBAC permissions", "roleDefinitionId", roleDefinitionId, "first5Permissions", l.getSamplePermissions(permissions, 5))
	}
	return permissions
}

// getSamplePermissions returns first n permissions for debugging
func (l *Neo4jImporterLink) getSamplePermissions(permissions []string, n int) []string {
	if len(permissions) <= n {
		return permissions
	}
	return permissions[:n]
}

// isDangerousPermission checks if a permission is considered dangerous/interesting for security analysis
func (l *Neo4jImporterLink) isDangerousPermission(permission string) bool {
	// Define dangerous Entra ID permissions
	entraDangerousPermissions := map[string]bool{
		// Critical write permissions
		"microsoft.directory/users/password/update":                       true,
		"microsoft.directory/users/userPrincipalName/update":              true,
		"microsoft.directory/users/allProperties/allTasks":                true,  // MISSING - Global Admin has this
		"microsoft.directory/applications/credentials/update":             true,
		"microsoft.directory/applications/allProperties/allTasks":         true,  // MISSING - Global Admin has this
		"microsoft.directory/servicePrincipals/credentials/update":        true,
		"microsoft.directory/servicePrincipals/allProperties/allTasks":    true,  // MISSING - Global Admin has this
		"microsoft.directory/domains/federation/update":                   true,

		// Role management
		"microsoft.directory/roles/allProperties/allTasks":                true,
		"microsoft.directory/roleAssignments/allProperties/allTasks":      true,
		"microsoft.directory/directoryRoles/allProperties/allTasks":       true,

		// Group management
		"microsoft.directory/groups/members/update":                       true,
		"microsoft.directory/groups/owners/update":                        true,
		"microsoft.directory/groups/allProperties/allTasks":               true,

		// Conditional access
		"microsoft.directory/conditionalAccessPolicies/create":            true,
		"microsoft.directory/conditionalAccessPolicies/delete":            true,
		"microsoft.directory/conditionalAccessPolicies/basic/update":      true,
		"microsoft.directory/conditionalAccessPolicies/allProperties/allTasks": true,

		// Identity providers and authentication
		"microsoft.directory/identityProviders/allProperties/allTasks":    true,
		"microsoft.directory/authenticationMethods/allProperties/allTasks": true,

		// Administrative units
		"microsoft.directory/administrativeUnits/allProperties/allTasks":  true,
		"microsoft.directory/administrativeUnits/members/update":          true,
	}

	// Define dangerous RBAC permissions
	rbacDangerousPermissions := map[string]bool{
		// Identity & Access Management - High Priority
		"Microsoft.Authorization/roleAssignments/write":                   true, // Can grant RBAC permissions
		"Microsoft.Authorization/roleAssignments/delete":                  true, // Can remove RBAC permissions
		"Microsoft.Authorization/roleDefinitions/write":                   true, // Can create custom roles
		"Microsoft.Authorization/roleDefinitions/delete":                  true, // Can delete role definitions
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true, // Can modify managed identities
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true, // Can assign managed identities

		// Compute - Direct System Access
		"Microsoft.Compute/virtualMachines/write":                         true, // Can modify VMs
		"Microsoft.Compute/virtualMachines/runCommand/action":             true, // Can execute commands on VMs
		"Microsoft.Compute/virtualMachines/extensions/write":              true, // Can install VM extensions
		"Microsoft.Compute/virtualMachines/restart/action":                true, // Can restart VMs
		"Microsoft.Compute/virtualMachines/start/action":                  true, // Can start VMs
		"Microsoft.Compute/virtualMachineScaleSets/write":                 true, // Can modify VMSS
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":      true, // Can install VMSS extensions

		// Storage - Data Access
		"Microsoft.Storage/storageAccounts/write":                         true, // Can modify storage accounts
		"Microsoft.Storage/storageAccounts/listKeys/action":               true, // Can list storage keys
		"Microsoft.Storage/storageAccounts/regeneratekey/action":          true, // Can regenerate storage keys
		"Microsoft.Storage/storageAccounts/blobServices/containers/write": true, // Can modify containers
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true, // Can generate delegation keys

		// Key Vault - Secrets Access
		"Microsoft.KeyVault/vaults/write":                                 true, // Can modify Key Vault
		"Microsoft.KeyVault/vaults/delete":                                true, // Can delete Key Vault
		"Microsoft.KeyVault/vaults/secrets/write":                         true, // Can write secrets
		"Microsoft.KeyVault/vaults/secrets/delete":                        true, // Can delete secrets
		"Microsoft.KeyVault/vaults/keys/write":                            true, // Can write keys
		"Microsoft.KeyVault/vaults/keys/delete":                           true, // Can delete keys
		"Microsoft.KeyVault/vaults/certificates/write":                    true, // Can write certificates
		"Microsoft.KeyVault/vaults/accessPolicies/write":                  true, // Can modify access policies

		// Database Access
		"Microsoft.Sql/servers/write":                                     true, // Can modify SQL servers
		"Microsoft.Sql/servers/databases/write":                           true, // Can modify databases
		"Microsoft.Sql/servers/firewallRules/write":                       true, // Can modify firewall rules
		"Microsoft.Sql/servers/administrators/write":                      true, // Can modify administrators
		"Microsoft.DocumentDB/databaseAccounts/write":                     true, // Can modify Cosmos DB
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":           true, // Can list Cosmos DB keys

		// Networking - Security Controls
		"Microsoft.Network/networkSecurityGroups/write":                   true, // Can modify NSGs
		"Microsoft.Network/networkSecurityGroups/securityRules/write":     true, // Can modify NSG rules
		"Microsoft.Network/routeTables/write":                             true, // Can modify route tables
		"Microsoft.Network/routeTables/routes/write":                      true, // Can modify routes
		"Microsoft.Network/virtualNetworks/write":                         true, // Can modify VNets
		"Microsoft.Network/publicIPAddresses/write":                       true, // Can modify public IPs
		"Microsoft.Network/azureFirewalls/write":                          true, // Can modify Azure Firewall
		"Microsoft.Network/applicationGateways/write":                     true, // Can modify App Gateway

		// Container & Kubernetes
		"Microsoft.ContainerService/managedClusters/write":                true, // Can modify AKS clusters
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true, // Can get AKS credentials
		"Microsoft.ContainerRegistry/registries/write":                    true, // Can modify ACR
		"Microsoft.ContainerRegistry/registries/artifacts/delete":         true, // Can delete container images

		// Resource Management
		"Microsoft.Resources/subscriptions/write":                         true, // Can modify subscriptions
		"Microsoft.Resources/subscriptions/resourceGroups/write":          true, // Can modify resource groups
		"Microsoft.Resources/deployments/write":                           true, // Can deploy ARM templates
		"Microsoft.Resources/deployments/delete":                          true, // Can delete deployments

		// Privileged Operations
		"Microsoft.Automation/automationAccounts/write":                   true, // Can modify automation accounts
		"Microsoft.Automation/automationAccounts/runbooks/write":          true, // Can modify runbooks
		"Microsoft.Logic/workflows/write":                                 true, // Can modify logic apps
		"Microsoft.Web/sites/write":                                       true, // Can modify web apps
		"Microsoft.Web/sites/config/write":                                true, // Can modify web app config
		"Microsoft.Web/sites/functions/write":                             true, // Can modify functions
	}

	// Check both Entra ID and RBAC dangerous permissions
	return entraDangerousPermissions[permission] || rbacDangerousPermissions[permission]
}

// isDangerousEntraPermission checks if an Entra ID permission is considered dangerous
func (l *Neo4jImporterLink) isDangerousEntraPermission(permission string) bool {
	// Define dangerous Entra ID permissions
	entraDangerousPermissions := map[string]bool{
		// Critical write permissions
		"microsoft.directory/users/password/update":                       true,
		"microsoft.directory/users/userPrincipalName/update":              true,
		"microsoft.directory/users/allProperties/allTasks":                true,  // Global Admin has this
		"microsoft.directory/applications/credentials/update":             true,
		"microsoft.directory/applications/allProperties/allTasks":         true,  // Global Admin has this
		"microsoft.directory/servicePrincipals/credentials/update":        true,
		"microsoft.directory/servicePrincipals/allProperties/allTasks":    true,  // Global Admin has this
		"microsoft.directory/domains/federation/update":                   true,

		// Role management
		"microsoft.directory/roles/allProperties/allTasks":                true,
		"microsoft.directory/roleAssignments/allProperties/allTasks":      true,
		"microsoft.directory/directoryRoles/allProperties/allTasks":       true,

		// Group management
		"microsoft.directory/groups/allProperties/allTasks":               true,
		"microsoft.directory/groups/members/update":                       true,

		// Device management
		"microsoft.directory/devices/allProperties/allTasks":              true,
		"microsoft.directory/bitlockerKeys/key/read":                      true,

		// Conditional access
		"microsoft.directory/policies/conditionalAccess/allProperties/allTasks": true,

		// Administrative units
		"microsoft.directory/administrativeUnits/allProperties/allTasks":  true,
		"microsoft.directory/administrativeUnits/members/update":          true,
	}

	return entraDangerousPermissions[permission]
}

// isDangerousRBACPermission checks if an Azure RBAC permission is considered dangerous
func (l *Neo4jImporterLink) isDangerousRBACPermission(permission string) bool {
	l.Logger.Debug("Checking if RBAC permission is dangerous", "permission", permission)
	// Define dangerous RBAC permissions
	rbacDangerousPermissions := map[string]bool{
		// Identity & Access Management - High Priority
		"Microsoft.Authorization/roleAssignments/write":                   true, // Can grant RBAC permissions
		"Microsoft.Authorization/roleAssignments/delete":                  true, // Can remove RBAC permissions
		"Microsoft.Authorization/roleDefinitions/write":                   true, // Can create custom roles
		"Microsoft.Authorization/roleDefinitions/delete":                  true, // Can delete role definitions
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true, // Can modify managed identities
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true, // Can assign managed identities

		// Compute - Direct System Access
		"Microsoft.Compute/virtualMachines/write":                         true, // Can modify VMs
		"Microsoft.Compute/virtualMachines/runCommand/action":             true, // Can execute commands on VMs
		"Microsoft.Compute/virtualMachines/extensions/write":              true, // Can install VM extensions
		"Microsoft.Compute/virtualMachines/restart/action":                true, // Can restart VMs
		"Microsoft.Compute/virtualMachines/start/action":                  true, // Can start VMs
		"Microsoft.Compute/virtualMachineScaleSets/write":                 true, // Can modify VMSS
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":      true, // Can install VMSS extensions

		// Storage - Data Access
		"Microsoft.Storage/storageAccounts/write":                         true, // Can modify storage accounts
		"Microsoft.Storage/storageAccounts/listKeys/action":               true, // Can list storage keys
		"Microsoft.Storage/storageAccounts/regeneratekey/action":          true, // Can regenerate storage keys
		"Microsoft.Storage/storageAccounts/blobServices/containers/write": true, // Can modify containers
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true, // Can generate delegation keys

		// Key Vault - Secrets Access
		"Microsoft.KeyVault/vaults/write":                                 true, // Can modify Key Vault
		"Microsoft.KeyVault/vaults/delete":                                true, // Can delete Key Vault
		"Microsoft.KeyVault/vaults/secrets/write":                         true, // Can write secrets
		"Microsoft.KeyVault/vaults/secrets/delete":                        true, // Can delete secrets
		"Microsoft.KeyVault/vaults/keys/write":                            true, // Can write keys
		"Microsoft.KeyVault/vaults/keys/delete":                           true, // Can delete keys
		"Microsoft.KeyVault/vaults/certificates/write":                    true, // Can write certificates
		"Microsoft.KeyVault/vaults/accessPolicies/write":                  true, // Can modify access policies

		// Database Access
		"Microsoft.Sql/servers/write":                                     true, // Can modify SQL servers
		"Microsoft.Sql/servers/databases/write":                           true, // Can modify databases
		"Microsoft.Sql/servers/firewallRules/write":                       true, // Can modify firewall rules
		"Microsoft.Sql/servers/administrators/write":                      true, // Can modify administrators
		"Microsoft.DocumentDB/databaseAccounts/write":                     true, // Can modify Cosmos DB
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":           true, // Can list Cosmos DB keys

		// Networking - Security Controls
		"Microsoft.Network/networkSecurityGroups/write":                   true, // Can modify NSGs
		"Microsoft.Network/networkSecurityGroups/securityRules/write":     true, // Can modify NSG rules
		"Microsoft.Network/virtualNetworks/write":                         true, // Can modify VNets
		"Microsoft.Network/publicIPAddresses/write":                       true, // Can modify public IPs
		"Microsoft.Network/loadBalancers/write":                           true, // Can modify load balancers

		// Container Services
		"Microsoft.ContainerService/managedClusters/write":                true, // Can modify AKS clusters
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true, // Can get AKS credentials
		"Microsoft.ContainerRegistry/registries/write":                    true, // Can modify ACR
		"Microsoft.ContainerRegistry/registries/artifacts/delete":         true, // Can delete container images

		// Resource Management
		"Microsoft.Resources/subscriptions/write":                         true, // Can modify subscriptions
		"Microsoft.Resources/subscriptions/resourceGroups/write":          true, // Can modify resource groups
		"Microsoft.Resources/deployments/write":                           true, // Can deploy ARM templates
		"Microsoft.Resources/deployments/delete":                          true, // Can delete deployments

		// Privileged Operations
		"Microsoft.Automation/automationAccounts/write":                   true, // Can modify automation accounts
		"Microsoft.Automation/automationAccounts/runbooks/write":          true, // Can modify runbooks
		"Microsoft.Logic/workflows/write":                                 true, // Can modify logic apps
		"Microsoft.Web/sites/write":                                       true, // Can modify web apps
		"Microsoft.Web/sites/config/write":                                true, // Can modify web app config
		"Microsoft.Web/sites/functions/write":                             true, // Can modify functions
	}

	// Check exact matches first
	if rbacDangerousPermissions[permission] {
		l.Logger.Debug("RBAC permission matched exact dangerous permission", "permission", permission)
		return true
	}

	// Check if this wildcard permission covers any dangerous permissions
	if strings.Contains(permission, "*") {
		l.Logger.Debug("RBAC permission contains wildcard, checking matches", "permission", permission)
		matchCount := 0
		for dangerousPermission := range rbacDangerousPermissions {
			if l.matchesRBACWildcard(permission, dangerousPermission) {
				matchCount++
				l.Logger.Debug("RBAC wildcard covers dangerous permission",
					"pattern", permission, "dangerousPermission", dangerousPermission)
			}
		}
		if matchCount > 0 {
			l.Logger.Debug("RBAC wildcard permission is dangerous", "permission", permission, "matchedDangerousPermissions", matchCount)
			return true
		} else {
			l.Logger.Debug("RBAC wildcard permission matched no dangerous permissions", "permission", permission)
		}
	} else {
		l.Logger.Debug("RBAC permission contains no wildcards", "permission", permission)
	}

	l.Logger.Debug("RBAC permission is not dangerous", "permission", permission)
	return false
}

// expandRBACWildcardToDangerousPermissions expands a wildcard permission to all dangerous permissions it covers
func (l *Neo4jImporterLink) expandRBACWildcardToDangerousPermissions(permission string) []string {
	// Define dangerous RBAC permissions (same list as in isDangerousRBACPermission)
	rbacDangerousPermissions := map[string]bool{
		// Identity & Access Management - High Priority
		"Microsoft.Authorization/roleAssignments/write":                   true,
		"Microsoft.Authorization/roleAssignments/delete":                  true,
		"Microsoft.Authorization/roleDefinitions/write":                   true,
		"Microsoft.Authorization/roleDefinitions/delete":                  true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true,

		// Compute - Direct System Access
		"Microsoft.Compute/virtualMachines/write":                         true,
		"Microsoft.Compute/virtualMachines/runCommand/action":             true,
		"Microsoft.Compute/virtualMachines/extensions/write":              true,
		"Microsoft.Compute/virtualMachines/restart/action":                true,
		"Microsoft.Compute/virtualMachines/start/action":                  true,
		"Microsoft.Compute/virtualMachineScaleSets/write":                 true,
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":      true,

		// Storage - Data Access
		"Microsoft.Storage/storageAccounts/write":                         true,
		"Microsoft.Storage/storageAccounts/listKeys/action":               true,
		"Microsoft.Storage/storageAccounts/regeneratekey/action":          true,
		"Microsoft.Storage/storageAccounts/blobServices/containers/write": true,
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true,

		// Key Vault - Secrets Access
		"Microsoft.KeyVault/vaults/write":                                 true,
		"Microsoft.KeyVault/vaults/delete":                                true,
		"Microsoft.KeyVault/vaults/secrets/write":                         true,
		"Microsoft.KeyVault/vaults/secrets/delete":                        true,
		"Microsoft.KeyVault/vaults/keys/write":                            true,
		"Microsoft.KeyVault/vaults/keys/delete":                           true,
		"Microsoft.KeyVault/vaults/certificates/write":                    true,
		"Microsoft.KeyVault/vaults/accessPolicies/write":                  true,

		// Database Access
		"Microsoft.Sql/servers/write":                                     true,
		"Microsoft.Sql/servers/databases/write":                           true,
		"Microsoft.Sql/servers/firewallRules/write":                       true,
		"Microsoft.Sql/servers/administrators/write":                      true,
		"Microsoft.DocumentDB/databaseAccounts/write":                     true,
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":           true,

		// Networking - Security Controls
		"Microsoft.Network/networkSecurityGroups/write":                   true,
		"Microsoft.Network/networkSecurityGroups/securityRules/write":     true,
		"Microsoft.Network/virtualNetworks/write":                         true,
		"Microsoft.Network/publicIPAddresses/write":                       true,
		"Microsoft.Network/loadBalancers/write":                           true,

		// Container Services
		"Microsoft.ContainerService/managedClusters/write":                true,
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true,
		"Microsoft.ContainerRegistry/registries/write":                    true,
		"Microsoft.ContainerRegistry/registries/artifacts/delete":         true,

		// Resource Management
		"Microsoft.Resources/subscriptions/write":                         true,
		"Microsoft.Resources/subscriptions/resourceGroups/write":          true,
		"Microsoft.Resources/deployments/write":                           true,
		"Microsoft.Resources/deployments/delete":                          true,

		// Privileged Operations
		"Microsoft.Automation/automationAccounts/write":                   true,
		"Microsoft.Automation/automationAccounts/runbooks/write":          true,
		"Microsoft.Logic/workflows/write":                                 true,
		"Microsoft.Web/sites/write":                                       true,
		"Microsoft.Web/sites/config/write":                                true,
		"Microsoft.Web/sites/functions/write":                             true,
	}

	var result []string

	// Check if it's an exact match first
	if rbacDangerousPermissions[permission] {
		result = append(result, permission)
		return result
	}

	// If it contains wildcards, expand to matching dangerous permissions
	if strings.Contains(permission, "*") {
		for dangerousPermission := range rbacDangerousPermissions {
			if l.matchesRBACWildcard(permission, dangerousPermission) {
				result = append(result, dangerousPermission)
			}
		}
	}

	return result
}

// processScopedRBACAssignments processes RBAC assignments for a specific scope type and creates HAS_PERMISSION edges
func (l *Neo4jImporterLink) processScopedRBACAssignments(assignments []interface{}, scopeType string) []map[string]interface{} {
	var permissions []map[string]interface{}

	for _, assignment := range assignments {
		assignmentMap, ok := assignment.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract assignment properties - handle both SDK collector format (direct fields) and REST API format (properties wrapper)
		var principalId, roleDefinitionId, scope, principalType string

		// Check if this has direct fields (SDK collector format) or properties wrapper (REST API format)
		if directPrincipalId := l.getStringValue(assignmentMap, "principalId"); directPrincipalId != "" {
			// SDK collector format with direct fields
			principalId = directPrincipalId
			roleDefinitionId = l.getStringValue(assignmentMap, "roleDefinitionId")
			scope = l.getStringValue(assignmentMap, "scope")
			principalType = l.getStringValue(assignmentMap, "principalType")
		} else if properties := l.getMapValue(assignmentMap, "properties"); properties != nil {
			// Azure REST API format with properties wrapper
			principalId = l.getStringValue(properties, "principalId")
			roleDefinitionId = l.getStringValue(properties, "roleDefinitionId")
			scope = l.getStringValue(properties, "scope")
			principalType = l.getStringValue(properties, "principalType")
		} else {
			continue
		}

		if principalId == "" || roleDefinitionId == "" || scope == "" {
			continue
		}

		// Parse scope to identify target resource
		targetResourceType, targetResourceId := l.parseAssignmentScope(scope)
		if targetResourceType == "" || targetResourceId == "" {
			l.Logger.Debug("Could not parse assignment scope - skipping", "scope", scope)
			continue
		}

		// Expand RBAC role to individual permissions using roleDefinitionId
		expandedPermissions := l.expandRBACRoleToPermissions(roleDefinitionId)

		// Only process if we have expanded permissions
		if len(expandedPermissions) > 0 {
			l.Logger.Debug("Found expanded RBAC permissions", "roleDefinitionId", roleDefinitionId, "permissionCount", len(expandedPermissions), "scopeType", scopeType)
			// Create edges for each dangerous permission at the granted scope only
			for _, permission := range expandedPermissions {
				// Expand wildcards to specific dangerous permissions
				dangerousPerms := l.expandRBACWildcardToDangerousPermissions(permission)
				for _, dangPerm := range dangerousPerms {
					l.Logger.Debug("Found dangerous RBAC permission at granted scope", "roleDefinitionId", roleDefinitionId, "permission", dangPerm, "principalId", principalId, "targetResource", targetResourceId, "scopeType", scopeType)
					permissions = append(permissions, map[string]interface{}{
						"principalId":        principalId,
						"permission":         dangPerm,
						"targetResourceId":   targetResourceId,
						"targetResourceType": targetResourceType,
						"grantedAt":          scopeType,
						"roleDefinitionId":   roleDefinitionId,
						"principalType":      principalType,
						"source":             "Azure RBAC",
					})
				}
			}
		}
	}

	return permissions
}

// parseAssignmentScope parses an Azure RBAC assignment scope to determine the target resource
func (l *Neo4jImporterLink) parseAssignmentScope(scope string) (resourceType, resourceId string) {
	// Handle different Azure scope formats:
	// /subscriptions/{subscription-id}
	// /subscriptions/{subscription-id}/resourceGroups/{resource-group-name}
	// /subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{resource-provider}/{resource-type}/{resource-name}
	// /subscriptions/{subscription-id}/providers/{resource-provider}/{resource-type}/{resource-name}

	if scope == "" {
		return "", ""
	}

	// Split scope into parts, removing empty elements
	parts := make([]string, 0)
	for _, part := range strings.Split(scope, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}

	if len(parts) < 2 {
		return "", ""
	}

	// Check if it's a subscription-level scope
	if len(parts) == 2 && parts[0] == "subscriptions" {
		return "Subscription", parts[1]
	}

	// Check if it's a resource group-level scope
	if len(parts) == 4 && parts[0] == "subscriptions" && parts[2] == "resourceGroups" {
		// For resource groups, we need to construct the resource ID
		subscriptionId := parts[1]
		resourceGroupName := parts[3]
		resourceId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionId, resourceGroupName)
		return "ResourceGroup", resourceId
	}

	// Check if it's a resource-level scope
	if len(parts) >= 6 && parts[0] == "subscriptions" {
		// For individual resources, use the full scope as the resource ID
		return "Resource", scope
	}

	// Fallback: treat as generic resource
	return "Resource", scope
}

// matchesRBACWildcard checks if an Azure RBAC wildcard pattern matches a specific permission
func (l *Neo4jImporterLink) matchesRBACWildcard(pattern, permission string) bool {
	// Handle the universal wildcard
	if pattern == "*" {
		return true
	}

	// Handle patterns ending with /* (e.g., "Microsoft.Authorization/*")
	// This matches any permission that starts with the prefix, regardless of nesting depth
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(permission, prefix+"/")
	}

	// No wildcards - exact match (should have been caught earlier, but handle defensively)
	return pattern == permission
}

// toJSONString safely converts a map to JSON string with proper escaping
func (l *Neo4jImporterLink) toJSONString(data map[string]interface{}) string {
	if data == nil || len(data) == 0 {
		return "{}"
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		l.Logger.Debug("Failed to marshal metadata to JSON", "error", err)
		return "{}"
	}

	return string(jsonBytes)
}

// Helper utility methods
func (l *Neo4jImporterLink) getMapValue(data map[string]interface{}, key string) map[string]interface{} {
	if value, ok := data[key]; ok {
		if mapValue, ok := value.(map[string]interface{}); ok {
			return mapValue
		}
	}
	return make(map[string]interface{})
}

func (l *Neo4jImporterLink) getArrayValue(data map[string]interface{}, key string) []interface{} {
	if value, ok := data[key]; ok {
		if arrayValue, ok := value.([]interface{}); ok {
			return arrayValue
		}
	}
	return []interface{}{}
}

func (l *Neo4jImporterLink) getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok {
		if stringValue, ok := value.(string); ok {
			return stringValue
		}
	}
	return ""
}

func (l *Neo4jImporterLink) getMapKeys(data map[string]interface{}) []string {
	if data == nil {
		return []string{}
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}

// convertToInt64 handles Neo4j result type conversion from int or int64
func (l *Neo4jImporterLink) convertToInt64(result interface{}) (int64, bool) {
	switch v := result.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}

func (l *Neo4jImporterLink) processIdentityData(resourceMap map[string]interface{}) {
	// Extract identity data to simple primitive properties - exactly like AzureDumperConsolidated
	if identity, ok := resourceMap["identity"]; ok {
		if identityMap, ok := identity.(map[string]interface{}); ok {
			identityType := l.getStringValue(identityMap, "type")
			if identityType != "None" && identityType != "" {
				resourceMap["identityType"] = identityType

				if identityType == "SystemAssigned" {
					resourceMap["identityPrincipalId"] = l.getStringValue(identityMap, "principalId")
				} else if identityType == "UserAssigned" {
					// Extract principalId from first user-assigned identity
					if userIdentities, ok := identityMap["userAssignedIdentities"]; ok {
						if userIdMap, ok := userIdentities.(map[string]interface{}); ok {
							for _, identity := range userIdMap {
								if identityData, ok := identity.(map[string]interface{}); ok {
									resourceMap["identityPrincipalId"] = l.getStringValue(identityData, "principalId")
									break
								}
							}
						}
					}
				}
			} else {
				resourceMap["identityType"] = nil
				resourceMap["identityPrincipalId"] = nil
			}

			// Remove complex identity object for Neo4j compatibility
			delete(resourceMap, "identity")
		}
	}
}

func (l *Neo4jImporterLink) extractConstraintName(constraint string) string {
	// Extract constraint name from CREATE CONSTRAINT statement
	parts := strings.Split(constraint, "FOR")
	if len(parts) > 1 {
		beforeRequire := strings.Split(parts[1], "REQUIRE")
		if len(beforeRequire) > 0 {
			return strings.TrimSpace(beforeRequire[0])
		}
	}
	return "unknown"
}