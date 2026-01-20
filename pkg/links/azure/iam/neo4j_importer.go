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

	// Step 11: Create transitive HAS_PERMISSION edges for group members
	message.Info("🔐 Phase 2c: Creating transitive HAS_PERMISSION edges for group members")
	if !l.createGroupMemberPermissionEdges() {
		l.Logger.Warn("No group member HAS_PERMISSION edges were created")
	}

	// Step 12: Create HAS_PERMISSION edges for Graph API permissions
	message.Info("🔐 Phase 2d: Creating HAS_PERMISSION edges (Microsoft Graph API permissions)")
	if err := l.createGraphPermissionEdges(); err != nil {
		l.Logger.Error("Failed to create Graph permission edges", "error", err)
	}

	// Step 13: Create application ownership edges (must run BEFORE group owner potential)
	message.Info("🔐 Phase 2e: Creating application ownership edges")
	if err := l.createApplicationOwnershipEdges(); err != nil {
		l.Logger.Error("Failed to create application ownership edges", "error", err)
	}

	// Step 14: Create group owner potential HAS_PERMISSION edges (requires OWNS edges from Step 13)
	message.Info("🔐 Phase 2f: Creating group owner potential HAS_PERMISSION edges")
	if !l.createGroupOwnerPotentialPermissionEdges() {
		l.Logger.Warn("No group owner potential HAS_PERMISSION edges were created")
	}

	// Step 15: Create validated CAN_ESCALATE edges (privilege escalation paths)
	message.Info("⚡ Phase 4: Creating validated CAN_ESCALATE edges (privilege escalation paths)")
	if !l.createValidatedEscalationEdges() {
		l.Logger.Warn("No CAN_ESCALATE edges were created")
	}

	// Step 16: Generate summary
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

	// Create synthetic MI resource nodes for system-assigned managed identities
	systemMICount := l.createSystemAssignedManagedIdentityResources()
	totalNodes += systemMICount

	message.Info("Resource node creation summary:", "identity_nodes", identityCount, "hierarchy_nodes", hierarchyCount, "azure_resource_nodes", azureResourceCount, "system_mi_nodes", systemMICount, "total_nodes", totalNodes)

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
					"id": l.normalizeResourceId(l.getStringValue(userMap, "id")),
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
					"id": l.normalizeResourceId(l.getStringValue(groupMap, "id")),
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
					"id": l.normalizeResourceId(l.getStringValue(spMap, "id")),
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
					"id": l.normalizeResourceId(l.getStringValue(appMap, "id")),
					"resourceType": "Microsoft.DirectoryServices/applications",
					"displayName": l.getStringValue(appMap, "displayName"),
					"appId": l.getStringValue(appMap, "appId"),
					"signInAudience": l.getStringValue(appMap, "signInAudience"),
					"credentialSummary_hasCredentials": l.getBoolValue(appMap, "credentialSummary_hasCredentials"),
					"credentialSummary_totalCredentials": l.getIntValue(appMap, "credentialSummary_totalCredentials"),
				}

				// Add credential metadata if present
				if credentialSummary, ok := appMap["credentialSummary_passwordCredentials"]; ok {
					resourceNode["credentialSummary_passwordCredentials"] = credentialSummary
				}
				if keyCredentials, ok := appMap["credentialSummary_keyCredentials"]; ok {
					resourceNode["credentialSummary_keyCredentials"] = keyCredentials
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

// createSystemAssignedManagedIdentityResources creates synthetic MI resource nodes for system-assigned managed identities
func (l *Neo4jImporterLink) createSystemAssignedManagedIdentityResources() int {
	message.Info("=== Creating Synthetic System-Assigned MI Resource Nodes ===")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Query Neo4j for Azure resources with system-assigned identities
	// These resources already have identityType and identityPrincipalId properties set
	cypher := `
		MATCH (resource:Resource)
		WHERE toLower(resource.identityType) CONTAINS "systemassigned"
		  AND resource.identityPrincipalId IS NOT NULL
		  AND NOT toLower(resource.resourceType) CONTAINS "managedidentity"  // Exclude MI resources themselves
		WITH resource
		// Create synthetic MI resource node for the system-assigned identity
		MERGE (mi:Resource:AzureResource {id: "/virtual/managedidentity/system/" + resource.identityPrincipalId})
		ON CREATE SET
			mi.resourceType = "Microsoft.ManagedIdentity/systemAssigned",
			mi.displayName = resource.displayName + " (System-Assigned)",
			mi.principalId = resource.identityPrincipalId,
			mi.subscriptionId = resource.subscriptionId,
			mi.location = resource.location,
			mi.resourceGroup = resource.resourceGroup,
			mi.metadata = '{"assignmentType":"System-Assigned","synthetic":true}'
		RETURN count(mi) as created
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

		return summary.Counters().NodesCreated(), nil
	})

	if err != nil {
		l.Logger.Error("Error creating synthetic system-assigned MI nodes", "error", err)
		return 0
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		created := int(nodesCreated)
		if created > 0 {
			message.Info("Created synthetic system-assigned MI resource nodes", "count", created)
		}
		return created
	}

	return 0
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
			"tenantId": strings.ToLower(tenantID),
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
				"id": l.normalizeResourceId(tenantID),
				"resourceType": "Microsoft.DirectoryServices/tenant",
				"displayName": "Azure AD Tenant",
				"tenantId": strings.ToLower(tenantID),
				"metadata": l.toJSONString(tenantMetadata),
			},
		}

		if created := l.createResourceNodesBatch(session, ctx, tenantNodes, []string{"Resource", "Hierarchy"}); created > 0 {
			totalCreated += created
			message.Info("Created Tenant resource node", "tenantId", tenantID)
		}

		// Create Root Management Group (always exists in Azure with tenant ID)
		rootMgId := l.normalizeResourceId("/providers/Microsoft.Management/managementGroups/" + tenantID)
		rootMgMetadata := map[string]interface{}{
			"managementGroupId": tenantID,
			"tenantId":          tenantID,
			"isRoot":            true,
		}

		rootMgNodes := []map[string]interface{}{
			{
				"id":                 l.normalizeResourceId(rootMgId),
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
						"id":           l.normalizeResourceId("/providers/Microsoft.Management/managementGroups/" + mgID),
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
				"id": l.normalizeResourceId("/subscriptions/" + subscriptionId),
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
							normalizedRgId := l.normalizeResourceId(rgId)

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
							"id": l.normalizeResourceId(l.getStringValue(resourceMap, "id")),
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


					// Add identity attachment data (from processIdentityData)
					if identityType := l.getStringValue(resourceMap, "identityType"); identityType != "" {
						resourceNode["identityType"] = identityType
					}
					if identityPrincipalId := l.getStringValue(resourceMap, "identityPrincipalId"); identityPrincipalId != "" {
						resourceNode["identityPrincipalId"] = identityPrincipalId
					}
				if userAssignedIds, ok := resourceMap["userAssignedIdentities"].([]string); ok && len(userAssignedIds) > 0 {
					resourceNode["userAssignedIdentities"] = userAssignedIds
				}
						// For managed identities, preserve the principalId and add assignmentType metadata
						if strings.Contains(strings.ToLower(resourceType), "managedidentity") {
							if properties := l.getMapValue(resourceMap, "properties"); properties != nil {
								if principalId := l.getStringValue(properties, "principalId"); principalId != "" {
									resourceNode["principalId"] = principalId

									// Add assignmentType metadata for user-assigned MIs
									metadata := map[string]interface{}{
										"assignmentType": "User-Assigned",
										"synthetic":      false,
									}
									resourceNode["metadata"] = l.toJSONString(metadata)

									l.Logger.Debug("Extracted principalId from user-assigned managed identity", "resourceName", l.getStringValue(resourceMap, "name"), "principalId", principalId)
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
		MERGE (r:%s {id: resource.id})
		ON CREATE SET
			r.resourceType = resource.resourceType,
			r.displayName = resource.displayName,
			r.metadata = COALESCE(resource.metadata, '{}'),
			r.location = resource.location,
			r.subscriptionId = resource.subscriptionId,
			r.resourceGroup = resource.resourceGroup,
			r.principalId = resource.principalId,
			r.appId = resource.appId,
			r.userPrincipalName = resource.userPrincipalName,
			r.servicePrincipalType = resource.servicePrincipalType,
			r.signInAudience = resource.signInAudience,
			r.accountEnabled = resource.accountEnabled,
			r.identityType = resource.identityType,
			r.identityPrincipalId = resource.identityPrincipalId,
			r.userAssignedIdentities = resource.userAssignedIdentities
		ON MATCH SET
			r.displayName = resource.displayName,
			r.metadata = COALESCE(resource.metadata, '{}'),
			r.accountEnabled = resource.accountEnabled
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
		WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
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
		WHERE toLower(rootMg.resourceType) = "microsoft.management/managementgroups"
		AND rootMg.id = "/providers/microsoft.management/managementgroups/" + $tenantId
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
						fullParentId = l.normalizeResourceId("/providers/Microsoft.Management/managementGroups/" + parentId)
					}

					managementGroupHierarchy = append(managementGroupHierarchy, map[string]interface{}{
						"childMgId":  l.normalizeResourceId(mgId),
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
		WHERE toLower(parentMg.resourceType) = "microsoft.management/managementgroups"
		AND parentMg.id = rel.parentMgId
		MATCH (childMg:Resource)
		WHERE toLower(childMg.resourceType) = "microsoft.management/managementgroups"
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
						WHERE toLower(mg.resourceType) = "microsoft.management/managementgroups"
						AND mg.id = "/providers/microsoft.management/managementgroups/" + $mgId
						MATCH (subscription:Resource {id: "/subscriptions/" + $subscriptionId})
						WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
						MERGE (mg)-[:CONTAINS]->(subscription)
					`

					result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
						result, err := tx.Run(ctx, cypher, map[string]interface{}{
							"mgId":          strings.ToLower(parentMgId),
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
		WHERE toLower(rootMg.resourceType) = "microsoft.management/managementgroups"
		AND rootMg.id = "/providers/microsoft.management/managementgroups/" + $tenantId
		MATCH (subscription:Resource)
		WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
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
			"tenantId":           strings.ToLower(tenantID),
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
		WHERE toLower(subscription.resourceType) = "microsoft.resources/subscriptions"
		MATCH (rg:Resource)
		WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
		AND rg.id STARTS WITH subscription.id + "/resourcegroups/"
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
		WHERE toLower(rg.resourceType) = "microsoft.resources/resourcegroups"
		MATCH (resource:Resource)
		WHERE toLower(resource.resourceType) STARTS WITH "microsoft."
		AND toLower(resource.resourceType) <> "microsoft.resources/subscriptions"
		AND toLower(resource.resourceType) <> "microsoft.resources/resourcegroups"
		AND toLower(resource.resourceType) <> "microsoft.directoryservices/tenant"
		AND resource.resourceGroup IS NOT NULL
		AND resource.resourceGroup = rg.displayName
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
		WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
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
		WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
		MATCH (sp:Resource)
		WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
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

	// OAuth2 Graph API permissions are handled by createGraphPermissionEdges() below

	// Process Azure RBAC permissions (new logic)
	rbacEdgesCreated := l.createRBACPermissionEdges()
	rbacEdgeCount := 0
	if rbacEdgesCreated {
		rbacEdgeCount = l.edgeCounts["HAS_PERMISSION"] - initialEdgeCount - entraIDEdgeCount
	}

	// Process PIM assignments - enrich HAS_PERMISSION edges with PIM metadata and create CAN_ESCALATE edges
	pimProcessed := l.createPIMEnrichedPermissionEdges()

	// Update final total edge count (PIM enrichment doesn't create new HAS_PERMISSION edges, just updates existing)
	totalEdgesCreated := entraIDEdgeCount + rbacEdgeCount
	l.edgeCounts["HAS_PERMISSION"] = initialEdgeCount + totalEdgesCreated

	success := entraIDEdgesCreated || rbacEdgesCreated || pimProcessed
	if success {
		message.Info("✅ Permission edge creation completed successfully!")
		if pimProcessed {
			message.Info("📊 Summary: %d Entra ID edges + %d RBAC edges = %d total HAS_PERMISSION edges (with PIM enrichment)", entraIDEdgeCount, rbacEdgeCount, totalEdgesCreated)
		} else {
			message.Info("📊 Summary: %d Entra ID edges + %d RBAC edges = %d total HAS_PERMISSION edges", entraIDEdgeCount, rbacEdgeCount, totalEdgesCreated)
		}
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

		// Create direct directory role relationship with roleName and templateId
		// This enables escalation logic to match on roleName and templateId fields
		permissions = append(permissions, map[string]interface{}{
			"principalId":     principalId,
			"permission":      roleName, // Use role name as permission
			"scope":           "/",      // Entra ID roles are tenant-scoped
			"roleId":          roleId,
			"roleName":        roleName,
			"roleTemplateId":  roleTemplateId, // Add template ID for escalation matching
			"principalType":   principalType,
			"source":          "Entra ID Directory Role",
		})

		l.Logger.Debug("Created directory role assignment", "roleName", roleName, "roleTemplateId", roleTemplateId, "principalId", principalId)
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
		MATCH (tenant:Resource)
		WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
		MERGE (principal)-[r:HAS_PERMISSION {templateId: perm.roleTemplateId, permission: perm.permission}]->(tenant)
		ON CREATE SET
			r.roleId = perm.roleId,
			r.roleName = perm.roleName,
			r.principalType = perm.principalType,
			r.source = perm.source,
			r.createdAt = datetime()
		ON MATCH SET
			r.roleName = perm.roleName,
			r.source = perm.source
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

// createPIMEnrichedPermissionEdges processes PIM eligible assignments to mark HAS_PERMISSION edges
// as either "PIM" or "Permanent" assignments. Ignores Active PIM (just transient state of Eligible).
func (l *Neo4jImporterLink) createPIMEnrichedPermissionEdges() bool {
	message.Info("Processing PIM eligible assignments to classify permission types...")

	// Get PIM data
	pimData := l.getMapValue(l.consolidatedData, "pim")
	if pimData == nil {
		message.Info("No PIM data found - marking all as Permanent")
		return l.markAllAsPermanent()
	}

	// Get eligible PIM assignments (ignore active_assignments - that's just transient state)
	eligiblePIMAssignments := l.getArrayValue(pimData, "eligible_assignments")

	if len(eligiblePIMAssignments) == 0 {
		message.Info("No eligible PIM assignments found - marking all as Permanent")
		return l.markAllAsPermanent()
	}

	message.Info("Found %d eligible PIM assignments", len(eligiblePIMAssignments))

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Process eligible PIM assignments
	pimEdgesMarked := 0
	pimEdgesCreated := 0

	for _, assignment := range eligiblePIMAssignments {
		assignmentMap, ok := assignment.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract subject (principal) information
		// Try SDK flat format first, then fall back to legacy nested format
		principalId := l.getStringValue(assignmentMap, "principalId")
		if principalId == "" {
			// Fall back to legacy nested format
			subject := l.getMapValue(assignmentMap, "subject")
			if subject == nil {
				l.Logger.Debug("Skipping PIM assignment: missing principalId and subject")
				continue
			}
			principalId = l.getStringValue(subject, "id")
			if principalId == "" {
				l.Logger.Debug("Skipping PIM assignment: empty principalId in subject")
				continue
			}
		}
		// Normalize for case-consistent Neo4j matching
		principalId = l.normalizeResourceId(principalId)

		// Extract role definition information
		// Try SDK flat format first
		roleTemplateId := ""
		roleDefinitionId := l.getStringValue(assignmentMap, "roleDefinitionId")
		if roleDefinitionId != "" {
			// Extract template ID from path: /subscriptions/.../roleDefinitions/GUID
			parts := strings.Split(roleDefinitionId, "/")
			if len(parts) > 0 {
				roleTemplateId = parts[len(parts)-1]
			}
		} else {
			// Fall back to legacy nested format
			roleDefinition := l.getMapValue(assignmentMap, "roleDefinition")
			if roleDefinition == nil {
				l.Logger.Debug("Skipping PIM assignment: missing roleDefinitionId and roleDefinition", "principalId", principalId)
				continue
			}
			roleTemplateId = l.getStringValue(roleDefinition, "templateId")
		}

		// Extract role name (both formats use displayName at top level or nested)
		roleName := l.getStringValue(assignmentMap, "displayName")
		if roleName == "" {
			roleDefinition := l.getMapValue(assignmentMap, "roleDefinition")
			if roleDefinition != nil {
				roleName = l.getStringValue(roleDefinition, "displayName")
			}
		}

		if principalId == "" || roleTemplateId == "" || roleName == "" {
			continue
		}

		// Try to mark existing HAS_PERMISSION edge as PIM (if user is currently activated or permanent)
		cypherUpdate := `
		MATCH (principal:Resource {id: $principalId})-[r:HAS_PERMISSION]->(tenant:Resource)
		WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
		  AND r.templateId = $roleTemplateId
		SET r.assignmentType = "PIM",
			r.pimProcessed = true
		RETURN count(r) as updated
		`

		updateResult, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypherUpdate, map[string]interface{}{
				"principalId":    principalId,
				"roleTemplateId": roleTemplateId,
			})
			if err != nil {
				return 0, err
			}

			if result.Next(ctx) {
				record := result.Record()
				if updated, ok := record.Get("updated"); ok {
					return updated, nil
				}
			}
			return 0, nil
		})

		if err != nil {
			l.Logger.Warn("Failed to mark existing HAS_PERMISSION as PIM", "principalId", principalId, "role", roleName, "error", err)
			continue
		}

		if updated, ok := l.convertToInt64(updateResult); ok && updated > 0 {
			pimEdgesMarked += int(updated)
			l.Logger.Debug("Marked existing HAS_PERMISSION as PIM", "principalId", principalId, "role", roleName)
			continue // Edge already exists, no need to create
		}

		// Edge doesn't exist - user has eligible assignment but hasn't activated yet
		// Create new HAS_PERMISSION edge
		cypherCreate := `
		MATCH (principal:Resource {id: $principalId})
		MATCH (tenant:Resource)
		WHERE toLower(tenant.resourceType) = "microsoft.directoryservices/tenant"
		MERGE (principal)-[r:HAS_PERMISSION {templateId: $roleTemplateId, permission: $roleName}]->(tenant)
		ON CREATE SET
			r.roleId = $roleTemplateId,
			r.roleName = $roleName,
			r.principalType = "User",
			r.source = "Entra ID Directory Role",
			r.assignmentType = "PIM",
			r.pimProcessed = true,
			r.createdAt = datetime()
		ON MATCH SET
			r.assignmentType = "PIM",
			r.pimProcessed = true
		RETURN count(r) as created
		`

		createResult, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypherCreate, map[string]interface{}{
				"principalId":    principalId,
				"roleTemplateId": roleTemplateId,
				"roleName":       roleName,
			})
			if err != nil {
				return 0, err
			}

			if result.Next(ctx) {
				record := result.Record()
				if created, ok := record.Get("created"); ok {
					return created, nil
				}
			}
			return 0, nil
		})

		if err != nil {
			l.Logger.Warn("Failed to create HAS_PERMISSION for eligible PIM", "principalId", principalId, "role", roleName, "error", err)
			continue
		}

		if created, ok := l.convertToInt64(createResult); ok && created > 0 {
			pimEdgesCreated += int(created)
			l.Logger.Debug("Created HAS_PERMISSION for eligible PIM", "principalId", principalId, "role", roleName)
		}
	}

	message.Info("Processed eligible PIM: %d edges marked, %d edges created", pimEdgesMarked, pimEdgesCreated)

	// Mark remaining Entra ID HAS_PERMISSION edges as "Permanent" (not PIM-eligible)
	cypherMarkPermanent := `
	MATCH ()-[r:HAS_PERMISSION]->()
	WHERE r.source = "Entra ID Directory Role" AND r.pimProcessed IS NULL
	SET r.assignmentType = "Permanent"
	RETURN count(r) as marked
	`

	permanentResult, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypherMarkPermanent, nil)
		if err != nil {
			return 0, err
		}

		if result.Next(ctx) {
			record := result.Record()
			if marked, ok := record.Get("marked"); ok {
				return marked, nil
			}
		}
		return 0, nil
	})

	permanentCount := 0
	if err == nil {
		if marked, ok := l.convertToInt64(permanentResult); ok {
			permanentCount = int(marked)
		}
	}

	message.Info("Marked %d HAS_PERMISSION edges as Permanent assignments", permanentCount)

	// Update edge counts for newly created edges
	l.edgeCounts["HAS_PERMISSION"] = l.edgeCounts["HAS_PERMISSION"] + pimEdgesCreated

	message.Info("✅ PIM classification completed: %d PIM (marked) + %d PIM (created) + %d Permanent",
		pimEdgesMarked, pimEdgesCreated, permanentCount)

	return true
}

// markAllAsPermanent marks all Entra ID HAS_PERMISSION edges as Permanent when no PIM data exists
func (l *Neo4jImporterLink) markAllAsPermanent() bool {
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypherMarkPermanent := `
	MATCH ()-[r:HAS_PERMISSION]->()
	WHERE r.source = "Entra ID Directory Role" AND r.assignmentType IS NULL
	SET r.assignmentType = "Permanent"
	RETURN count(r) as marked
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypherMarkPermanent, nil)
		if err != nil {
			return 0, err
		}

		if result.Next(ctx) {
			record := result.Record()
			if marked, ok := record.Get("marked"); ok {
				return marked, nil
			}
		}
		return 0, nil
	})

	if err != nil {
		l.Logger.Error("Failed to mark edges as Permanent", "error", err)
		return false
	}

	if marked, ok := l.convertToInt64(result); ok && marked > 0 {
		message.Info("Marked %d HAS_PERMISSION edges as Permanent (no PIM data)", marked)
		return true
	}

	return false
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
				l.Logger.Debug("*** DEFINITELY CALLING NEW RBAC LOGIC FOR SUBSCRIPTIONS ***")
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
		MERGE (principal)-[r:HAS_PERMISSION {roleDefinitionId: perm.roleDefinitionId, permission: perm.permission}]->(target)
		ON CREATE SET
			r.roleName = perm.roleName,
			r.principalType = perm.principalType,
			r.source = perm.source,
			r.grantedAt = perm.grantedAt,
			r.targetResourceType = perm.targetResourceType,
			r.createdAt = datetime()
		ON MATCH SET
			r.roleName = perm.roleName,
			r.source = perm.source
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

// createGroupMemberPermissionEdges materializes transitive permissions from groups to their members
func (l *Neo4jImporterLink) createGroupMemberPermissionEdges() bool {
	message.Info("Creating transitive HAS_PERMISSION edges for group members...")

	// Query for all group HAS_PERMISSION edges and their members in a single query
	cypher := `
	MATCH (group:Resource)-[groupPerm:HAS_PERMISSION]->(target:Resource)
	MATCH (group)-[:CONTAINS]->(member:Resource)
	WHERE groupPerm.permission IS NOT NULL
	RETURN
		group.id as groupId,
		group.displayName as groupName,
		member.id as memberId,
		target.id as targetId,
		groupPerm.permission as permission,
		groupPerm.roleDefinitionId as roleDefinitionId,
		groupPerm.roleName as roleName,
		groupPerm.roleId as roleId,
		groupPerm.principalType as originalPrincipalType,
		groupPerm.source as originalSource,
		groupPerm.grantedAt as grantedAt,
		groupPerm.targetResourceType as targetResourceType
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}

		var permissions []map[string]interface{}
		for result.Next(ctx) {
			record := result.Record()

			// Create permission record for the member
			permission := map[string]interface{}{
				"memberId":              record.Values[2], // member.id
				"targetId":              record.Values[3], // target.id
				"permission":            record.Values[4], // permission
				"source":                "group_membership",
				"groupId":               record.Values[0], // group.id
				"groupName":             record.Values[1], // group.displayName
				"principalType":         "User", // Members are typically users or service principals
			}

			// Add optional fields if they exist
			if roleDefId := record.Values[5]; roleDefId != nil {
				permission["roleDefinitionId"] = roleDefId
			}
			if roleName := record.Values[6]; roleName != nil {
				permission["roleName"] = roleName
			}
			if roleId := record.Values[7]; roleId != nil {
				permission["roleId"] = roleId
			}
			if grantedAt := record.Values[9]; grantedAt != nil {
				permission["grantedAt"] = grantedAt
			}
			if targetResourceType := record.Values[11]; targetResourceType != nil {
				permission["targetResourceType"] = targetResourceType
			}

			permissions = append(permissions, permission)
		}

		return permissions, result.Err()
	})

	if err != nil {
		l.Logger.Error("Error querying for group permissions and memberships", "error", err)
		return false
	}

	permissions, ok := result.([]map[string]interface{})
	if !ok || len(permissions) == 0 {
		message.Info("No group member permissions to materialize")
		return false
	}

	message.Info("Found %d group member permissions to materialize", len(permissions))

	// Process in batches
	batchSize := 10000
	totalEdgesCreated := 0

	for i := 0; i < len(permissions); i += batchSize {
		end := i + batchSize
		if end > len(permissions) {
			end = len(permissions)
		}

		batch := permissions[i:end]

		createCypher := `
		UNWIND $permissions AS perm
		WITH perm
		WHERE perm.memberId IS NOT NULL AND perm.permission IS NOT NULL AND perm.targetId IS NOT NULL
		MATCH (member:Resource {id: perm.memberId})
		MATCH (target:Resource {id: perm.targetId})
		MERGE (member)-[r:HAS_PERMISSION {permission: perm.permission}]->(target)
		ON CREATE SET
			r.source = perm.source,
			r.groupId = perm.groupId,
			r.groupName = perm.groupName,
			r.principalType = perm.principalType,
			r.createdAt = datetime()
		ON MATCH SET
			r.grantedByGroups = CASE
				WHEN r.grantedByGroups IS NULL THEN [perm.groupId]
				WHEN perm.groupId IN r.grantedByGroups THEN r.grantedByGroups
				ELSE r.grantedByGroups + [perm.groupId]
			END
		`

		// Add optional properties if they exist
		if len(batch) > 0 {
			// Check if we have roleDefinitionId in the first item to determine which properties to set
			if batch[0]["roleDefinitionId"] != nil {
				createCypher += `, r.roleDefinitionId = perm.roleDefinitionId`
			}
			if batch[0]["roleName"] != nil {
				createCypher += `, r.roleName = perm.roleName`
			}
			if batch[0]["roleId"] != nil {
				createCypher += `, r.roleId = perm.roleId`
			}
			if batch[0]["grantedAt"] != nil {
				createCypher += `, r.grantedAt = perm.grantedAt`
			}
			if batch[0]["targetResourceType"] != nil {
				createCypher += `, r.targetResourceType = perm.targetResourceType`
			}
		}

		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, createCypher, map[string]interface{}{"permissions": batch})
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
			l.Logger.Error("Error creating group member HAS_PERMISSION edges for batch", "error", err, "batch", i/batchSize+1)
			continue
		}

		if edgesCreated, ok := l.convertToInt64(result); ok {
			totalEdgesCreated += int(edgesCreated)
			message.Info("Batch %d/%d: Created %d group member HAS_PERMISSION edges", i/batchSize+1, (len(permissions)+batchSize-1)/batchSize, edgesCreated)
		}
	}

	// Add group member edges to the existing HAS_PERMISSION count
	currentCount := l.edgeCounts["HAS_PERMISSION"]
	l.edgeCounts["HAS_PERMISSION"] = currentCount + totalEdgesCreated

	message.Info("Created %d total group member HAS_PERMISSION edges", totalEdgesCreated)
	return totalEdgesCreated > 0
}

// createGroupOwnerPotentialPermissionEdges creates HAS_PERMISSION edges for group owners
// showing permissions they can obtain by adding themselves to groups they own
func (l *Neo4jImporterLink) createGroupOwnerPotentialPermissionEdges() bool {
	message.Info("Creating group owner potential HAS_PERMISSION edges...")

	cypher := l.getGroupOwnerPotentialPermissionQuery()
	l.Logger.Debug("Group owner query", "cypher", cypher)

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			l.Logger.Error("Query execution error", "error", err)
			return 0, err
		}

		if result.Next(ctx) {
			record := result.Record()
			l.Logger.Debug("Got result record", "keys", record.Keys, "values", record.Values)
			if created, ok := record.Get("created"); ok {
				l.Logger.Debug("Created field found", "value", created, "type", fmt.Sprintf("%T", created))
				return created, nil
			} else {
				l.Logger.Debug("Created field not found in record")
			}
		} else {
			l.Logger.Debug("No result records returned")
		}
		return 0, nil
	})

	if err != nil {
		l.Logger.Error("Error creating group owner potential HAS_PERMISSION edges", "error", err)
		return false
	}

	l.Logger.Debug("Result from transaction", "result", result, "type", fmt.Sprintf("%T", result))
	if edgesCreated, ok := l.convertToInt64(result); ok && edgesCreated > 0 {
		// Add to existing HAS_PERMISSION count
		currentCount := l.edgeCounts["HAS_PERMISSION"]
		l.edgeCounts["HAS_PERMISSION"] = currentCount + int(edgesCreated)
		message.Info("Created %d group owner potential HAS_PERMISSION edges", edgesCreated)
		return true
	}

	message.Info("No group owner potential HAS_PERMISSION edges created")
	return false
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
							// Store with full subscription-scoped ID
							l.roleDefinitionsMap[roleDefinitionId] = roleDefMap

							// Also store with normalized key format to match role assignments
							// Extract role GUID and create normalized key
							if roleGUID := l.getStringValue(roleDefMap, "name"); roleGUID != "" {
								normalizedKey := l.normalizeResourceId("/providers/Microsoft.Authorization/RoleDefinitions/" + roleGUID)
								l.roleDefinitionsMap[normalizedKey] = roleDefMap
								l.Logger.Debug("Cached role definition with both keys", "fullId", roleDefinitionId, "normalizedKey", normalizedKey)
							}
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

// getGraphPermissionName maps well-known Graph permission GUIDs to their permission names
func (l *Neo4jImporterLink) getGraphPermissionName(appRoleId string) string {
	// Map of well-known Microsoft Graph permission GUIDs to their names
	// IMPORTANT: These GUIDs are verified against Microsoft Graph API (2024)
	// Verified with: az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'" --query "value[0].appRoles"
	graphPermissionMap := map[string]string{
		// Critical Permissions for Escalation (VERIFIED)
		"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
		"19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
		"741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
		"62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
		"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
		"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",

		// Read permissions (VERIFIED)
		"df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
		"5b567255-7703-4780-807c-7be8301ae99b": "Group.Read.All",
		"9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30": "Application.Read.All",
		"7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
		"483bed4a-2ad3-4361-a73b-c83ccdbdc53c": "RoleManagement.Read.Directory",

		// Additional permissions (VERIFIED)
		"18a4783c-866b-4cc7-a460-3d5e5662c884": "Application.ReadWrite.OwnedBy",
		"246dd0d5-5bd0-4def-940b-0421030a5b68": "Policy.Read.All",
		"c7fbd983-d9aa-4fa7-84b8-17382c103bc4": "RoleManagement.Read.All",
		"fdc4c997-9942-4479-bfcb-75a36d1138df": "RoleManagementPolicy.Read.Directory",
		"69e67828-780e-47fd-b28c-7b27d14864e6": "RoleManagementPolicy.Read.AzureADGroup",
		"ff278e11-4a33-4d0c-83d2-d01dc58929a5": "RoleEligibilitySchedule.Read.Directory",
		"5df6fe86-1be0-44eb-b916-7bd443a71236": "PrivilegedAccess.Read.AzureResources",

		// Special cases
		"00000000-0000-0000-0000-000000000000": "User.Read", // Default permission
	}

	if permissionName, exists := graphPermissionMap[appRoleId]; exists {
		return permissionName
	}

	// Return the GUID if no mapping found - for debugging
	return appRoleId
}

// getRBACRoleName gets the display name for an RBAC role definition
func (l *Neo4jImporterLink) getRBACRoleName(roleDefinitionId string) string {
	// Look up role definition by roleDefinitionId
	roleDef, exists := l.roleDefinitionsMap[roleDefinitionId]
	if !exists {
		// Fallback: try to find by any key containing the role GUID
		if strings.Contains(roleDefinitionId, "/RoleDefinitions/") {
			parts := strings.Split(roleDefinitionId, "/")
			if len(parts) > 0 {
				roleGUID := parts[len(parts)-1]
				for cachedKey, cachedRoleDef := range l.roleDefinitionsMap {
					if strings.HasSuffix(cachedKey, roleGUID) {
						l.Logger.Debug("Found RBAC role via fallback lookup for name", "searchKey", roleDefinitionId, "foundKey", cachedKey)
						roleDef = cachedRoleDef
						exists = true
						break
					}
				}
			}
		}

		if !exists {
			l.Logger.Debug("RBAC role definition not found for name lookup", "roleDefinitionId", roleDefinitionId)
			return ""
		}
	}

	// Extract role name - Azure RBAC role definitions use "displayName" field
	if roleDefMap, ok := roleDef.(map[string]interface{}); ok {
		// First check properties.displayName (most common for Azure RBAC)
		if properties := l.getMapValue(roleDefMap, "properties"); properties != nil {
			if displayName := l.getStringValue(properties, "displayName"); displayName != "" {
				return displayName
			}
			if roleName := l.getStringValue(properties, "roleName"); roleName != "" {
				return roleName
			}
		}
		// Then try direct fields
		if displayName := l.getStringValue(roleDefMap, "displayName"); displayName != "" {
			return displayName
		}
		if roleName := l.getStringValue(roleDefMap, "roleName"); roleName != "" {
			return roleName
		}
		// Don't use "name" field as it's the GUID, not the display name
	}

	l.Logger.Debug("Could not extract role name from definition", "roleDefinitionId", roleDefinitionId)
	return ""
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

	// Define dangerous RBAC permissions - focused BloodHound/AzureHound aligned list
	rbacDangerousPermissions := map[string]bool{
		// Identity & Access Management (Privilege Escalation)
		"Microsoft.Authorization/roleAssignments/write":                   true,
		"Microsoft.Authorization/roleDefinitions/write":                   true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true,

		// Application/Service Principal Control (Backdoor Access)
		"Microsoft.Graph/applications/credentials/update":                 true,
		"Microsoft.Graph/servicePrincipals/credentials/update":           true,
		"Microsoft.Directory/applications/credentials/update":            true,
		"Microsoft.Directory/servicePrincipals/credentials/update":       true,

		// Code Execution (Direct System Access)
		"Microsoft.Compute/virtualMachines/runCommand/action":            true,
		"Microsoft.Compute/virtualMachines/write":                        true,
		"Microsoft.Compute/virtualMachines/extensions/write":             true,
		"Microsoft.Compute/virtualMachineScaleSets/write":                true,
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":     true,
		"Microsoft.Automation/automationAccounts/write":                  true,
		"Microsoft.Automation/automationAccounts/runbooks/write":         true,
		"Microsoft.Logic/workflows/write":                                true,
		"Microsoft.Web/sites/write":                                      true,
		"Microsoft.Web/sites/config/write":                               true,
		"Microsoft.Web/sites/functions/write":                            true,

		// Storage & Data Access (Credential Theft)
		"Microsoft.Storage/storageAccounts/write":                        true,
		"Microsoft.Storage/storageAccounts/listKeys/action":              true,
		"Microsoft.Storage/storageAccounts/regeneratekey/action":         true,
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true,

		// Key Vault (Secrets Access)
		"Microsoft.KeyVault/vaults/write":                                true,
		"Microsoft.KeyVault/vaults/secrets/write":                        true,
		"Microsoft.KeyVault/vaults/keys/write":                           true,
		"Microsoft.KeyVault/vaults/accessPolicies/write":                 true,

		// Database Access (Data & Credential Theft)
		"Microsoft.Sql/servers/databases/write":                          true,
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":          true,
		"Microsoft.DocumentDB/databaseAccounts/write":                    true,

		// Container & Registry (Supply Chain Attacks)
		"Microsoft.ContainerService/managedClusters/write":               true,
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true,
		"Microsoft.ContainerRegistry/registries/write":                   true,
		"Microsoft.ContainerRegistry/registries/importImage/action":      true,

		// Network Control (Lateral Movement)
		"Microsoft.Network/networkSecurityGroups/write":                  true,
		"Microsoft.Network/networkSecurityGroups/securityRules/write":    true,
		"Microsoft.Network/virtualNetworks/write":                        true,

		// Message Queue & Event Systems (Persistence & C2)
		"Microsoft.ServiceBus/namespaces/write":                          true,
		"Microsoft.EventHub/namespaces/write":                            true,
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
	// Define dangerous RBAC permissions - focused BloodHound/AzureHound aligned list
	rbacDangerousPermissions := map[string]bool{
		// Identity & Access Management (Privilege Escalation)
		"Microsoft.Authorization/roleAssignments/write":                   true,
		"Microsoft.Authorization/roleDefinitions/write":                   true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true,

		// Application/Service Principal Control (Backdoor Access)
		"Microsoft.Graph/applications/credentials/update":                 true,
		"Microsoft.Graph/servicePrincipals/credentials/update":           true,
		"Microsoft.Directory/applications/credentials/update":            true,
		"Microsoft.Directory/servicePrincipals/credentials/update":       true,

		// Code Execution (Direct System Access)
		"Microsoft.Compute/virtualMachines/runCommand/action":            true,
		"Microsoft.Compute/virtualMachines/write":                        true,
		"Microsoft.Compute/virtualMachines/extensions/write":             true,
		"Microsoft.Compute/virtualMachineScaleSets/write":                true,
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":     true,
		"Microsoft.Automation/automationAccounts/write":                  true,
		"Microsoft.Automation/automationAccounts/runbooks/write":         true,
		"Microsoft.Logic/workflows/write":                                true,
		"Microsoft.Web/sites/write":                                      true,
		"Microsoft.Web/sites/config/write":                               true,
		"Microsoft.Web/sites/functions/write":                            true,

		// Storage & Data Access (Credential Theft)
		"Microsoft.Storage/storageAccounts/write":                        true,
		"Microsoft.Storage/storageAccounts/listKeys/action":              true,
		"Microsoft.Storage/storageAccounts/regeneratekey/action":         true,
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true,

		// Key Vault (Secrets Access)
		"Microsoft.KeyVault/vaults/write":                                true,
		"Microsoft.KeyVault/vaults/secrets/write":                        true,
		"Microsoft.KeyVault/vaults/keys/write":                           true,
		"Microsoft.KeyVault/vaults/accessPolicies/write":                 true,

		// Database Access (Data & Credential Theft)
		"Microsoft.Sql/servers/databases/write":                          true,
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":          true,
		"Microsoft.DocumentDB/databaseAccounts/write":                    true,

		// Container & Registry (Supply Chain Attacks)
		"Microsoft.ContainerService/managedClusters/write":               true,
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true,
		"Microsoft.ContainerRegistry/registries/write":                   true,
		"Microsoft.ContainerRegistry/registries/importImage/action":      true,

		// Network Control (Lateral Movement)
		"Microsoft.Network/networkSecurityGroups/write":                  true,
		"Microsoft.Network/networkSecurityGroups/securityRules/write":    true,
		"Microsoft.Network/virtualNetworks/write":                        true,

		// Message Queue & Event Systems (Persistence & C2)
		"Microsoft.ServiceBus/namespaces/write":                          true,
		"Microsoft.EventHub/namespaces/write":                            true,
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
		// Identity & Access Management (Privilege Escalation)
		"Microsoft.Authorization/roleAssignments/write":                   true,
		"Microsoft.Authorization/roleDefinitions/write":                   true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/write":         true,
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action": true,

		// Application/Service Principal Control (Backdoor Access)
		"Microsoft.Graph/applications/credentials/update":                 true,
		"Microsoft.Graph/servicePrincipals/credentials/update":           true,
		"Microsoft.Directory/applications/credentials/update":            true,
		"Microsoft.Directory/servicePrincipals/credentials/update":       true,

		// Code Execution (Direct System Access)
		"Microsoft.Compute/virtualMachines/runCommand/action":            true,
		"Microsoft.Compute/virtualMachines/write":                        true,
		"Microsoft.Compute/virtualMachines/extensions/write":             true,
		"Microsoft.Compute/virtualMachineScaleSets/write":                true,
		"Microsoft.Compute/virtualMachineScaleSets/extensions/write":     true,
		"Microsoft.Automation/automationAccounts/write":                  true,
		"Microsoft.Automation/automationAccounts/runbooks/write":         true,
		"Microsoft.Logic/workflows/write":                                true,
		"Microsoft.Web/sites/write":                                      true,
		"Microsoft.Web/sites/config/write":                               true,
		"Microsoft.Web/sites/functions/write":                            true,

		// Storage & Data Access (Credential Theft)
		"Microsoft.Storage/storageAccounts/write":                        true,
		"Microsoft.Storage/storageAccounts/listKeys/action":              true,
		"Microsoft.Storage/storageAccounts/regeneratekey/action":         true,
		"Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action": true,

		// Key Vault (Secrets Access)
		"Microsoft.KeyVault/vaults/write":                                true,
		"Microsoft.KeyVault/vaults/secrets/write":                        true,
		"Microsoft.KeyVault/vaults/keys/write":                           true,
		"Microsoft.KeyVault/vaults/accessPolicies/write":                 true,

		// Database Access (Data & Credential Theft)
		"Microsoft.Sql/servers/databases/write":                          true,
		"Microsoft.DocumentDB/databaseAccounts/listKeys/action":          true,
		"Microsoft.DocumentDB/databaseAccounts/write":                    true,

		// Container & Registry (Supply Chain Attacks)
		"Microsoft.ContainerService/managedClusters/write":               true,
		"Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action": true,
		"Microsoft.ContainerRegistry/registries/write":                   true,
		"Microsoft.ContainerRegistry/registries/push/write":              true,

		// Resource Management (Infrastructure Takeover)
		"Microsoft.Resources/deployments/write":                          true,
		"Microsoft.Resources/subscriptions/resourceGroups/write":         true,

		// Additional Managed Identity Services
		"Microsoft.ContainerService/managedClusters/agentPools/write":    true,
		"Microsoft.Sql/servers/write":                                    true,
		"Microsoft.DataFactory/factories/write":                          true,
		"Microsoft.Batch/batchAccounts/write":                            true,
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
	l.Logger.Debug("*** ENTERING processScopedRBACAssignments ***", "assignmentCount", len(assignments), "scopeType", scopeType)
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

		// Get RBAC role name instead of expanding to individual permissions
		l.Logger.Debug("*** NEW RBAC LOGIC: Getting role name ***", "roleDefinitionId", roleDefinitionId)
		roleName := l.getRBACRoleName(roleDefinitionId)
		l.Logger.Debug("*** NEW RBAC LOGIC: Got role name ***", "roleDefinitionId", roleDefinitionId, "roleName", roleName)

		// Create direct RBAC role assignment with role name as permission
		// This aligns with the simplified Entra ID approach
		if roleName != "" {
			l.Logger.Debug("Created RBAC role assignment", "roleName", roleName, "roleDefinitionId", roleDefinitionId, "principalId", principalId, "targetResource", targetResourceId, "scopeType", scopeType)
			permissions = append(permissions, map[string]interface{}{
				"principalId":        principalId,
				"permission":         roleName, // Use role name as permission
				"targetResourceId":   l.normalizeResourceId(targetResourceId),
				"targetResourceType": targetResourceType,
				"grantedAt":          scopeType,
				"roleDefinitionId":   roleDefinitionId,
				"roleName":          roleName, // Store role name for escalation matching
				"principalType":      principalType,
				"source":             "Azure RBAC",
			})
		} else {
			l.Logger.Debug("Could not get role name - skipping role assignment", "roleDefinitionId", roleDefinitionId, "principalId", principalId)
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
	// /providers/Microsoft.Management/managementGroups/{management-group-id}
	// / (tenant root)

	// Handle tenant root scope - map to Tenant Root Management Group
	if scope == "/" || scope == "" {
		// Get tenant ID from metadata to construct the proper management group resource ID
		metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
		tenantID := l.getStringValue(metadata, "tenant_id")
		if tenantID != "" {
			return "ManagementGroup", l.normalizeResourceId(fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", tenantID))
		}
		return "Tenant", "/"
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

	// Check if it's a management group scope
	// Format: /providers/Microsoft.Management/managementGroups/{management-group-id}
	if len(parts) >= 4 && parts[0] == "providers" && parts[1] == "Microsoft.Management" && parts[2] == "managementGroups" {
		managementGroupId := parts[3]
		return "ManagementGroup", l.normalizeResourceId(fmt.Sprintf("/providers/Microsoft.Management/managementGroups/%s", managementGroupId))
	}

	// Check if it's a subscription-level scope
	if len(parts) == 2 && parts[0] == "subscriptions" {
		return "Microsoft.Resources/subscriptions", l.normalizeResourceId(fmt.Sprintf("/subscriptions/%s", parts[1]))
	}

	// Check if it's a resource group-level scope
	if len(parts) == 4 && parts[0] == "subscriptions" && parts[2] == "resourceGroups" {
		// For resource groups, we need to construct the resource ID
		subscriptionId := parts[1]
		resourceGroupName := parts[3]
		resourceId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionId, resourceGroupName)
		return "ResourceGroup", l.normalizeResourceId(resourceId)
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

// normalizeResourceId normalizes Azure resource IDs to lowercase for consistent matching
// This fixes case sensitivity issues between RBAC assignments and resource node IDs
func (l *Neo4jImporterLink) normalizeResourceId(resourceId string) string {
	return strings.ToLower(resourceId)
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

func (l *Neo4jImporterLink) getBoolValue(data map[string]interface{}, key string) bool {
	if value, ok := data[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}
	return false
}

func (l *Neo4jImporterLink) getIntValue(data map[string]interface{}, key string) int {
	if value, ok := data[key]; ok {
		if intValue, ok := value.(int); ok {
			return intValue
		}
		if floatValue, ok := value.(float64); ok {
			return int(floatValue)
		}
	}
	return 0
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

				// Handle SystemAssigned (alone or combined with UserAssigned)
				if strings.Contains(identityType, "SystemAssigned") {
					resourceMap["identityPrincipalId"] = l.getStringValue(identityMap, "principalId")
				}

				// Extract user-assigned identities (if present)
				if strings.Contains(identityType, "UserAssigned") {
					if userIdentities, ok := identityMap["userAssignedIdentities"]; ok {
						if userIdMap, ok := userIdentities.(map[string]interface{}); ok {
							// Extract resource IDs from the keys
							userAssignedMIResourceIds := make([]string, 0)
							for resourceId := range userIdMap {
								normalizedId := l.normalizeResourceId(resourceId)
								userAssignedMIResourceIds = append(userAssignedMIResourceIds, normalizedId)
							}
							if len(userAssignedMIResourceIds) > 0 {
								// Store as JSON array in metadata
								resourceMap["userAssignedIdentities"] = userAssignedMIResourceIds
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

// createGraphPermissionEdges creates HAS_PERMISSION relationships for Microsoft Graph API permissions
func (l *Neo4jImporterLink) createGraphPermissionEdges() error {
	l.Logger.Info("Creating Microsoft Graph API permission relationships...")

	var allGraphPermissions []CompleteGraphPermission

	// Check if we have a single subscription data format (new format from comprehensive collector)
	// Structure: {azure_ad: {...}, pim: {...}, management_groups: {...}, azure_resources: {...}}
	if azureADData, exists := l.consolidatedData["azure_ad"]; exists {
		// This is the new single subscription format
		if azureADMap, ok := azureADData.(map[string]interface{}); ok {
			allGraphPermissions = l.extractGraphPermissionsFromAzureAD(azureADMap, allGraphPermissions)
		}
		l.Logger.Info(fmt.Sprintf("Extracted %d Graph permissions from consolidated data", len(allGraphPermissions)))
	} else {
		// Legacy multi-subscription format - extract graph permissions from each subscription's data
		for subscriptionID, subscriptionData := range l.consolidatedData {
			subscriptionMap, ok := subscriptionData.(map[string]interface{})
			if !ok {
				continue
			}

			if azureADData, exists := subscriptionMap["azure_ad"]; exists {
				if azureADMap, ok := azureADData.(map[string]interface{}); ok {
					beforeCount := len(allGraphPermissions)
					allGraphPermissions = l.extractGraphPermissionsFromAzureAD(azureADMap, allGraphPermissions)
					afterCount := len(allGraphPermissions)
					l.Logger.Info(fmt.Sprintf("Extracted %d Graph permissions from subscription %s (added: %d, total: %d)", subscriptionID, afterCount-beforeCount, afterCount))
				}
			}
		}
	}

	if len(allGraphPermissions) == 0 {
		l.Logger.Info("No Graph permissions found to import")
		return nil
	}

	// Create relationships in batches
	const batchSize = 1000
	totalBatches := (len(allGraphPermissions) + batchSize - 1) / batchSize

	totalCreated := 0
	for j := 0; j < len(allGraphPermissions); j += batchSize {
		end := j + batchSize
		if end > len(allGraphPermissions) {
			end = len(allGraphPermissions)
		}

		batch := allGraphPermissions[j:end]
		batchNum := j/batchSize + 1

		created, err := l.processBatchGraphPermissions(batch, batchNum, totalBatches)
		if err != nil {
			return fmt.Errorf("failed to process Graph permission batch %d: %w", batchNum, err)
		}
		totalCreated += created
	}

	l.Logger.Info(fmt.Sprintf("✅ Graph permission edge creation completed successfully!"))
	l.Logger.Info(fmt.Sprintf("📊 Summary: %d total HAS_PERMISSION edges created (source: Microsoft Graph)", totalCreated))
	message.Info("Created %d total HAS_PERMISSION edges (source: Microsoft Graph)", totalCreated)

	return nil
}

// processBatchGraphPermissions processes a batch of Graph permissions and creates Neo4j relationships
func (l *Neo4jImporterLink) processBatchGraphPermissions(permissions []CompleteGraphPermission, batchNum, totalBatches int) (int, error) {
	cypher := `
	UNWIND $permissions as perm
	// Find the principal (could be service principal, user, or group)
	OPTIONAL MATCH (sp:Resource {id: perm.servicePrincipalId}) WHERE perm.servicePrincipalId <> ""
	OPTIONAL MATCH (user:Resource {id: perm.userId}) WHERE perm.userId <> ""
	OPTIONAL MATCH (group:Resource {id: perm.groupId}) WHERE perm.groupId <> ""

	// Find the resource app (target of the permission)
	MATCH (target:Resource {id: perm.resourceAppId})

	// Create the relationship from whichever principal exists
	WITH perm, target,
		 CASE
		   WHEN sp IS NOT NULL THEN sp
		   WHEN user IS NOT NULL THEN user
		   WHEN group IS NOT NULL THEN group
		   ELSE null
		 END as principal
	WHERE principal IS NOT NULL

	MERGE (principal)-[r:HAS_PERMISSION {
		permission: perm.permission,
		permissionType: perm.permissionType,
		consentType: perm.consentType,
		id: perm.id
	}]->(target)
	SET r.source = "Microsoft Graph",
		r.type = perm.type,
		r.resourceAppId = perm.resourceAppId,
		r.resourceAppName = perm.resourceAppName,
		r.grantedFor = perm.grantedFor,
		r.createdDateTime = perm.createdDateTime,
		r.expiryDateTime = perm.expiryDateTime,
		r.appRoleId = perm.appRoleId,
		r.scope = perm.scope,
		r.sourceLocation = perm.source,
		r.lastUpdated = datetime()
	RETURN count(r) as created
	`

	// Convert permissions to map format for Cypher
	var permissionMaps []map[string]interface{}
	for _, perm := range permissions {
		permissionMaps = append(permissionMaps, map[string]interface{}{
			"id":                   l.normalizeResourceId(perm.ID),
			"type":                 perm.Type,
			"servicePrincipalId":   l.normalizeResourceId(perm.ServicePrincipalID),
			"servicePrincipalName": perm.ServicePrincipalName,
			"userId":               l.normalizeResourceId(perm.UserID),
			"userName":             perm.UserName,
			"groupId":              l.normalizeResourceId(perm.GroupID),
			"groupName":            perm.GroupName,
			"resourceAppId":        l.normalizeResourceId(perm.ResourceAppID),
			"resourceAppName":      perm.ResourceAppName,
			"permissionType":       perm.PermissionType,
			"permission":           perm.Permission,
			"consentType":          perm.ConsentType,
			"grantedFor":           perm.GrantedFor,
			"createdDateTime":      perm.CreatedDateTime,
			"expiryDateTime":       perm.ExpiryDateTime,
			"appRoleId":            perm.AppRoleID,
			"scope":                perm.Scope,
			"source":               perm.Source,
		})
	}

	params := map[string]interface{}{
		"permissions": permissionMaps,
	}

	ctx := context.Background()
	result, err := neo4j.ExecuteQuery(ctx, l.driver, cypher, params, neo4j.EagerResultTransformer)
	if err != nil {
		return 0, fmt.Errorf("failed to create Graph permission relationships: %w", err)
	}

	created := 0
	if len(result.Records) > 0 {
		if createdValue, exists := result.Records[0].Get("created"); exists {
			if createdInt, ok := createdValue.(int64); ok {
				created = int(createdInt)
			}
		}
		l.Logger.Info(fmt.Sprintf("Batch %d/%d: Created %d Graph permission edges", batchNum, totalBatches, created))
	}

	return created, nil
}

// extractGraphPermissionsFromAzureAD extracts oauth2PermissionGrants and appRoleAssignments from Azure AD data
func (l *Neo4jImporterLink) extractGraphPermissionsFromAzureAD(azureADMap map[string]interface{}, allGraphPermissions []CompleteGraphPermission) []CompleteGraphPermission {
	// Process oauth2PermissionGrants
	if oauth2Grants, exists := azureADMap["oauth2PermissionGrants"]; exists {
		if grantsList, ok := oauth2Grants.([]interface{}); ok {
			l.Logger.Info(fmt.Sprintf("Processing %d oauth2PermissionGrants", len(grantsList)))
			for _, grantInterface := range grantsList {
				if grantData, ok := grantInterface.(map[string]interface{}); ok {
					permission := CompleteGraphPermission{
						ID:                l.getStringField(grantData, "id"),
						Type:              "oauth2PermissionGrant",
						ServicePrincipalID: l.getStringField(grantData, "clientId"),
						ServicePrincipalName: "", // Will be resolved by Neo4j query
						UserID:            l.getStringField(grantData, "principalId"),
						UserName:          "", // Will be resolved by Neo4j query
						ResourceAppID:     l.getStringField(grantData, "resourceId"),
						ResourceAppName:   "", // Will be resolved by Neo4j query
						PermissionType:    "Delegated",
						Permission:        l.getStringField(grantData, "scope"),
						ConsentType:       l.getStringField(grantData, "consentType"),
						GrantedFor:        "User",
						CreatedDateTime:   "", // Not available in oauth2PermissionGrants
						ExpiryDateTime:    l.getStringField(grantData, "expiryTime"),
						Scope:             l.getStringField(grantData, "scope"),
						Source:            "oauth2PermissionGrants",
					}
					allGraphPermissions = append(allGraphPermissions, permission)
				}
			}
		}
	}

	// Process appRoleAssignments
	if appRoles, exists := azureADMap["appRoleAssignments"]; exists {
		if rolesList, ok := appRoles.([]interface{}); ok {
			l.Logger.Info(fmt.Sprintf("Processing %d appRoleAssignments", len(rolesList)))
			for _, roleInterface := range rolesList {
				if roleData, ok := roleInterface.(map[string]interface{}); ok {
					permission := CompleteGraphPermission{
						ID:                l.getStringField(roleData, "id"),
						Type:              "appRoleAssignment",
						ServicePrincipalID: l.getStringField(roleData, "principalId"),
						ServicePrincipalName: "", // Will be resolved by Neo4j query
						ResourceAppID:     l.getStringField(roleData, "resourceId"),
						ResourceAppName:   "", // Will be resolved by Neo4j query
						PermissionType:    "Application",
						Permission:        l.getGraphPermissionName(l.getStringField(roleData, "appRoleId")),
						ConsentType:       "AllPrincipals",
						GrantedFor:        "Application",
						CreatedDateTime:   l.getStringField(roleData, "createdDateTime"),
						AppRoleID:         l.getStringField(roleData, "appRoleId"),
						Source:            "appRoleAssignments",
					}
					allGraphPermissions = append(allGraphPermissions, permission)
				}
			}
		}
	}

	return allGraphPermissions
}

func (l *Neo4jImporterLink) createApplicationOwnershipEdges() error {
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	if azureAD == nil {
		l.Logger.Info("No azure_ad data found for application ownership")
		return nil
	}

	var totalEdges int

	// Process application ownership - direct ownership relationships
	applicationOwnership := l.getArrayValue(azureAD, "applicationOwnership")
	if len(applicationOwnership) > 0 {
		count, err := l.createApplicationOwnershipDirectEdges(applicationOwnership)
		if err != nil {
			return fmt.Errorf("failed to create direct ownership edges: %w", err)
		}
		totalEdges += count
		l.edgeCounts["OWNS"] = count
	}

	// Process group ownership - direct ownership relationships
	groupOwnership := l.getArrayValue(azureAD, "groupOwnership")
	if len(groupOwnership) > 0 {
		count, err := l.createGroupOwnershipDirectEdges(groupOwnership)
		if err != nil {
			return fmt.Errorf("failed to create group ownership edges: %w", err)
		}
		totalEdges += count
		l.edgeCounts["OWNS"] += count // Add to existing OWNS count
	}

	// Process service principal ownership - direct ownership relationships
	servicePrincipalOwnership := l.getArrayValue(azureAD, "servicePrincipalOwnership")
	if len(servicePrincipalOwnership) > 0 {
		count, err := l.createServicePrincipalOwnershipDirectEdges(servicePrincipalOwnership)
		if err != nil {
			return fmt.Errorf("failed to create service principal ownership edges: %w", err)
		}
		totalEdges += count
		l.edgeCounts["OWNS"] += count // Add to existing OWNS count
	}

	if totalEdges > 0 {
		l.Logger.Info("Created application ownership edges", "total", totalEdges)
	} else {
		l.Logger.Info("No application ownership data to process")
	}

	return nil
}

func (l *Neo4jImporterLink) createApplicationOwnershipDirectEdges(applicationOwnership []interface{}) (int, error) {
	if len(applicationOwnership) == 0 {
		return 0, nil
	}

	l.Logger.Info("Creating direct application ownership edges", "count", len(applicationOwnership))

	var edges []map[string]interface{}
	currentTime := time.Now().Unix()

	for _, item := range applicationOwnership {
		ownershipMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		applicationID := l.getStringValue(ownershipMap, "applicationId")
		if applicationID == "" {
			continue
		}

		ownerID := l.getStringValue(ownershipMap, "ownerId")
		if ownerID == "" {
			continue
		}

		edge := map[string]interface{}{
			"sourceId":    ownerID,
			"targetId":    applicationID,
			"source":      "ApplicationOwnership",
			"createdAt":   currentTime,
		}
		edges = append(edges, edge)
	}

	if len(edges) == 0 {
		l.Logger.Info("No valid application ownership edges to create")
		return 0, nil
	}

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: ""})
	defer session.Close(ctx)

	batchSize := 500
	totalProcessed := 0

	for i := 0; i < len(edges); i += batchSize {
		end := i + batchSize
		if end > len(edges) {
			end = len(edges)
		}
		batch := edges[i:end]

		query := `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (target {id: edge.targetId})
		WHERE toLower(target.resourceType) = "microsoft.directoryservices/applications"
		MERGE (source)-[r:OWNS]->(target)
		SET r.source = edge.source,
		    r.createdAt = edge.createdAt
		RETURN count(r) as created`

		result, err := session.Run(ctx, query, map[string]interface{}{"edges": batch})
		if err != nil {
			return totalProcessed, fmt.Errorf("failed to create ownership edges batch: %w", err)
		}

		if result.Next(ctx) {
			if count, ok := result.Record().Get("created"); ok {
				if c, ok := count.(int64); ok {
					totalProcessed += int(c)
				}
			}
		}

		if err := result.Err(); err != nil {
			return totalProcessed, fmt.Errorf("error processing ownership edges batch: %w", err)
		}
	}

	l.Logger.Info("Created direct ownership edges", "count", totalProcessed)
	return totalProcessed, nil
}

func (l *Neo4jImporterLink) createGroupOwnershipDirectEdges(groupOwnership []interface{}) (int, error) {
	if len(groupOwnership) == 0 {
		return 0, nil
	}

	l.Logger.Info("Creating direct group ownership edges", "count", len(groupOwnership))

	var edges []map[string]interface{}
	currentTime := time.Now().Unix()

	for _, item := range groupOwnership {
		ownershipMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		groupID := l.getStringValue(ownershipMap, "groupId")
		if groupID == "" {
			continue
		}

		ownerID := l.getStringValue(ownershipMap, "ownerId")
		if ownerID == "" {
			continue
		}

		edge := map[string]interface{}{
			"sourceId":    ownerID,
			"targetId":    groupID,
			"source":      "GroupOwnership",
			"createdAt":   currentTime,
		}
		edges = append(edges, edge)
	}

	if len(edges) == 0 {
		l.Logger.Info("No valid group ownership edges to create")
		return 0, nil
	}

	// Process in batches (same pattern as application ownership)
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	batchSize := 1000
	totalProcessed := 0

	for i := 0; i < len(edges); i += batchSize {
		end := i + batchSize
		if end > len(edges) {
			end = len(edges)
		}
		batch := edges[i:end]

		query := `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (target {id: edge.targetId})
		WHERE toLower(target.resourceType) = "microsoft.directoryservices/groups"
		MERGE (source)-[r:OWNS]->(target)
		SET r.source = edge.source,
		    r.createdAt = edge.createdAt
		RETURN count(r) as created`

		result, err := session.Run(ctx, query, map[string]interface{}{"edges": batch})
		if err != nil {
			return totalProcessed, fmt.Errorf("failed to create group ownership edges batch: %w", err)
		}

		if result.Next(ctx) {
			if count, ok := result.Record().Get("created"); ok {
				if c, ok := count.(int64); ok {
					totalProcessed += int(c)
				}
			}
		}

		if err := result.Err(); err != nil {
			return totalProcessed, fmt.Errorf("error processing group ownership edges batch: %w", err)
		}
	}

	l.Logger.Info("Created direct group ownership edges", "count", totalProcessed)
	return totalProcessed, nil
}

func (l *Neo4jImporterLink) createServicePrincipalOwnershipDirectEdges(servicePrincipalOwnership []interface{}) (int, error) {
	if len(servicePrincipalOwnership) == 0 {
		return 0, nil
	}

	l.Logger.Info("Creating direct service principal ownership edges", "count", len(servicePrincipalOwnership))

	var edges []map[string]interface{}
	currentTime := time.Now().Unix()

	for _, item := range servicePrincipalOwnership {
		ownershipMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		servicePrincipalID := l.getStringValue(ownershipMap, "servicePrincipalId")
		if servicePrincipalID == "" {
			continue
		}

		ownerID := l.getStringValue(ownershipMap, "ownerId")
		if ownerID == "" {
			continue
		}

		edge := map[string]interface{}{
			"sourceId":    ownerID,
			"targetId":    servicePrincipalID,
			"source":      "ServicePrincipalOwnership",
			"createdAt":   currentTime,
		}
		edges = append(edges, edge)
	}

	if len(edges) == 0 {
		l.Logger.Info("No valid service principal ownership edges to create")
		return 0, nil
	}

	// Process in batches (same pattern as others)
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	batchSize := 1000
	totalProcessed := 0

	for i := 0; i < len(edges); i += batchSize {
		end := i + batchSize
		if end > len(edges) {
			end = len(edges)
		}
		batch := edges[i:end]

		query := `
		UNWIND $edges AS edge
		MATCH (source {id: edge.sourceId})
		MATCH (target {id: edge.targetId})
		WHERE toLower(target.resourceType) = "microsoft.directoryservices/serviceprincipals"
		MERGE (source)-[r:OWNS]->(target)
		SET r.source = edge.source,
		    r.createdAt = edge.createdAt
		RETURN count(r) as created`

		result, err := session.Run(ctx, query, map[string]interface{}{"edges": batch})
		if err != nil {
			return totalProcessed, fmt.Errorf("failed to create service principal ownership edges batch: %w", err)
		}

		if result.Next(ctx) {
			if count, ok := result.Record().Get("created"); ok {
				if c, ok := count.(int64); ok {
					totalProcessed += int(c)
				}
			}
		}

		if err := result.Err(); err != nil {
			return totalProcessed, fmt.Errorf("error processing service principal ownership edges batch: %w", err)
		}
	}

	l.Logger.Info("Created direct service principal ownership edges", "count", totalProcessed)
	return totalProcessed, nil
}

// getStringField safely extracts string fields from map data
func (l *Neo4jImporterLink) getStringField(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// createValidatedEscalationEdges creates only validated, production-ready CAN_ESCALATE edges
func (l *Neo4jImporterLink) createValidatedEscalationEdges() bool {
	message.Info("Creating validated CAN_ESCALATE edges - 19 production-ready attack vectors...")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	totalCreated := 0

	// VALIDATED ATTACK VECTORS - Only using existing schema relationships and properties
	validatedQueries := []struct {
		name  string
		query string
	}{
		// DIRECTORY ROLES (8 vectors) - Use HAS_PERMISSION.roleName/templateId
		{"DirectoryRole_GlobalAdmin", l.getValidatedGlobalAdminQuery()},
		{"DirectoryRole_PrivilegedRoleAdmin", l.getValidatedPrivilegedRoleAdminQuery()},
		{"DirectoryRole_PrivilegedAuthAdmin", l.getValidatedPrivilegedAuthAdminQuery()},
		{"DirectoryRole_ApplicationAdmin", l.getValidatedApplicationAdminQuery()},
		{"DirectoryRole_CloudApplicationAdmin", l.getValidatedCloudApplicationAdminQuery()},
		{"DirectoryRole_GroupsAdmin", l.getValidatedGroupsAdminQuery()},
		{"DirectoryRole_UserAdmin", l.getValidatedUserAdminQuery()},
		{"DirectoryRole_AuthenticationAdmin", l.getValidatedAuthenticationAdminQuery()},

		// GRAPH PERMISSIONS (6 vectors) - Query HAS_PERMISSION with source="Microsoft Graph"
		{"GraphPermission_RoleManagement", l.getValidatedGraphRoleManagementQuery()},
		{"GraphPermission_DirectoryReadWrite", l.getValidatedGraphDirectoryReadWriteQuery()},
		{"GraphPermission_ApplicationReadWrite", l.getValidatedGraphApplicationReadWriteQuery()},
		{"GraphPermission_AppRoleAssignment", l.getValidatedGraphAppRoleAssignmentQuery()},
		{"GraphPermission_UserReadWrite", l.getValidatedGraphUserReadWriteQuery()},
		{"GraphPermission_GroupReadWrite", l.getValidatedGraphGroupReadWriteQuery()},

		// AZURE RBAC (2 vectors) - Use HAS_PERMISSION.permission
		{"RBAC_Owner", l.getValidatedRBACOwnerQuery()},
		{"RBAC_UserAccessAdmin", l.getValidatedRBACUserAccessAdminQuery()},

		// GROUP-BASED: Removed - now handled via HAS_PERMISSION edges in Phase 2c
		// Group owners get HAS_PERMISSION edges to resources, then existing escalation queries process them

		// APPLICATION/SP (3 vectors) - Use OWNS, CONTAINS
		{"Application_SPOwnerAddSecret", l.getValidatedSPOwnerAddSecretQuery()},
		{"Application_AppOwnerAddSecret", l.getValidatedAppOwnerAddSecretQuery()},
		{"Application_ToServicePrincipal", l.getValidatedApplicationToServicePrincipalQuery()},

		// MANAGED IDENTITY (3 vectors) - Use CONTAINS
		{"ManagedIdentity_ToServicePrincipal", l.getValidatedManagedIdentityToServicePrincipalQuery()},
		{"Resource_ToSystemAssignedMI", l.getValidatedAzureResourceToManagedIdentityQuery()},
		{"Resource_ToUserAssignedMI", l.getValidatedAzureResourceToUserAssignedMIQuery()},
	}

	// Execute each query individually for better error handling and reporting
	for _, eq := range validatedQueries {
		result, err := session.Run(ctx, eq.query, map[string]interface{}{})
		if err != nil {
			l.Logger.Error("Failed to create CAN_ESCALATE edges", "query", eq.name, "error", err)
			continue
		}

		count := 0
		for result.Next(ctx) {
			if created, ok := result.Record().Get("created"); ok {
				if c, ok := created.(int64); ok {
					count += int(c)
				}
			}
		}

		if err := result.Err(); err != nil {
			l.Logger.Error("Error processing CAN_ESCALATE edges", "query", eq.name, "error", err)
			continue
		}

		if count > 0 {
			l.Logger.Info("Created CAN_ESCALATE edges", "query", eq.name, "count", count)
		}
		totalCreated += count
	}

	// Update edge counts for summary
	l.edgeCounts["CAN_ESCALATE"] += totalCreated

	message.Info("Completed validated CAN_ESCALATE edge creation", "total_created", totalCreated)
	return totalCreated > 0
}

// VALIDATED DIRECTORY ROLE FUNCTIONS (8 functions)

// getValidatedGlobalAdminQuery - Global Administrator complete tenant control
func (l *Neo4jImporterLink) getValidatedGlobalAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(tenant:Resource)
	WHERE perm.roleName = "Global Administrator" OR perm.templateId = "62e90394-69f5-4237-9190-012177145e10"
	WITH user, tenant, perm
	MATCH (tenant)-[:CONTAINS*]->(escalate_target:Resource)
	WHERE escalate_target <> user
	WITH DISTINCT user, escalate_target, perm
	CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "GlobalAdministrator",
	    r.condition = "Global Administrator role provides complete tenant control and can escalate to all resources in tenant hierarchy",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedPrivilegedRoleAdminQuery - Privileged Role Administrator can assign any directory role
func (l *Neo4jImporterLink) getValidatedPrivilegedRoleAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Privileged Role Administrator" OR perm.templateId = "e8611ab8-c189-46e8-94e1-60213ab1f814"
	WITH user, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> user
	  AND toLower(escalate_target.resourceType) IN ["microsoft.directoryservices/users", "microsoft.directoryservices/serviceprincipals", "microsoft.directoryservices/groups"]
	WITH DISTINCT user, escalate_target, perm
	CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "PrivilegedRoleAdmin",
	    r.condition = "Privileged Role Administrator can assign Global Administrator or any other directory role to any principal",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedPrivilegedAuthAdminQuery - Privileged Authentication Administrator can reset ANY user's auth
func (l *Neo4jImporterLink) getValidatedPrivilegedAuthAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Privileged Authentication Administrator" OR perm.templateId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
	WITH user, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> user AND toLower(escalate_target.resourceType) = "microsoft.directoryservices/users"
	WITH DISTINCT user, escalate_target, perm
	CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "PrivilegedAuthenticationAdmin",
	    r.condition = "Can reset passwords and authentication methods for ANY user including Global Administrators",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedApplicationAdminQuery - Application Administrator can add credentials to apps/SPs
func (l *Neo4jImporterLink) getValidatedApplicationAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Application Administrator" OR perm.templateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
	WITH user, perm
	MATCH (app:Resource)
	WHERE toLower(app.resourceType) IN ["microsoft.directoryservices/applications", "microsoft.directoryservices/serviceprincipals"]
	WITH DISTINCT user, app, perm
	CREATE (user)-[r:CAN_ESCALATE]->(app)
	SET r.method = "ApplicationAdmin",
	    r.condition = "Application Administrator can add credentials to applications/service principals to assume their identity and inherit permissions",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedCloudApplicationAdminQuery - Cloud Application Administrator except Application Proxy apps
func (l *Neo4jImporterLink) getValidatedCloudApplicationAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Cloud Application Administrator" OR perm.templateId = "158c047a-c907-4556-b7ef-446551a6b5f7"
	WITH user, perm
	MATCH (app:Resource)
	WHERE toLower(app.resourceType) IN ["microsoft.directoryservices/applications", "microsoft.directoryservices/serviceprincipals"]
	WITH DISTINCT user, app, perm
	CREATE (user)-[r:CAN_ESCALATE]->(app)
	SET r.method = "CloudApplicationAdmin",
	    r.condition = "Cloud Application Administrator can add credentials to applications and service principals",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGroupsAdminQuery - Groups Administrator full control over all groups
func (l *Neo4jImporterLink) getValidatedGroupsAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Groups Administrator" OR perm.templateId = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
	WITH user, perm
	MATCH (group:Resource)
	WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"
	WITH DISTINCT user, group, perm
	CREATE (user)-[r:CAN_ESCALATE]->(group)
	SET r.method = "GroupsAdministrator",
	    r.condition = "Groups Administrator can create, delete, and manage all aspects of groups including privileged group memberships",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedUserAdminQuery - User Administrator reset passwords for non-admin users
func (l *Neo4jImporterLink) getValidatedUserAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "User Administrator" OR perm.templateId = "fe930be7-5e62-47db-91af-98c3a49a38b1"
	WITH user, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> user AND toLower(escalate_target.resourceType) = "microsoft.directoryservices/users"
	  AND NOT EXISTS { (escalate_target)-[admin_perm:HAS_PERMISSION]->(:Resource) WHERE toLower(admin_perm.roleName) CONTAINS "administrator" }
	WITH DISTINCT user, escalate_target, perm
	CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "UserAdministrator",
	    r.condition = "Can reset passwords and modify properties of non-administrator users",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedAuthenticationAdminQuery - Authentication Administrator for non-admin users
func (l *Neo4jImporterLink) getValidatedAuthenticationAdminQuery() string {
	return `
	MATCH (user:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.roleName = "Authentication Administrator" OR perm.templateId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
	WITH user, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> user AND toLower(escalate_target.resourceType) = "microsoft.directoryservices/users"
	  AND NOT EXISTS { (escalate_target)-[admin_perm:HAS_PERMISSION]->(:Resource) WHERE toLower(admin_perm.roleName) CONTAINS "administrator" }
	WITH DISTINCT user, escalate_target, perm
	CREATE (user)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "AuthenticationAdmin",
	    r.condition = "Can reset authentication methods including passwords and MFA for non-administrator users",
	    r.category = "DirectoryRole",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// VALIDATED GRAPH PERMISSION FUNCTIONS (6 functions)

// getValidatedGraphRoleManagementQuery - RoleManagement.ReadWrite.Directory permission
func (l *Neo4jImporterLink) getValidatedGraphRoleManagementQuery() string {
	return `
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.source = "Microsoft Graph"
	  AND perm.permission = "RoleManagement.ReadWrite.Directory"
	  AND perm.permissionType = "Application"
	  AND perm.consentType = "AllPrincipals"
	WITH sp, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> sp
	  AND toLower(escalate_target.resourceType) IN ["microsoft.directoryservices/users", "microsoft.directoryservices/serviceprincipals", "microsoft.directoryservices/groups"]
	WITH DISTINCT sp, escalate_target, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "GraphRoleManagement",
	    r.condition = "Service Principal with RoleManagement.ReadWrite.Directory can directly assign Global Administrator or any directory role to any principal",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGraphDirectoryReadWriteQuery - Directory.ReadWrite.All permission
func (l *Neo4jImporterLink) getValidatedGraphDirectoryReadWriteQuery() string {
	return `
	// Match HAS_PERMISSION for Directory.ReadWrite.All (now unified with Graph permissions)
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.permission = "Directory.ReadWrite.All"
	  AND (perm.source = "Microsoft Graph" OR perm.source = "Graph API OAuth2 Grant")
	  AND (perm.permissionType = "Application" OR perm.permissionType IS NULL)
	  AND (perm.consentType = "AllPrincipals" OR perm.consentType IS NULL)
	WITH sp, perm
	MATCH (escalate_target:Resource)
	WHERE escalate_target <> sp
	  AND toLower(escalate_target.resourceType) STARTS WITH "microsoft.directoryservices/"
	WITH DISTINCT sp, escalate_target, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "Directory.ReadWrite.All",
	    r.condition = "Service Principal with Directory.ReadWrite.All can modify any directory object including role assignments",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGraphApplicationReadWriteQuery - Application.ReadWrite.All permission
func (l *Neo4jImporterLink) getValidatedGraphApplicationReadWriteQuery() string {
	return `
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.source = "Microsoft Graph"
	  AND perm.permission = "Application.ReadWrite.All"
	  AND perm.permissionType = "Application"
	  AND perm.consentType = "AllPrincipals"
	WITH sp, perm
	MATCH (escalate_target:Resource)
	WHERE toLower(escalate_target.resourceType) IN ["microsoft.directoryservices/applications", "microsoft.directoryservices/serviceprincipals"] AND escalate_target <> sp
	WITH DISTINCT sp, escalate_target, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "GraphApplicationReadWrite",
	    r.condition = "Service Principal with Application.ReadWrite.All can add credentials to any application or service principal then authenticate as them",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGraphAppRoleAssignmentQuery - AppRoleAssignment.ReadWrite.All permission
func (l *Neo4jImporterLink) getValidatedGraphAppRoleAssignmentQuery() string {
	return `
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.source = "Microsoft Graph"
	  AND perm.permission = "AppRoleAssignment.ReadWrite.All"
	  AND perm.permissionType = "Application"
	  AND perm.consentType = "AllPrincipals"
	WITH sp, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(sp)
	SET r.method = "GraphAppRoleAssignment",
	    r.condition = "Service Principal with AppRoleAssignment.ReadWrite.All can grant itself any permission including RoleManagement.ReadWrite.Directory",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGraphUserReadWriteQuery - User.ReadWrite.All permission
func (l *Neo4jImporterLink) getValidatedGraphUserReadWriteQuery() string {
	return `
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.source = "Microsoft Graph"
	  AND perm.permission = "User.ReadWrite.All"
	  AND perm.permissionType = "Application"
	  AND perm.consentType = "AllPrincipals"
	WITH sp, perm
	MATCH (user:Resource)
	WHERE toLower(user.resourceType) = "microsoft.directoryservices/users" AND user <> sp
	WITH DISTINCT sp, user, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(user)
	SET r.method = "GraphUserReadWrite",
	    r.condition = "Service Principal with User.ReadWrite.All can reset passwords, modify profiles, and disable accounts for any user",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedGraphGroupReadWriteQuery - Group.ReadWrite.All permission
func (l *Neo4jImporterLink) getValidatedGraphGroupReadWriteQuery() string {
	return `
	MATCH (sp:Resource)-[perm:HAS_PERMISSION]->(target:Resource)
	WHERE perm.source = "Microsoft Graph"
	  AND perm.permission = "Group.ReadWrite.All"
	  AND perm.permissionType = "Application"
	  AND perm.consentType = "AllPrincipals"
	WITH sp, perm
	MATCH (group:Resource)
	WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups" AND group <> sp
	WITH DISTINCT sp, group, perm
	CREATE (sp)-[r:CAN_ESCALATE]->(group)
	SET r.method = "GraphGroupReadWrite",
	    r.condition = "Service Principal with Group.ReadWrite.All can modify group memberships to add users to privileged groups",
	    r.category = "GraphPermission",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// VALIDATED AZURE RBAC FUNCTIONS (2 functions)

// getValidatedRBACOwnerQuery - Owner role at any scope
func (l *Neo4jImporterLink) getValidatedRBACOwnerQuery() string {
	return `
	MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(scope:Resource)
	WHERE perm.roleName = "Owner" OR perm.roleDefinitionId CONTAINS "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	WITH DISTINCT principal, scope, perm
	MATCH (scope)-[:CONTAINS*0..]->(escalate_target:Resource)
	WHERE escalate_target <> principal
	  AND NOT toLower(escalate_target.resourceType) STARTS WITH "microsoft.directoryservices/"
	WITH DISTINCT principal, escalate_target, perm
	CREATE (principal)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "AzureOwner",
	    r.condition = "Owner role at any scope provides full control over Azure resources within that scope and can assign roles",
	    r.category = "RBAC",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// getValidatedRBACUserAccessAdminQuery - User Access Administrator role
func (l *Neo4jImporterLink) getValidatedRBACUserAccessAdminQuery() string {
	return `
	MATCH (principal:Resource)-[perm:HAS_PERMISSION]->(scope:Resource)
	WHERE perm.roleName = "User Access Administrator" OR perm.roleDefinitionId CONTAINS "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
	WITH DISTINCT principal, scope, perm
	MATCH (scope)-[:CONTAINS*0..]->(escalate_target:Resource)
	WHERE escalate_target <> principal
	  AND NOT toLower(escalate_target.resourceType) STARTS WITH "microsoft.directoryservices/"
	WITH DISTINCT principal, escalate_target, perm
	CREATE (principal)-[r:CAN_ESCALATE]->(escalate_target)
	SET r.method = "UserAccessAdmin",
	    r.condition = "User Access Administrator can assign any Azure role within scope to compromise identities in that scope",
	    r.category = "RBAC",
	    r.sourcePermission = perm.source,
	    r.viaGroup = perm.viaGroupName,
	    r.grantedByGroups = perm.grantedByGroups,
	    r.targetRole = coalesce(perm.roleName, perm.permission)
	RETURN count(r) as created
	`
}

// VALIDATED GROUP-BASED FUNCTIONS (2 functions)

// getGroupOwnerPotentialPermissionQuery creates HAS_PERMISSION edges showing what permissions
// group owners can obtain by adding themselves to groups they own
func (l *Neo4jImporterLink) getGroupOwnerPotentialPermissionQuery() string {
	return `
	// Find owners of groups that have permissions
	MATCH (owner:Resource)-[:OWNS]->(group:Resource)
	WHERE toLower(group.resourceType) = "microsoft.directoryservices/groups"

	// Get the permissions the group has
	MATCH (group)-[groupPerm:HAS_PERMISSION]->(scope:Resource)
	WHERE (groupPerm.roleName IS NOT NULL OR groupPerm.permission IS NOT NULL)
	  AND NOT EXISTS {
		MATCH (owner)-[existing:HAS_PERMISSION]->(scope)
		WHERE (groupPerm.roleName IS NOT NULL AND existing.roleName = groupPerm.roleName)
		   OR (groupPerm.permission IS NOT NULL AND existing.permission = groupPerm.permission)
	  }

	WITH DISTINCT owner, group, groupPerm, scope

	// Create HAS_PERMISSION edge (not CAN_ESCALATE - let escalation logic handle that)
	CREATE (owner)-[r:HAS_PERMISSION]->(scope)
	SET r.permission = coalesce(groupPerm.roleName, groupPerm.permission),
		r.roleName = groupPerm.roleName,
		r.roleDefinitionId = groupPerm.roleDefinitionId,
		r.templateId = groupPerm.templateId,
		r.principalType = "User",
		r.source = "Owner of Entra User Group",
		r.grantedAt = groupPerm.grantedAt,
		r.targetResourceType = groupPerm.targetResourceType,
		r.viaGroupId = group.id,
		r.viaGroupName = group.displayName,
		r.requiresAction = "Add self to group",
		r.assignmentType = "Potential",
		r.createdAt = datetime()

	RETURN count(r) as created
	`
}

// VALIDATED APPLICATION/SP FUNCTIONS (3 functions)

// getValidatedSPOwnerAddSecretQuery - Service Principal owner can add secrets if not locked
func (l *Neo4jImporterLink) getValidatedSPOwnerAddSecretQuery() string {
	return `
	MATCH (owner:Resource)-[:OWNS]->(sp:Resource)
	WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
	WITH DISTINCT owner, sp
	CREATE (owner)-[r:CAN_ESCALATE]->(sp)
	SET r.method = "ServicePrincipalAddSecret",
	    r.condition = "Service Principal owner can add client secrets and modify SP configuration",
	    r.category = "ApplicationOwnership"
	RETURN count(r) as created
	`
}

// getValidatedAppOwnerAddSecretQuery - Application owner can add secrets to corresponding SP
func (l *Neo4jImporterLink) getValidatedAppOwnerAddSecretQuery() string {
	return `
	MATCH (owner:Resource)-[:OWNS]->(app:Resource)
	WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
	WITH owner, app
	MATCH (app)-[:CONTAINS]->(sp:Resource)
	WHERE toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
	WITH DISTINCT owner, sp
	CREATE (owner)-[r:CAN_ESCALATE]->(sp)
	SET r.method = "ApplicationAddSecret",
	    r.condition = "Application owner can add secrets to corresponding service principal",
	    r.category = "ApplicationOwnership"
	RETURN count(r) as created
	`
}

// getValidatedApplicationToServicePrincipalQuery - Applications can escalate to their Service Principals
func (l *Neo4jImporterLink) getValidatedApplicationToServicePrincipalQuery() string {
	return `
	MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
	WHERE toLower(app.resourceType) = "microsoft.directoryservices/applications"
	  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
	WITH DISTINCT app, sp
	CREATE (app)-[r:CAN_ESCALATE]->(sp)
	SET r.method = "ApplicationToServicePrincipal",
	    r.condition = "Application compromise (credential addition) provides access to corresponding Service Principal and all its permissions",
	    r.category = "ApplicationIdentity"
	RETURN count(r) as created
	`
}

// getValidatedManagedIdentityToServicePrincipalQuery - Managed Identities can escalate to their Service Principals
func (l *Neo4jImporterLink) getValidatedManagedIdentityToServicePrincipalQuery() string {
	return `
	MATCH (mi:Resource)-[:CONTAINS]->(sp:Resource)
	WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
	  AND toLower(sp.resourceType) = "microsoft.directoryservices/serviceprincipals"
	WITH DISTINCT mi, sp
	CREATE (mi)-[r:CAN_ESCALATE]->(sp)
	SET r.method = "ManagedIdentityToServicePrincipal",
	    r.condition = "Managed Identity compromise (via IMDS token theft from attached resource) provides access to Service Principal and all its permissions",
	    r.category = "ManagedIdentity"
	RETURN count(r) as created
	`
}
// getValidatedAzureResourceToManagedIdentityQuery - Azure resources with attached MIs can escalate to those identities
func (l *Neo4jImporterLink) getValidatedAzureResourceToManagedIdentityQuery() string {
	return `
	MATCH (resource:Resource)
	WHERE resource.identityPrincipalId IS NOT NULL
	  AND resource.identityType IS NOT NULL

	// Find the MI resource (either real user-assigned or synthetic system-assigned)
	MATCH (mi:Resource)
	WHERE toLower(mi.resourceType) CONTAINS "managedidentity"
	  AND mi.principalId = resource.identityPrincipalId

	WITH DISTINCT resource, mi
	CREATE (resource)-[r:CAN_ESCALATE]->(mi)
	SET r.method = "ResourceAttachedIdentity",
	    r.condition = "Resource compromise provides IMDS access to steal attached Managed Identity token",
	    r.category = "ManagedIdentity",
	    r.identityType = resource.identityType
	RETURN count(r) as created
	`
}

// getValidatedAzureResourceToUserAssignedMIQuery - Azure resources with user-assigned MIs can escalate to those identities
func (l *Neo4jImporterLink) getValidatedAzureResourceToUserAssignedMIQuery() string {
	return `
	MATCH (resource:Resource)
	WHERE resource.userAssignedIdentities IS NOT NULL
	  AND size(resource.userAssignedIdentities) > 0

	// Unwind the array of user-assigned MI resource IDs
	UNWIND resource.userAssignedIdentities AS miResourceId

	// Find the corresponding MI resource node
	MATCH (mi:Resource {id: miResourceId})
	WHERE toLower(mi.resourceType) CONTAINS "managedidentity"

	WITH DISTINCT resource, mi
	CREATE (resource)-[r:CAN_ESCALATE]->(mi)
	SET r.method = "ResourceAttachedUserAssignedIdentity",
	    r.condition = "Resource compromise provides IMDS access to steal attached User-Assigned Managed Identity token",
	    r.category = "ManagedIdentity",
	    r.assignmentType = "User-Assigned"
	RETURN count(r) as created
	`
}
