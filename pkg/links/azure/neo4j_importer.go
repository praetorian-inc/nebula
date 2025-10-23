package azure

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

// Neo4jImporterLink imports consolidated AzureHunter data into Neo4j using real driver
// Direct port of AzureDumperConsolidated logic using actual Neo4j operations
type Neo4jImporterLink struct {
	*chain.Base
	consolidatedData map[string]interface{}
	nodeCounts       map[string]int
	edgeCounts       map[string]int
	driver           neo4j.DriverWithContext
	neo4jURL         string
	neo4jUser        string
	neo4jPassword    string
}

func NewNeo4jImporterLink(configs ...cfg.Config) chain.Link {
	l := &Neo4jImporterLink{}
	l.Base = chain.NewBase(l, configs...)
	l.nodeCounts = make(map[string]int)
	l.edgeCounts = make(map[string]int)
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
	message.Info("📊 AzureDumper - Neo4j Import Tool for AzureHunter Data")
	message.Info("🔍 Phase 1: Creating optimized Azure attack path nodes")

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

	// Step 5: Create all nodes
	if err := l.createAllNodes(); err != nil {
		return fmt.Errorf("failed to create nodes: %v", err)
	}

	// Step 6: Create all edges
	message.Info("🔗 Starting Phase 2: Edge creation")
	if err := l.createAllEdges(); err != nil {
		return fmt.Errorf("failed to create edges: %v", err)
	}

	// Step 7: Generate summary
	summary := l.generateImportSummary()
	message.Info("🎉 Edge creation completed successfully!")
	message.Info("📈 Ready for BloodHound attack path analysis")

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
		return fmt.Errorf("Neo4j connection test failed: %v", err)
	}

	if testValue, ok := l.convertToInt64(result); ok && testValue == 1 {
		message.Info("Successfully connected to Neo4j")
		return nil
	}

	return fmt.Errorf("unexpected test result: %v", result)
}

// clearDatabase clears existing data with enhanced constraint and data clearing
func (l *Neo4jImporterLink) clearDatabase() error {
	message.Info("=== Clearing Neo4j Database ===")

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Step 1: Count existing nodes first
	existingCount, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, "MATCH (n) RETURN count(n) AS nodeCount", nil)
		if err != nil {
			return 0, err
		}

		if result.Next(ctx) {
			return result.Record().Values[0], nil
		}
		return 0, nil
	})

	if err != nil {
		return fmt.Errorf("failed to count existing nodes: %v", err)
	}

	if count, ok := existingCount.(int64); ok && count > 0 {
		message.Info("Found %d existing nodes, clearing database...", count)

		// Step 2: Drop all existing constraints first to avoid validation issues
		message.Info("Dropping existing constraints...")
		constraintNames := []string{
			"user_object_id", "group_object_id", "sp_object_id", "app_object_id",
			"device_object_id", "resource_id", "ca_policy_id", "role_def_id",
			"pim_eligible_id", "pim_active_id", "tenant_id", "subscription_id", "resource_group_id",
		}

		for _, constraintName := range constraintNames {
			_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
				_, err := tx.Run(ctx, "DROP CONSTRAINT "+constraintName+" IF EXISTS", nil)
				return nil, err
			})
			// Ignore errors for constraints that don't exist
		}

		// Step 3: Clear all data
		_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
			return nil, err
		})

		if err != nil {
			return fmt.Errorf("failed to clear database: %v", err)
		}

		// Step 4: Verify database is actually empty
		verifyCount, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, "MATCH (n) RETURN count(n) AS nodeCount", nil)
			if err != nil {
				return 0, err
			}

			if result.Next(ctx) {
				return result.Record().Values[0], nil
			}
			return 0, nil
		})

		if err != nil {
			return fmt.Errorf("failed to verify database clearing: %v", err)
		}

		if verifyCount, ok := verifyCount.(int64); ok && verifyCount == 0 {
			message.Info("Database cleared successfully - verified empty")
		} else {
			return fmt.Errorf("database clearing verification failed: %d nodes still exist", verifyCount)
		}
	} else {
		message.Info("Database is already empty")
	}

	return nil
}

// createConstraints creates constraints - exactly like AzureDumperConsolidated
func (l *Neo4jImporterLink) createConstraints() error {
	message.Info("=== Creating Neo4j Constraints ===")

	constraints := []string{
		"CREATE CONSTRAINT user_object_id IF NOT EXISTS FOR (u:User) REQUIRE u.objectId IS UNIQUE",
		"CREATE CONSTRAINT group_object_id IF NOT EXISTS FOR (g:Group) REQUIRE g.objectId IS UNIQUE",
		"CREATE CONSTRAINT sp_object_id IF NOT EXISTS FOR (sp:ServicePrincipal) REQUIRE sp.objectId IS UNIQUE",
		"CREATE CONSTRAINT app_object_id IF NOT EXISTS FOR (app:Application) REQUIRE app.objectId IS UNIQUE",
		"CREATE CONSTRAINT device_object_id IF NOT EXISTS FOR (d:Device) REQUIRE d.objectId IS UNIQUE",
		"CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:AzureResource) REQUIRE r.resourceId IS UNIQUE",
		"CREATE CONSTRAINT ca_policy_id IF NOT EXISTS FOR (cp:ConditionalAccessPolicy) REQUIRE cp.policyId IS UNIQUE",
		"CREATE CONSTRAINT role_def_id IF NOT EXISTS FOR (rd:RoleDefinition) REQUIRE rd.roleId IS UNIQUE",
		"CREATE CONSTRAINT pim_eligible_id IF NOT EXISTS FOR (pe:PIMEligibleAssignment) REQUIRE pe.assignmentId IS UNIQUE",
		"CREATE CONSTRAINT pim_active_id IF NOT EXISTS FOR (pa:PIMActiveAssignment) REQUIRE pa.assignmentId IS UNIQUE",
		"CREATE CONSTRAINT tenant_id IF NOT EXISTS FOR (t:Tenant) REQUIRE t.objectId IS UNIQUE",
		"CREATE CONSTRAINT subscription_id IF NOT EXISTS FOR (s:Subscription) REQUIRE s.objectId IS UNIQUE",
		"CREATE CONSTRAINT resource_group_id IF NOT EXISTS FOR (rg:ResourceGroup) REQUIRE rg.objectId IS UNIQUE",
	}

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	for _, constraint := range constraints {
		_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			_, err := tx.Run(ctx, constraint, nil)
			return nil, err
		})

		constraintName := l.extractConstraintName(constraint)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				message.Info("Constraint already exists: %s", constraintName)
			} else {
				l.Logger.Error("Error creating constraint", "constraint", constraintName, "error", err)
			}
		} else {
			message.Info("Created constraint: %s", constraintName)
		}
	}

	return nil
}

// loadConsolidatedData loads the consolidated JSON file - handles both array and object formats
func (l *Neo4jImporterLink) loadConsolidatedData(dataFile string) error {
	message.Info("Loading AzureHunter data from: %s", dataFile)

	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return fmt.Errorf("AzureHunter data file not found: %s", dataFile)
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

	message.Info("Successfully loaded consolidated AzureHunter data")

	// Show data summary
	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	message.Info("Tenant ID: %s", l.getStringValue(metadata, "tenant_id"))
	message.Info("Collection timestamp: %s", l.getStringValue(metadata, "collection_timestamp"))

	return nil
}

// createAllNodes creates all node types with real Neo4j operations
func (l *Neo4jImporterLink) createAllNodes() error {
	message.Info("=== Creating All Azure Nodes ===")

	successCount := 0

	// Create Tenant first
	if l.createTenant() {
		successCount++
	}

	// Create Users
	if l.createUsers() {
		successCount++
	}

	// Create Groups
	if l.createGroups() {
		successCount++
	}

	// Create Service Principals
	if l.createServicePrincipals() {
		successCount++
	}

	// Create Applications
	if l.createApplications() {
		successCount++
	}

	// Create Devices
	if l.createDevices() {
		successCount++
	}

	// Create ConditionalAccessPolicies
	if l.createConditionalAccessPolicies() {
		successCount++
	}

	// Create PIM Assignments
	if l.createPIMAssignments() {
		successCount++
	}

	// Create RoleDefinitions
	if l.createRoleDefinitions() {
		successCount++
	}

	// Create Subscriptions
	if l.createSubscriptions() {
		successCount++
	}

	// Create ResourceGroups
	if l.createResourceGroups() {
		successCount++
	}

	// Create CertificateStores
	if l.createCertificateStores() {
		successCount++
	}

	// Create Azure Resources
	if l.createAzureResources() {
		successCount++
	}

	if successCount > 0 {
		message.Info("🎉 Node creation completed successfully!")
		return nil
	}

	return fmt.Errorf("node creation failed")
}

// createUsers creates User nodes with real Neo4j operations - exactly like AzureDumperConsolidated
func (l *Neo4jImporterLink) createUsers() bool {
	message.Info("=== Creating User Nodes ===")

	l.Logger.Debug("Checking consolidated data structure", "has_data", l.consolidatedData != nil)
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	l.Logger.Debug("Azure AD data", "has_azure_ad", azureAD != nil, "azure_ad_keys", fmt.Sprintf("%v", l.getMapKeys(azureAD)))
	users := l.getArrayValue(azureAD, "users")
	l.Logger.Debug("Users data", "user_count", len(users))

	if len(users) == 0 {
		message.Info("No users found")
		return false
	}

	cypher := `
	UNWIND $users AS user
	CREATE (u:User {
		objectId: user.id,
		displayName: user.displayName,
		userPrincipalName: user.userPrincipalName
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"users": users})
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
		l.Logger.Error("Error creating User nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["User"] = int(nodesCreated)
		message.Info("Created %d User nodes", nodesCreated)
		return true
	}

	l.Logger.Error("Unexpected result type from user creation", "result", result, "type", fmt.Sprintf("%T", result))
	return false
}

// createGroups creates Group nodes with real Neo4j operations
func (l *Neo4jImporterLink) createGroups() bool {
	message.Info("=== Creating Group Nodes ===")

	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	groups := l.getArrayValue(azureAD, "groups")

	if len(groups) == 0 {
		message.Info("No groups found")
		return false
	}

	cypher := `
	UNWIND $groups AS group
	CREATE (g:Group {
		objectId: group.id,
		displayName: group.displayName,
		description: group.description,
		groupTypes: group.groupTypes,
		securityEnabled: group.securityEnabled,
		mailEnabled: group.mailEnabled,
		createdDateTime: group.createdDateTime,
		membershipRule: group.membershipRule,
		mail: group.mail,
		mailNickname: group.mailNickname
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"groups": groups})
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
		l.Logger.Error("Error creating Group nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["Group"] = int(nodesCreated)
		message.Info("Created %d Group nodes", nodesCreated)
		return true
	}

	return false
}

// createServicePrincipals creates ServicePrincipal nodes with real Neo4j operations
func (l *Neo4jImporterLink) createServicePrincipals() bool {
	message.Info("=== Creating ServicePrincipal Nodes ===")

	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	servicePrincipals := l.getArrayValue(azureAD, "servicePrincipals")

	if len(servicePrincipals) == 0 {
		message.Info("No service principals found")
		return false
	}

	// Process key credentials for security analysis - exactly like AzureDumperConsolidated
	withCredentials := 0
	for _, sp := range servicePrincipals {
		if spMap, ok := sp.(map[string]interface{}); ok {
			keyCredentials := l.getArrayValue(spMap, "keyCredentials")
			hasCredentials := len(keyCredentials) > 0
			spMap["hasKeyCredentials"] = hasCredentials
			spMap["certificateCount"] = len(keyCredentials)

			// Check for signing key
			preferredThumbprint := l.getStringValue(spMap, "preferredTokenSigningKeyThumbprint")
			spMap["hasSigningKey"] = preferredThumbprint != ""

			if hasCredentials {
				withCredentials++
			}
		}
	}

	cypher := `
	UNWIND $servicePrincipals AS sp
	CREATE (s:ServicePrincipal {
		objectId: sp.id,
		displayName: sp.displayName,
		appId: sp.appId,
		servicePrincipalType: sp.servicePrincipalType,
		accountEnabled: sp.accountEnabled,
		hasKeyCredentials: sp.hasKeyCredentials,
		certificateCount: sp.certificateCount,
		hasSigningKey: sp.hasSigningKey,
		createdDateTime: sp.createdDateTime,
		appDisplayName: sp.appDisplayName,
		replyUrls: sp.replyUrls,
		signInAudience: sp.signInAudience
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"servicePrincipals": servicePrincipals})
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
		l.Logger.Error("Error creating ServicePrincipal nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["ServicePrincipal"] = int(nodesCreated)
		message.Info("Created %d ServicePrincipal nodes", nodesCreated)
		message.Info("%d have key credentials", withCredentials)
		return true
	}

	return false
}

// createApplications creates Application nodes with real Neo4j operations
func (l *Neo4jImporterLink) createApplications() bool {
	message.Info("=== Creating Application Nodes ===")

	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	applications := l.getArrayValue(azureAD, "applications")

	if len(applications) == 0 {
		message.Info("No applications found")
		return false
	}

	cypher := `
	UNWIND $applications AS app
	CREATE (a:Application {
		objectId: app.id,
		displayName: app.displayName,
		appId: app.appId,
		publisherDomain: app.publisherDomain,
		signInAudience: app.signInAudience,
		createdDateTime: app.createdDateTime
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"applications": applications})
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
		l.Logger.Error("Error creating Application nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["Application"] = int(nodesCreated)
		message.Info("Created %d Application nodes", nodesCreated)
		return true
	}

	return false
}

// createDevices creates Device nodes with real Neo4j operations
func (l *Neo4jImporterLink) createDevices() bool {
	message.Info("=== Creating Device Nodes ===")

	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	devices := l.getArrayValue(azureAD, "devices")

	if len(devices) == 0 {
		message.Info("No devices found")
		return false
	}

	cypher := `
	UNWIND $devices AS device
	CREATE (d:Device {
		objectId: device.id,
		displayName: device.displayName,
		deviceId: device.deviceId,
		operatingSystem: device.operatingSystem,
		operatingSystemVersion: device.operatingSystemVersion,
		trustType: device.trustType,
		isCompliant: device.isCompliant,
		isManaged: device.isManaged,
		accountEnabled: device.accountEnabled,
		createdDateTime: device.createdDateTime,
		manufacturer: device.manufacturer,
		model: device.model
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"devices": devices})
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
		l.Logger.Error("Error creating Device nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["Device"] = int(nodesCreated)
		message.Info("Created %d Device nodes", nodesCreated)
		return true
	}

	return false
}

// createTenant creates Tenant node with real Neo4j operations - exactly like AzureHunter
func (l *Neo4jImporterLink) createTenant() bool {
	message.Info("=== Creating Tenant Node ===")

	metadata := l.getMapValue(l.consolidatedData, "collection_metadata")
	tenantID := l.getStringValue(metadata, "tenant_id")

	if tenantID == "" {
		message.Info("No tenant ID found")
		return false
	}

	// Fix Cypher syntax - concatenate in Go instead of in Cypher
	displayName := tenantID + ".onmicrosoft.com"

	cypher := `
	CREATE (tenant:Tenant {
		objectId: $tenant_id,
		displayName: $display_name,
		tenantId: $tenant_id
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{
			"tenant_id": tenantID,
			"display_name": displayName,
		})
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
		l.Logger.Error("Error creating Tenant node", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["Tenant"] = int(nodesCreated)
		message.Info("Created %d Tenant node", nodesCreated)
		return true
	}

	return false
}

// createConditionalAccessPolicies creates ConditionalAccessPolicy nodes - exactly like AzureHunter
func (l *Neo4jImporterLink) createConditionalAccessPolicies() bool {
	message.Info("=== Creating ConditionalAccessPolicy Nodes ===")

	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	policies := l.getArrayValue(azureAD, "conditionalAccessPolicies")

	if len(policies) == 0 {
		message.Info("No conditional access policies found")
		return false
	}

	cypher := `
	UNWIND $policies AS policy
	CREATE (cp:ConditionalAccessPolicy {
		policyId: policy.id,
		displayName: policy.displayName,
		state: policy.state,
		createdDateTime: policy.createdDateTime,
		modifiedDateTime: policy.modifiedDateTime,
		templateId: policy.templateId
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"policies": policies})
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
		l.Logger.Error("Error creating ConditionalAccessPolicy nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["ConditionalAccessPolicy"] = int(nodesCreated)
		message.Info("Created %d ConditionalAccessPolicy nodes", nodesCreated)
		return true
	}

	return false
}

// createPIMAssignments creates PIMEligibleAssignment and PIMActiveAssignment nodes - exactly like AzureHunter
func (l *Neo4jImporterLink) createPIMAssignments() bool {
	message.Info("=== Creating PIM Assignment Nodes ===")

	pimData := l.getMapValue(l.consolidatedData, "pim")
	successCount := 0

	// Create PIM Eligible assignments
	eligibleAssignments := l.getArrayValue(pimData, "eligible_assignments")
	if len(eligibleAssignments) > 0 {
		cypher := `
		UNWIND $assignments AS assignment
		CREATE (pe:PIMEligibleAssignment {
			assignmentId: assignment.id,
			principalId: assignment.subject.id,
			roleDefinitionId: assignment.roleDefinition.id,
			scope: assignment.scopedResource.id,
			assignmentState: assignment.assignmentState,
			principalDisplayName: assignment.subject.displayName,
			roleDisplayName: assignment.roleDefinition.displayName
		})
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
		defer session.Close(ctx)

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": eligibleAssignments})
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
			l.Logger.Error("Error creating PIMEligibleAssignment nodes", "error", err)
		} else if nodesCreated, ok := l.convertToInt64(result); ok {
			l.nodeCounts["PIMEligibleAssignment"] = int(nodesCreated)
			message.Info("Created %d PIMEligibleAssignment nodes", nodesCreated)
			successCount++
		}
	}

	// Create PIM Active assignments
	activeAssignments := l.getArrayValue(pimData, "active_assignments")
	if len(activeAssignments) > 0 {
		cypher := `
		UNWIND $assignments AS assignment
		CREATE (pa:PIMActiveAssignment {
			assignmentId: assignment.id,
			principalId: assignment.subject.id,
			roleDefinitionId: assignment.roleDefinition.id,
			scope: assignment.scopedResource.id,
			assignmentState: assignment.assignmentState,
			principalDisplayName: assignment.subject.displayName,
			roleDisplayName: assignment.roleDefinition.displayName
		})
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
		defer session.Close(ctx)

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": activeAssignments})
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
			l.Logger.Error("Error creating PIMActiveAssignment nodes", "error", err)
		} else if nodesCreated, ok := l.convertToInt64(result); ok {
			l.nodeCounts["PIMActiveAssignment"] = int(nodesCreated)
			message.Info("Created %d PIMActiveAssignment nodes", nodesCreated)
			successCount++
		}
	}

	return successCount > 0 || (len(eligibleAssignments) == 0 && len(activeAssignments) == 0)
}

// createRoleDefinitions creates RoleDefinition nodes from Azure RM and Entra ID - exactly like AzureHunter
func (l *Neo4jImporterLink) createRoleDefinitions() bool {
	message.Info("=== Creating RoleDefinition Nodes ===")

	successCount := 0

	// Create Azure RM Role Definitions
	azureResourcesData := l.getMapValue(l.consolidatedData, "azure_resources")
	allRoles := []interface{}{}
	roleIDsSeen := make(map[string]bool)

	// Process each subscription's role definitions
	for subID, subDataInterface := range azureResourcesData {
		if subData, ok := subDataInterface.(map[string]interface{}); ok {
			roles := l.getArrayValue(subData, "azureRoleDefinitions")

			// Deduplicate role definitions
			for _, roleInterface := range roles {
				if role, ok := roleInterface.(map[string]interface{}); ok {
					roleID := l.getStringValue(role, "id")
					if roleID != "" && !roleIDsSeen[roleID] {
						roleIDsSeen[roleID] = true
						allRoles = append(allRoles, role)
					}
				}
			}
			l.Logger.Debug("Processed role definitions", "subscription", subID, "roles_found", len(roles))
		}
	}

	if len(allRoles) > 0 {
		cypher := `
		UNWIND $roles AS role
		CREATE (rd:RoleDefinition {
			roleId: role.id,
			displayName: role.properties.roleName,
			type: role.properties.type,
			description: role.properties.description,
			roleName: role.properties.roleName,
			assignableScopes: role.properties.assignableScopes
		})
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
		defer session.Close(ctx)

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"roles": allRoles})
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
			l.Logger.Error("Error creating RoleDefinition nodes", "error", err)
		} else if nodesCreated, ok := l.convertToInt64(result); ok {
			l.nodeCounts["RoleDefinition"] = int(nodesCreated)
			message.Info("Created %d RoleDefinition nodes", nodesCreated)
			successCount++
		}
	}

	// Create Entra ID Role Definitions
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	directoryRoles := l.getArrayValue(azureAD, "directoryRoles")

	if len(directoryRoles) > 0 {
		cypher := `
		UNWIND $roles AS role
		MERGE (rd:RoleDefinition {roleId: role.roleTemplateId})
		SET rd.displayName = role.displayName,
			rd.description = role.description,
			rd.type = 'EntraIDRole',
			rd.roleName = role.displayName
		`

		ctx := context.Background()
		session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
		defer session.Close(ctx)

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"roles": directoryRoles})
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
			l.Logger.Error("Error creating Entra ID RoleDefinition nodes", "error", err)
		} else if nodesCreated, ok := l.convertToInt64(result); ok {
			currentCount := l.nodeCounts["RoleDefinition"]
			l.nodeCounts["RoleDefinition"] = currentCount + int(nodesCreated)
			message.Info("Created/Updated %d Entra ID RoleDefinition nodes", nodesCreated)
			successCount++
		}
	}

	return successCount > 0 || (len(allRoles) == 0 && len(directoryRoles) == 0)
}

// createSubscriptions creates Subscription nodes - exactly like AzureHunter
func (l *Neo4jImporterLink) createSubscriptions() bool {
	message.Info("=== Creating Subscription Nodes ===")

	azureResourcesData := l.getMapValue(l.consolidatedData, "azure_resources")
	if len(azureResourcesData) == 0 {
		message.Info("No azure_resources data found")
		return false
	}

	subscriptionsData := []map[string]interface{}{}
	for subID := range azureResourcesData {
		subscriptionsData = append(subscriptionsData, map[string]interface{}{
			"subscriptionId": subID,
			"displayName":    fmt.Sprintf("Subscription %s", subID),
			"objectId":       subID,
		})
	}

	cypher := `
	UNWIND $subscriptions AS sub
	CREATE (s:Subscription {
		objectId: sub.subscriptionId,
		subscriptionId: sub.subscriptionId,
		displayName: sub.displayName
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"subscriptions": subscriptionsData})
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
		l.Logger.Error("Error creating Subscription nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["Subscription"] = int(nodesCreated)
		message.Info("Created %d Subscription nodes", nodesCreated)
		return true
	}

	return false
}

// createResourceGroups creates ResourceGroup nodes - exactly like AzureHunter
func (l *Neo4jImporterLink) createResourceGroups() bool {
	message.Info("=== Creating ResourceGroup Nodes ===")

	azureResourcesData := l.getMapValue(l.consolidatedData, "azure_resources")
	allResourceGroups := make(map[string]map[string]interface{}) // Use map to deduplicate

	for subID, subDataInterface := range azureResourcesData {
		if subData, ok := subDataInterface.(map[string]interface{}); ok {
			resources := l.getArrayValue(subData, "azureResources")
			for _, resourceInterface := range resources {
				if resource, ok := resourceInterface.(map[string]interface{}); ok {
					rgName := l.getStringValue(resource, "resourceGroup")
					if rgName != "" {
						rgID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subID, rgName)
						allResourceGroups[rgID] = map[string]interface{}{
							"resourceGroupId": rgID,
							"name":            rgName,
							"subscriptionId":  subID,
							"displayName":     rgName,
						}
					}
				}
			}
		}
	}

	if len(allResourceGroups) == 0 {
		message.Info("No resource groups found")
		return false
	}

	// Convert map to slice for Cypher
	rgData := make([]interface{}, 0, len(allResourceGroups))
	for _, rg := range allResourceGroups {
		rgData = append(rgData, rg)
	}

	cypher := `
	UNWIND $resourceGroups AS rg
	CREATE (r:ResourceGroup {
		objectId: rg.resourceGroupId,
		resourceGroupId: rg.resourceGroupId,
		name: rg.name,
		subscriptionId: rg.subscriptionId,
		displayName: rg.displayName
	})
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"resourceGroups": rgData})
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
		l.Logger.Error("Error creating ResourceGroup nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["ResourceGroup"] = int(nodesCreated)
		message.Info("Created %d ResourceGroup nodes", nodesCreated)
		return true
	}

	return false
}

// createCertificateStores creates CertificateStore nodes - exactly like AzureHunter
func (l *Neo4jImporterLink) createCertificateStores() bool {
	message.Info("=== Creating CertificateStore Nodes ===")

	// For now, this will be a placeholder as certificate store creation
	// requires certificate data that may not be present in all datasets
	// This matches AzureHunter's conditional creation approach

	message.Info("No certificate stores found")
	return false
}

// createAzureResources creates AzureResource nodes with real Neo4j operations
func (l *Neo4jImporterLink) createAzureResources() bool {
	message.Info("=== Creating AzureResource Nodes ===")

	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if len(azureResources) == 0 {
		message.Info("No Azure resources found")
		return false
	}

	var allResources []interface{}

	// Process each subscription's resources
	for _, subData := range azureResources {
		if subMap, ok := subData.(map[string]interface{}); ok {
			resources := l.getArrayValue(subMap, "azureResources")
			if len(resources) > 0 {
				// Pre-process for Neo4j compatibility - exactly like AzureDumperConsolidated
				for _, resource := range resources {
					if resourceMap, ok := resource.(map[string]interface{}); ok {
						// Create display name
						resourceType := l.getStringValue(resourceMap, "type")
						resourceName := l.getStringValue(resourceMap, "name")
						resourceTypeShort := resourceType
						if strings.Contains(resourceType, "/") {
							parts := strings.Split(resourceType, "/")
							resourceTypeShort = parts[len(parts)-1]
						}
						resourceMap["displayName"] = fmt.Sprintf("%s (%s)", resourceName, resourceTypeShort)

						// Extract identity data for Neo4j compatibility
						l.processIdentityData(resourceMap)
					}
				}
				allResources = append(allResources, resources...)
			}
		}
	}

	if len(allResources) == 0 {
		message.Info("No Azure resources found across all subscriptions")
		return false
	}

	cypher := `
	UNWIND $resources AS resource
	CREATE (r:AzureResource)
	SET r.displayName = resource.displayName,
		r.resourceId = resource.id,
		r.name = resource.name,
		r.resourceType = resource.type,
		r.kind = resource.kind,
		r.location = resource.location,
		r.subscriptionId = resource.subscriptionId,
		r.resourceGroup = resource.resourceGroup,
		r.identityType = resource.identityType,
		r.identityPrincipalId = resource.identityPrincipalId
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"resources": allResources})
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
		l.Logger.Error("Error creating AzureResource nodes", "error", err)
		return false
	}

	if nodesCreated, ok := l.convertToInt64(result); ok {
		l.nodeCounts["AzureResource"] = int(nodesCreated)
		message.Info("Created %d AzureResource nodes across all subscriptions", nodesCreated)
		return true
	}

	return false
}

// createAllEdges creates all relationship edges with real Neo4j operations
func (l *Neo4jImporterLink) createAllEdges() error {
	message.Info("=== Creating All Azure Edges ===")

	// Create group membership edges
	if l.createMemberOfEdges() {
		message.Info("AZMemberOf: SUCCESS")
	}

	// Create application to service principal edges
	if l.createRunsAsEdges() {
		message.Info("AZRunsAs: SUCCESS")
	}

	// Create RBAC edges (AZHasRole)
	if l.createHasRoleEdges() {
		message.Info("AZHasRole: SUCCESS")
	}

	// Create PIM edges (AZRoleEligible, AZRoleActive)
	if l.createPIMEdges() {
		message.Info("PIM Edges: SUCCESS")
	}

	// Create ARM role assignment edges (Principal → RoleDefinition)
	if l.createARMRoleAssignmentEdges() {
		message.Info("ARM Role Assignments: SUCCESS")
	}

	// Create direct RBAC resource edges (Principal → Resource) - temporarily disabled due to volume
	// if l.createRBACResourceEdges() {
	//	message.Info("RBAC Resource Edges: SUCCESS")
	// }

	// Create containment hierarchy edges (AZContains)
	if l.createContainmentEdges() {
		message.Info("AZContains: SUCCESS")
	}

	// Create role capability edges
	if l.createRoleCapabilityEdges() {
		message.Info("Role Capabilities: SUCCESS")
	}

	// Create Key Vault permission edges
	if l.createKeyVaultPermissionEdges() {
		message.Info("Key Vault Permissions: SUCCESS")
	}

	return nil
}

// createMemberOfEdges creates AZMemberOf edges with real Neo4j operations
func (l *Neo4jImporterLink) createMemberOfEdges() bool {
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	groupMemberships := l.getArrayValue(azureAD, "groupMemberships")

	if len(groupMemberships) == 0 {
		return false
	}

	cypher := `
	UNWIND $memberships AS membership
	MATCH (member {objectId: membership.memberId})
	MATCH (group:Group {objectId: membership.groupId})
	MERGE (member)-[:AZMemberOf]->(group)
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"memberships": groupMemberships})
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
		l.Logger.Error("Error creating AZMemberOf edges", "error", err)
		return false
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		l.edgeCounts["AZMemberOf"] = int(edgesCreated)
		message.Info("Created %d AZMemberOf edges", edgesCreated)
		return true
	}

	return false
}

// createRunsAsEdges creates AZRunsAs edges with real Neo4j operations
func (l *Neo4jImporterLink) createRunsAsEdges() bool {
	cypher := `
	MATCH (app:Application), (sp:ServicePrincipal)
	WHERE app.appId = sp.appId
	MERGE (app)-[:AZRunsAs]->(sp)
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

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
		l.Logger.Error("Error creating AZRunsAs edges", "error", err)
		return false
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		l.edgeCounts["AZRunsAs"] = int(edgesCreated)
		message.Info("Created %d AZRunsAs edges", edgesCreated)
		return true
	}

	return false
}

// createHasRoleEdges creates AZHasRole edges for RBAC assignments - exactly like AzureHunter
func (l *Neo4jImporterLink) createHasRoleEdges() bool {
	azureAD := l.getMapValue(l.consolidatedData, "azure_ad")
	directoryRoleAssignments := l.getArrayValue(azureAD, "directoryRoleAssignments")

	if len(directoryRoleAssignments) == 0 {
		return false
	}

	cypher := `
	UNWIND $assignments AS assignment
	MATCH (principal {objectId: assignment.principalId})
	MATCH (role:RoleDefinition {roleId: assignment.roleTemplateId})
	MERGE (principal)-[:AZHasRole]->(role)
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": directoryRoleAssignments})
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
		l.Logger.Error("Error creating AZHasRole edges", "error", err)
		return false
	}

	if edgesCreated, ok := l.convertToInt64(result); ok {
		l.edgeCounts["AZHasRole"] = int(edgesCreated)
		message.Info("Created %d AZHasRole edges", edgesCreated)
		return true
	}

	return false
}

// createPIMEdges creates PIM-related edges (AZRoleEligible, AZRoleActive) - exactly like AzureHunter
func (l *Neo4jImporterLink) createPIMEdges() bool {
	successCount := 0

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Create AZRoleEligible edges
	cypher1 := `
	MATCH (pim:PIMEligibleAssignment)
	MATCH (principal {objectId: pim.principalId})
	MATCH (role:RoleDefinition {roleId: pim.roleDefinitionId})
	MERGE (principal)-[:AZRoleEligible]->(role)
	`

	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher1, nil)
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
		l.Logger.Error("Error creating AZRoleEligible edges", "error", err)
	} else if edgesCreated, ok := l.convertToInt64(result); ok {
		l.edgeCounts["AZRoleEligible"] = int(edgesCreated)
		message.Info("Created %d AZRoleEligible edges", edgesCreated)
		successCount++
	}

	// Create AZRoleActive edges
	cypher2 := `
	MATCH (pim:PIMActiveAssignment)
	MATCH (principal {objectId: pim.principalId})
	MATCH (role:RoleDefinition {roleId: pim.roleDefinitionId})
	MERGE (principal)-[:AZRoleActive]->(role)
	`

	result2, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher2, nil)
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
		l.Logger.Error("Error creating AZRoleActive edges", "error", err)
	} else if edgesCreated, ok := l.convertToInt64(result2); ok {
		l.edgeCounts["AZRoleActive"] = int(edgesCreated)
		message.Info("Created %d AZRoleActive edges", edgesCreated)
		successCount++
	}

	return successCount > 0
}

// createARMRoleAssignmentEdges creates ARM role assignment edges for all Azure RBAC assignments
func (l *Neo4jImporterLink) createARMRoleAssignmentEdges() bool {
	message.Info("Creating ARM role assignment edges...")

	// Get Azure Resources data
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources == nil {
		message.Info("No azure_resources data found")
		return false
	}

	// Collect all ARM role assignments from all subscriptions
	var allAssignments []interface{}

	// Process each subscription's role assignments
	for subscriptionId, subscriptionData := range azureResources {
		subData, ok := subscriptionData.(map[string]interface{})
		if !ok {
			continue
		}

		// Process subscription level assignments
		subscriptionAssignments := l.getArrayValue(subData, "subscriptionRoleAssignments")
		for _, assignment := range subscriptionAssignments {
			if assignmentMap, ok := assignment.(map[string]interface{}); ok {
				assignmentMap["inheritanceLevel"] = "subscription"
				assignmentMap["subscriptionId"] = subscriptionId
				allAssignments = append(allAssignments, assignmentMap)
			}
		}

		// Process resource group level assignments
		rgAssignments := l.getArrayValue(subData, "resourceGroupRoleAssignments")
		for _, assignment := range rgAssignments {
			if assignmentMap, ok := assignment.(map[string]interface{}); ok {
				assignmentMap["inheritanceLevel"] = "resourcegroup"
				assignmentMap["subscriptionId"] = subscriptionId
				allAssignments = append(allAssignments, assignmentMap)
			}
		}

		// Process resource level assignments
		resourceAssignments := l.getArrayValue(subData, "resourceLevelRoleAssignments")
		for _, assignment := range resourceAssignments {
			if assignmentMap, ok := assignment.(map[string]interface{}); ok {
				assignmentMap["inheritanceLevel"] = "resource"
				assignmentMap["subscriptionId"] = subscriptionId
				allAssignments = append(allAssignments, assignmentMap)
			}
		}
	}

	if len(allAssignments) == 0 {
		message.Info("No ARM role assignments found")
		return false
	}

	message.Info("Found %d total ARM role assignments", len(allAssignments))

	// Process in batches to avoid timeouts
	batchSize := 15000
	totalEdgesCreated := 0

	// Create Cypher query to create edges
	cypher := `
	UNWIND $assignments AS assignment
	WITH assignment,
		 assignment.properties.principalId AS principalId,
		 assignment.properties.roleDefinitionId AS roleDefId,
		 assignment.properties.scope AS scope,
		 assignment.inheritanceLevel AS inheritanceLevel,
		 assignment.id AS assignmentId,
		 assignment.properties.principalType AS principalType
	WHERE principalId IS NOT NULL AND roleDefId IS NOT NULL
	MATCH (principal {objectId: principalId})
	MATCH (role:RoleDefinition)
	WHERE role.roleId ENDS WITH split(roleDefId, '/')[-1]
	MERGE (principal)-[r:AZRoleActive]->(role)
	SET r.scope = scope,
		r.inheritanceLevel = inheritanceLevel,
		r.assignmentId = assignmentId,
		r.principalType = principalType
	`

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Process in batches
	for i := 0; i < len(allAssignments); i += batchSize {
		end := i + batchSize
		if end > len(allAssignments) {
			end = len(allAssignments)
		}

		batch := allAssignments[i:end]
		message.Info("Processing ARM role assignment batch %d-%d of %d", i+1, end, len(allAssignments))

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": batch})
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
			l.Logger.Error("Error creating ARM role assignment edges for batch %d-%d", "start", i+1, "end", end, "error", err)
			continue
		}

		if edgesCreated, ok := l.convertToInt64(result); ok {
			totalEdgesCreated += int(edgesCreated)
			message.Info("Created %d edges in batch %d-%d", edgesCreated, i+1, end)
		}
	}

	if l.edgeCounts["AZRoleActive"] == 0 {
		l.edgeCounts["AZRoleActive"] = totalEdgesCreated
	} else {
		l.edgeCounts["AZRoleActive"] += totalEdgesCreated
	}

	message.Info("Created %d total ARM role assignment edges", totalEdgesCreated)
	return totalEdgesCreated > 0
}

// createRBACResourceEdges creates direct principal-to-resource RBAC edges for better attack path visualization
func (l *Neo4jImporterLink) createRBACResourceEdges() bool {
	message.Info("Creating direct principal-to-resource RBAC edges...")

	// Define Azure built-in role mappings with resource type filtering
	roleMap := map[string]map[string]interface{}{
		// Broad-scope roles (apply to all resource types)
		"ba92f5b4-2d11-453d-a403-e96b0029c9fe": {"edge_type": "AZOwner", "resource_filter": []string{}},        // Owner
		"b24988ac-6180-42a0-ab88-20f7382dd24c": {"edge_type": "AZContributor", "resource_filter": []string{}}, // Contributor
		"acdd72a7-3385-48ef-bd42-f606fba81ae7": {"edge_type": "AZReader", "resource_filter": []string{}},      // Reader

		// Resource-specific roles
		"9980e02c-c2be-4d73-94e8-173b1dc7cf3c": {"edge_type": "AZVMContributor", "resource_filter": []string{"microsoft.compute/virtualmachines"}},    // VM Contributor
		"de139f84-1756-47ae-9be6-808fbbe84772": {"edge_type": "AZWebsiteContributor", "resource_filter": []string{"microsoft.web/sites"}},              // Website Contributor
		"f25e0fa2-a7c8-4377-a976-54943a77a395": {"edge_type": "AZKeyVaultContributor", "resource_filter": []string{"microsoft.keyvault/vaults"}},        // Key Vault Contributor
		"17d1049b-9a84-46fb-8f53-869881c3d3ab": {"edge_type": "AZStorageAccountContributor", "resource_filter": []string{"microsoft.storage/storageaccounts"}}, // Storage Account Contributor
		"1c0163c0-47e6-4577-8991-ea5c82e286e4": {"edge_type": "AZVMAdminLogin", "resource_filter": []string{"microsoft.compute/virtualmachines"}},      // VM Admin Login
		"69a216fc-b8fb-44d8-bc22-1f3c2cd27a39": {"edge_type": "AZServiceBusDataSender", "resource_filter": []string{"microsoft.servicebus"}},           // Service Bus Data Sender
	}

	// Get Azure Resources data
	azureResources := l.getMapValue(l.consolidatedData, "azure_resources")
	if azureResources == nil {
		message.Info("No azure_resources data found")
		return false
	}

	// Collect all ARM role assignments from all subscriptions
	var allAssignments []interface{}

	// Process each subscription's role assignments
	for subscriptionId, subscriptionData := range azureResources {
		subData, ok := subscriptionData.(map[string]interface{})
		if !ok {
			continue
		}

		// Process all three levels of assignments
		for _, assignmentType := range []string{"subscriptionRoleAssignments", "resourceGroupRoleAssignments", "resourceLevelRoleAssignments"} {
			assignments := l.getArrayValue(subData, assignmentType)
			for _, assignment := range assignments {
				if assignmentMap, ok := assignment.(map[string]interface{}); ok {
					switch assignmentType {
					case "subscriptionRoleAssignments":
						assignmentMap["inheritanceLevel"] = "subscription"
					case "resourceGroupRoleAssignments":
						assignmentMap["inheritanceLevel"] = "resourcegroup"
					case "resourceLevelRoleAssignments":
						assignmentMap["inheritanceLevel"] = "resource"
					}
					assignmentMap["subscriptionId"] = subscriptionId
					allAssignments = append(allAssignments, assignmentMap)
				}
			}
		}
	}

	if len(allAssignments) == 0 {
		message.Info("No ARM role assignments found for resource edges")
		return false
	}

	// Process assignments and create edges grouped by edge type
	assignmentsByType := make(map[string][]map[string]interface{})
	customRoleAssignments := []map[string]interface{}{}

	for _, assignment := range allAssignments {
		assignmentMap, ok := assignment.(map[string]interface{})
		if !ok {
			continue
		}

		props := l.getMapValue(assignmentMap, "properties")
		if props == nil {
			continue
		}

		principalId := l.getStringValue(props, "principalId")
		roleDefinitionId := l.getStringValue(props, "roleDefinitionId")
		scope := l.getStringValue(props, "scope")

		if principalId == "" || roleDefinitionId == "" {
			continue
		}

		// Extract role ID from full roleDefinitionId path
		parts := strings.Split(roleDefinitionId, "/")
		roleId := parts[len(parts)-1]

		// Get resource context if available
		resourceContext := l.getMapValue(assignmentMap, "_resourceContext")
		var resourceId, resourceType string
		if resourceContext != nil {
			resourceId = l.getStringValue(resourceContext, "resourceId")
			resourceType = l.getStringValue(resourceContext, "resourceType")
		}

		// Check if this is a known role
		if roleConfig, exists := roleMap[roleId]; exists {
			edgeType := roleConfig["edge_type"].(string)
			resourceFilter := roleConfig["resource_filter"].([]string)

			// Apply resource type filtering
			if len(resourceFilter) > 0 {
				matchesFilter := false
				for _, filter := range resourceFilter {
					if strings.Contains(strings.ToLower(resourceType), strings.ToLower(filter)) {
						matchesFilter = true
						break
					}
				}
				if !matchesFilter {
					continue
				}
			}

			// Add to appropriate edge type group
			assignmentData := map[string]interface{}{
				"principalId":       principalId,
				"resourceId":        resourceId,
				"resourceType":      resourceType,
				"roleId":           roleId,
				"scope":            scope,
				"inheritanceLevel": assignmentMap["inheritanceLevel"],
				"assignmentId":     l.getStringValue(assignmentMap, "id"),
			}

			if assignmentsByType[edgeType] == nil {
				assignmentsByType[edgeType] = []map[string]interface{}{}
			}
			assignmentsByType[edgeType] = append(assignmentsByType[edgeType], assignmentData)
		} else {
			// Custom role - handle separately
			assignmentData := map[string]interface{}{
				"principalId":       principalId,
				"resourceId":        resourceId,
				"resourceType":      resourceType,
				"roleId":           roleId,
				"scope":            scope,
				"inheritanceLevel": assignmentMap["inheritanceLevel"],
				"assignmentId":     l.getStringValue(assignmentMap, "id"),
			}
			customRoleAssignments = append(customRoleAssignments, assignmentData)
		}
	}

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	totalEdgesCreated := 0

	// Create edges for known built-in roles
	for edgeType, assignments := range assignmentsByType {
		if len(assignments) == 0 {
			continue
		}

		cypher := fmt.Sprintf(`
		UNWIND $assignments AS assignment
		MATCH (principal {objectId: assignment.principalId})
		MATCH (resource:AzureResource {resourceId: assignment.resourceId})
		MERGE (principal)-[r:%s]->(resource)
		SET r.roleId = assignment.roleId,
			r.scope = assignment.scope,
			r.inheritanceLevel = assignment.inheritanceLevel,
			r.assignmentId = assignment.assignmentId
		`, edgeType)

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": assignments})
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
			l.Logger.Error("Error creating %s edges", "edgeType", edgeType, "error", err)
			continue
		}

		if edgesCreated, ok := l.convertToInt64(result); ok {
			l.edgeCounts[edgeType] = int(edgesCreated)
			message.Info("Created %d %s direct edges to resources", edgesCreated, edgeType)
			totalEdgesCreated += int(edgesCreated)
		}
	}

	// Create edges for custom roles
	if len(customRoleAssignments) > 0 {
		cypher := `
		UNWIND $assignments AS assignment
		MATCH (principal {objectId: assignment.principalId})
		MATCH (resource:AzureResource {resourceId: assignment.resourceId})
		MATCH (role:RoleDefinition)
		WHERE role.roleId ENDS WITH assignment.roleId
		MERGE (principal)-[r:AZCustomRole]->(resource)
		SET r.roleId = assignment.roleId,
			r.roleName = role.roleName,
			r.scope = assignment.scope,
			r.inheritanceLevel = assignment.inheritanceLevel,
			r.assignmentId = assignment.assignmentId
		`

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"assignments": customRoleAssignments})
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
			l.Logger.Error("Error creating AZCustomRole edges", "error", err)
		} else if edgesCreated, ok := l.convertToInt64(result); ok {
			l.edgeCounts["AZCustomRole"] = int(edgesCreated)
			message.Info("Created %d AZCustomRole direct edges to resources", edgesCreated)
			totalEdgesCreated += int(edgesCreated)
		}
	}

	message.Info("Created %d total direct principal-to-resource RBAC edges", totalEdgesCreated)
	return totalEdgesCreated > 0
}

// createContainmentEdges creates AZContains hierarchy edges - exactly like AzureHunter
func (l *Neo4jImporterLink) createContainmentEdges() bool {
	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	totalEdges := 0

	// Create Tenant → Subscription edges
	cypher1 := `
	MATCH (tenant:Tenant), (sub:Subscription)
	MERGE (tenant)-[:AZContains]->(sub)
	`

	result1, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher1, nil)
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
		l.Logger.Error("Error creating Tenant→Subscription edges", "error", err)
	} else if edgesCreated, ok := l.convertToInt64(result1); ok {
		message.Info("Created %d Tenant→Subscription AZContains edges", edgesCreated)
		totalEdges += int(edgesCreated)
	}

	// Create Subscription → ResourceGroup edges
	cypher2 := `
	MATCH (sub:Subscription), (rg:ResourceGroup)
	WHERE rg.subscriptionId = sub.subscriptionId
	MERGE (sub)-[:AZContains]->(rg)
	`

	result2, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher2, nil)
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
		l.Logger.Error("Error creating Subscription→ResourceGroup edges", "error", err)
	} else if edgesCreated, ok := l.convertToInt64(result2); ok {
		message.Info("Created %d Subscription→ResourceGroup AZContains edges", edgesCreated)
		totalEdges += int(edgesCreated)
	}

	// Create ResourceGroup → Resource edges
	cypher3 := `
	MATCH (rg:ResourceGroup), (resource:AzureResource)
	WHERE rg.subscriptionId = resource.subscriptionId
	  AND rg.name = resource.resourceGroup
	MERGE (rg)-[:AZContains]->(resource)
	`

	result3, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		result, err := tx.Run(ctx, cypher3, nil)
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
		l.Logger.Error("Error creating ResourceGroup→Resource edges", "error", err)
	} else if edgesCreated, ok := l.convertToInt64(result3); ok {
		message.Info("Created %d ResourceGroup→Resource AZContains edges", edgesCreated)
		totalEdges += int(edgesCreated)
	}

	l.edgeCounts["AZContains"] = totalEdges
	message.Info("Created %d total AZContains hierarchy edges", totalEdges)

	return totalEdges > 0
}

// createRoleCapabilityEdges creates role capability edges from RoleDefinitions - exactly like AzureHunter
func (l *Neo4jImporterLink) createRoleCapabilityEdges() bool {
	// Define role capability mappings following AzureHound standard
	roleCapabilities := []map[string]interface{}{
		// Tenant-level administrative roles (Entra ID ONLY)
		{"roleName": "Global Administrator", "edgeType": "AZGlobalAdmin", "targetType": "Tenant"},
		{"roleName": "Application Administrator", "edgeType": "AZApplicationAdmin", "targetType": "Tenant"},
		{"roleName": "User Administrator", "edgeType": "AZUserAdmin", "targetType": "Tenant"},
		{"roleName": "Security Administrator", "edgeType": "AZSecurityAdmin", "targetType": "Tenant"},
		{"roleName": "Privileged Role Administrator", "edgeType": "AZPrivilegedRoleAdmin", "targetType": "Tenant"},
		// Add more role mappings as needed
	}

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	totalEdges := 0

	for _, capability := range roleCapabilities {
		cypher := fmt.Sprintf(`
		MATCH (role:RoleDefinition)
		WHERE role.displayName = $roleName OR role.roleName = $roleName
		MATCH (target:%s)
		MERGE (role)-[:%s]->(target)
		`, capability["targetType"].(string), capability["edgeType"].(string))

		result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, cypher, map[string]interface{}{"roleName": capability["roleName"]})
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
			l.Logger.Error("Error creating role capability edges", "role", capability["roleName"], "error", err)
		} else if edgesCreated, ok := l.convertToInt64(result); ok {
			totalEdges += int(edgesCreated)
		}
	}

	if totalEdges > 0 {
		l.edgeCounts["RoleCapabilities"] = totalEdges
		message.Info("Created %d role capability edges", totalEdges)
		return true
	}

	return false
}

// createKeyVaultPermissionEdges creates Key Vault permission edges - exactly like AzureHunter
func (l *Neo4jImporterLink) createKeyVaultPermissionEdges() bool {
	azureResourcesData := l.getMapValue(l.consolidatedData, "azure_resources")
	totalEdges := 0

	ctx := context.Background()
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Process Key Vault access policies from each subscription
	for subID, subDataInterface := range azureResourcesData {
		if subData, ok := subDataInterface.(map[string]interface{}); ok {
			kvPolicies := l.getArrayValue(subData, "keyVaultAccessPolicies")

			for _, policyInterface := range kvPolicies {
				if policy, ok := policyInterface.(map[string]interface{}); ok {
					vaultID := l.getStringValue(policy, "vaultId")
					principalID := l.getStringValue(policy, "principalId")
					permissions := l.getMapValue(policy, "permissions")

					if vaultID != "" && principalID != "" {
						// Create AZGetCertificates edges
						if certs := l.getArrayValue(permissions, "certificates"); len(certs) > 0 {
							cypher := `
							MERGE (keyvault:AzureResource {resourceId: $vaultId})
							MATCH (principal {objectId: $principalId})
							MERGE (principal)-[:AZGetCertificates {permissions: $permissions}]->(keyvault)
							`

							result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
								result, err := tx.Run(ctx, cypher, map[string]interface{}{
									"vaultId":     vaultID,
									"principalId": principalID,
									"permissions": certs,
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

							if err == nil {
								if edgesCreated, ok := l.convertToInt64(result); ok {
									totalEdges += int(edgesCreated)
								}
							}
						}

						// Create AZGetSecrets edges
						if secrets := l.getArrayValue(permissions, "secrets"); len(secrets) > 0 {
							cypher := `
							MERGE (keyvault:AzureResource {resourceId: $vaultId})
							MATCH (principal {objectId: $principalId})
							MERGE (principal)-[:AZGetSecrets {permissions: $permissions}]->(keyvault)
							`

							result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
								result, err := tx.Run(ctx, cypher, map[string]interface{}{
									"vaultId":     vaultID,
									"principalId": principalID,
									"permissions": secrets,
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

							if err == nil {
								if edgesCreated, ok := l.convertToInt64(result); ok {
									totalEdges += int(edgesCreated)
								}
							}
						}

						// Create AZGetKeys edges
						if keys := l.getArrayValue(permissions, "keys"); len(keys) > 0 {
							cypher := `
							MERGE (keyvault:AzureResource {resourceId: $vaultId})
							MATCH (principal {objectId: $principalId})
							MERGE (principal)-[:AZGetKeys {permissions: $permissions}]->(keyvault)
							`

							result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
								result, err := tx.Run(ctx, cypher, map[string]interface{}{
									"vaultId":     vaultID,
									"principalId": principalID,
									"permissions": keys,
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

							if err == nil {
								if edgesCreated, ok := l.convertToInt64(result); ok {
									totalEdges += int(edgesCreated)
								}
							}
						}
					}
				}
			}
		}
		l.Logger.Debug("Processed Key Vault policies", "subscription", subID)
	}

	if totalEdges > 0 {
		l.edgeCounts["KeyVaultPermissions"] = totalEdges
		message.Info("Created %d Key Vault permission edges", totalEdges)
		return true
	}

	return false
}

// generateImportSummary generates the final import summary
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