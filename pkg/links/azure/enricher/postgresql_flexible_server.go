package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// PostgreSQLFlexibleServerEnricher implements enrichment for PostgreSQL Flexible Server instances
type PostgreSQLFlexibleServerEnricher struct{}

func (p *PostgreSQLFlexibleServerEnricher) CanEnrich(templateID string) bool {
	return templateID == "postgresql_flexible_server_public_access"
}

func (p *PostgreSQLFlexibleServerEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract PostgreSQL Flexible Server name and construct FQDN
	serverName := resource.Name
	if serverName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing PostgreSQL Flexible Server name",
			ActualOutput: "Error: PostgreSQL Flexible Server name is empty",
		})
		return commands
	}

	// Construct PostgreSQL Flexible Server FQDN
	postgresServerFQDN := fmt.Sprintf("%s.postgres.database.azure.com", serverName)

	// Test 1: TCP connectivity to PostgreSQL port 5432
	conn, err := net.DialTimeout("tcp", postgresServerFQDN+":5432", 10*time.Second)

	tcpConnCommand := Command{
		Command:                   fmt.Sprintf("nc -zv %s 5432", postgresServerFQDN),
		Description:               "Test TCP connectivity to PostgreSQL port 5432",
		ExpectedOutputDescription: "Connection succeeded = accessible | Connection failed/timeout = blocked/firewall rules active",
	}

	if err != nil {
		tcpConnCommand.Error = err.Error()
		tcpConnCommand.ActualOutput = fmt.Sprintf("Connection failed: %s", err.Error())
		tcpConnCommand.ExitCode = 1
	} else {
		conn.Close()
		tcpConnCommand.ActualOutput = "Connection successful - PostgreSQL port is accessible"
		tcpConnCommand.ExitCode = 0
	}

	commands = append(commands, tcpConnCommand)

	// Test 2: PostgreSQL connection attempt with username and password
	username := "<USERNAME>"
	password := "<PASSWORD>"
	database := "postgres"

	psqlCommand := fmt.Sprintf("PGPASSWORD='%s' psql -h %s -U %s -d %s -c 'SELECT version();' -w --set=connect_timeout=10", password, postgresServerFQDN, username, database)
	description := fmt.Sprintf("Test PostgreSQL connection with credentials '%s:%s'", username, password)

	psqlTestCommand := Command{
		Command:                   psqlCommand,
		Description:               description,
		ExpectedOutputDescription: "Version info = authentication successful | Password authentication failed = invalid credentials | Connection failed = network/access issue",
		ActualOutput:              "Manual execution required - requires psql client tool",
	}

	commands = append(commands, psqlTestCommand)

	// Test 3: Retrieve PostgreSQL Flexible Server firewall rules
	firewallCommand := p.getFirewallRulesCommand(ctx, resource)
	commands = append(commands, firewallCommand)

	return commands
}

// getFirewallRulesCommand retrieves firewall rules and creates a command with the results
func (p *PostgreSQLFlexibleServerEnricher) getFirewallRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az postgres flexible-server firewall-rule list --resource-group %s --server-name %s", resourceGroupName, serverName)

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve PostgreSQL Flexible Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get firewall rules from Azure SDK
	firewallRules, err := p.retrieveFirewallRules(ctx, subscriptionID, resourceGroupName, serverName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve PostgreSQL Flexible Server firewall rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "List of firewall rules with IP ranges | Error = insufficient permissions or server not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with firewall rules
	output := p.formatFirewallRules(firewallRules)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve PostgreSQL Flexible Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveFirewallRules gets firewall rules using Azure SDK
func (p *PostgreSQLFlexibleServerEnricher) retrieveFirewallRules(ctx context.Context, subscriptionID, resourceGroupName, serverName string) ([]*armpostgresqlflexibleservers.FirewallRule, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create firewall rules client directly (no client factory in this SDK)
	firewallClient, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall rules client: %w", err)
	}

	// List firewall rules
	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var rules []*armpostgresqlflexibleservers.FirewallRule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get firewall rules: %w", err)
		}

		rules = append(rules, page.Value...)
	}

	return rules, nil
}

// PostgreSQLFirewallRuleOutput represents the Azure CLI output format for firewall rules
type PostgreSQLFirewallRuleOutput struct {
	EndIPAddress   string `json:"endIpAddress"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	ResourceGroup  string `json:"resourceGroup"`
	StartIPAddress string `json:"startIpAddress"`
	Type           string `json:"type"`
}

// formatFirewallRules formats firewall rules to match Azure CLI JSON output
func (p *PostgreSQLFlexibleServerEnricher) formatFirewallRules(rules []*armpostgresqlflexibleservers.FirewallRule) string {
	if len(rules) == 0 {
		return "[]"
	}

	var outputRules []PostgreSQLFirewallRuleOutput

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		outputRule := PostgreSQLFirewallRuleOutput{
			Type: "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
		}

		if rule.Name != nil {
			outputRule.Name = *rule.Name
		}
		if rule.ID != nil {
			outputRule.ID = *rule.ID
		}
		if rule.Properties != nil {
			if rule.Properties.StartIPAddress != nil {
				outputRule.StartIPAddress = *rule.Properties.StartIPAddress
			}
			if rule.Properties.EndIPAddress != nil {
				outputRule.EndIPAddress = *rule.Properties.EndIPAddress
			}
		}

		// Extract resource group from ID if available
		if outputRule.ID != "" {
			parts := strings.Split(outputRule.ID, "/")
			for i, part := range parts {
				if part == "resourceGroups" && i+1 < len(parts) {
					outputRule.ResourceGroup = parts[i+1]
					break
				}
			}
		}

		outputRules = append(outputRules, outputRule)
	}

	jsonOutput, err := json.MarshalIndent(outputRules, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}

	return string(jsonOutput)
}
