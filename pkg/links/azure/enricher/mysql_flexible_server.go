package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// MySQLFlexibleServerEnricher implements enrichment for MySQL Flexible Server instances
type MySQLFlexibleServerEnricher struct{}

func (m *MySQLFlexibleServerEnricher) CanEnrich(templateID string) bool {
	return templateID == "mysql_flexible_server_public_access"
}

func (m *MySQLFlexibleServerEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract MySQL Flexible Server name and construct FQDN
	serverName := resource.Name
	if serverName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing MySQL Flexible Server name",
			ActualOutput: "Error: MySQL Flexible Server name is empty",
		})
		return commands
	}

	// Construct MySQL Flexible Server FQDN
	mysqlServerFQDN := fmt.Sprintf("%s.mysql.database.azure.com", serverName)

	// Test 1: TCP connectivity to MySQL port 3306
	conn, err := net.DialTimeout("tcp", mysqlServerFQDN+":3306", 10*time.Second)

	tcpConnCommand := Command{
		Command:                   fmt.Sprintf("nc -zv %s 3306", mysqlServerFQDN),
		Description:               "Test TCP connectivity to MySQL port 3306",
		ExpectedOutputDescription: "Connection succeeded = accessible | Connection failed/timeout = blocked/firewall rules active",
	}

	if err != nil {
		tcpConnCommand.Error = err.Error()
		tcpConnCommand.ActualOutput = fmt.Sprintf("Connection failed: %s", err.Error())
		tcpConnCommand.ExitCode = 1
	} else {
		conn.Close()
		tcpConnCommand.ActualOutput = "Connection successful - MySQL port is accessible"
		tcpConnCommand.ExitCode = 0
	}

	commands = append(commands, tcpConnCommand)

	// Test 2: MySQL connection attempt with username and password
	username := "<USERNAME>"
	password := "<PASSWORD>"

	mysqlCommand := fmt.Sprintf("mysql -h %s -u %s -p'%s' -e 'SELECT VERSION();' --connect-timeout=10", mysqlServerFQDN, username, password)
	description := fmt.Sprintf("Test MySQL connection with credentials '%s:%s'", username, password)

	mysqlTestCommand := Command{
		Command:                   mysqlCommand,
		Description:               description,
		ExpectedOutputDescription: "Version info = authentication successful | Access denied = invalid credentials | Connection failed = network/access issue",
		ActualOutput:              "Manual execution required - requires mysql client tool",
	}

	commands = append(commands, mysqlTestCommand)

	// Test 3: Retrieve MySQL Flexible Server firewall rules
	firewallCommand := m.getFirewallRulesCommand(ctx, resource)
	commands = append(commands, firewallCommand)

	return commands
}

// getFirewallRulesCommand retrieves firewall rules and creates a command with the results
func (m *MySQLFlexibleServerEnricher) getFirewallRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az mysql flexible-server firewall-rule list --resource-group %s --server-name %s", resourceGroupName, serverName)

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve MySQL Flexible Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get firewall rules from Azure SDK
	firewallRules, err := m.retrieveFirewallRules(ctx, subscriptionID, resourceGroupName, serverName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve MySQL Flexible Server firewall rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "List of firewall rules with IP ranges | Error = insufficient permissions or server not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with firewall rules
	output := m.formatFirewallRules(firewallRules)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve MySQL Flexible Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveFirewallRules gets firewall rules using Azure SDK
func (m *MySQLFlexibleServerEnricher) retrieveFirewallRules(ctx context.Context, subscriptionID, resourceGroupName, serverName string) ([]*armmysqlflexibleservers.FirewallRule, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create MySQL Flexible Servers client factory
	clientFactory, err := armmysqlflexibleservers.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory: %w", err)
	}

	// Create firewall rules client
	firewallClient := clientFactory.NewFirewallRulesClient()

	// List firewall rules
	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var rules []*armmysqlflexibleservers.FirewallRule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get firewall rules: %w", err)
		}

		rules = append(rules, page.Value...)
	}

	return rules, nil
}

// MySQLFirewallRuleOutput represents the Azure CLI output format for firewall rules
type MySQLFirewallRuleOutput struct {
	EndIPAddress   string `json:"endIpAddress"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	ResourceGroup  string `json:"resourceGroup"`
	StartIPAddress string `json:"startIpAddress"`
	Type           string `json:"type"`
}

// formatFirewallRules formats firewall rules to match Azure CLI JSON output
func (m *MySQLFlexibleServerEnricher) formatFirewallRules(rules []*armmysqlflexibleservers.FirewallRule) string {
	if len(rules) == 0 {
		return "[]"
	}

	var outputRules []MySQLFirewallRuleOutput

	for _, rule := range rules {
		if rule == nil {
			continue
		}

		outputRule := MySQLFirewallRuleOutput{
			Type: "Microsoft.DBforMySQL/flexibleServers/firewallRules",
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
