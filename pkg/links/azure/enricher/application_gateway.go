package enricher

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ApplicationGatewayEnricher implements enrichment for Azure Application Gateway instances
type ApplicationGatewayEnricher struct{}

func (a *ApplicationGatewayEnricher) CanEnrich(templateID string) bool {
	return templateID == "application_gateway_public_access"
}

func (a *ApplicationGatewayEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	gatewayName := resource.Name
	resourceGroup := resource.ResourceGroup
	if gatewayName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Application Gateway name",
			ActualOutput: "Error: Application Gateway name is empty",
		})
		return commands
	}

	if resourceGroup == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing resource group",
			ActualOutput: "Error: Resource group is empty",
		})
		return commands
	}

	// Extract publicIpId from resource properties
	publicIpId := ""
	if publicIpIdProp, exists := resource.Properties["publicIpId"].(string); exists && publicIpIdProp != "" {
		publicIpId = publicIpIdProp
	}

	// Test 1: Resolve public IP address (requires Azure CLI)
	resolveIPCmd := a.resolvePublicIP(publicIpId)
	commands = append(commands, resolveIPCmd)

	// Test 2: Check WAF configuration
	wafCmd := a.testWAFStatus(gatewayName, resourceGroup)
	commands = append(commands, wafCmd)

	// CLI fallback command
	cliCmd := a.cliCommand(gatewayName, resourceGroup)
	commands = append(commands, cliCmd)

	return commands
}

// resolvePublicIP generates CLI command to resolve public IP address
func (a *ApplicationGatewayEnricher) resolvePublicIP(publicIpId string) Command {
	if publicIpId == "" {
		return Command{
			Command:                   "",
			Description:               "Resolve public IP address of Application Gateway",
			ExpectedOutputDescription: "IP address = gateway has public IP | Error = IP not found",
			ActualOutput:              "Error: publicIpId not available in resource properties",
		}
	}

	return Command{
		Command:                   fmt.Sprintf("az network public-ip show --ids %s --query ipAddress -o tsv", publicIpId),
		Description:               "Resolve public IP address of Application Gateway",
		ExpectedOutputDescription: "IP address = gateway has public IP | Error = IP not found",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}

// testWAFStatus generates CLI command to check WAF configuration
func (a *ApplicationGatewayEnricher) testWAFStatus(name, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az network application-gateway waf-config show --gateway-name %s --resource-group %s", name, resourceGroup),
		Description:               "Check Application Gateway WAF configuration",
		ExpectedOutputDescription: "WAF config = WAF is enabled | Error = WAF not configured (higher risk)",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}

// cliCommand returns an Azure CLI fallback command for Application Gateway
func (a *ApplicationGatewayEnricher) cliCommand(name, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az network application-gateway show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Application Gateway details",
		ExpectedOutputDescription: "Gateway details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
