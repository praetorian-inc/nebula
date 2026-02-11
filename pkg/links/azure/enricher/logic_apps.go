package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// LogicAppsEnricher implements enrichment for Azure Logic Apps
type LogicAppsEnricher struct{}

func (l *LogicAppsEnricher) CanEnrich(templateID string) bool {
	return templateID == "logic_apps_public_access"
}

func (l *LogicAppsEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract accessEndpoint from resource.Properties["accessEndpoint"]
	accessEndpoint := ""
	if endpoint, ok := resource.Properties["accessEndpoint"].(string); ok {
		accessEndpoint = endpoint
	}

	if accessEndpoint == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Logic App access endpoint",
			ActualOutput: "Error: Logic App access endpoint is empty",
		})
		return commands
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	triggerDiscoveryCommand := l.testTriggerDiscovery(client, accessEndpoint)
	commands = append(commands, triggerDiscoveryCommand)

	cliCommand := l.cliCommand(resource.Name, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testTriggerDiscovery tests the Logic App trigger discovery endpoint
func (l *LogicAppsEnricher) testTriggerDiscovery(client *http.Client, endpoint string) Command {
	// Ensure endpoint doesn't end with slash
	endpoint = strings.TrimSuffix(endpoint, "/")
	triggersURL := fmt.Sprintf("%s/triggers?api-version=2016-10-01", endpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", triggersURL),
		Description:               "Test Logic App trigger discovery endpoint",
		ExpectedOutputDescription: "401 = requires SAS token | 403 = forbidden | 200 = triggers accessible (critical)",
	}

	resp, err := client.Get(triggersURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1500))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, truncateString(string(body), 800))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

// cliCommand returns an Azure CLI command for Logic Apps
func (l *LogicAppsEnricher) cliCommand(name, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az logic workflow show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Logic App workflow details",
		ExpectedOutputDescription: "Workflow details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
