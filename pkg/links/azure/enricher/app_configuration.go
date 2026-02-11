package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AppConfigurationEnricher implements enrichment for Azure App Configuration stores
type AppConfigurationEnricher struct{}

func (a *AppConfigurationEnricher) CanEnrich(templateID string) bool {
	return templateID == "app_configuration_public_access"
}

func (a *AppConfigurationEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	namespaceName := resource.Name
	if namespaceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing App Configuration store name",
			ActualOutput: "Error: App Configuration store name is empty",
		})
		return commands
	}

	appConfigEndpoint := fmt.Sprintf("https://%s.azconfig.io", namespaceName)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	mainEndpointCommand := a.testMainEndpoint(client, appConfigEndpoint)
	commands = append(commands, mainEndpointCommand)

	keyValuesEndpointCommand := a.testKeyValuesEndpoint(client, appConfigEndpoint)
	commands = append(commands, keyValuesEndpointCommand)

	cliCommand := a.cliCommand(namespaceName)
	commands = append(commands, cliCommand)

	return commands
}

// testMainEndpoint tests if the App Configuration endpoint is accessible
func (a *AppConfigurationEnricher) testMainEndpoint(client *http.Client, endpoint string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if App Configuration endpoint is accessible",
		ExpectedOutputDescription: "401 = requires authentication | 403 = forbidden | 200 = accessible without key (unusual)",
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, truncateString(string(body), 500))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

// testKeyValuesEndpoint tests the App Configuration key-values endpoint
func (a *AppConfigurationEnricher) testKeyValuesEndpoint(client *http.Client, endpoint string) Command {
	keyValuesURL := fmt.Sprintf("%s/kv", endpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", keyValuesURL),
		Description:               "Test App Configuration key-values endpoint",
		ExpectedOutputDescription: "401 = requires API key | 403 = forbidden | 200 = key-values accessible",
	}

	resp, err := client.Get(keyValuesURL)
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

// cliCommand returns an Azure CLI command for App Configuration
func (a *AppConfigurationEnricher) cliCommand(name string) Command {
	return Command{
		Command:                   fmt.Sprintf("az appconfig show --name %s", name),
		Description:               "Azure CLI command to show App Configuration details",
		ExpectedOutputDescription: "Configuration details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
