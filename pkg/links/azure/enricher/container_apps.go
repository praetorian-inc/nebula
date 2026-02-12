package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ContainerAppsEnricher implements enrichment for Azure Container Apps
type ContainerAppsEnricher struct{}

func (c *ContainerAppsEnricher) CanEnrich(templateID string) bool {
	return templateID == "container_apps_public_access"
}

func (c *ContainerAppsEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract FQDN from properties
	var fqdn string
	if ingressFqdn, ok := resource.Properties["ingressFqdn"].(string); ok && ingressFqdn != "" {
		fqdn = ingressFqdn
	} else if latestRevisionFqdn, ok := resource.Properties["latestRevisionFqdn"].(string); ok && latestRevisionFqdn != "" {
		fqdn = latestRevisionFqdn
	}

	if fqdn == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Container App FQDN",
			ActualOutput: "Error: Neither ingressFqdn nor latestRevisionFqdn available",
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

	fqdnEndpointCommand := c.testFQDNEndpoint(client, fqdn)
	commands = append(commands, fqdnEndpointCommand)

	healthEndpointCommand := c.testHealthEndpoint(client, fqdn)
	commands = append(commands, healthEndpointCommand)

	cliCommand := c.cliCommand(resource.Name, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testFQDNEndpoint tests if the Container App FQDN is accessible
func (c *ContainerAppsEnricher) testFQDNEndpoint(client *http.Client, fqdn string) Command {
	endpoint := fmt.Sprintf("https://%s", fqdn)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if Container App FQDN is accessible",
		ExpectedOutputDescription: "200 = app responding | 401/403 = auth required | 502 = backend error | Timeout = not reachable",
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

// testHealthEndpoint tests the Container App health endpoint
func (c *ContainerAppsEnricher) testHealthEndpoint(client *http.Client, fqdn string) Command {
	// Try /health first, then /healthz as fallback
	healthURL := fmt.Sprintf("https://%s/health", fqdn)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", healthURL),
		Description:               "Test Container App health endpoint",
		ExpectedOutputDescription: "200 = health endpoint accessible | 404 = no health endpoint | 401 = auth required",
	}

	resp, err := client.Get(healthURL)
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

// cliCommand returns an Azure CLI command for Container Apps
func (c *ContainerAppsEnricher) cliCommand(name, resourceGroup string) Command {
	// Handle empty values
	if name == "" || resourceGroup == "" {
		return Command{
			Command:                   "# Missing container app name or resource group",
			Description:               "Azure CLI command to show Container App details",
			ExpectedOutputDescription: "Container App details = accessible via Azure API | Error = access denied",
			ActualOutput:              "Error: Cannot generate CLI command - missing name or resource group",
		}
	}

	return Command{
		Command:                   fmt.Sprintf("az containerapp show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Container App details",
		ExpectedOutputDescription: "Container App details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
