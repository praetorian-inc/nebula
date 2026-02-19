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

// SynapseEnricher implements enrichment for Azure Synapse Analytics workspaces
type SynapseEnricher struct{}

func (s *SynapseEnricher) CanEnrich(templateID string) bool {
	return templateID == "synapse_public_access"
}

func (s *SynapseEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	workspaceName := resource.Name
	if workspaceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Synapse workspace name",
			ActualOutput: "Error: Synapse workspace name is empty",
		})
		return commands
	}

	// Extract connectivity endpoints from properties
	var devEndpoint string
	var sqlEndpoint string
	if resource.Properties != nil {
		if endpoints, ok := resource.Properties["connectivityEndpoints"].(map[string]interface{}); ok {
			// Try to extract dev endpoint
			if dev, ok := endpoints["dev"].(string); ok && dev != "" {
				devEndpoint = dev
			}
			// Try to extract sql endpoint
			if sql, ok := endpoints["sql"].(string); ok && sql != "" {
				sqlEndpoint = sql
			}
		}
	}


	// Ensure endpoints have https:// scheme (ARG returns hostnames without scheme)
	if devEndpoint != "" && !strings.HasPrefix(devEndpoint, "https://") && !strings.HasPrefix(devEndpoint, "http://") {
		devEndpoint = "https://" + devEndpoint
	}
	if sqlEndpoint != "" && !strings.HasPrefix(sqlEndpoint, "https://") && !strings.HasPrefix(sqlEndpoint, "http://") {
		sqlEndpoint = "https://" + sqlEndpoint
	}
	// Construct dev endpoint if not found in properties
	if devEndpoint == "" {
		devEndpoint = fmt.Sprintf("https://%s.dev.azuresynapse.net", workspaceName)
	}

	// Construct SQL on-demand endpoint if not found in properties
	if sqlEndpoint == "" {
		sqlEndpoint = fmt.Sprintf("https://%s-ondemand.sql.azuresynapse.net", workspaceName)
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

	devEndpointCommand := s.testDevEndpoint(client, devEndpoint)
	commands = append(commands, devEndpointCommand)

	sqlEndpointCommand := s.testSQLEndpoint(client, sqlEndpoint)
	commands = append(commands, sqlEndpointCommand)

	cliCommand := s.cliCommand(workspaceName, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testDevEndpoint tests if the Synapse development endpoint is accessible
func (s *SynapseEnricher) testDevEndpoint(client *http.Client, uri string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", uri),
		Description:               "Test if Synapse development endpoint is accessible",
		ExpectedOutputDescription: "401 = requires Azure AD authentication | 403 = forbidden | 200 = accessible (unusual)",
	}

	resp, err := client.Get(uri)
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

// testSQLEndpoint tests the Synapse SQL on-demand endpoint
func (s *SynapseEnricher) testSQLEndpoint(client *http.Client, uri string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", uri),
		Description:               "Test Synapse SQL on-demand endpoint accessibility",
		ExpectedOutputDescription: "Connection response = SQL endpoint reachable | Timeout = not accessible",
	}

	resp, err := client.Get(uri)
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

// cliCommand returns an Azure CLI command for Synapse workspace
func (s *SynapseEnricher) cliCommand(name string, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az synapse workspace show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Synapse workspace details",
		ExpectedOutputDescription: "Workspace details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
