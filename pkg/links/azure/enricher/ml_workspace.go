package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// MLWorkspaceEnricher implements enrichment for Azure Machine Learning workspaces
type MLWorkspaceEnricher struct{}

func (m *MLWorkspaceEnricher) CanEnrich(templateID string) bool {
	return templateID == "ml_workspace_public_access"
}

func (m *MLWorkspaceEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract discovery URL and notebook FQDN from properties
	discoveryURL := ""
	notebookFqdn := ""
	if resource.Properties != nil {
		if discoveryProp, ok := resource.Properties["discoveryUrl"].(string); ok && discoveryProp != "" {
			discoveryURL = discoveryProp
		}
		if nbFqdn, ok := resource.Properties["notebookFqdn"].(string); ok && nbFqdn != "" {
			notebookFqdn = nbFqdn
		}
	}

	// If no discovery URL in properties, construct from region
	if discoveryURL == "" {
		region := resource.Region
		if region == "" {
			commands = append(commands, Command{
				Command:      "",
				Description:  "Missing ML workspace region",
				ActualOutput: "Error: ML workspace region is empty",
			})
			return commands
		}
		discoveryURL = fmt.Sprintf("https://%s.api.azureml.ms", region)
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

	discoveryEndpointCommand := m.testDiscoveryEndpoint(client, discoveryURL)
	commands = append(commands, discoveryEndpointCommand)

	// Test workspace-specific notebook endpoint if available
	if notebookFqdn != "" {
		notebookCommand := m.testNotebookEndpoint(client, notebookFqdn)
		commands = append(commands, notebookCommand)
	}

	cliCommand := m.cliCommand(resource.Name, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testDiscoveryEndpoint tests if the ML workspace discovery endpoint is accessible
func (m *MLWorkspaceEnricher) testDiscoveryEndpoint(client *http.Client, discoveryURL string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", discoveryURL),
		Description:               "Test if ML workspace discovery endpoint is accessible",
		ExpectedOutputDescription: "401 = requires Azure AD authentication | 403 = forbidden | 200 = discovery accessible",
	}

	resp, err := client.Get(discoveryURL)
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

// testNotebookEndpoint tests if the workspace-specific notebook endpoint is accessible
func (m *MLWorkspaceEnricher) testNotebookEndpoint(client *http.Client, notebookFqdn string) Command {
	notebookURL := fmt.Sprintf("https://%s", notebookFqdn)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", notebookURL),
		Description:               "Test workspace-specific notebook endpoint accessibility",
		ExpectedOutputDescription: "401 = authentication required (workspace publicly reachable) | 403 = forbidden | Timeout = not publicly accessible",
	}

	resp, err := client.Get(notebookURL)
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

// cliCommand returns an Azure CLI command for ML workspace
func (m *MLWorkspaceEnricher) cliCommand(name string, resourceGroup string) Command {
	if name == "" || resourceGroup == "" {
		return Command{
			Command:      "",
			Description:  "Azure CLI command to show ML workspace details",
			ActualOutput: "Error: workspace name or resource group is empty",
		}
	}

	return Command{
		Command:                   fmt.Sprintf("az ml workspace show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show ML workspace details",
		ExpectedOutputDescription: "Workspace details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
