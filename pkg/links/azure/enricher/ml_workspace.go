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

	// Extract workspace-specific notebook FQDN from properties
	notebookFqdn := ""
	if resource.Properties != nil {
		if nbFqdn, ok := resource.Properties["notebookFqdn"].(string); ok && nbFqdn != "" {
			notebookFqdn = nbFqdn
		}
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

	// Test workspace-specific notebook endpoint
	if notebookFqdn != "" {
		notebookCommand := m.testNotebookEndpoint(client, notebookFqdn)
		commands = append(commands, notebookCommand)
	}

	cliCommand := m.cliCommand(resource.Name, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
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
