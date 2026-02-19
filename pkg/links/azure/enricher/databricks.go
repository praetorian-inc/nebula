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

// DatabricksEnricher implements enrichment for Azure Databricks workspaces
type DatabricksEnricher struct{}

func (d *DatabricksEnricher) CanEnrich(templateID string) bool {
	return templateID == "databricks_public_access"
}

func (d *DatabricksEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	workspaceName := resource.Name
	if workspaceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Databricks workspace name",
			ActualOutput: "Error: Databricks workspace name is empty",
		})
		return commands
	}

	// Extract workspace URL from properties
	var workspaceURL string
	if resource.Properties != nil {
		if url, ok := resource.Properties["workspaceUrl"].(string); ok && url != "" {
			workspaceURL = strings.TrimSuffix(url, "/")
			if !strings.HasPrefix(workspaceURL, "https://") {
				workspaceURL = "https://" + workspaceURL
			}
		}
	}
	if workspaceURL == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Databricks workspace URL",
			ActualOutput: "Error: Could not determine workspace URL from resource properties",
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

	workspaceCommand := d.testWorkspaceEndpoint(client, workspaceURL)
	commands = append(commands, workspaceCommand)

	apiCommand := d.testRESTAPIEndpoint(client, workspaceURL)
	commands = append(commands, apiCommand)

	cliCommand := d.cliCommand(workspaceName, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testWorkspaceEndpoint tests if the Databricks workspace is accessible
func (d *DatabricksEnricher) testWorkspaceEndpoint(client *http.Client, workspaceURL string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", workspaceURL),
		Description:               "Test if Databricks workspace is accessible",
		ExpectedOutputDescription: "403 = requires Azure AD authentication | 302 = redirect to login | 200 = workspace accessible",
	}

	resp, err := client.Get(workspaceURL)
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

// testRESTAPIEndpoint tests the Databricks REST API endpoint
func (d *DatabricksEnricher) testRESTAPIEndpoint(client *http.Client, workspaceURL string) Command {
	apiURL := fmt.Sprintf("%s/api/2.0/clusters/list", workspaceURL)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s/api/2.0/clusters/list' --max-time 10", workspaceURL),
		Description:               "Test Databricks REST API endpoint",
		ExpectedOutputDescription: "401/403 = requires authentication token | 200 = API accessible (critical)",
	}

	resp, err := client.Get(apiURL)
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

// cliCommand returns an Azure CLI command for Databricks
func (d *DatabricksEnricher) cliCommand(name string, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az databricks workspace show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Databricks workspace details",
		ExpectedOutputDescription: "Workspace details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
