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

// DataExplorerEnricher implements enrichment for Azure Data Explorer (Kusto) clusters
type DataExplorerEnricher struct{}

func (d *DataExplorerEnricher) CanEnrich(templateID string) bool {
	return templateID == "data_explorer_public_access"
}

func (d *DataExplorerEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	clusterName := resource.Name
	if clusterName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Data Explorer cluster name",
			ActualOutput: "Error: Data Explorer cluster name is empty",
		})
		return commands
	}

	// Extract URI from properties if available, otherwise construct
	var clusterURI string
	if resource.Properties != nil {
		if uri, ok := resource.Properties["uri"].(string); ok && uri != "" {
			clusterURI = strings.TrimSuffix(uri, "/")
		}
	}
	if clusterURI == "" {
		clusterURI = fmt.Sprintf("https://%s.%s.kusto.windows.net", clusterName, resource.Region)
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

	mainEndpointCommand := d.testMainEndpoint(client, clusterURI)
	commands = append(commands, mainEndpointCommand)

	managementEndpointCommand := d.testManagementEndpoint(client, clusterURI)
	commands = append(commands, managementEndpointCommand)

	cliCommand := d.cliCommand(clusterName, resource.ResourceGroup)
	commands = append(commands, cliCommand)

	return commands
}

// testMainEndpoint tests if the Data Explorer cluster endpoint is accessible
func (d *DataExplorerEnricher) testMainEndpoint(client *http.Client, uri string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", uri),
		Description:               "Test if Data Explorer cluster endpoint is accessible",
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

// testManagementEndpoint tests the Data Explorer management endpoint
func (d *DataExplorerEnricher) testManagementEndpoint(client *http.Client, uri string) Command {
	managementURL := fmt.Sprintf("%s/v1/rest/mgmt", uri)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s/v1/rest/mgmt' --max-time 10", uri),
		Description:               "Test Data Explorer management endpoint",
		ExpectedOutputDescription: "401 = requires authentication | 403 = forbidden | 200 = management accessible",
	}

	resp, err := client.Get(managementURL)
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

// cliCommand returns an Azure CLI command for Data Explorer
func (d *DataExplorerEnricher) cliCommand(name string, resourceGroup string) Command {
	return Command{
		Command:                   fmt.Sprintf("az kusto cluster show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show Data Explorer cluster details",
		ExpectedOutputDescription: "Cluster details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
}
