package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"
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

	// Add network rules command
	networkRulesCommand := d.getNetworkRulesCommand(ctx, resource)
	commands = append(commands, networkRulesCommand)

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

// getNetworkRulesCommand retrieves network rules for the Data Explorer cluster
func (d *DataExplorerEnricher) getNetworkRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	clusterName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az kusto cluster show --name %s --resource-group %s --query '{publicNetworkAccess:properties.publicNetworkAccess,allowedIpRangeList:properties.allowedIpRangeList,publicIPType:properties.publicIPType,enableAutoStop:properties.enableAutoStop,state:properties.state}'", clusterName, resourceGroupName)

	if clusterName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve Data Explorer cluster network rules",
			ActualOutput: "Error: Cluster name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get cluster details from Azure SDK
	clusterDetails, err := d.retrieveClusterDetails(ctx, subscriptionID, resourceGroupName, clusterName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve Data Explorer cluster network rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "Network configuration with publicNetworkAccess, allowedIpRangeList, and other network settings | Error = insufficient permissions or cluster not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with network rules
	output := d.formatClusterNetworkRules(clusterDetails)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve Data Explorer cluster network rules",
		ExpectedOutputDescription: "Network configuration showing public access status and IP restrictions",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveClusterDetails gets cluster details using Azure SDK
func (d *DataExplorerEnricher) retrieveClusterDetails(ctx context.Context, subscriptionID, resourceGroupName, clusterName string) (*armkusto.Cluster, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Kusto client
	client, err := armkusto.NewClustersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kusto client: %w", err)
	}

	// Get cluster
	response, err := client.Get(ctx, resourceGroupName, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster details: %w", err)
	}

	return &response.Cluster, nil
}

// KustoNetworkRulesOutput represents the network configuration output for Kusto cluster
type KustoNetworkRulesOutput struct {
	PublicNetworkAccess string   `json:"publicNetworkAccess"`
	AllowedIPRangeList  []string `json:"allowedIpRangeList"`
	PublicIPType        string   `json:"publicIPType,omitempty"`
	EnableAutoStop      bool     `json:"enableAutoStop"`
	State               string   `json:"state"`
}

// formatClusterNetworkRules formats cluster network rules to match Azure CLI JSON output
func (d *DataExplorerEnricher) formatClusterNetworkRules(cluster *armkusto.Cluster) string {
	if cluster == nil || cluster.Properties == nil {
		return "null"
	}

	output := KustoNetworkRulesOutput{
		AllowedIPRangeList: []string{},
		EnableAutoStop:     false,
	}

	props := cluster.Properties

	// Extract PublicNetworkAccess
	if props.PublicNetworkAccess != nil {
		output.PublicNetworkAccess = string(*props.PublicNetworkAccess)
	}

	// Extract AllowedIpRangeList
	if props.AllowedIPRangeList != nil {
		for _, ipRange := range props.AllowedIPRangeList {
			if ipRange != nil {
				output.AllowedIPRangeList = append(output.AllowedIPRangeList, *ipRange)
			}
		}
	}

	// Extract PublicIPType
	if props.PublicIPType != nil {
		output.PublicIPType = string(*props.PublicIPType)
	}

	// Extract EnableAutoStop
	if props.EnableAutoStop != nil {
		output.EnableAutoStop = *props.EnableAutoStop
	}

	// Extract State
	if props.State != nil {
		output.State = string(*props.State)
	}

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}

	return string(jsonOutput)
}
