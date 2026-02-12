package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ContainerInstancesEnricher implements enrichment for Azure Container Instances
type ContainerInstancesEnricher struct{}

func (c *ContainerInstancesEnricher) CanEnrich(templateID string) bool {
	return templateID == "container_instances_public_access"
}

func (c *ContainerInstancesEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract container instance details
	name := resource.Name
	resourceGroup := resource.ResourceGroup

	if name == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing container instance name",
			ActualOutput: "Error: container instance name is empty",
		})
		return commands
	}

	// Extract public IP address from properties
	var ipAddress string
	if ip, ok := resource.Properties["ipAddress"].(string); ok && ip != "" {
		ipAddress = ip
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Test 1: Test HTTP endpoint on port 80 if IP is available
	if ipAddress != "" {
		httpTestCommand := c.testHTTPEndpoint(client, ipAddress)
		commands = append(commands, httpTestCommand)

		// Test 2: Test container port connectivity
		portTestCommand := c.testContainerPorts(client, ipAddress)
		commands = append(commands, portTestCommand)
	} else {
		commands = append(commands, Command{
			Command:      "",
			Description:  "No public IP address available",
			ActualOutput: "Container instance does not have a public IP address",
		})
	}

	// Test 3: CLI fallback for container details
	cliCommand := Command{
		Command:                   fmt.Sprintf("az container show --name %s --resource-group %s", name, resourceGroup),
		Description:               "Azure CLI command to show container instance details",
		ExpectedOutputDescription: "Container details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	}
	commands = append(commands, cliCommand)

	return commands
}

// testHTTPEndpoint tests HTTP connectivity to container instance public IP
func (c *ContainerInstancesEnricher) testHTTPEndpoint(client *http.Client, ipAddress string) Command {
	testURL := fmt.Sprintf("http://%s", ipAddress)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", testURL),
		Description:               "Test HTTP connectivity to container instance public IP",
		ExpectedOutputDescription: "200 = container app responding | Connection refused = port not open | Timeout = IP not reachable",
	}

	resp, err := client.Get(testURL)
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

// testContainerPorts tests connectivity to container on exposed port
func (c *ContainerInstancesEnricher) testContainerPorts(client *http.Client, ipAddress string) Command {
	// Test port 80 HTTP GET
	port := 80
	testURL := fmt.Sprintf("http://%s:%d", ipAddress, port)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", testURL),
		Description:               fmt.Sprintf("Test connectivity to container on exposed port %d", port),
		ExpectedOutputDescription: "Response = service running | Connection refused = port blocked | Timeout = unreachable",
	}

	resp, err := client.Get(testURL)
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
