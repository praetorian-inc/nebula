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

// IoTHubEnricher implements enrichment for Azure IoT Hub instances
type IoTHubEnricher struct{}

func (i *IoTHubEnricher) CanEnrich(templateID string) bool {
	return templateID == "iot_hub_public_access"
}

func (i *IoTHubEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract IoT Hub name
	iotHubName := resource.Name
	if iotHubName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing IoT Hub name",
			ActualOutput: "Error: IoT Hub name is empty",
		})
		return commands
	}

	// Construct IoT Hub endpoint URL
	iotHubEndpoint := fmt.Sprintf("https://%s.azure-devices.net", iotHubName)

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

	// Test 1: Check main endpoint accessibility
	mainEndpointCommand := i.testMainEndpoint(client, iotHubEndpoint)
	commands = append(commands, mainEndpointCommand)

	// Test 2: Test device registry endpoint
	registryAPICommand := i.testRegistryAPI(client, iotHubEndpoint)
	commands = append(commands, registryAPICommand)

	return commands
}

// testMainEndpoint tests if the IoT Hub endpoint is accessible
func (i *IoTHubEnricher) testMainEndpoint(client *http.Client, endpoint string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if IoT Hub endpoint is accessible",
		ExpectedOutputDescription: "401 = requires authentication | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
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

// testRegistryAPI tests the device registry API endpoint
func (i *IoTHubEnricher) testRegistryAPI(client *http.Client, endpoint string) Command {
	// Remove trailing slashes and port for clean URL construction
	cleanEndpoint := strings.TrimSuffix(endpoint, "/")
	if strings.HasSuffix(cleanEndpoint, ":443") {
		cleanEndpoint = strings.TrimSuffix(cleanEndpoint, ":443")
	}

	registryURL := fmt.Sprintf("%s/devices", cleanEndpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", registryURL),
		Description:               "Test IoT Hub device registry endpoint (enumeration test)",
		ExpectedOutputDescription: "401 = requires API key | 403 = forbidden | 404 = not found | 200 = devices accessible",
	}

	resp, err := client.Get(registryURL)
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
