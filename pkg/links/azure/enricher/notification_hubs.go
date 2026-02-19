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

// NotificationHubsEnricher implements enrichment for Notification Hub namespace instances
type NotificationHubsEnricher struct{}

func (n *NotificationHubsEnricher) CanEnrich(templateID string) bool {
	return templateID == "notification_hubs_public_access"
}

func (n *NotificationHubsEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Notification Hubs namespace name
	namespaceName := resource.Name
	if namespaceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Notification Hubs namespace name",
			ActualOutput: "Error: Notification Hubs namespace name is empty",
		})
		return commands
	}

	// Construct Notification Hubs endpoint URL
	notificationEndpoint := fmt.Sprintf("https://%s.servicebus.windows.net", namespaceName)

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
	mainEndpointCommand := n.testMainEndpoint(client, notificationEndpoint)
	commands = append(commands, mainEndpointCommand)

	// Test 2: Test namespace management endpoint
	managementEndpointCommand := n.testManagementEndpoint(client, notificationEndpoint)
	commands = append(commands, managementEndpointCommand)

	return commands
}

// testMainEndpoint tests if the Notification Hubs endpoint is accessible
func (n *NotificationHubsEnricher) testMainEndpoint(client *http.Client, endpoint string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if Notification Hubs endpoint is accessible",
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

// testManagementEndpoint tests the namespace management endpoint
func (n *NotificationHubsEnricher) testManagementEndpoint(client *http.Client, endpoint string) Command {
	// Remove trailing slashes for clean URL construction
	cleanEndpoint := strings.TrimSuffix(endpoint, "/")
	if strings.HasSuffix(cleanEndpoint, ":443") {
		cleanEndpoint = strings.TrimSuffix(cleanEndpoint, ":443")
	}

	managementURL := fmt.Sprintf("%s/$management", cleanEndpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", managementURL),
		Description:               "Test Notification Hubs namespace management endpoint",
		ExpectedOutputDescription: "401 = requires shared access key | 403 = forbidden | 404 = not found | 200 = accessible",
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
