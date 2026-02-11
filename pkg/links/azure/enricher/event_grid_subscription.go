package enricher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// EventGridSubscriptionEnricher implements enrichment for Event Grid Subscription instances
type EventGridSubscriptionEnricher struct{}

func (e *EventGridSubscriptionEnricher) CanEnrich(templateID string) bool {
	return templateID == "event_grid_subscription_webhook_auth"
}

func (e *EventGridSubscriptionEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	subscriptionName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup
	resourceType := strings.ToLower(string(resource.ResourceType))

	if subscriptionName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check Event Grid Subscription webhook authentication",
			ActualOutput: "Error: Subscription name, subscription ID, or resource group is missing",
			ExitCode:     -1, // Setup error - missing required configuration
		}}
	}

	// Parse resource type to determine parent type and name
	parentType, parentName, err := parseEventGridResourceID(resource.Properties, resourceType)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check Event Grid Subscription webhook authentication",
			ActualOutput: fmt.Sprintf("Error parsing resource ID: %s", err.Error()),
			ExitCode:     -1, // Setup error - missing required configuration
		}}
	}

	// Check if Azure AD authentication is configured (from properties)
	hasAzureADAuth := false
	var azureAdTenantId, endpointUrl string

	if props, ok := resource.Properties["destinationProps"].(map[string]interface{}); ok {
		if tenantId, exists := props["azureActiveDirectoryTenantId"].(string); exists && tenantId != "" {
			hasAzureADAuth = true
			azureAdTenantId = tenantId
		}
		if url, exists := props["endpointUrl"].(string); exists {
			endpointUrl = url
		}
	}

	// Also check direct properties for backward compatibility
	if !hasAzureADAuth {
		if tenantId, exists := resource.Properties["azureAdTenantId"].(string); exists && tenantId != "" {
			hasAzureADAuth = true
			azureAdTenantId = tenantId
		}
	}
	if endpointUrl == "" {
		if url, exists := resource.Properties["endpointUrl"].(string); exists {
			endpointUrl = url
		}
	}

	// If Azure AD auth is configured, return SECURE verdict
	if hasAzureADAuth {
		return []Command{{
			Command:      "",
			Description:  "Check Event Grid Subscription webhook authentication",
			ActualOutput: fmt.Sprintf("✅ SECURE: Azure AD authentication enabled (Tenant ID: %s)", azureAdTenantId),
			ExitCode:     0,
		}}
	}

	// If we don't have endpoint URL from properties, try to fetch via SDK
	if endpointUrl == "" {
		endpointUrl, err = e.fetchWebhookEndpoint(ctx, subscriptionID, resourceGroupName, parentType, parentName, subscriptionName)
		if err != nil {
			return []Command{{
				Command:      e.getAzureCLICommand(parentType, parentName, resourceGroupName, subscriptionName),
				Description:  "Manually verify Event Grid Subscription webhook authentication",
				ActualOutput: fmt.Sprintf("Unable to fetch webhook endpoint via SDK: %s. Manual verification required.", err.Error()),
				ExitCode:     1,
			}}
		}
	}

	// Perform dynamic webhook testing
	testResult := e.testWebhookAuthentication(ctx, endpointUrl)
	commands = append(commands, testResult)

	// Add manual verification command
	commands = append(commands, Command{
		Command:                   e.getAzureCLICommand(parentType, parentName, resourceGroupName, subscriptionName),
		Description:               "Azure CLI command to show Event Grid Subscription details",
		ExpectedOutputDescription: "Use to verify webhook URL and authentication settings",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
		ExitCode:                  0,
	})

	return commands
}

// fetchWebhookEndpoint retrieves the webhook endpoint URL using Azure SDK
func (e *EventGridSubscriptionEnricher) fetchWebhookEndpoint(ctx context.Context, subscriptionID, resourceGroupName, parentType, parentName, subscriptionName string) (string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	clientFactory, err := armeventgrid.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create client factory: %w", err)
	}

	var destination interface{}

	switch parentType {
	case "systemtopics":
		client := clientFactory.NewSystemTopicEventSubscriptionsClient()
		resp, err := client.Get(ctx, resourceGroupName, parentName, subscriptionName, nil)
		if err != nil {
			return "", fmt.Errorf("failed to get system topic event subscription: %w", err)
		}
		if resp.Properties != nil && resp.Properties.Destination != nil {
			destination = resp.Properties.Destination
		}

	case "topics":
		client := clientFactory.NewEventSubscriptionsClient()
		scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/topics/%s",
			subscriptionID, resourceGroupName, parentName)
		resp, err := client.Get(ctx, scope, subscriptionName, nil)
		if err != nil {
			return "", fmt.Errorf("failed to get topic event subscription: %w", err)
		}
		if resp.Properties != nil && resp.Properties.Destination != nil {
			destination = resp.Properties.Destination
		}

	case "domains":
		client := clientFactory.NewDomainEventSubscriptionsClient()
		resp, err := client.Get(ctx, resourceGroupName, parentName, subscriptionName, nil)
		if err != nil {
			return "", fmt.Errorf("failed to get domain event subscription: %w", err)
		}
		if resp.Properties != nil && resp.Properties.Destination != nil {
			destination = resp.Properties.Destination
		}

	default:
		return "", fmt.Errorf("unknown parent type: %s", parentType)
	}

	// Extract endpoint URL from webhook destination
	if webhook, ok := destination.(*armeventgrid.WebHookEventSubscriptionDestination); ok {
		if webhook.Properties != nil && webhook.Properties.EndpointURL != nil {
			return *webhook.Properties.EndpointURL, nil
		}
	}

	return "", fmt.Errorf("webhook endpoint not found in destination properties")
}

// testWebhookAuthentication dynamically tests the webhook endpoint
func (e *EventGridSubscriptionEnricher) testWebhookAuthentication(ctx context.Context, webhookURL string) Command {
	// Create a minimal test Event Grid event payload
	testEvent := []map[string]interface{}{
		{
			"id":          "test-event-id",
			"eventType":   "test.event",
			"subject":     "test-subject",
			"eventTime":   time.Now().UTC().Format(time.RFC3339),
			"data":        map[string]interface{}{"test": true},
			"dataVersion": "1.0",
		},
	}

	payloadBytes, err := json.Marshal(testEvent)
	if err != nil {
		return Command{
			Command:      fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -H 'aeg-event-type: Notification' -d '<test-payload>' '%s' --max-time 5", webhookURL),
			Description:  "Test webhook endpoint for authentication requirements",
			ActualOutput: fmt.Sprintf("Error creating test payload: %s", err.Error()),
			ExitCode:     -1, // Setup error - missing required configuration
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return Command{
			Command:      fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -H 'aeg-event-type: Notification' -d '<test-payload>' '%s' --max-time 5", webhookURL),
			Description:  "Test webhook endpoint for authentication requirements",
			ActualOutput: fmt.Sprintf("Error creating request: %s", err.Error()),
			ExitCode:     -1, // Setup error - missing required configuration
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("aeg-event-type", "Notification")

	resp, err := client.Do(req)

	curlCommand := fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -H 'aeg-event-type: Notification' -d '%s' -i '%s' --max-time 5", string(payloadBytes), webhookURL)

	command := Command{
		Command:                   curlCommand,
		Description:               "Dynamic test of webhook endpoint authentication",
		ExpectedOutputDescription: "401/403 = auth required | 400 = schema validation | 200 = vulnerable | timeout = firewalled",
	}

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			command.ActualOutput = "✅ SECURE: Connection timeout - webhook likely behind firewall or private endpoint"
			command.ExitCode = 0
		} else if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
			command.ActualOutput = "✅ SECURE: Connection refused - webhook not publicly accessible"
			command.ExitCode = 0
		} else {
			command.ActualOutput = fmt.Sprintf("Network error: %s (webhook may be behind firewall)", err.Error())
			command.ExitCode = 0
		}
		return command
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	command.ExitCode = statusCode

	switch {
	case statusCode == 401 || statusCode == 403:
		command.ActualOutput = fmt.Sprintf("✅ SECURE: HTTP %d - Authentication required (webhook rejected unauthenticated request)", statusCode)
		command.ExitCode = 0
	case statusCode == 400:
		command.ActualOutput = fmt.Sprintf("⚠️ MANUAL REVIEW: HTTP %d - Bad Request (schema validation active, may have alternative auth method)", statusCode)
		command.ExitCode = 1
	case statusCode == 200 || statusCode == 202 || statusCode == 204:
		command.ActualOutput = fmt.Sprintf("🚨 VULNERABLE: HTTP %d - Webhook accepted unauthenticated request (no authentication enforced)", statusCode)
		command.ExitCode = 2
	case statusCode == 502 || statusCode == 503 || statusCode == 504:
		command.ActualOutput = fmt.Sprintf("⚠️ UNCLEAR: HTTP %d - Gateway error (unable to determine authentication status)", statusCode)
		command.ExitCode = 1
	default:
		command.ActualOutput = fmt.Sprintf("⚠️ MANUAL REVIEW: HTTP %d - Unexpected response (review manually)", statusCode)
		command.ExitCode = 1
	}

	return command
}

// parseEventGridResourceID extracts parent type and name from resource properties or type
func parseEventGridResourceID(properties map[string]interface{}, resourceType string) (parentType, parentName string, err error) {
	if id, exists := properties["id"].(string); exists && id != "" {
		parts := strings.Split(strings.TrimPrefix(id, "/"), "/")
		if len(parts) >= 10 {
			for i, part := range parts {
				if strings.EqualFold(part, "Microsoft.EventGrid") && i+2 < len(parts) {
					parentType = strings.ToLower(parts[i+1])
					parentName = parts[i+2]
					return parentType, parentName, nil
				}
			}
		}
	}

	parts := strings.Split(resourceType, "/")
	if len(parts) >= 2 {
		parentType = strings.ToLower(parts[1])

		switch parentType {
		case "systemtopics":
			if name, exists := properties["systemTopicName"].(string); exists {
				parentName = name
			}
		case "topics":
			if name, exists := properties["topicName"].(string); exists {
				parentName = name
			}
		case "domains":
			if name, exists := properties["domainName"].(string); exists {
				parentName = name
			}
		}

		if parentName == "" {
			return "", "", fmt.Errorf("unable to extract parent name from properties")
		}

		return parentType, parentName, nil
	}

	return "", "", fmt.Errorf("unable to parse resource type: %s", resourceType)
}

// getAzureCLICommand generates the appropriate Azure CLI command based on parent type
func (e *EventGridSubscriptionEnricher) getAzureCLICommand(parentType, parentName, resourceGroup, subscriptionName string) string {
	switch parentType {
	case "systemtopics":
		return fmt.Sprintf("az eventgrid system-topic event-subscription show --name %s --system-topic-name %s --resource-group %s",
			subscriptionName, parentName, resourceGroup)
	case "topics":
		return fmt.Sprintf("az eventgrid topic event-subscription show --name %s --topic-name %s --resource-group %s",
			subscriptionName, parentName, resourceGroup)
	case "domains":
		return fmt.Sprintf("az eventgrid domain event-subscription show --name %s --domain-name %s --resource-group %s",
			subscriptionName, parentName, resourceGroup)
	default:
		return fmt.Sprintf("az eventgrid event-subscription show --name %s --resource-group %s", subscriptionName, resourceGroup)
	}
}
