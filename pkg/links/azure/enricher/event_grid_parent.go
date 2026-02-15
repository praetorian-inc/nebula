package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// EventGridParentEnricher enumerates Event Grid child subscriptions for parent resources
type EventGridParentEnricher struct{}

func (e *EventGridParentEnricher) CanEnrich(templateID string) bool {
	return templateID == "event_grid_parent_resources"
}

// getAzureCLINames maps internal parent types to Azure CLI subcommand and flag names
func getAzureCLINames(parentType string) (subcommand string, flagName string) {
	switch parentType {
	case "systemtopics":
		return "system-topic", "system-topic-name"
	case "topics":
		return "topic", "topic-name"
	case "domains":
		return "domain", "domain-name"
	default:
		return parentType, strings.TrimSuffix(parentType, "s") + "-name"
	}
}

func (e *EventGridParentEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	resourceType := strings.ToLower(string(resource.ResourceType))
	parentType := ""

	// Determine parent type
	if strings.Contains(resourceType, "systemtopics") {
		parentType = "systemtopics"
	} else if strings.Contains(resourceType, "topics") && !strings.Contains(resourceType, "system") {
		parentType = "topics"
	} else if strings.Contains(resourceType, "domains") {
		parentType = "domains"
	} else {
		return []Command{{
			Description:  "Enumerate Event Grid subscriptions",
			ActualOutput: fmt.Sprintf("Unknown Event Grid resource type: %s", resourceType),
			ExitCode:     -1,
		}}
	}

	// Enumerate child subscriptions
	subscriptions, err := e.enumerateSubscriptions(ctx, resource, parentType)
	if err != nil {
		return []Command{{
			Description:  "Enumerate Event Grid subscriptions",
			ActualOutput: fmt.Sprintf("Error enumerating subscriptions: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Check each subscription for vulnerable webhooks
	vulnerableCount := 0
	secureCount := 0
	otherCount := 0

	for _, sub := range subscriptions {
		if sub.isWebhook && !sub.hasAzureADAuth {
			vulnerableCount++
			// Create detailed finding for each vulnerable subscription
			subcommand, flagName := getAzureCLINames(parentType)

			// Build CLI command - add --domain-topic-name for domain topic subscriptions
			cliCommand := fmt.Sprintf("az eventgrid %s event-subscription show --name %s --%s %s",
				subcommand, sub.name, flagName, resource.Name)

			// For domain topic subscriptions, add the topic name flag
			if sub.domainTopicName != "" {
				cliCommand += fmt.Sprintf(" --domain-topic-name %s", sub.domainTopicName)
			}

			cliCommand += fmt.Sprintf(" --resource-group %s", resource.ResourceGroup)

			commands = append(commands, Command{
				Command: cliCommand,
				Description:               fmt.Sprintf("🚨 VULNERABLE: Webhook subscription '%s' lacks Azure AD authentication", sub.name),
				ExpectedOutputDescription: "Webhook should have azureActiveDirectoryTenantId configured",
				ActualOutput: fmt.Sprintf("Subscription: %s\nDestination Type: WebHook\nAzure AD Auth: ❌ NOT CONFIGURED\nEndpoint: %s\n\n"+
					"SECURITY RISK: This webhook accepts events from any sender without authentication.\n"+
					"Anyone who discovers the webhook URL can send spoofed events.\n\n"+
					"RECOMMENDATION: Enable Azure AD authentication or use alternative auth methods.",
					sub.name, sub.endpointURL),
				ExitCode: 2, // Exit code 2 indicates vulnerability found
			})
		} else if sub.isWebhook && sub.hasAzureADAuth {
			secureCount++
		} else {
			otherCount++
		}
	}

	// Add summary command
	summary := fmt.Sprintf("Enumerated %d event subscriptions for %s '%s':\n"+
		"  🚨 Vulnerable webhooks (no Azure AD auth): %d\n"+
		"  ✅ Secure webhooks (with Azure AD auth): %d\n"+
		"  ℹ️  Other subscription types: %d",
		len(subscriptions), parentType, resource.Name,
		vulnerableCount, secureCount, otherCount)

	if vulnerableCount > 0 {
		summary += fmt.Sprintf("\n\n⚠️  CRITICAL: Found %d webhook(s) without Azure AD authentication!", vulnerableCount)
	}

	commands = append(commands, Command{
		Description:  fmt.Sprintf("Event Grid subscription enumeration summary for %s", resource.Name),
		ActualOutput: summary,
		ExitCode:     0,
	})

	return commands
}

type subscriptionInfo struct {
	name            string
	isWebhook       bool
	hasAzureADAuth  bool
	endpointURL     string
	domainTopicName string // For domain topic subscriptions, tracks which topic this subscription belongs to
}

func (e *EventGridParentEnricher) enumerateSubscriptions(ctx context.Context, resource *model.AzureResource, parentType string) ([]subscriptionInfo, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	clientFactory, err := armeventgrid.NewClientFactory(resource.AccountRef, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Event Grid client factory: %w", err)
	}

	var subscriptions []subscriptionInfo

	switch parentType {
	case "systemtopics":
		client := clientFactory.NewSystemTopicEventSubscriptionsClient()
		pager := client.NewListBySystemTopicPager(resource.ResourceGroup, resource.Name, nil)

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list system topic subscriptions: %w", err)
			}

			for _, sub := range page.Value {
				info := e.extractSubscriptionInfo(sub.Name, sub.Properties)
				subscriptions = append(subscriptions, info)
			}
		}

	case "topics":
		client := clientFactory.NewEventSubscriptionsClient()
		pager := client.NewListByResourcePager(
			resource.ResourceGroup,
			"Microsoft.EventGrid",
			"topics",
			resource.Name,
			nil,
		)

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list topic subscriptions: %w", err)
			}

			for _, sub := range page.Value {
				info := e.extractSubscriptionInfo(sub.Name, sub.Properties)
				subscriptions = append(subscriptions, info)
			}
		}

	case "domains":
		// List domain-level subscriptions
		client := clientFactory.NewDomainEventSubscriptionsClient()
		pager := client.NewListPager(resource.ResourceGroup, resource.Name, nil)

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list domain subscriptions: %w", err)
			}

			for _, sub := range page.Value {
				info := e.extractSubscriptionInfo(sub.Name, sub.Properties)
				subscriptions = append(subscriptions, info)
			}
		}

		// Also enumerate domain topics and their subscriptions
		topicsClient := clientFactory.NewDomainTopicsClient()
		topicsPager := topicsClient.NewListByDomainPager(resource.ResourceGroup, resource.Name, nil)

		for topicsPager.More() {
			topicsPage, err := topicsPager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list domain topics: %w", err)
			}

			// For each domain topic, list its subscriptions
			for _, topic := range topicsPage.Value {
				if topic.Name == nil {
					continue
				}

				topicSubClient := clientFactory.NewDomainTopicEventSubscriptionsClient()
				topicSubPager := topicSubClient.NewListPager(resource.ResourceGroup, resource.Name, *topic.Name, nil)

				for topicSubPager.More() {
					topicSubPage, err := topicSubPager.NextPage(ctx)
					if err != nil {
						return nil, fmt.Errorf("failed to list domain topic subscriptions for topic %s: %w", *topic.Name, err)
					}

					for _, sub := range topicSubPage.Value {
						info := e.extractSubscriptionInfo(sub.Name, sub.Properties)
						// Track which domain topic this subscription belongs to
						info.domainTopicName = *topic.Name
						subscriptions = append(subscriptions, info)
					}
				}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported parent type: %s", parentType)
	}

	return subscriptions, nil
}

func (e *EventGridParentEnricher) extractSubscriptionInfo(name *string, props *armeventgrid.EventSubscriptionProperties) subscriptionInfo {
	info := subscriptionInfo{
		name:           safeString(name),
		isWebhook:      false,
		hasAzureADAuth: false,
		endpointURL:    "",
	}

	if props == nil || props.Destination == nil {
		return info
	}

	// Check if it's a webhook destination
	if webhook, ok := props.Destination.(*armeventgrid.WebHookEventSubscriptionDestination); ok {
		info.isWebhook = true

		if webhook.Properties != nil {
			// Check for Azure AD authentication
			if webhook.Properties.AzureActiveDirectoryTenantID != nil && *webhook.Properties.AzureActiveDirectoryTenantID != "" {
				info.hasAzureADAuth = true
			}

			// Get endpoint URL (may be masked)
			if webhook.Properties.EndpointURL != nil {
				info.endpointURL = *webhook.Properties.EndpointURL
			} else if webhook.Properties.EndpointBaseURL != nil {
				info.endpointURL = *webhook.Properties.EndpointBaseURL
			}
		}
	}

	return info
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
