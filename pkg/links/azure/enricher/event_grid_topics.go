package enricher

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// EventGridTopicsEnricher implements enrichment for Event Grid Topics instances
type EventGridTopicsEnricher struct{}

func (e *EventGridTopicsEnricher) CanEnrich(templateID string) bool {
	return templateID == "event_grid_topics_public_access"
}

func (e *EventGridTopicsEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	topicName := resource.Name
	location := resource.Region
	if location == "" {
		if loc, ok := resource.Properties["location"].(string); ok && loc != "" {
			location = loc
		}
	}

	var topicEndpoint string
	if endpoint, exists := resource.Properties["endpoint"].(string); exists && endpoint != "" {
		topicEndpoint = endpoint
		if !strings.HasSuffix(topicEndpoint, "/api/events") {
			topicEndpoint = strings.TrimSuffix(topicEndpoint, "/") + "/api/events"
		}
	} else {
		if location == "" {
			return commands
		}
		if topicName == "" {
			commands = append(commands, Command{
				Command:      "",
				Description:  "Missing Event Grid Topic name",
				ActualOutput: "Error: Event Grid Topic name is empty",
			})
			return commands
		}
		normalizedLocation := strings.TrimSpace(strings.ToLower(location))
		topicEndpoint = fmt.Sprintf("https://%s.%s-1.eventgrid.azure.net/api/events", topicName, normalizedLocation)
	}
	client := &http.Client{Timeout: 10 * time.Second}

	body := bytes.NewBuffer([]byte("[]"))
	req, err := http.NewRequestWithContext(ctx, "POST", topicEndpoint, body)
	if err != nil {
		return commands
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)

	postCommand := Command{
		Command:                   fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '[]' -i '%s' --max-time 10", topicEndpoint),
		Description:               "Test Event Grid Topic POST endpoint",
		ExpectedOutputDescription: "401/405 = publicly accessible but authentication required | 403 = blocked via firewall rules",
	}

	if err != nil {
		postCommand.Error = err.Error()
		postCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		postCommand.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		postCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, postCommand)

	// Test 2: Azure CLI Event Grid Topic test
	commands = append(commands, Command{
		Command:                   fmt.Sprintf("az eventgrid topic show --name %s --resource-group %s", topicName, resource.ResourceGroup),
		Description:               "Azure CLI command to show Event Grid Topic details",
		ExpectedOutputDescription: "Topic details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	})

	return commands
}
