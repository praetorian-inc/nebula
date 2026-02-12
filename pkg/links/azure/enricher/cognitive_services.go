package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// CognitiveServicesEnricher implements enrichment for Cognitive Services instances
type CognitiveServicesEnricher struct{}

func (c *CognitiveServicesEnricher) CanEnrich(templateID string) bool {
	return templateID == "cognitive_services_public_access"
}

func (c *CognitiveServicesEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Cognitive Services name
	serviceName := resource.Name
	if serviceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Cognitive Services name",
			ActualOutput: "Error: Cognitive Services name is empty",
		})
		return commands
	}

	// Construct Cognitive Services endpoint URL
	// Try to detect if this is OpenAI service
	kind := ""
	if k, ok := resource.Properties["kind"].(string); ok {
		kind = k
	}

	var cognitiveEndpoint string
	if kind == "OpenAI" {
		cognitiveEndpoint = fmt.Sprintf("https://%s.openai.azure.com", serviceName)
	} else {
		cognitiveEndpoint = fmt.Sprintf("https://%s.cognitiveservices.azure.com", serviceName)
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

	// Test 1: Check if endpoint is accessible (should return 401 if key required)
	endpointCommand := c.testEndpointAccess(client, cognitiveEndpoint)
	commands = append(commands, endpointCommand)

	// Test 2: Test OpenAI-specific endpoint if this is an OpenAI service
	if kind == "OpenAI" {
		openaiCommand := c.testOpenAIDeployments(client, cognitiveEndpoint)
		commands = append(commands, openaiCommand)
	}

	return commands
}

// testEndpointAccess tests if the Cognitive Services endpoint is accessible
func (c *CognitiveServicesEnricher) testEndpointAccess(client *http.Client, endpoint string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if Cognitive Services endpoint is accessible",
		ExpectedOutputDescription: "401 = requires authentication (API key) | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
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

// testOpenAIDeployments tests the OpenAI deployments endpoint
func (c *CognitiveServicesEnricher) testOpenAIDeployments(client *http.Client, baseEndpoint string) Command {
	deploymentsURL := fmt.Sprintf("%s/openai/deployments", baseEndpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", deploymentsURL),
		Description:               "Test OpenAI deployments endpoint (lists available models)",
		ExpectedOutputDescription: "401 = requires authentication | 403 = forbidden | 404 = not found | 200 = deployments accessible",
	}

	resp, err := client.Get(deploymentsURL)
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
