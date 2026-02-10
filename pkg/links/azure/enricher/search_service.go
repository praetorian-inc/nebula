package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// SearchServiceEnricher implements enrichment for Azure Search Service instances
type SearchServiceEnricher struct{}

func (s *SearchServiceEnricher) CanEnrich(templateID string) bool {
	return templateID == "search_service_public_access"
}

func (s *SearchServiceEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Search Service name
	serviceName := resource.Name
	if serviceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Search Service name",
			ActualOutput: "Error: Search Service name is empty",
		})
		return commands
	}

	// Construct Search Service endpoint URL
	searchEndpoint := fmt.Sprintf("https://%s.search.windows.net", serviceName)

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
	mainEndpointCommand := s.testMainEndpoint(client, searchEndpoint)
	commands = append(commands, mainEndpointCommand)

	// Test 2: Test search API endpoint
	searchAPICommand := s.testSearchAPI(client, searchEndpoint)
	commands = append(commands, searchAPICommand)

	return commands
}

// testMainEndpoint tests if the Search Service endpoint is accessible
func (s *SearchServiceEnricher) testMainEndpoint(client *http.Client, endpoint string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", endpoint),
		Description:               "Test if Search Service endpoint is accessible",
		ExpectedOutputDescription: "401 = requires API key | 403 = forbidden | 404 = not found | 200 = accessible without key (unusual)",
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

// testSearchAPI tests the search API endpoint
func (s *SearchServiceEnricher) testSearchAPI(client *http.Client, endpoint string) Command {
	indexesURL := fmt.Sprintf("%s/indexes", endpoint)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", indexesURL),
		Description:               "Test Search Service indexes endpoint (enumeration test)",
		ExpectedOutputDescription: "401 = requires API key | 403 = forbidden | 404 = not found | 200 = indexes accessible",
	}

	resp, err := client.Get(indexesURL)
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
