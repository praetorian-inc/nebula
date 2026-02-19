package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// FunctionAppEnricher implements enrichment for Azure Function Apps
type FunctionAppEnricher struct{}

func (f *FunctionAppEnricher) CanEnrich(templateID string) bool {
	return templateID == "function_apps_public_http_triggers"
}

func (f *FunctionAppEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Function App name
	appName := resource.Name
	if appName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Function App name",
			ActualOutput: "Error: Function App name is empty",
		})
		return commands
	}

	// Construct Function App URL
	appURL := fmt.Sprintf("https://%s.azurewebsites.net", appName)

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

	// Test 1: HTTP GET to main page
	mainPageCommand := f.testMainPage(client, appURL)
	commands = append(commands, mainPageCommand)

	// Test 2: Test runtime endpoint
	runtimeCommand := f.testRuntimeEndpoint(client, appURL)
	commands = append(commands, runtimeCommand)

	// Test 3: Test SCM/Kudu site
	scmCommand := f.testSCMSite(client, appName)
	commands = append(commands, scmCommand)

	return commands
}

// testMainPage tests the main function app endpoint
func (f *FunctionAppEnricher) testMainPage(client *http.Client, appURL string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i -L '%s' --max-time 10", appURL),
		Description:               "Test HTTP GET to Function App main page",
		ExpectedOutputDescription: "200 = accessible | 401/403 = authentication required | 404 = not found | 503 = app stopped",
	}

	resp, err := client.Get(appURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, truncateString(string(body), 800))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

// testRuntimeEndpoint tests the runtime API endpoint
func (f *FunctionAppEnricher) testRuntimeEndpoint(client *http.Client, appURL string) Command {
	runtimeURL := fmt.Sprintf("%s/api/", appURL)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", runtimeURL),
		Description:               "Test Function App runtime API endpoint",
		ExpectedOutputDescription: "200/404 = endpoint exists | 401/403 = authentication required | timeout = blocked",
	}

	resp, err := client.Get(runtimeURL)
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

// testSCMSite tests the SCM/Kudu management site
func (f *FunctionAppEnricher) testSCMSite(client *http.Client, appName string) Command {
	scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net", appName)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", scmURL),
		Description:               "Test access to SCM/Kudu management site (high risk if accessible)",
		ExpectedOutputDescription: "200 = SCM accessible (HIGH RISK) | 401/403 = authentication required | timeout = blocked",
	}

	resp, err := client.Get(scmURL)
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
