package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AppServiceEnricher implements enrichment for App Service instances
type AppServiceEnricher struct{}

func (a *AppServiceEnricher) CanEnrich(templateID string) bool {
	return templateID == "app_services_public_access" || templateID == "app_service_remote_debugging_enabled"
}

func (a *AppServiceEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	// Get template ID to determine which enrichment to perform
	templateID, _ := resource.Properties["templateID"].(string)

	// Route to appropriate enrichment logic
	switch templateID {
	case "app_service_remote_debugging_enabled":
		return a.checkRemoteDebugging(ctx, resource)
	case "app_services_public_access":
		return a.checkPublicAccess(ctx, resource)
	default:
		return []Command{}
	}
}

// checkRemoteDebugging checks if remote debugging is enabled via Azure API
func (a *AppServiceEnricher) checkRemoteDebugging(ctx context.Context, resource *model.AzureResource) []Command {
	appServiceName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if appServiceName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check App Service remote debugging configuration",
			ActualOutput: "Error: App Service name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check App Service remote debugging configuration",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Create App Service client
	webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check App Service remote debugging configuration",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Get site configuration
	siteConfig, err := webAppsClient.GetConfiguration(ctx, resourceGroupName, appServiceName, nil)
	if err != nil {
		return []Command{{
			Command:      fmt.Sprintf("az webapp config show --resource-group %s --name %s --query remoteDebuggingEnabled", resourceGroupName, appServiceName),
			Description:  "Check App Service remote debugging configuration",
			ActualOutput: fmt.Sprintf("Error getting site configuration: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Check if remote debugging is enabled
	remoteDebuggingEnabled := false
	remoteDebuggingVersion := "N/A"

	if siteConfig.Properties != nil && siteConfig.Properties.RemoteDebuggingEnabled != nil {
		remoteDebuggingEnabled = *siteConfig.Properties.RemoteDebuggingEnabled
		if siteConfig.Properties.RemoteDebuggingVersion != nil {
			remoteDebuggingVersion = *siteConfig.Properties.RemoteDebuggingVersion
		}
	}

	// If remote debugging is NOT enabled, this resource should not be flagged
	// Return a command indicating it's secure
	if !remoteDebuggingEnabled {
		return []Command{{
			Command:      fmt.Sprintf("az webapp config show --resource-group %s --name %s --query remoteDebuggingEnabled", resourceGroupName, appServiceName),
			Description:  "Verify remote debugging is disabled",
			ActualOutput: fmt.Sprintf("✓ Remote debugging is DISABLED (secure configuration)"),
			ExitCode:     0,
		}}
	}

	// Remote debugging IS enabled - this is a vulnerability
	return []Command{
		{
			Command:                   fmt.Sprintf("az webapp config show --resource-group %s --name %s --query '{remoteDebuggingEnabled: remoteDebuggingEnabled, remoteDebuggingVersion: remoteDebuggingVersion}'", resourceGroupName, appServiceName),
			Description:               "Check remote debugging configuration",
			ExpectedOutputDescription: "remoteDebuggingEnabled should be false for production environments",
			ActualOutput:              fmt.Sprintf("✗ VULNERABLE: Remote debugging is ENABLED\nVersion: %s\nThis provides RCE-equivalent access to the application", remoteDebuggingVersion),
			ExitCode:                  1,
		},
		{
			Command:                   fmt.Sprintf("az webapp config set --resource-group %s --name %s --remote-debugging-enabled false", resourceGroupName, appServiceName),
			Description:               "Remediation: Disable remote debugging",
			ExpectedOutputDescription: "Remote debugging will be disabled",
			ActualOutput:              "Run this command to disable remote debugging",
			ExitCode:                  0,
		},
	}
}

// checkPublicAccess performs HTTP testing for publicly accessible App Services
func (a *AppServiceEnricher) checkPublicAccess(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract App Service name
	appServiceName := resource.Name
	if appServiceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing App Service name",
			ActualOutput: "Error: App Service name is empty",
		})
		return commands
	}

	// Construct App Service URL
	appServiceURL := fmt.Sprintf("https://%s.azurewebsites.net", appServiceName)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow more than 5 redirects
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Test 1: HTTP GET to main page
	resp, err := client.Get(appServiceURL)

	httpGetCommand := Command{
		Command:                   fmt.Sprintf("curl -i -L '%s' --max-time 10", appServiceURL),
		Description:               "Test HTTP GET to App Service default page",
		ExpectedOutputDescription: "200 = accessible | 401/403 = authentication required | 404 = not found but accessible | 503 = app stopped/error",
	}

	if err != nil {
		httpGetCommand.Error = err.Error()
		httpGetCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		httpGetCommand.ExitCode = -1
	} else {
		defer resp.Body.Close()
		// Read full response body (limit to first 2000 characters for App Service responses)
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2000))
		if readErr != nil {
			httpGetCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			httpGetCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		httpGetCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, httpGetCommand)

	// Test 2: Check for SCM/Kudu site (if accessible)
	scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net", appServiceName)

	scmResp, scmErr := client.Get(scmURL)

	scmCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", scmURL),
		Description:               "Test access to SCM/Kudu management site",
		ExpectedOutputDescription: "200 = SCM accessible (high risk) | 401/403 = authentication required | timeout = blocked",
	}

	if scmErr != nil {
		scmCommand.Error = scmErr.Error()
		scmCommand.ActualOutput = fmt.Sprintf("Request failed: %s", scmErr.Error())
		scmCommand.ExitCode = -1
	} else {
		defer scmResp.Body.Close()
		// Read SCM response body
		body, readErr := io.ReadAll(io.LimitReader(scmResp.Body, 1000))
		if readErr != nil {
			scmCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			scmCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		scmCommand.ExitCode = scmResp.StatusCode
	}

	commands = append(commands, scmCommand)

	return commands
}
