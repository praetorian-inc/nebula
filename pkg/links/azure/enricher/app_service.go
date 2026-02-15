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
	return templateID == "app_services_public_access" ||
		templateID == "app_service_remote_debugging_enabled" ||
		templateID == "function_app_http_anonymous_access" ||
		templateID == "app_service_auth_disabled"
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
	case "function_app_http_anonymous_access":
		return a.checkFunctionAppAnonymousAccess(ctx, resource)
	case "app_service_auth_disabled":
		return a.checkAuthenticationDisabled(ctx, resource)
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

// checkFunctionAppAnonymousAccess detects HTTP-triggered functions with anonymous authentication
func (a *AppServiceEnricher) checkFunctionAppAnonymousAccess(ctx context.Context, resource *model.AzureResource) []Command {
	functionAppName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if functionAppName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: "Error: Function App name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Create Web Apps client
	webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// List functions in the Function App
	functionsPager := webAppsClient.NewListFunctionsPager(resourceGroupName, functionAppName, nil)

	var allFunctions []*armappservice.FunctionEnvelope
	for functionsPager.More() {
		page, err := functionsPager.NextPage(ctx)
		if err != nil {
			return []Command{{
				Command:      fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, functionAppName),
				Description:  "List functions in Function App",
				ActualOutput: fmt.Sprintf("Error listing functions: %s", err.Error()),
				ExitCode:     1,
			}}
		}
		allFunctions = append(allFunctions, page.Value...)
	}

	// No functions deployed
	if len(allFunctions) == 0 {
		return []Command{{
			Command:      fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, functionAppName),
			Description:  "List functions in Function App",
			ActualOutput: "✓ No functions deployed in this Function App",
			ExitCode:     0,
		}}
	}

	// Parse functions to find HTTP triggers with anonymous access
	type AnonymousFunction struct {
		Name       string
		InvokeURL  string
		Methods    []string
		IsDisabled bool
	}

	var anonymousFunctions []AnonymousFunction
	var totalHTTPFunctions int

	for _, function := range allFunctions {
		if function.Properties == nil || function.Properties.Config == nil {
			continue
		}

		// Parse function configuration to find HTTP triggers
		// Config is interface{} containing a map with "bindings" key
		configMap, ok := function.Properties.Config.(map[string]interface{})
		if !ok {
			continue
		}

		bindingsRaw, exists := configMap["bindings"]
		if !exists {
			continue
		}

		// bindings is an array of binding configurations
		bindings, ok := bindingsRaw.([]interface{})
		if !ok {
			continue
		}

		for _, binding := range bindings {
			bindingMap, ok := binding.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if this is an HTTP trigger
			bindingType, _ := bindingMap["type"].(string)
			if bindingType != "httpTrigger" {
				continue
			}

			totalHTTPFunctions++

			// Check authentication level
			authLevel, _ := bindingMap["authLevel"].(string)
			if authLevel == "anonymous" {
				// Extract HTTP methods
				var methods []string
				if methodsRaw, exists := bindingMap["methods"]; exists {
					if methodsArr, ok := methodsRaw.([]interface{}); ok {
						for _, m := range methodsArr {
							if method, ok := m.(string); ok {
								methods = append(methods, method)
							}
						}
					}
				}

				// Get function name and invoke URL
				functionName := ""
				invokeURL := ""
				isDisabled := false

				if function.Name != nil {
					functionName = *function.Name
				}
				if function.Properties.InvokeURLTemplate != nil {
					invokeURL = *function.Properties.InvokeURLTemplate
				}
				if function.Properties.IsDisabled != nil {
					isDisabled = *function.Properties.IsDisabled
				}

				anonymousFunctions = append(anonymousFunctions, AnonymousFunction{
					Name:       functionName,
					InvokeURL:  invokeURL,
					Methods:    methods,
					IsDisabled: isDisabled,
				})
			}
		}
	}

	// If no anonymous functions found, return success
	if len(anonymousFunctions) == 0 {
		return []Command{{
			Command:      fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, functionAppName),
			Description:  "Check HTTP-triggered functions for anonymous access",
			ActualOutput: fmt.Sprintf("✓ No anonymous HTTP triggers found (%d HTTP function(s) checked, all require authentication)", totalHTTPFunctions),
			ExitCode:     0,
		}}
	}

	// Anonymous functions found - build detailed output
	var outputBuilder string
	outputBuilder = fmt.Sprintf("✗ VULNERABLE: Found %d HTTP-triggered function(s) with anonymous access:\n\n", len(anonymousFunctions))

	for i, fn := range anonymousFunctions {
		outputBuilder += fmt.Sprintf("%d. Function: %s\n", i+1, fn.Name)
		outputBuilder += fmt.Sprintf("   URL: %s\n", fn.InvokeURL)
		if len(fn.Methods) > 0 {
			outputBuilder += fmt.Sprintf("   Methods: %v\n", fn.Methods)
		}
		if fn.IsDisabled {
			outputBuilder += "   Status: DISABLED (but still vulnerable if re-enabled)\n"
		} else {
			outputBuilder += "   Status: ENABLED and ACCESSIBLE without authentication\n"
		}
		outputBuilder += "\n"
	}

	outputBuilder += "Security Impact:\n"
	outputBuilder += "- These functions can be invoked by anyone without authentication\n"
	outputBuilder += "- Function URLs are publicly accessible from the internet\n"
	outputBuilder += "- No function keys or authentication tokens required\n\n"

	outputBuilder += "Remediation:\n"
	outputBuilder += "1. Change authLevel from 'anonymous' to 'function' or 'admin' in function.json\n"
	outputBuilder += "2. Redeploy the Function App after configuration changes\n"
	outputBuilder += "3. For legitimate public functions, implement application-level authentication\n"
	outputBuilder += "4. Consider using IP restrictions or private endpoints for sensitive functions\n"

	return []Command{
		{
			Command:                   fmt.Sprintf("az rest --method GET --uri \"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s/functions?api-version=2023-12-01\" --query \"value[].{name:properties.name, authLevel:properties.config.bindings[?type=='httpTrigger'].authLevel | [0], invokeUrl:properties.invoke_url_template}\"", subscriptionID, resourceGroupName, functionAppName),
			Description:               "List HTTP-triggered functions with authentication levels",
			ExpectedOutputDescription: "All HTTP triggers should have authLevel set to 'function' or 'admin', not 'anonymous'",
			ActualOutput:              outputBuilder,
			ExitCode:                  1,
		},
	}
}

// checkAuthenticationDisabled checks if App Service Authentication (Easy Auth) is disabled
func (a *AppServiceEnricher) checkAuthenticationDisabled(ctx context.Context, resource *model.AzureResource) []Command {
	appServiceName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if appServiceName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check App Service authentication configuration",
			ActualOutput: "Error: App Service name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check App Service authentication configuration",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Create Web Apps client
	webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check App Service authentication configuration",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Get authentication settings V2
	authSettings, err := webAppsClient.GetAuthSettingsV2(ctx, resourceGroupName, appServiceName, nil)
	if err != nil {
		return []Command{{
			Command:      fmt.Sprintf("az webapp auth show --resource-group %s --name %s", resourceGroupName, appServiceName),
			Description:  "Check App Service authentication configuration",
			ActualOutput: fmt.Sprintf("Error getting authentication settings: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	// Check if authentication is enabled
	authEnabled := false
	if authSettings.Properties != nil && authSettings.Properties.Platform != nil && authSettings.Properties.Platform.Enabled != nil {
		authEnabled = *authSettings.Properties.Platform.Enabled
	}

	// If authentication is enabled, this resource should not be flagged
	if authEnabled {
		return []Command{{
			Command:      fmt.Sprintf("az webapp auth show --resource-group %s --name %s", resourceGroupName, appServiceName),
			Description:  "Verify App Service authentication is enabled",
			ActualOutput: "✓ App Service Authentication (Easy Auth) is ENABLED (secure configuration)",
			ExitCode:     0,
		}}
	}

	// Authentication is disabled - this is a potential vulnerability
	return []Command{
		{
			Command:                   fmt.Sprintf("az webapp auth show --resource-group %s --name %s", resourceGroupName, appServiceName),
			Description:               "Check App Service authentication configuration",
			ExpectedOutputDescription: "Authentication should be enabled for applications requiring identity verification",
			ActualOutput:              "✗ POTENTIAL ISSUE: App Service Authentication (Easy Auth) is DISABLED\n\nThis means:\n- No platform-level authentication is enforced\n- Requests reach application code without identity verification\n- Azure AD or other identity provider controls are not applied at platform level\n\nConsiderations:\n- Verify if application implements its own authentication (application-level auth)\n- Check if app is behind API Management or Application Gateway with authentication\n- Determine if this is a public-facing application or internal service\n- Review network access restrictions (private endpoints, IP allowlists)\n- Assess if authentication is required based on application purpose\n\nIf authentication is required, enable Easy Auth with Azure AD or another identity provider.",
			ExitCode:                  1,
		},
		{
			Command:                   fmt.Sprintf("az webapp auth update --resource-group %s --name %s --enabled true --action LoginWithAzureActiveDirectory", resourceGroupName, appServiceName),
			Description:               "Remediation: Enable App Service Authentication with Azure AD",
			ExpectedOutputDescription: "Authentication will be enabled with Azure AD as the provider",
			ActualOutput:              "Run this command to enable Easy Auth (requires configuring Azure AD app registration)",
			ExitCode:                  0,
		},
	}
}
