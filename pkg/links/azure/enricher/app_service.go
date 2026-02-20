package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// checkPublicAccess performs enrichment for publicly accessible App Services.
// For function apps (kind contains "functionapp"), it uses the Management API to enumerate
// HTTP triggers with auth levels, check IP restrictions, and check EasyAuth — providing
// actionable triage data beyond simple curl probes.
func (a *AppServiceEnricher) checkPublicAccess(ctx context.Context, resource *model.AzureResource) []Command {
	appServiceName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if appServiceName == "" {
		return []Command{{
			Description:  "Enrich publicly accessible App Service",
			ActualOutput: "Error: App Service name is empty",
			ExitCode:     1,
		}}
	}

	// Create HTTP client — do not follow redirects so we can detect auth gates
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var commands []Command

	// Step 1: HTTP probe to main page (applies to all app services)
	mainCmd := a.probeMainPage(httpClient, appServiceName)
	commands = append(commands, mainCmd)

	// Step 2: SCM/Kudu probe
	scmCmd := a.probeSCMSite(httpClient, appServiceName)
	commands = append(commands, scmCmd)

	// Step 3: For function apps, enumerate triggers via Management API
	kind, _ := resource.Properties["kind"].(string)
	isFunctionApp := strings.Contains(strings.ToLower(kind), "functionapp")

	if isFunctionApp && subscriptionID != "" && resourceGroupName != "" {
		mgmtCmds := a.enrichFunctionApp(ctx, subscriptionID, resourceGroupName, appServiceName)
		commands = append(commands, mgmtCmds...)
	}

	return commands
}

// probeMainPage sends an HTTP GET to the App Service default page and returns a clean
// status summary instead of the raw HTML body (which breaks markdown rendering).
func (a *AppServiceEnricher) probeMainPage(client *http.Client, appName string) Command {
	appURL := fmt.Sprintf("https://%s.azurewebsites.net", appName)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", appURL),
		Description:               "Test HTTP GET to App Service default page",
		ExpectedOutputDescription: "200 = accessible | 3xx = redirect (auth) | 401/403 = auth required or stopped | timeout = blocked",
	}

	resp, err := client.Get(appURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4000))
	bodyStr := string(body)

	// Extract a meaningful summary instead of dumping raw HTML
	title := extractHTMLTitle(bodyStr)

	var verdict string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		verdict = "ACCESSIBLE"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		verdict = fmt.Sprintf("REDIRECT to %s (likely auth gate)", location)
	case resp.StatusCode == 401:
		verdict = "AUTH REQUIRED (401)"
	case resp.StatusCode == 403:
		if strings.Contains(bodyStr, "stopped") || strings.Contains(bodyStr, "Unavailable") {
			verdict = "APP STOPPED (403 - Web App Unavailable)"
		} else {
			verdict = "FORBIDDEN (403)"
		}
	default:
		verdict = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	if title != "" {
		cmd.ActualOutput = fmt.Sprintf("Status: %d, %s\nPage title: %s", resp.StatusCode, verdict, title)
	} else {
		cmd.ActualOutput = fmt.Sprintf("Status: %d, %s\nBody preview: %s", resp.StatusCode, verdict, truncateString(bodyStr, 200))
	}

	// Semantic exit code: 1 = finding (accessible), 0 = ok (blocked/stopped)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		cmd.ExitCode = 1
	case resp.StatusCode == 403 && (strings.Contains(bodyStr, "stopped") || strings.Contains(bodyStr, "Unavailable")):
		cmd.ExitCode = 0
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		cmd.ExitCode = 1 // reachable, just auth-gated
	default:
		cmd.ExitCode = 0
	}

	return cmd
}

// probeSCMSite tests the SCM/Kudu management endpoint.
func (a *AppServiceEnricher) probeSCMSite(client *http.Client, appName string) Command {
	scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net", appName)

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", scmURL),
		Description:               "Test access to SCM/Kudu management site (high risk if accessible)",
		ExpectedOutputDescription: "200 = SCM accessible (HIGH RISK) | 3xx = redirect (auth) | 401/403 = auth required | timeout = blocked",
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

	var exitCode int
	var verdict string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		exitCode = 1
		verdict = "SCM ACCESSIBLE (HIGH RISK)"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		exitCode = 0
		verdict = "Redirect (auth required)"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		exitCode = 0
		verdict = "Auth required"
	default:
		exitCode = 0
		verdict = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	cmd.ActualOutput = fmt.Sprintf("Status: %d, %s\nBody preview: %s", resp.StatusCode, verdict, truncateString(string(body), 200))
	cmd.ExitCode = exitCode

	return cmd
}

// enrichFunctionApp uses the Management API to enumerate HTTP triggers, check IP restrictions,
// and check EasyAuth for a function app. Returns additional enrichment commands.
func (a *AppServiceEnricher) enrichFunctionApp(ctx context.Context, subscriptionID, resourceGroupName, appName string) []Command {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Description:  "Enumerate Function App triggers via Management API",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     -1,
		}}
	}

	webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Description:  "Enumerate Function App triggers via Management API",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     -1,
		}}
	}

	var commands []Command

	// Check IP restrictions (ARG doesn't index this)
	ipCmd := a.checkIPRestrictions(ctx, webAppsClient, resourceGroupName, appName)
	commands = append(commands, ipCmd)

	// Enumerate HTTP triggers
	cliEquiv := fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, appName)
	triggers, totalFunctions, err := ListHTTPTriggers(ctx, webAppsClient, resourceGroupName, appName, "")
	if err != nil {
		commands = append(commands, Command{
			Command:      cliEquiv,
			Description:  "Enumerate Function App HTTP triggers via Management API",
			ActualOutput: fmt.Sprintf("Error: %s", err.Error()),
			ExitCode:     -1,
		})
		return commands
	}

	// Build trigger summary with auth level counts
	anonymousCount := 0
	functionKeyCount := 0
	adminKeyCount := 0
	for _, t := range triggers {
		switch strings.ToLower(t.AuthLevel) {
		case "anonymous":
			anonymousCount++
		case "function":
			functionKeyCount++
		case "admin":
			adminKeyCount++
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Function App: %s | Total functions: %d | HTTP triggers: %d\n", appName, totalFunctions, len(triggers)))
	sb.WriteString(fmt.Sprintf("Auth levels — Anonymous: %d | Function key: %d | Admin key: %d\n\n", anonymousCount, functionKeyCount, adminKeyCount))

	for _, t := range triggers {
		status := "enabled"
		if t.IsDisabled {
			status = "DISABLED"
		}
		methods := "ANY"
		if len(t.Methods) > 0 {
			methods = strings.Join(t.Methods, ", ")
		}
		sb.WriteString(fmt.Sprintf("  %-30s | auth=%-10s | route=%-25s | methods=%-10s | %s\n", t.FunctionName, t.AuthLevel, t.Route, methods, status))
		if t.InvokeURL != "" {
			sb.WriteString(fmt.Sprintf("  %-30s   invoke: %s\n", "", t.InvokeURL))
		}
	}

	if anonymousCount > 0 {
		sb.WriteString(fmt.Sprintf("\nFINDING: %d anonymous HTTP trigger(s) — no function key or auth token required", anonymousCount))
	} else if len(triggers) == 0 && totalFunctions > 0 {
		sb.WriteString("No HTTP triggers found — all functions use non-HTTP triggers (queue, timer, etc.)")
	} else if len(triggers) == 0 && totalFunctions == 0 {
		sb.WriteString("No functions deployed in this Function App")
	} else {
		sb.WriteString("All HTTP triggers require authentication (function key or admin key)")
	}

	exitCode := 0
	if anonymousCount > 0 {
		exitCode = 1
	}

	commands = append(commands, Command{
		Command:                   cliEquiv,
		Description:               "Enumerate Function App HTTP triggers via Management API",
		ExpectedOutputDescription: "Lists all HTTP triggers with auth levels, invoke URLs, and methods",
		ActualOutput:              sb.String(),
		ExitCode:                  exitCode,
	})

	// Check EasyAuth as compensating control
	easyAuthCmd := a.checkEasyAuth(ctx, webAppsClient, resourceGroupName, appName)
	commands = append(commands, easyAuthCmd)

	return commands
}

// checkIPRestrictions queries IP security restrictions via Management API.
// ARG does not index siteConfig.ipSecurityRestrictions (always null).
func (a *AppServiceEnricher) checkIPRestrictions(ctx context.Context, client *armappservice.WebAppsClient, resourceGroupName, appName string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("az webapp config access-restriction show --resource-group %s --name %s", resourceGroupName, appName),
		Description:               "Check IP security restrictions via Management API (not available in ARG)",
		ExpectedOutputDescription: "IP restrictions present = lower severity | No restrictions = fully open to internet",
	}

	siteConfig, err := client.GetConfiguration(ctx, resourceGroupName, appName, nil)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Error getting site configuration: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	if siteConfig.Properties == nil || siteConfig.Properties.IPSecurityRestrictions == nil {
		cmd.ActualOutput = "No IP restrictions configured — App Service is fully open to all internet traffic."
		cmd.ExitCode = 1
		return cmd
	}

	restrictions := siteConfig.Properties.IPSecurityRestrictions

	// Filter out the default "Allow all" rule (priority 2147483647)
	var meaningful []*armappservice.IPSecurityRestriction
	for _, r := range restrictions {
		if r.Priority != nil && *r.Priority == 2147483647 {
			continue
		}
		meaningful = append(meaningful, r)
	}

	if len(meaningful) == 0 {
		cmd.ActualOutput = "No IP restrictions configured — App Service is fully open to all internet traffic."
		cmd.ExitCode = 1
		return cmd
	}

	var rsb strings.Builder
	rsb.WriteString(fmt.Sprintf("IP restrictions found: %d rule(s)\n", len(meaningful)))
	for _, r := range meaningful {
		name := ""
		if r.Name != nil {
			name = *r.Name
		}
		action := ""
		if r.Action != nil {
			action = *r.Action
		}
		ipAddress := ""
		if r.IPAddress != nil {
			ipAddress = *r.IPAddress
		}
		priority := int32(0)
		if r.Priority != nil {
			priority = *r.Priority
		}
		rsb.WriteString(fmt.Sprintf("  [%d] %s: %s %s\n", priority, name, action, ipAddress))
	}
	rsb.WriteString("\nIP restrictions are present — network-level filtering is in place.")

	cmd.ActualOutput = rsb.String()
	cmd.ExitCode = 0
	return cmd
}

// checkEasyAuth queries EasyAuth / Entra ID platform authentication status.
func (a *AppServiceEnricher) checkEasyAuth(ctx context.Context, client *armappservice.WebAppsClient, resourceGroupName, appName string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("az webapp auth show --resource-group %s --name %s", resourceGroupName, appName),
		Description:               "Check EasyAuth / Entra ID platform authentication",
		ExpectedOutputDescription: "Enabled = compensating control | Disabled = anonymous triggers are truly unauthenticated",
	}

	status := CheckEasyAuth(ctx, client, resourceGroupName, appName)
	if status.Err != nil {
		cmd.Error = status.Err.Error()
		cmd.ActualOutput = fmt.Sprintf("Error checking EasyAuth: %s", status.Err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	if status.Enabled {
		cmd.ActualOutput = "EasyAuth is ENABLED — platform enforces authentication before requests reach function code. Anonymous trigger auth levels are overridden by EasyAuth."
		cmd.ExitCode = 0
	} else {
		cmd.ActualOutput = "EasyAuth is DISABLED — no platform-level authentication. Anonymous triggers are truly accessible without any authentication."
		cmd.ExitCode = 1
	}

	return cmd
}

// extractHTMLTitle extracts the <title> content from an HTML response body.
// Returns empty string if no title is found.
func extractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Find the closing > of the opening tag
	tagEnd := strings.Index(body[start:], ">")
	if tagEnd == -1 {
		return ""
	}
	contentStart := start + tagEnd + 1
	end := strings.Index(lower[contentStart:], "</title")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[contentStart : contentStart+end])
}

// checkFunctionAppAnonymousAccess detects HTTP-triggered functions with anonymous authentication.
// Uses the shared ListHTTPTriggers helper (fix #3: deduplication with FunctionAppEnricher).
func (a *AppServiceEnricher) checkFunctionAppAnonymousAccess(ctx context.Context, resource *model.AzureResource) []Command {
	functionAppName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if functionAppName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: "Error: Function App name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Description:  "Check Function App for anonymous HTTP triggers",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	cliEquiv := fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, functionAppName)

	triggers, totalFunctions, err := ListHTTPTriggers(ctx, webAppsClient, resourceGroupName, functionAppName, "")
	if err != nil {
		return []Command{{
			Command:      cliEquiv,
			Description:  "List functions in Function App",
			ActualOutput: fmt.Sprintf("Error listing functions: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	if totalFunctions == 0 {
		return []Command{{
			Command:      cliEquiv,
			Description:  "List functions in Function App",
			ActualOutput: "No functions deployed in this Function App",
			ExitCode:     0,
		}}
	}

	// Filter to anonymous triggers (case-insensitive)
	var anonymousTriggers []HTTPTriggerInfo
	for _, t := range triggers {
		if strings.EqualFold(t.AuthLevel, "anonymous") {
			anonymousTriggers = append(anonymousTriggers, t)
		}
	}

	if len(anonymousTriggers) == 0 {
		return []Command{{
			Command:      cliEquiv,
			Description:  "Check HTTP-triggered functions for anonymous access",
			ActualOutput: fmt.Sprintf("No anonymous HTTP triggers found (%d HTTP function(s) checked, all require authentication)", len(triggers)),
			ExitCode:     0,
		}}
	}

	// Build detailed output for anonymous triggers
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d HTTP-triggered function(s) with anonymous access:\n\n", len(anonymousTriggers)))

	for i, fn := range anonymousTriggers {
		sb.WriteString(fmt.Sprintf("%d. Function: %s\n", i+1, fn.FunctionName))
		sb.WriteString(fmt.Sprintf("   URL: %s\n", fn.InvokeURL))
		if len(fn.Methods) > 0 {
			sb.WriteString(fmt.Sprintf("   Methods: %v\n", fn.Methods))
		}
		if fn.IsDisabled {
			sb.WriteString("   Status: DISABLED (but still vulnerable if re-enabled)\n")
		} else {
			sb.WriteString("   Status: ENABLED and ACCESSIBLE without authentication\n")
		}
		sb.WriteString("\n")
	}

	return []Command{{
		Command:                   cliEquiv,
		Description:               "List HTTP-triggered functions with authentication levels",
		ExpectedOutputDescription: "All HTTP triggers should have authLevel set to 'function' or 'admin', not 'anonymous'",
		ActualOutput:              sb.String(),
		ExitCode:                  1,
	}}
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
