package enricher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// APIManagementEnricher implements enrichment for Azure API Management instances
// to test for the cross-tenant signup bypass vulnerability (GHSA-vcwf-73jp-r7mv)
type APIManagementEnricher struct{}

func (a *APIManagementEnricher) CanEnrich(templateID string) bool {
	return templateID == "apim_cross_tenant_signup_bypass" ||
	       templateID == "api_management_public_access"
}

// signupPayload represents the test payload for the signup API
type signupPayload struct {
	Challenge  signupChallenge `json:"challenge"`
	SignupData signupData      `json:"signupData"`
}

type signupChallenge struct {
	TestCaptchaRequest captchaRequest `json:"testCaptchaRequest"`
	AzureRegion        string         `json:"azureRegion"`
	ChallengeType      string         `json:"challengeType"`
}

type captchaRequest struct {
	ChallengeID   string `json:"challengeId"`
	InputSolution string `json:"inputSolution"`
}

type signupData struct {
	Email        string `json:"email"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Password     string `json:"password"`
	Confirmation string `json:"confirmation"`
	AppType      string `json:"appType"`
}

func (a *APIManagementEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract APIM name from the resource
	apimName := resource.Name
	if apimName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing APIM name",
			ActualOutput: "Error: APIM name is empty",
		})
		return commands
	}

	// Extract resource group from ID
	resourceGroup := ""
	if resourceID, ok := resource.Properties["id"].(string); ok {
		parts := strings.Split(resourceID, "/")
		for i, part := range parts {
			if strings.ToLower(part) == "resourcegroups" && i+1 < len(parts) {
				resourceGroup = parts[i+1]
				break
			}
		}
	}

	// Extract gateway URL from properties with fallback
	var gatewayURL string
	if gwURL, ok := resource.Properties["gatewayUrl"].(string); ok && gwURL != "" {
		gatewayURL = gwURL
	} else {
		// Fallback: construct gateway URL
		gatewayURL = fmt.Sprintf("https://%s.azure-api.net", apimName)
	}
	gatewayURL = strings.TrimSuffix(gatewayURL, "/")

	// Extract developer portal URL from properties (no fallback - may not exist)
	var developerPortalURL string
	if portalURL, ok := resource.Properties["developerPortalUrl"].(string); ok && portalURL != "" {
		developerPortalURL = strings.TrimSuffix(portalURL, "/")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Test 1: Check if gateway endpoint is accessible
	gatewayAccessCommand := a.testGatewayAccess(client, gatewayURL)
	commands = append(commands, gatewayAccessCommand)

	// Tests 2-4: Developer portal tests (only if developer portal exists)
	if developerPortalURL != "" {
		// Test 2: Check if Developer Portal is accessible
		portalAccessCommand := a.testPortalAccess(client, developerPortalURL)
		commands = append(commands, portalAccessCommand)

		// Test 3: Check if /signup page is accessible (GET)
		signupPageCommand := a.testSignupPageAccess(client, developerPortalURL)
		commands = append(commands, signupPageCommand)

		// Test 4: Test the signup API endpoint directly (POST) - the actual vulnerability test
		signupAPICommand := a.testSignupAPI(client, developerPortalURL)
		commands = append(commands, signupAPICommand)
	} else {
		// Developer portal URL not found - likely Consumption tier
		commands = append(commands, Command{
			Command:      "",
			Description:  "Developer portal URL not found in resource properties",
			ActualOutput: "Developer portal URL not found in resource properties - likely Consumption tier (no developer portal). Signup vulnerability tests skipped.",
			ExitCode:     0,
		})
	}

	// Add Azure CLI command for manual inspection
	if resourceGroup != "" {
		azCommand := Command{
			Command:                   fmt.Sprintf("az apim show --name %s --resource-group %s", apimName, resourceGroup),
			Description:               "Get full APIM configuration via Azure CLI",
			ExpectedOutputDescription: "Shows complete APIM configuration including SKU tier",
		}
		commands = append(commands, azCommand)
	}

	return commands
}

// testGatewayAccess tests if the APIM gateway endpoint is accessible
func (a *APIManagementEnricher) testGatewayAccess(client *http.Client, gatewayURL string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", gatewayURL),
		Description:               "Test if APIM gateway endpoint is accessible",
		ExpectedOutputDescription: "401 = authentication required | 200 = gateway accessible | 403 = blocked",
	}

	resp, err := client.Get(gatewayURL)
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

// testPortalAccess tests if the Developer Portal is accessible
func (a *APIManagementEnricher) testPortalAccess(client *http.Client, baseURL string) Command {
	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", baseURL),
		Description:               "Test if Developer Portal is accessible",
		ExpectedOutputDescription: "200 = portal accessible | 403 = blocked | timeout = not reachable",
	}

	resp, err := client.Get(baseURL)
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

// testSignupPageAccess tests if the signup page is accessible via GET
func (a *APIManagementEnricher) testSignupPageAccess(client *http.Client, baseURL string) Command {
	signupURL := baseURL + "/signup"

	cmd := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", signupURL),
		Description:               "Test if signup page is accessible (UI check)",
		ExpectedOutputDescription: "200 = signup visible in UI | 404 = signup hidden in UI (but API may still work!) | redirect = disabled",
	}

	resp, err := client.Get(signupURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, truncateString(string(body), 300))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

// testSignupAPI tests the signup API endpoint directly - this is the vulnerability test
func (a *APIManagementEnricher) testSignupAPI(client *http.Client, baseURL string) Command {
	signupURL := baseURL + "/signup"

	// Construct the test payload with fake captcha (will fail validation but proves API is active)
	payload := signupPayload{
		Challenge: signupChallenge{
			TestCaptchaRequest: captchaRequest{
				ChallengeID:   "00000000-0000-0000-0000-000000000000",
				InputSolution: "AAAAAA",
			},
			AzureRegion:   "NorthCentralUS",
			ChallengeType: "visual",
		},
		SignupData: signupData{
			Email:        "nebula-vuln-probe@nonexistent-invalid-domain.test",
			FirstName:    "Nebula",
			LastName:     "Probe",
			Password:     "NebulaProbe123!",
			Confirmation: "signup",
			AppType:      "developerPortal",
		},
	}

	payloadBytes, _ := json.Marshal(payload)

	// Create the equivalent curl command for reference
	curlCmd := fmt.Sprintf(`curl -X POST '%s' \
  -H 'Content-Type: application/json' \
  -H 'Origin: %s' \
  --data-raw '%s' --max-time 15`, signupURL, baseURL, string(payloadBytes))

	cmd := Command{
		Command:     curlCmd,
		Description: "Test signup API endpoint directly (VULNERABILITY TEST - GHSA-vcwf-73jp-r7mv)",
		ExpectedOutputDescription: `400 with captcha/challenge error = VULNERABLE (API active despite UI disabled)
404 = NOT vulnerable (API disabled)
200/201 = CRITICAL - signup succeeded!
409 = VULNERABLE (conflict/duplicate)`,
	}

	// Create the POST request
	req, err := http.NewRequest("POST", signupURL, bytes.NewReader(payloadBytes))
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Failed to create request: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", signupURL)

	resp, err := client.Do(req)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1500))
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Analyze the response to determine vulnerability status
	var vulnStatus string
	switch {
	case resp.StatusCode == 404:
		vulnStatus = "NOT VULNERABLE - Signup API not found (disabled)"
	case resp.StatusCode == 400:
		if strings.Contains(bodyLower, "captcha") || strings.Contains(bodyLower, "challenge") {
			vulnStatus = "VULNERABLE - Signup API is ACTIVE (captcha validation response)"
		} else if strings.Contains(bodyLower, "email") || strings.Contains(bodyLower, "password") || strings.Contains(bodyLower, "invalid") || strings.Contains(bodyLower, "validation") {
			vulnStatus = "VULNERABLE - Signup API is ACTIVE (input validation response)"
		} else {
			vulnStatus = "LIKELY VULNERABLE - Signup API responds to requests"
		}
	case resp.StatusCode == 409:
		vulnStatus = "VULNERABLE - Signup API is ACTIVE (conflict response)"
	case resp.StatusCode == 200 || resp.StatusCode == 201:
		vulnStatus = "CRITICAL - Signup API ACCEPTS registrations!"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		vulnStatus = "API responds but requires auth - further investigation needed"
	case resp.StatusCode == 422:
		vulnStatus = "VULNERABLE - Signup API validates input (422 response)"
	default:
		vulnStatus = fmt.Sprintf("Unexpected response (%d) - manual investigation needed", resp.StatusCode)
	}

	cmd.ActualOutput = fmt.Sprintf("ASSESSMENT: %s\n\nStatus: %d\nResponse: %s",
		vulnStatus, resp.StatusCode, truncateString(bodyStr, 800))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
