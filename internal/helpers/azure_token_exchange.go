package helpers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse represents the response from Azure token exchange
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeRefreshToken exchanges a refresh token for an access token
// Direct port of AzureHunter's token_exchange.py logic
func ExchangeRefreshToken(refreshToken, clientID, tenantID, scope, proxyURL string) (*TokenResponse, error) {
	// Detect which format to use based on client_id
	useBrokerFormat := (clientID == "c44b4083-3bb0-49c1-b47d-974e53cbdf3c") // Azure Portal broker

	var tokenURL string
	var formData url.Values

	if useBrokerFormat {
		// Use simple format for Azure Portal broker (no query params, no redirect_uri)
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
		formData = url.Values{
			"client_id":                    {clientID},
			"scope":                        {scope},
			"grant_type":                   {"refresh_token"},
			"client_info":                  {"1"},
			"x-client-SKU":                 {"msal.js.browser"},
			"x-client-VER":                 {"4.21.0"},
			"x-ms-lib-capability":          {"retry-after, h429"},
			"x-client-current-telemetry":   {"5|61,0,,,|,"},
			"x-client-last-telemetry":      {"5|0|||0,0"},
			"refresh_token":                {refreshToken},
		}
	} else {
		// Use broker format for other clients (with query params and redirect_uri)
		brkClientID := "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
		brkRedirectURI := "https://portal.azure.com/"
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token?brk_client_id=%s&brk_redirect_uri=%s",
			tenantID, brkClientID, url.QueryEscape(brkRedirectURI))

		encodedRedirectURI := fmt.Sprintf("brk-%s://portal.azure.com", brkClientID)
		formData = url.Values{
			"client_id":         {clientID},
			"redirect_uri":      {encodedRedirectURI},
			"scope":             {scope},
			"grant_type":        {"refresh_token"},
			"refresh_token":     {refreshToken},
			"brk_client_id":     {brkClientID},
			"brk_redirect_uri":  {brkRedirectURI},
		}
	}

	// Create HTTP client with optional proxy support
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if proxyURL != "" {
		proxyParsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyParsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Disable SSL verification for proxy
		}
		client.Transport = transport
	}

	// Create request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers to match AzureHunter
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Origin", "https://portal.azure.com")
	req.Header.Set("Referer", "https://portal.azure.com/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Priority", "u=4")
	req.Header.Set("Te", "trailers")

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var tokenResp TokenResponse
	if resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %v", err)
		}
		return &tokenResp, nil
	}

	// Handle error response
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, buf.String())
}

// GetGraphAPIToken gets a Graph API access token
func GetGraphAPIToken(refreshToken, tenantID, proxyURL string) (*TokenResponse, error) {
	clientID := "74658136-14ec-4630-ad9b-26e160ff0fc6" // Microsoft Graph API client ID
	scope := "https://graph.microsoft.com/.default"
	return ExchangeRefreshToken(refreshToken, clientID, tenantID, scope, proxyURL)
}

// GetPIMToken gets a PIM API access token - EXACTLY like AzureHunter
func GetPIMToken(refreshToken, tenantID, proxyURL string) (*TokenResponse, error) {
	clientID := "74658136-14ec-4630-ad9b-26e160ff0fc6" // Microsoft Graph API client ID for PIM
	pimAudience := "01fc33a7-78ba-4d2f-a4b7-768e336e890e"     // EXACT PIM audience from AzureHunter
	scope := pimAudience + "/.default"                        // EXACT scope format from AzureHunter
	return ExchangeRefreshToken(refreshToken, clientID, tenantID, scope, proxyURL)
}

// GetAzureRMToken gets an Azure Resource Manager access token
func GetAzureRMToken(refreshToken, tenantID, proxyURL string) (*TokenResponse, error) {
	clientID := "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" // Azure Management API client ID
	scope := "https://management.core.windows.net//.default"
	return ExchangeRefreshToken(refreshToken, clientID, tenantID, scope, proxyURL)
}