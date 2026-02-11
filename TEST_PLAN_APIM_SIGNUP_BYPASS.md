# End-to-End Test Plan: APIM Cross-Tenant Signup Bypass Detection (PR #224)

**Test Objective:** Validate detection of GHSA-vcwf-73jp-r7mv vulnerability in Azure API Management instances

**Branch:** `tanishqrupaal/clo-61-apim-cross-tenant-signup-issue`

**Date:** 2026-02-10

---

## Prerequisites

### Azure Environment Setup

You need access to an Azure subscription with permissions to:
- Create API Management instances
- Configure identity providers
- Query Azure Resource Graph

### Test APIM Instances Required

Create the following test instances to cover all scenarios:

| Instance Name | SKU | Developer Portal | Basic Auth | Expected Result |
|--------------|-----|------------------|------------|-----------------|
| `apim-vuln-test` | Standard | Enabled | ✅ Configured | **VULNERABLE** |
| `apim-safe-aad` | Standard | Enabled | ❌ Only Azure AD | **NOT VULNERABLE** |
| `apim-portal-disabled` | Standard | Disabled | ✅ Configured | **NOT VULNERABLE** |
| `apim-consumption` | Consumption | N/A | N/A | **NOT DETECTED** (filtered by query) |
| `apim-private-network` | Standard | Enabled | ✅ Configured | **VULNERABLE** (ARG), unreachable (enricher) |

### Local Environment

```bash
# Ensure you're on the PR branch
git checkout tanishqrupaal/clo-61-apim-cross-tenant-signup-issue

# Build nebula
go build -v ./...

# Verify binary created
ls -lh ./nebula

# Authenticate to Azure
az login
az account show
```

---

## Phase 1: ARG Query Validation

**Objective:** Verify the ARG query correctly identifies vulnerable instances

### Test 1.1: Query Syntax Validation

```bash
# Test the ARG query directly
az graph query -q "
resources
| where type == 'microsoft.apimanagement/service'
| where properties.developerPortalStatus == 'Enabled'
| where sku.name != 'Consumption'
| join kind=inner (
    resources
    | where type == 'microsoft.apimanagement/service/identityproviders'
    | where name endswith '/basic'
    | extend apimId = tolower(tostring(split(id, '/identityProviders/')[0]))
) on \$left.id == \$right.apimId
| project
    id,
    name,
    type,
    location,
    resourceGroup,
    subscriptionId,
    developerPortalStatus = tostring(properties.developerPortalStatus),
    skuName = tostring(sku.name),
    developerPortalUrl = tostring(properties.developerPortalUrl),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    basicAuthConfigured = true
"
```

**Expected Results:**
- ✅ Query executes without syntax errors
- ✅ Returns `apim-vuln-test` instance
- ✅ Does NOT return `apim-safe-aad` (no Basic Auth)
- ✅ Does NOT return `apim-portal-disabled` (portal disabled)
- ✅ Does NOT return `apim-consumption` (Consumption SKU filtered)
- ✅ Returns `apim-private-network` (ARG doesn't test connectivity)

**Validation:**
```bash
# Count should match number of vulnerable instances
az graph query -q "..." --query "count(data)"

# Verify each returned instance has:
# - developerPortalStatus == "Enabled"
# - sku.name != "Consumption"
# - basicAuthConfigured == true
```

### Test 1.2: Template Loading

```bash
# Verify template is properly formatted
cat pkg/templates/apim_signup_bypass.yaml | grep -A 5 "^id:"
cat pkg/templates/apim_signup_bypass.yaml | grep -A 5 "^query:"

# Check template ID matches enricher
grep "apim_cross_tenant_signup_bypass" pkg/templates/apim_signup_bypass.yaml
grep "apim_cross_tenant_signup_bypass" pkg/links/azure/enricher/api_management.go
```

**Expected Results:**
- ✅ Template ID: `apim_cross_tenant_signup_bypass`
- ✅ Enricher `CanEnrich()` matches template ID
- ✅ YAML is valid (no parse errors)

---

## Phase 2: Enricher Validation

**Objective:** Verify active probing correctly tests signup API endpoints

### Test 2.1: Enricher Registration

```bash
# Verify enricher is registered
grep -A 60 "func NewEnrichmentRegistry" pkg/links/azure/enricher/registry.go | grep "APIManagementEnricher"
```

**Expected Results:**
- ✅ `&APIManagementEnricher{}` present in registry
- ✅ Enricher appears in "API Management" section (line ~56)

### Test 2.2: Enricher Logic Unit Tests

**Test Case: Developer Portal URL Construction**

For instance `apim-vuln-test`, verify:
- If `developerPortalUrl` property exists → use it
- If missing → construct as `https://{apim-name}.developer.azure-api.net`

**Test Case: HTTP Response Analysis**

Expected vulnerability assessments:

| HTTP Status | Response Body Contains | Vulnerability Status |
|-------------|----------------------|---------------------|
| 404 | (any) | NOT VULNERABLE - API disabled |
| 400 | "captcha" or "challenge" | VULNERABLE - API active (captcha validation) |
| 400 | "email" + "required" | VULNERABLE - API active (input validation) |
| 409 | (any) | VULNERABLE - API active (conflict) |
| 200/201 | (any) | CRITICAL - Signup succeeded! |
| 401/403 | (any) | Requires auth - needs investigation |

### Test 2.3: Manual Enricher Testing

```bash
# Run nebula with just the ARG scan (no enrichment yet)
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --output /tmp/apim-arg-results.json

# Inspect ARG results
cat /tmp/apim-arg-results.json | jq '.resources[] | {name, developerPortalUrl, basicAuthConfigured}'

# Run with enrichment enabled
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --enrich \
  --output /tmp/apim-enriched-results.json

# Inspect enrichment commands
cat /tmp/apim-enriched-results.json | jq '.resources[0].enrichment_commands'
```

**Expected Enrichment Commands (per instance):**

For `apim-vuln-test`:
1. **Command 1:** `curl -i 'https://apim-vuln-test.developer.azure-api.net' --max-time 15`
   - Description: "Test if Developer Portal is accessible"
   - Expected: Status 200 (portal loads)

2. **Command 2:** `curl -i 'https://apim-vuln-test.developer.azure-api.net/signup' --max-time 15`
   - Description: "Test if signup page is accessible (UI check)"
   - Expected: Status 200/404 (depends on UI setting)

3. **Command 3:** `curl -X POST 'https://apim-vuln-test.developer.azure-api.net/signup' -H 'Content-Type: application/json' --data-raw '...'`
   - Description: "Test signup API endpoint directly (VULNERABILITY TEST - GHSA-vcwf-73jp-r7mv)"
   - Expected: Status 400 with captcha error → **VULNERABLE**

For `apim-private-network`:
1. **Command 1:** Portal access test
   - Expected: `"error": "Request failed: context deadline exceeded"` or connection timeout
   - Exit code: -1

---

## Phase 3: End-to-End Workflow

**Objective:** Full nebula execution from ARG scan through Neo4j import

### Test 3.1: Complete Scan Execution

```bash
# Set subscription context
export AZURE_SUBSCRIPTION_ID="your-test-subscription-id"

# Run full nebula workflow
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --enrich \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --output /tmp/apim-e2e-test.json

# Verify output structure
cat /tmp/apim-e2e-test.json | jq 'keys'
# Expected: ["resources", "errors", "public_network_access", "anonymous_access", "public_network_and_anonymous_access"]
```

### Test 3.2: Result Categorization

```bash
# Check which category vulnerable instances appear in
cat /tmp/apim-e2e-test.json | jq '.resources[] | select(.name == "apim-vuln-test")'

# Instances with public developer portal should appear in public_network_access
cat /tmp/apim-e2e-test.json | jq '.public_network_access[] | select(.name == "apim-vuln-test")'
```

**Expected Categorization:**

| Instance | `resources[]` | `public_network_access[]` | `anonymous_access[]` |
|----------|---------------|--------------------------|---------------------|
| `apim-vuln-test` | ✅ | ✅ (portal is public) | ❓ (depends on config) |
| `apim-private-network` | ✅ | ❌ (private endpoint) | ❌ |

### Test 3.3: Neo4j Import (if applicable)

```bash
# If nebula supports Neo4j import for ARG findings
./nebula azure push \
  --input /tmp/apim-e2e-test.json \
  --neo4j-uri bolt://localhost:7687

# Query Neo4j for APIM vulnerabilities
# (This depends on how nebula models ARG findings in the graph)
```

---

## Phase 4: Negative Test Cases

**Objective:** Verify false positives are avoided

### Test 4.1: Azure AD Only Authentication

**Setup:**
- Instance: `apim-safe-aad`
- Config: Developer Portal enabled, only Azure AD identity provider

```bash
# Verify Basic Auth is NOT configured
az apim identity-provider list \
  --resource-group test-rg \
  --service-name apim-safe-aad \
  --query "[?type=='Basic']"
# Expected: []

# Run nebula scan
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --output /tmp/apim-negative-test.json

# Verify instance is NOT flagged
cat /tmp/apim-negative-test.json | jq '.resources[] | select(.name == "apim-safe-aad")'
# Expected: null (no results)
```

### Test 4.2: Developer Portal Disabled

**Setup:**
- Instance: `apim-portal-disabled`
- Config: Basic Auth configured BUT Developer Portal disabled

```bash
# Verify portal is disabled
az apim show \
  --resource-group test-rg \
  --name apim-portal-disabled \
  --query properties.developerPortalStatus
# Expected: "Disabled"

# Run nebula scan
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --output /tmp/apim-portal-disabled-test.json

# Verify instance is NOT flagged
cat /tmp/apim-portal-disabled-test.json | jq '.resources[] | select(.name == "apim-portal-disabled")'
# Expected: null (no results)
```

### Test 4.3: Consumption SKU

**Setup:**
- Instance: `apim-consumption`
- SKU: Consumption (no Developer Portal support)

```bash
# Verify SKU
az apim show \
  --resource-group test-rg \
  --name apim-consumption \
  --query sku.name
# Expected: "Consumption"

# Run nebula scan
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --output /tmp/apim-consumption-test.json

# Verify instance is NOT flagged
cat /tmp/apim-consumption-test.json | jq '.resources[] | select(.name == "apim-consumption")'
# Expected: null (no results)
```

---

## Phase 5: Positive Test Cases

**Objective:** Verify true vulnerabilities are detected

### Test 5.1: Standard Vulnerable Configuration

**Setup:**
- Instance: `apim-vuln-test`
- Config: Developer Portal enabled, Basic Auth configured, signup disabled in UI

```bash
# Verify configuration
az apim show \
  --resource-group test-rg \
  --name apim-vuln-test \
  --query "{portal: properties.developerPortalStatus, sku: sku.name}"
# Expected: {"portal": "Enabled", "sku": "Standard"}

az apim identity-provider show \
  --resource-group test-rg \
  --service-name apim-vuln-test \
  --identity-provider-name basic
# Expected: Details of basic identity provider

# Run nebula scan with enrichment
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --enrich \
  --output /tmp/apim-vuln-test.json

# Verify instance IS flagged
cat /tmp/apim-vuln-test.json | jq '.resources[] | select(.name == "apim-vuln-test")'
# Expected: Full resource details with enrichment commands

# Verify vulnerability assessment
cat /tmp/apim-vuln-test.json | jq '.resources[] | select(.name == "apim-vuln-test") | .enrichment_commands[2].actual_output'
# Expected: Contains "VULNERABLE - Signup API is ACTIVE"
```

### Test 5.2: Manual Signup API Test (Ground Truth)

**Verify the vulnerability actually exists:**

```bash
# Get developer portal URL
PORTAL_URL=$(az apim show \
  --resource-group test-rg \
  --name apim-vuln-test \
  --query properties.developerPortalUrl -o tsv)

echo "Portal URL: $PORTAL_URL"

# Test 1: Check if portal is accessible
curl -i "$PORTAL_URL"
# Expected: 200 OK

# Test 2: Check signup page
curl -i "$PORTAL_URL/signup"
# Expected: 200 or 404 (depends on UI setting)

# Test 3: Test signup API endpoint (THE VULNERABILITY)
curl -X POST "$PORTAL_URL/signup" \
  -H 'Content-Type: application/json' \
  -H "Origin: $PORTAL_URL" \
  -d '{
    "challenge": {
      "testCaptchaRequest": {
        "challengeId": "00000000-0000-0000-0000-000000000000",
        "inputSolution": "AAAAAA"
      },
      "azureRegion": "NorthCentralUS",
      "challengeType": "visual"
    },
    "signupData": {
      "email": "test@example.com",
      "firstName": "Test",
      "lastName": "User",
      "password": "TestPass123!",
      "confirmation": "signup",
      "appType": "developerPortal"
    }
  }' \
  --max-time 15 \
  -v

# Expected Response Patterns:
# - 400 with captcha error → VULNERABLE (API is processing requests despite UI disabled)
# - 404 → NOT VULNERABLE (API truly disabled)
# - 200/201 → CRITICAL (signup succeeded - very bad!)
```

### Test 5.3: Cross-Tenant Attack Simulation

**Simulate the actual attack vector:**

```bash
# Prerequisite: You need TWO APIM instances
# - apim-attacker: Your instance with signup enabled
# - apim-victim: Target instance with signup "disabled" in UI

# Step 1: On attacker's portal, intercept signup request
# (Use browser DevTools Network tab to capture the POST request)

# Step 2: Replay request against victim instance
VICTIM_PORTAL="https://apim-victim.developer.azure-api.net"

curl -X POST "$VICTIM_PORTAL/signup" \
  -H 'Content-Type: application/json' \
  -H "Host: apim-victim.developer.azure-api.net" \
  -H "Origin: $VICTIM_PORTAL" \
  -d '{...signup payload...}'

# If you get captcha validation error, the vulnerability exists
# If you get 404, the instance is NOT vulnerable
```

---

## Phase 6: Edge Cases

### Test 6.1: Private Network Access

**Setup:**
- Instance: `apim-private-network`
- Config: Vulnerable configuration BUT behind private endpoint

```bash
# Verify private endpoint configuration
az apim show \
  --resource-group test-rg \
  --name apim-private-network \
  --query properties.publicNetworkAccess
# Expected: "Disabled"

# Run nebula scan
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --enrich \
  --output /tmp/apim-private-test.json

# Verify ARG detects it
cat /tmp/apim-private-test.json | jq '.resources[] | select(.name == "apim-private-network")'
# Expected: Resource found

# Verify enricher cannot reach it
cat /tmp/apim-private-test.json | jq '.resources[] | select(.name == "apim-private-network") | .enrichment_commands[0]'
# Expected: "error": "Request failed: ...", "exit_code": -1
```

**Interpretation:**
- ARG correctly identifies the vulnerable CONFIGURATION
- Enricher correctly identifies it's not EXPLOITABLE from external network
- Triage note should indicate: "Requires internal network access to exploit"

### Test 6.2: Multiple Identity Providers

**Setup:**
- Instance with BOTH Basic Auth AND Azure AD configured

```bash
# Verify both providers exist
az apim identity-provider list \
  --resource-group test-rg \
  --service-name apim-multi-auth \
  --query "[].type"
# Expected: ["Basic", "AadB2C"] or similar

# Run scan
./nebula azure scan arg \
  --template apim_cross_tenant_signup_bypass \
  --enrich \
  --output /tmp/apim-multi-auth-test.json

# Verify instance IS flagged (Basic Auth exists = vulnerable)
cat /tmp/apim-multi-auth-test.json | jq '.resources[] | select(.name == "apim-multi-auth")'
# Expected: Resource found with vulnerability
```

---

## Success Criteria

### ARG Query
- ✅ Correctly identifies instances with (Portal Enabled + Basic Auth + Non-Consumption SKU)
- ✅ Excludes instances missing any required condition
- ✅ No syntax errors or query failures

### Enricher
- ✅ Registered in enrichment registry
- ✅ `CanEnrich()` matches template ID
- ✅ Generates 3 test commands per instance
- ✅ Correctly assesses vulnerability from HTTP responses
- ✅ Handles network errors gracefully

### End-to-End
- ✅ No false negatives (all vulnerable instances detected)
- ✅ No false positives (safe instances not flagged)
- ✅ Enrichment provides actionable triage data
- ✅ Results are properly categorized

### Triage Quality
- ✅ Output includes clear vulnerability assessment
- ✅ Distinguishes between "API active" vs "API disabled"
- ✅ Provides evidence (HTTP status + response body)
- ✅ Enrichment failures clearly marked

---

## Test Execution Checklist

```bash
# Pre-flight
[ ] Branch: tanishqrupaal/clo-61-apim-cross-tenant-signup-issue
[ ] Build successful: go build -v ./...
[ ] Azure authentication: az account show

# Phase 1: ARG Query
[ ] Test 1.1: Query syntax validation
[ ] Test 1.2: Template loading

# Phase 2: Enricher
[ ] Test 2.1: Enricher registration
[ ] Test 2.2: Response analysis logic
[ ] Test 2.3: Manual enricher testing

# Phase 3: End-to-End
[ ] Test 3.1: Complete scan execution
[ ] Test 3.2: Result categorization
[ ] Test 3.3: Neo4j import (if applicable)

# Phase 4: Negative Tests
[ ] Test 4.1: Azure AD only (no Basic Auth)
[ ] Test 4.2: Developer Portal disabled
[ ] Test 4.3: Consumption SKU

# Phase 5: Positive Tests
[ ] Test 5.1: Standard vulnerable config
[ ] Test 5.2: Manual signup API test
[ ] Test 5.3: Cross-tenant attack simulation

# Phase 6: Edge Cases
[ ] Test 6.1: Private network access
[ ] Test 6.2: Multiple identity providers

# Sign-off
[ ] All tests passed
[ ] No false positives observed
[ ] No false negatives observed
[ ] Enrichment provides actionable data
[ ] Ready for merge
```

---

## Troubleshooting

### Issue: ARG query returns no results

```bash
# Verify APIM instances exist
az graph query -q "resources | where type == 'microsoft.apimanagement/service'"

# Check developer portal status values
az graph query -q "resources | where type == 'microsoft.apimanagement/service' | project name, developerPortalStatus = properties.developerPortalStatus"

# Check identity providers
az graph query -q "resources | where type == 'microsoft.apimanagement/service/identityproviders' | project name, parent = split(id, '/identityProviders/')[0]"
```

### Issue: Enricher times out

```bash
# Test connectivity manually
curl -v https://your-apim.developer.azure-api.net --max-time 15

# Check firewall rules
az apim show --name your-apim --resource-group your-rg --query properties.publicNetworkAccess

# Verify developer portal is published
az apim show --name your-apim --resource-group your-rg --query properties.developerPortalStatus
```

### Issue: Signup API returns 404

**This could mean:**
1. ✅ Instance is NOT vulnerable (API truly disabled) - GOOD!
2. ❌ Basic Auth provider was removed - instance safe
3. ❌ Developer portal URL is incorrect

```bash
# Verify Basic Auth still exists
az apim identity-provider show \
  --resource-group your-rg \
  --service-name your-apim \
  --identity-provider-name basic

# Check developer portal URL
az apim show \
  --resource-group your-rg \
  --name your-apim \
  --query properties.developerPortalUrl
```

---

## Cleanup

```bash
# Remove test APIM instances (they're expensive!)
az apim delete --name apim-vuln-test --resource-group test-rg --yes --no-wait
az apim delete --name apim-safe-aad --resource-group test-rg --yes --no-wait
az apim delete --name apim-portal-disabled --resource-group test-rg --yes --no-wait
az apim delete --name apim-consumption --resource-group test-rg --yes --no-wait
az apim delete --name apim-private-network --resource-group test-rg --yes --no-wait

# Remove test output files
rm -f /tmp/apim-*.json
```

---

## Notes

- **Cost Warning:** APIM instances are expensive (~$50-200/month depending on SKU). Use Developer tier for testing when possible.
- **Setup Time:** APIM provisioning takes 30-45 minutes. Plan accordingly.
- **Microsoft's Position:** This vulnerability is "by design" - they won't patch it. Remediation is to remove Basic Auth entirely.
- **Detection vs Exploitation:** ARG query detects vulnerable CONFIGURATION. Enricher validates EXPLOITABILITY.
