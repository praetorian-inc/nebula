# E2E Testing: Event Grid Webhook Authentication Detection

This directory contains end-to-end testing infrastructure for the Event Grid Subscription Webhook Authentication ARG rule (Issue #220).

## Overview

The E2E test validates that the Nebula scanner correctly:
1. **Detects vulnerable** Event Grid subscriptions without Azure AD authentication
2. **Filters out secure** Event Grid subscriptions with Azure AD authentication
3. **Enricher performs** dynamic webhook testing and provides accurate verdicts

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- Azure subscription with permissions to create resources
- Go 1.21+ (to build Nebula)
- jq (for JSON parsing)
- Bash shell

## Test Architecture

```
Storage Account
    └── System Topic (Microsoft.Storage.StorageAccounts events)
        ├── vulnerable-webhook-XXX (NO Azure AD auth) ❌ Should be DETECTED
        └── secure-webhook-XXX (WITH Azure AD auth) ✅ Should NOT be detected
```

## Quick Start

### Step 1: Deploy Test Resources

```bash
cd test-infrastructure
./deploy-test-resources.sh
```

This creates:
- Resource group: `nebula-e2e-eventgrid-webhook`
- Storage account with System Topic
- Two Event Grid subscriptions:
  - **Vulnerable**: No Azure AD authentication (should be detected)
  - **Secure**: With Azure AD authentication (should NOT be detected)

### Step 2: Build and Run Nebula

```bash
cd ..
go build -o nebula .
./nebula azure recon arg-scan --subscription <YOUR_SUBSCRIPTION_ID>
```

Replace `<YOUR_SUBSCRIPTION_ID>` with your Azure subscription ID (printed by deploy script).

### Step 3: Verify Results

```bash
cd test-infrastructure
./verify-results.sh
```

This script checks:
- ✅ Vulnerable subscription appears in findings
- ✅ Secure subscription does NOT appear in findings
- ✅ Enricher output is present and accurate

### Step 4: Manual Inspection

#### View All Findings
```bash
cat ../nebula-output/arg-scan-<SUBSCRIPTION_ID>.json | \
  jq '.findings[] | select(.properties.templateID == "event_grid_subscription_webhook_auth")'
```

#### View Markdown Report
```bash
cat ../nebula-output/arg-scan-<SUBSCRIPTION_ID>.md
```

Search for "Event Grid Subscription Webhook Without Azure AD Authentication" section.

#### View Enrichment Output
```bash
cat ../nebula-output/arg-scan-<SUBSCRIPTION_ID>.json | \
  jq '.findings[] | select(.properties.templateID == "event_grid_subscription_webhook_auth") | .properties.enrichment'
```

### Step 5: Cleanup

```bash
az group delete --name nebula-e2e-eventgrid-webhook --yes --no-wait
```

## Expected Results

### Vulnerable Subscription (Should Be Detected)

**Finding Properties:**
- `name`: `vulnerable-webhook-<suffix>`
- `templateID`: `event_grid_subscription_webhook_auth`
- `azureAdTenantId`: Empty or null
- `destinationType`: `WebHook`

**Enrichment Output:**
```json
{
  "description": "Check Event Grid Subscription webhook authentication",
  "actualOutput": "⚠️ WARNING: No Azure AD authentication configured",
  "exitCode": 1
}
```

**Dynamic Test Results:**
- If webhook URL is reachable: HTTP status code and verdict
- If webhook is firewalled: "Connection timeout - webhook likely behind firewall"

### Secure Subscription (Should NOT Be Detected)

This subscription should **NOT appear in findings** because:
- `azureActiveDirectoryTenantId` is configured
- ARG query filters these out: `where isempty(azureAdTenantId) or isnull(azureAdTenantId)`

## Troubleshooting

### No Findings Returned

**Possible causes:**
1. Template not loaded by Nebula
   - Check: `./nebula azure recon arg-scan --help` for `--template-dir` flag
   - Verify: `pkg/templates/event_grid_webhook_auth.yaml` exists

2. Query doesn't match resources
   - Manually run the KQL query in Azure Portal → Resource Graph Explorer
   - Check subscription scope

3. Template ID mismatch
   - Verify enricher `CanEnrich()` matches template `id` field

### False Negative (Vulnerable Subscription Not Detected)

**Debug steps:**
1. Check ARG query in Azure Portal Resource Graph Explorer
2. Verify subscription actually lacks Azure AD auth:
   ```bash
   az eventgrid system-topic event-subscription show \
     --name vulnerable-webhook-XXX \
     --system-topic-name nebula-test-topic-XXX \
     --resource-group nebula-e2e-eventgrid-webhook
   ```
3. Check for `azureActiveDirectoryTenantId` in output (should be absent)

### False Positive (Secure Subscription Detected)

**Debug steps:**
1. Verify the subscription has Azure AD auth in Azure:
   ```bash
   az eventgrid system-topic event-subscription show \
     --name secure-webhook-XXX \
     --system-topic-name nebula-test-topic-XXX \
     --resource-group nebula-e2e-eventgrid-webhook | \
     jq '.destination.properties.azureActiveDirectoryTenantId'
   ```
2. Check ARG query filter logic
3. Verify enricher correctly identifies Azure AD auth

### Enricher Not Running

**Possible causes:**
1. Enricher not registered in `pkg/links/azure/enricher/registry.go`
2. `CanEnrich()` returns false (template ID mismatch)
3. Enrichment disabled: `--disable-enrichment` flag used

**Verify enricher registration:**
```bash
grep -n "EventGridSubscriptionEnricher" pkg/links/azure/enricher/registry.go
```

## Test Scenarios Beyond Basic E2E

### Advanced Testing

1. **Test webhook.site dynamic testing**
   - Vulnerable subscription uses webhook.site URL
   - Enricher should successfully POST to webhook.site
   - Check HTTP response codes in enrichment output

2. **Test behind-firewall scenario**
   - Modify Bicep to use internal webhook URL
   - Enricher should timeout and mark as SECURE

3. **Test different parent types**
   - Create subscriptions on custom topics and domains
   - Verify detection works for all parent types

## Files

- `bicep/test-eventgrid-webhook.bicep` - Infrastructure as Code
- `deploy-test-resources.sh` - Deployment automation
- `verify-results.sh` - Automated result validation
- `test-outputs.json` - Test configuration (generated)
- `README.md` - This file

## Success Criteria

✅ **Test PASSES if:**
1. Vulnerable subscription (no Azure AD auth) appears in findings
2. Secure subscription (with Azure AD auth) does NOT appear in findings
3. Enricher output is present for vulnerable subscription
4. Dynamic webhook test provides accurate verdict
5. No false positives or false negatives

## Integration with CI/CD

To integrate E2E testing into CI/CD:

```bash
# In CI pipeline
./test-infrastructure/deploy-test-resources.sh
go build -o nebula .
./nebula azure recon arg-scan --subscription $AZURE_SUBSCRIPTION_ID
./test-infrastructure/verify-results.sh
EXIT_CODE=$?

# Cleanup
az group delete --name nebula-e2e-eventgrid-webhook --yes --no-wait

exit $EXIT_CODE
```

## References

- ARG Template: `pkg/templates/event_grid_webhook_auth.yaml`
- Enricher: `pkg/links/azure/enricher/event_grid_subscription.go`
- Issue: #220 (Event Grid Subscription Webhook Custom Authentication)
