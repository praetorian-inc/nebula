#!/bin/bash
# Verify E2E test results for Event Grid Webhook Authentication detection

set -e

echo "🔍 Verifying E2E Test Results"
echo "=============================="

# Load test configuration
if [ ! -f "$(dirname "$0")/test-outputs.json" ]; then
  echo "❌ Error: test-outputs.json not found. Run deploy-test-resources.sh first."
  exit 1
fi

TEST_CONFIG=$(cat "$(dirname "$0")/test-outputs.json")
SUBSCRIPTION_ID=$(echo "$TEST_CONFIG" | jq -r '.subscriptionId')
VULNERABLE_SUB=$(echo "$TEST_CONFIG" | jq -r '.vulnerableSubscription')
SECURE_SUB=$(echo "$TEST_CONFIG" | jq -r '.secureSubscription')

echo ""
echo "📋 Test Configuration:"
echo "  Vulnerable Subscription: $VULNERABLE_SUB"
echo "  Secure Subscription: $SECURE_SUB"
echo "  Subscription ID: $SUBSCRIPTION_ID"
echo ""

# Check if Nebula output exists
OUTPUT_FILE="../nebula-output/arg-scan-${SUBSCRIPTION_ID}.json"
if [ ! -f "$OUTPUT_FILE" ]; then
  echo "❌ Error: Nebula output not found at $OUTPUT_FILE"
  echo "   Run: ./nebula azure recon arg-scan --subscription $SUBSCRIPTION_ID"
  exit 1
fi

echo "📂 Checking Nebula output: $OUTPUT_FILE"
echo ""

# Extract findings for our template
FINDINGS=$(cat "$OUTPUT_FILE" | jq '.findings[] | select(.properties.templateID == "event_grid_subscription_webhook_auth")')

if [ -z "$FINDINGS" ]; then
  echo "⚠️  Warning: No findings for template 'event_grid_subscription_webhook_auth'"
  echo "   This could mean:"
  echo "   - Template not loaded"
  echo "   - Query didn't match any resources"
  echo "   - Template ID mismatch"
  exit 1
fi

echo "✅ Found findings for event_grid_subscription_webhook_auth template"
echo ""

# Check for vulnerable subscription (should be detected)
VULNERABLE_FOUND=$(echo "$FINDINGS" | jq -r --arg name "$VULNERABLE_SUB" 'select(.name == $name) | .name')

if [ -n "$VULNERABLE_FOUND" ]; then
  echo "✅ PASS: Vulnerable subscription detected"
  echo "   Resource: $VULNERABLE_SUB"
  echo ""
  echo "   Finding details:"
  echo "$FINDINGS" | jq --arg name "$VULNERABLE_SUB" 'select(.name == $name)'
  echo ""
  VULNERABLE_PASS=true
else
  echo "❌ FAIL: Vulnerable subscription NOT detected"
  echo "   Expected: $VULNERABLE_SUB"
  echo "   This is a FALSE NEGATIVE - the template failed to detect the vulnerability"
  echo ""
  VULNERABLE_PASS=false
fi

# Check for secure subscription (should NOT be detected)
SECURE_FOUND=$(echo "$FINDINGS" | jq -r --arg name "$SECURE_SUB" 'select(.name == $name) | .name')

if [ -z "$SECURE_FOUND" ]; then
  echo "✅ PASS: Secure subscription NOT detected (correctly filtered out)"
  echo "   Resource: $SECURE_SUB"
  echo ""
  SECURE_PASS=true
else
  echo "❌ FAIL: Secure subscription incorrectly detected"
  echo "   Found: $SECURE_SUB"
  echo "   This is a FALSE POSITIVE - the template should filter out Azure AD authenticated webhooks"
  echo ""
  echo "   Incorrect finding:"
  echo "$FINDINGS" | jq --arg name "$SECURE_SUB" 'select(.name == $name)'
  echo ""
  SECURE_PASS=false
fi

# Check enricher output
echo "🔧 Checking Enricher Output:"
echo "============================="

if [ "$VULNERABLE_FOUND" ]; then
  ENRICHER_OUTPUT=$(echo "$FINDINGS" | jq -r --arg name "$VULNERABLE_SUB" 'select(.name == $name) | .properties.enrichment // empty')

  if [ -n "$ENRICHER_OUTPUT" ]; then
    echo "✅ Enricher executed for vulnerable subscription"
    echo ""
    echo "Enrichment commands:"
    echo "$ENRICHER_OUTPUT" | jq '.[]'
    echo ""
  else
    echo "⚠️  Warning: No enrichment output found (enricher may not have run)"
  fi
fi

# Overall result
echo "📊 E2E Test Summary"
echo "==================="
echo ""

if [ "$VULNERABLE_PASS" = true ] && [ "$SECURE_PASS" = true ]; then
  echo "✅ ALL TESTS PASSED"
  echo ""
  echo "✓ Vulnerable subscription (no Azure AD auth) was detected"
  echo "✓ Secure subscription (with Azure AD auth) was filtered out"
  echo ""
  echo "The template correctly identifies Event Grid subscriptions without Azure AD authentication."
  exit 0
else
  echo "❌ TESTS FAILED"
  echo ""
  [ "$VULNERABLE_PASS" = false ] && echo "✗ Failed to detect vulnerable subscription"
  [ "$SECURE_PASS" = false ] && echo "✗ Incorrectly flagged secure subscription (false positive)"
  echo ""
  echo "The template needs adjustment to correctly identify vulnerabilities."
  exit 1
fi
