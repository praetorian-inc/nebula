#!/bin/bash
# Deploy E2E test resources for Event Grid Webhook Authentication detection

set -e

echo "🚀 Deploying E2E Test Resources for Event Grid Webhook Authentication"
echo "========================================================================"

# Configuration
RESOURCE_GROUP="nebula-e2e-eventgrid-webhook"
LOCATION="eastus"
DEPLOYMENT_NAME="eventgrid-webhook-test-$(date +%s)"

# Create resource group
echo ""
echo "📦 Creating resource group: $RESOURCE_GROUP"
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION"

# Deploy Bicep template
echo ""
echo "🏗️  Deploying test infrastructure..."
DEPLOYMENT_OUTPUT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file "$(dirname "$0")/bicep/test-eventgrid-webhook.bicep" \
  --query 'properties.outputs' \
  --output json)

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📋 Test Resources Created:"
echo "=========================="

# Parse outputs
STORAGE_ACCOUNT=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.storageAccountName.value')
SYSTEM_TOPIC=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.systemTopicName.value')
VULNERABLE_SUB=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.vulnerableSubscriptionName.value')
SECURE_SUB=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.secureSubscriptionName.value')

echo "Storage Account: $STORAGE_ACCOUNT"
echo "System Topic: $SYSTEM_TOPIC"
echo "Vulnerable Subscription: $VULNERABLE_SUB (NO Azure AD auth)"
echo "Secure Subscription: $SECURE_SUB (WITH Azure AD auth)"
echo ""

# Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

echo "📝 Next Steps:"
echo "=============="
echo ""
echo "1. Run Nebula scan:"
echo "   cd .. && go build -o nebula ."
echo "   ./nebula azure recon arg-scan --subscription $SUBSCRIPTION_ID"
echo ""
echo "2. Check output:"
echo "   cat nebula-output/arg-scan-$SUBSCRIPTION_ID.json | jq '.findings[] | select(.properties.templateID == \"event_grid_subscription_webhook_auth\")'"
echo ""
echo "3. Expected results:"
echo "   - '$VULNERABLE_SUB' should appear in findings (no Azure AD auth)"
echo "   - '$SECURE_SUB' should NOT appear in findings (has Azure AD auth)"
echo ""
echo "4. Cleanup after testing:"
echo "   az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo ""

# Save outputs for verification script
cat > "$(dirname "$0")/test-outputs.json" <<EOF
{
  "resourceGroup": "$RESOURCE_GROUP",
  "storageAccount": "$STORAGE_ACCOUNT",
  "systemTopic": "$SYSTEM_TOPIC",
  "vulnerableSubscription": "$VULNERABLE_SUB",
  "secureSubscription": "$SECURE_SUB",
  "subscriptionId": "$SUBSCRIPTION_ID"
}
EOF

echo "💾 Test configuration saved to test-outputs.json"
