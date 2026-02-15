// Bicep template for E2E testing Event Grid Subscription Webhook Authentication
// Creates two scenarios: vulnerable (no auth) and secure (with Azure AD auth)

param location string = resourceGroup().location
param uniqueSuffix string = uniqueString(resourceGroup().id)

// Storage account to generate system topic events
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stnebulatest${uniqueSuffix}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
  }
}

// System Topic for the storage account
resource systemTopic 'Microsoft.EventGrid/systemTopics@2024-06-01-preview' = {
  name: 'nebula-test-topic-${uniqueSuffix}'
  location: location
  properties: {
    source: storageAccount.id
    topicType: 'Microsoft.Storage.StorageAccounts'
  }
}

// SCENARIO 1: VULNERABLE - Event subscription WITHOUT Azure AD authentication
resource vulnerableSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2024-06-01-preview' = {
  parent: systemTopic
  name: 'vulnerable-webhook-${uniqueSuffix}'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://webhook.site/${uniqueSuffix}-vulnerable'
        // NO azureActiveDirectoryTenantId or azureActiveDirectoryApplicationIdOrUri
        // This should be DETECTED as vulnerable
      }
    }
    filter: {
      includedEventTypes: [
        'Microsoft.Storage.BlobCreated'
      ]
    }
  }
}

// SCENARIO 2: SECURE - Event subscription WITH Azure AD authentication
resource secureSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2024-06-01-preview' = {
  parent: systemTopic
  name: 'secure-webhook-${uniqueSuffix}'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://webhook.site/${uniqueSuffix}-secure'
        azureActiveDirectoryTenantId: subscription().tenantId
        azureActiveDirectoryApplicationIdOrUri: 'api://nebula-test-app'
        // Has Azure AD auth - should NOT be detected as vulnerable
      }
    }
    filter: {
      includedEventTypes: [
        'Microsoft.Storage.BlobCreated'
      ]
    }
  }
}

output storageAccountName string = storageAccount.name
output systemTopicName string = systemTopic.name
output vulnerableSubscriptionName string = vulnerableSubscription.name
output secureSubscriptionName string = secureSubscription.name
output resourceGroupName string = resourceGroup().name
