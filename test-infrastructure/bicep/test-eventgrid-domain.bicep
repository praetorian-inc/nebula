// Bicep template for E2E testing Event Grid Domain with Domain Topics
param location string = resourceGroup().location
param uniqueSuffix string = uniqueString(resourceGroup().id)

// Event Grid Domain (supports multiple domain topics)
resource eventGridDomain 'Microsoft.EventGrid/domains@2024-06-01-preview' = {
  name: 'nebula-test-domain-${uniqueSuffix}'
  location: location
  properties: {
    inputSchema: 'EventGridSchema'
    publicNetworkAccess: 'Enabled'
  }
}

// Domain Topic 1 (with vulnerable subscription)
// Note: Domain topics are auto-created when subscriptions reference them

// VULNERABLE: Domain topic subscription WITHOUT Azure AD auth
resource vulnerableDomainTopicSub 'Microsoft.EventGrid/domains/eventSubscriptions@2024-06-01-preview' = {
  parent: eventGridDomain
  name: 'vulnerable-domain-topic-sub-${uniqueSuffix}'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://webhook.site/${uniqueSuffix}-domain-topic-vuln'
        // NO azureActiveDirectoryTenantId - should be DETECTED
      }
    }
    filter: {
      includedEventTypes: [
        'TestEvent'
      ]
      subjectBeginsWith: '/topic1/'
    }
  }
}

// SECURE: Domain topic subscription WITH Azure AD auth
resource secureDomainTopicSub 'Microsoft.EventGrid/domains/eventSubscriptions@2024-06-01-preview' = {
  parent: eventGridDomain
  name: 'secure-domain-topic-sub-${uniqueSuffix}'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://webhook.site/${uniqueSuffix}-domain-topic-secure'
        azureActiveDirectoryTenantId: subscription().tenantId
        azureActiveDirectoryApplicationIdOrUri: 'api://nebula-test-app'
        // Has Azure AD auth - should NOT be detected
      }
    }
    filter: {
      includedEventTypes: [
        'TestEvent'
      ]
      subjectBeginsWith: '/topic2/'
    }
  }
}

// VULNERABLE: Domain-level subscription WITHOUT Azure AD auth
resource vulnerableDomainSub 'Microsoft.EventGrid/domains/eventSubscriptions@2024-06-01-preview' = {
  parent: eventGridDomain
  name: 'vulnerable-domain-level-sub-${uniqueSuffix}'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://webhook.site/${uniqueSuffix}-domain-vuln'
        // NO azureActiveDirectoryTenantId - should be DETECTED
      }
    }
    filter: {
      includedEventTypes: [
        'TestEvent'
      ]
    }
  }
}

output domainName string = eventGridDomain.name
output vulnerableDomainTopicSubName string = vulnerableDomainTopicSub.name
output secureDomainTopicSubName string = secureDomainTopicSub.name
output vulnerableDomainSubName string = vulnerableDomainSub.name
output resourceGroupName string = resourceGroup().name
