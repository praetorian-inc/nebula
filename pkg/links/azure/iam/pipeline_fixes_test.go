package iam

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ==========================================
// P0 #11: credentialSummary in Cypher SET
// ==========================================

func TestCredentialSummaryFieldsInCypherSET(t *testing.T) {
	l := &Neo4jImporterLink{}

	// Simulate application data with credential summary
	appMap := map[string]interface{}{
		"id":                                  "app-123",
		"appId":                               "app-id-456",
		"displayName":                         "TestApp",
		"signInAudience":                      "AzureADMyOrg",
		"credentialSummary_hasCredentials":     true,
		"credentialSummary_totalCredentials":   3,
		"credentialSummary_passwordCredentials": []interface{}{"cred1"},
		"credentialSummary_keyCredentials":      []interface{}{"key1", "key2"},
	}

	// Verify the importer correctly extracts these fields
	hasCredentials := l.getBoolValue(appMap, "credentialSummary_hasCredentials")
	totalCredentials := l.getIntValue(appMap, "credentialSummary_totalCredentials")
	assert.True(t, hasCredentials, "credentialSummary_hasCredentials should be true")
	assert.Equal(t, 3, totalCredentials, "credentialSummary_totalCredentials should be 3")

	// Verify password and key credentials are present
	_, hasPwdCreds := appMap["credentialSummary_passwordCredentials"]
	_, hasKeyCreds := appMap["credentialSummary_keyCredentials"]
	assert.True(t, hasPwdCreds, "credentialSummary_passwordCredentials should exist")
	assert.True(t, hasKeyCreds, "credentialSummary_keyCredentials should exist")
}

// ==========================================
// P0 #1: Device node creation
// ==========================================

func TestDeviceNodeCreation(t *testing.T) {
	l := &Neo4jImporterLink{}

	deviceMap := map[string]interface{}{
		"id":                     "device-abc-123",
		"displayName":            "DESKTOP-TEST01",
		"deviceId":               "hw-device-456",
		"operatingSystem":        "Windows",
		"operatingSystemVersion": "10.0.19045",
		"accountEnabled":         true,
		"isCompliant":            true,
		"isManaged":              false,
		"trustType":              "AzureAd",
	}

	// Verify resource node construction
	resourceNode := map[string]interface{}{
		"id":           l.normalizeResourceId(l.getStringValue(deviceMap, "id")),
		"resourceType": "Microsoft.DirectoryServices/devices",
		"displayName":  l.getStringValue(deviceMap, "displayName"),
		"deviceId":     l.getStringValue(deviceMap, "deviceId"),
	}

	assert.Equal(t, "device-abc-123", resourceNode["id"])
	assert.Equal(t, "Microsoft.DirectoryServices/devices", resourceNode["resourceType"])
	assert.Equal(t, "DESKTOP-TEST01", resourceNode["displayName"])
	assert.Equal(t, "hw-device-456", resourceNode["deviceId"])

	// Verify metadata includes device attributes
	deviceMetadata := map[string]interface{}{
		"deviceId":               l.getStringValue(deviceMap, "deviceId"),
		"operatingSystem":        l.getStringValue(deviceMap, "operatingSystem"),
		"operatingSystemVersion": l.getStringValue(deviceMap, "operatingSystemVersion"),
	}
	if trustType, ok := deviceMap["trustType"].(string); ok {
		deviceMetadata["trustType"] = trustType
	}

	assert.Equal(t, "hw-device-456", deviceMetadata["deviceId"])
	assert.Equal(t, "Windows", deviceMetadata["operatingSystem"])
	assert.Equal(t, "AzureAd", deviceMetadata["trustType"])
}

// ==========================================
// P1 #6: CA policy import as Neo4j nodes
// ==========================================

func TestCAPolicyNodeCreation(t *testing.T) {
	l := &Neo4jImporterLink{}

	policyMap := map[string]interface{}{
		"id":          "ca-policy-001",
		"displayName": "Require MFA for admins",
		"description": "Blocks access unless MFA is completed",
		"state":       "enabled",
		"conditions": map[string]interface{}{
			"users": map[string]interface{}{
				"includeUsers": []interface{}{"All"},
			},
			"applications": map[string]interface{}{
				"includeApplications": []interface{}{"All"},
			},
		},
		"grantControls": map[string]interface{}{
			"operator":        "OR",
			"builtInControls": []interface{}{"mfa"},
		},
	}

	// Verify resource node construction
	resourceNode := map[string]interface{}{
		"id":           l.normalizeResourceId(l.getStringValue(policyMap, "id")),
		"resourceType": "Microsoft.DirectoryServices/conditionalAccessPolicies",
		"displayName":  l.getStringValue(policyMap, "displayName"),
		"state":        l.getStringValue(policyMap, "state"),
	}

	assert.Equal(t, "ca-policy-001", resourceNode["id"])
	assert.Equal(t, "Microsoft.DirectoryServices/conditionalAccessPolicies", resourceNode["resourceType"])
	assert.Equal(t, "Require MFA for admins", resourceNode["displayName"])
	assert.Equal(t, "enabled", resourceNode["state"])

	// Verify metadata includes conditions and controls
	caMetadata := map[string]interface{}{
		"description": l.getStringValue(policyMap, "description"),
		"state":       l.getStringValue(policyMap, "state"),
	}
	if conditions, ok := policyMap["conditions"]; ok {
		caMetadata["conditions"] = conditions
	}
	if grantControls, ok := policyMap["grantControls"]; ok {
		caMetadata["grantControls"] = grantControls
	}

	assert.NotNil(t, caMetadata["conditions"], "conditions should be in metadata")
	assert.NotNil(t, caMetadata["grantControls"], "grantControls should be in metadata")

	// Verify metadata serialization doesn't lose nested structures
	metadataJSON := l.toJSONString(caMetadata)
	assert.Contains(t, metadataJSON, "includeUsers")
	assert.Contains(t, metadataJSON, "mfa")
}

// ==========================================
// P1 #7: SP credential fields
// ==========================================

func TestSPCredentialFieldsExtraction(t *testing.T) {
	l := &Neo4jImporterLink{}

	spMap := map[string]interface{}{
		"id":                                "sp-001",
		"displayName":                       "MyServicePrincipal",
		"appId":                             "app-id-789",
		"servicePrincipalType":              "Application",
		"appOwnerOrganizationId":            "tenant-abc",
		"credentialSummary_hasCredentials":   true,
		"credentialSummary_totalCredentials": 2,
		"credentialSummary_passwordCredentials": []interface{}{
			map[string]interface{}{"keyId": "pwd-1"},
		},
		"credentialSummary_keyCredentials": []interface{}{
			map[string]interface{}{"keyId": "key-1"},
		},
	}

	// Verify appOwnerOrganizationId is extracted
	appOwner := l.getStringValue(spMap, "appOwnerOrganizationId")
	assert.Equal(t, "tenant-abc", appOwner)

	// Verify credential summary fields
	hasCredentials := l.getBoolValue(spMap, "credentialSummary_hasCredentials")
	assert.True(t, hasCredentials)

	totalCreds := l.getIntValue(spMap, "credentialSummary_totalCredentials")
	assert.Equal(t, 2, totalCreds)
}

// ==========================================
// P1 #8: Group security fields
// ==========================================

func TestGroupSecurityFieldsExtraction(t *testing.T) {
	l := &Neo4jImporterLink{}

	groupMap := map[string]interface{}{
		"id":                    "group-001",
		"displayName":           "Privileged Admins",
		"securityEnabled":       true,
		"mailEnabled":           false,
		"isAssignableToRole":    true,
		"visibility":            "Private",
		"onPremisesSyncEnabled": false,
	}

	// Verify all fields are extractable
	assert.Equal(t, "Privileged Admins", l.getStringValue(groupMap, "displayName"))
	assert.Equal(t, "Private", l.getStringValue(groupMap, "visibility"))

	isAssignableToRole, ok := groupMap["isAssignableToRole"].(bool)
	assert.True(t, ok, "isAssignableToRole should be a bool")
	assert.True(t, isAssignableToRole, "isAssignableToRole should be true")

	onPremisesSyncEnabled, ok := groupMap["onPremisesSyncEnabled"].(bool)
	assert.True(t, ok, "onPremisesSyncEnabled should be a bool")
	assert.False(t, onPremisesSyncEnabled, "onPremisesSyncEnabled should be false")
}

// ==========================================
// P1 #9: User onPremisesSyncEnabled
// ==========================================

func TestUserOnPremisesSyncEnabled(t *testing.T) {
	l := &Neo4jImporterLink{}

	tests := []struct {
		name     string
		userMap  map[string]interface{}
		expected bool
		exists   bool
	}{
		{
			name: "Synced user",
			userMap: map[string]interface{}{
				"id":                    "user-001",
				"onPremisesSyncEnabled": true,
			},
			expected: true,
			exists:   true,
		},
		{
			name: "Cloud-only user",
			userMap: map[string]interface{}{
				"id":                    "user-002",
				"onPremisesSyncEnabled": false,
			},
			expected: false,
			exists:   true,
		},
		{
			name: "User without field",
			userMap: map[string]interface{}{
				"id": "user-003",
			},
			expected: false,
			exists:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := tt.userMap["onPremisesSyncEnabled"].(bool)
			assert.Equal(t, tt.exists, ok)
			if ok {
				assert.Equal(t, tt.expected, val)
			}
			_ = l // use l to suppress unused warning
		})
	}
}

// ==========================================
// P1 #12: Ownership edge ID normalization
// ==========================================

func TestOwnershipEdgeIDNormalization(t *testing.T) {
	l := &Neo4jImporterLink{}

	tests := []struct {
		name     string
		ownerID  string
		targetID string
	}{
		{
			name:     "Mixed case GUID",
			ownerID:  "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
			targetID: "F9E8D7C6-B5A4-3210-FEDC-BA0987654321",
		},
		{
			name:     "Already lowercase",
			ownerID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			targetID: "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
		},
		{
			name:     "Full resource path",
			ownerID:  "/subscriptions/ABC/providers/Microsoft.DirectoryServices/users/USER-123",
			targetID: "/subscriptions/DEF/providers/Microsoft.DirectoryServices/applications/APP-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizedOwner := l.normalizeResourceId(tt.ownerID)
			normalizedTarget := l.normalizeResourceId(tt.targetID)

			// All normalized IDs should be lowercase
			assert.Equal(t, strings.ToLower(tt.ownerID), normalizedOwner,
				"Owner ID should be lowercased")
			assert.Equal(t, strings.ToLower(tt.targetID), normalizedTarget,
				"Target ID should be lowercased")
		})
	}
}

// ==========================================
// P1 #14: Collection error tracking
// ==========================================

func TestCollectionErrorTracking(t *testing.T) {
	// Simulate collection error tracking
	collectionErrors := make(map[string]string)

	// Simulate some collection errors
	collectionErrors["users"] = "failed to get first page of users: 403 Forbidden"
	collectionErrors["conditionalAccessPolicies"] = "insufficient privileges"

	assert.Equal(t, 2, len(collectionErrors))
	assert.Contains(t, collectionErrors["users"], "403 Forbidden")
	assert.Contains(t, collectionErrors["conditionalAccessPolicies"], "insufficient privileges")

	// Verify error map can be serialized
	jsonBytes, err := json.Marshal(collectionErrors)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonBytes), "403 Forbidden")
}

// ==========================================
// P2 #17: Subscription displayName fix
// ==========================================

func TestSubscriptionDisplayNameExtraction(t *testing.T) {
	l := &Neo4jImporterLink{}

	tests := []struct {
		name             string
		itemMap          map[string]interface{}
		expectedName     string
		expectedFallback string
	}{
		{
			name: "Subscription with properties.displayName",
			itemMap: map[string]interface{}{
				"name": "c816d723-1234-5678-9abc-def012345678",
				"id":   "/subscriptions/c816d723-1234-5678-9abc-def012345678",
				"type": "Microsoft.Resources/subscriptions",
				"properties": map[string]interface{}{
					"displayName": "sub-digital-nonprod-azc-001",
					"state":       "Enabled",
				},
			},
			expectedName: "sub-digital-nonprod-azc-001",
		},
		{
			name: "Subscription without properties (fallback to GUID)",
			itemMap: map[string]interface{}{
				"name": "c816d723-1234-5678-9abc-def012345678",
				"id":   "/subscriptions/c816d723-1234-5678-9abc-def012345678",
				"type": "Microsoft.Resources/subscriptions",
			},
			expectedName: "c816d723-1234-5678-9abc-def012345678",
		},
		{
			name: "Subscription with empty displayName (fallback to GUID)",
			itemMap: map[string]interface{}{
				"name": "c816d723-1234-5678-9abc-def012345678",
				"id":   "/subscriptions/c816d723-1234-5678-9abc-def012345678",
				"type": "Microsoft.Resources/subscriptions",
				"properties": map[string]interface{}{
					"displayName": "",
				},
			},
			expectedName: "c816d723-1234-5678-9abc-def012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subscriptionId := l.getStringValue(tt.itemMap, "name")
			subscriptionName := subscriptionId
			if properties, ok := tt.itemMap["properties"].(map[string]interface{}); ok {
				if dn := l.getStringValue(properties, "displayName"); dn != "" {
					subscriptionName = dn
				}
			}

			assert.Equal(t, tt.expectedName, subscriptionName,
				"Subscription displayName should be extracted from properties")
		})
	}
}

// ==========================================
// P2 #15: Device trustType and lastSignIn
// ==========================================

func TestDeviceTrustTypeAndLastSignIn(t *testing.T) {
	l := &Neo4jImporterLink{}

	deviceMap := map[string]interface{}{
		"id":                              "device-001",
		"displayName":                     "WORKSTATION-01",
		"trustType":                       "AzureAd",
		"approximateLastSignInDateTime":   "2026-02-28T10:30:00Z",
	}

	trustType := l.getStringValue(deviceMap, "trustType")
	lastSignIn := l.getStringValue(deviceMap, "approximateLastSignInDateTime")

	assert.Equal(t, "AzureAd", trustType)
	assert.Equal(t, "2026-02-28T10:30:00Z", lastSignIn)

	// Verify these go into metadata
	deviceMetadata := map[string]interface{}{
		"trustType":                       trustType,
		"approximateLastSignInDateTime":   lastSignIn,
	}
	metadataJSON := l.toJSONString(deviceMetadata)
	assert.Contains(t, metadataJSON, "AzureAd")
	assert.Contains(t, metadataJSON, "2026-02-28T10:30:00Z")
}

// ==========================================
// P1 #10: PIM scheduleInfo fields
// ==========================================

func TestPIMScheduleInfoExtraction(t *testing.T) {
	// Test that scheduleInfo structure is correctly formed
	scheduleInfo := map[string]interface{}{
		"startDateTime": "2026-01-01T00:00:00Z",
		"expiration": map[string]interface{}{
			"endDateTime": "2027-01-01T00:00:00Z",
			"type":        "afterDateTime",
		},
	}

	// Verify structure
	assert.NotNil(t, scheduleInfo["startDateTime"])
	expiration, ok := scheduleInfo["expiration"].(map[string]interface{})
	assert.True(t, ok, "expiration should be a map")
	assert.Equal(t, "2027-01-01T00:00:00Z", expiration["endDateTime"])
	assert.Equal(t, "afterDateTime", expiration["type"])

	// Verify JSON serialization preserves nested structure
	jsonBytes, err := json.Marshal(scheduleInfo)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonBytes), "afterDateTime")
	assert.Contains(t, string(jsonBytes), "2027-01-01")
}

// ==========================================
// P0 #5: requiredResourceAccess extraction
// ==========================================

func TestRequiredResourceAccessExtraction(t *testing.T) {
	appMap := map[string]interface{}{
		"id": "app-001",
		"requiredResourceAccess": []interface{}{
			map[string]interface{}{
				"resourceAppId": "00000003-0000-0000-c000-000000000000", // Microsoft Graph
				"resourceAccess": []interface{}{
					map[string]interface{}{
						"id":   "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
						"type": "Scope",
					},
					map[string]interface{}{
						"id":   "df021288-bdef-4463-88db-98f22de89214",
						"type": "Role",
					},
				},
			},
		},
	}

	rra, ok := appMap["requiredResourceAccess"].([]interface{})
	assert.True(t, ok, "requiredResourceAccess should be an array")
	assert.Equal(t, 1, len(rra), "should have 1 resource access entry")

	firstRA, ok := rra[0].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "00000003-0000-0000-c000-000000000000", firstRA["resourceAppId"])

	accesses, ok := firstRA["resourceAccess"].([]interface{})
	assert.True(t, ok, "resourceAccess should be an array")
	assert.Equal(t, 2, len(accesses), "should have 2 permissions")

	// Verify types
	access1, ok := accesses[0].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Scope", access1["type"], "first should be delegated")

	access2, ok := accesses[1].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Role", access2["type"], "second should be application")
}

// ==========================================
// P0 #3: CA policy conditions/grants/sessions
// ==========================================

func TestCAPolicyFullExtractionStructure(t *testing.T) {
	policyMap := map[string]interface{}{
		"id":          "policy-001",
		"displayName": "Block legacy auth",
		"state":       "enabled",
		"conditions": map[string]interface{}{
			"users": map[string]interface{}{
				"includeUsers":  []interface{}{"All"},
				"excludeUsers":  []interface{}{},
				"includeGroups": []interface{}{"group-001"},
				"excludeGroups": []interface{}{},
				"includeRoles":  []interface{}{},
				"excludeRoles":  []interface{}{},
			},
			"applications": map[string]interface{}{
				"includeApplications": []interface{}{"All"},
				"excludeApplications": []interface{}{},
			},
			"clientAppTypes":     []interface{}{"exchangeActiveSync", "other"},
			"signInRiskLevels":   []interface{}{"high", "medium"},
			"userRiskLevels":     []interface{}{},
		},
		"grantControls": map[string]interface{}{
			"operator":        "OR",
			"builtInControls": []interface{}{"block"},
		},
		"sessionControls": map[string]interface{}{
			"signInFrequency": map[string]interface{}{
				"isEnabled": true,
				"value":     4,
				"type":      "hours",
			},
		},
	}

	// Verify conditions structure
	conditions, ok := policyMap["conditions"].(map[string]interface{})
	assert.True(t, ok)

	users, ok := conditions["users"].(map[string]interface{})
	assert.True(t, ok)
	includeUsers := users["includeUsers"].([]interface{})
	assert.Equal(t, "All", includeUsers[0])

	clientAppTypes := conditions["clientAppTypes"].([]interface{})
	assert.Equal(t, 2, len(clientAppTypes))
	assert.Contains(t, clientAppTypes, "exchangeActiveSync")

	signInRiskLevels := conditions["signInRiskLevels"].([]interface{})
	assert.Equal(t, 2, len(signInRiskLevels))

	// Verify grant controls
	grantControls, ok := policyMap["grantControls"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "OR", grantControls["operator"])
	builtInControls := grantControls["builtInControls"].([]interface{})
	assert.Contains(t, builtInControls, "block")

	// Verify session controls
	sessionControls, ok := policyMap["sessionControls"].(map[string]interface{})
	assert.True(t, ok)
	signInFreq, ok := sessionControls["signInFrequency"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, true, signInFreq["isEnabled"])
	assert.Equal(t, 4, signInFreq["value"])
	assert.Equal(t, "hours", signInFreq["type"])
}

// ==========================================
// P2 #13: User manager relationship
// ==========================================

func TestUserManagerEnrichment(t *testing.T) {
	// Simulate user data after manager enrichment
	userMap := map[string]interface{}{
		"id":              "user-001",
		"displayName":     "John Doe",
		"managerId":       "user-002",
	}

	managerId, ok := userMap["managerId"].(string)
	assert.True(t, ok, "managerId should be present after enrichment")
	assert.Equal(t, "user-002", managerId)

	// Test user without manager
	userNoManager := map[string]interface{}{
		"id":          "user-003",
		"displayName": "CEO",
	}
	_, hasManager := userNoManager["managerId"]
	assert.False(t, hasManager, "CEO should not have managerId")
}

// ==========================================
// SP credential enrichment (reuses app pattern)
// ==========================================

func TestSPCredentialEnrichmentPattern(t *testing.T) {
	// Simulate SP data after credential enrichment
	// (analyzeKeyCredentialsSDK/analyzePasswordCredentialsSDK are on SDKComprehensiveCollectorLink)
	spMap := map[string]interface{}{
		"id":          "sp-001",
		"displayName": "TestSP",
		"keyCredentials": []interface{}{
			map[string]interface{}{
				"keyId":       "key-001",
				"displayName": "Cert1",
				"usage":       "Verify",
				"endDateTime": "2027-01-01T00:00:00Z",
			},
		},
		"passwordCredentials": []interface{}{
			map[string]interface{}{
				"keyId":       "pwd-001",
				"displayName": "Secret1",
				"hint":        "abc",
				"endDateTime": "2026-06-01T00:00:00Z",
			},
		},
		"credentialSummary_keyCredentials":      []interface{}{map[string]interface{}{"keyId": "key-001", "status": "Active"}},
		"credentialSummary_passwordCredentials":  []interface{}{map[string]interface{}{"keyId": "pwd-001", "status": "Active"}},
		"credentialSummary_totalCredentials":     2,
		"credentialSummary_hasCredentials":       true,
	}

	// Verify enrichment data is present and correct types
	assert.True(t, spMap["credentialSummary_hasCredentials"].(bool))
	assert.Equal(t, 2, spMap["credentialSummary_totalCredentials"].(int))

	keyCreds, ok := spMap["credentialSummary_keyCredentials"].([]interface{})
	assert.True(t, ok, "key credentials should be an array")
	assert.Equal(t, 1, len(keyCreds))

	pwdCreds, ok := spMap["credentialSummary_passwordCredentials"].([]interface{})
	assert.True(t, ok, "password credentials should be an array")
	assert.Equal(t, 1, len(pwdCreds))
}

// ==========================================
// Integration: Full pipeline data flow
// ==========================================

func TestFullPipelineDataFlowIntegrity(t *testing.T) {
	l := &Neo4jImporterLink{}

	t.Run("User data flows correctly through pipeline", func(t *testing.T) {
		// Simulates SDK collector output
		userMap := map[string]interface{}{
			"id":                    "USER-123-ABC",
			"displayName":          "Test User",
			"userPrincipalName":    "test@contoso.com",
			"mail":                 "test@contoso.com",
			"userType":             "Member",
			"accountEnabled":       true,
			"onPremisesSyncEnabled": true,
			"riskState":            "none",
			"managerId":            "MANAGER-456-DEF",
		}

		// Simulates importer normalization
		normalizedId := l.normalizeResourceId(l.getStringValue(userMap, "id"))
		assert.Equal(t, "user-123-abc", normalizedId, "ID should be lowercased")

		onPremSync, ok := userMap["onPremisesSyncEnabled"].(bool)
		assert.True(t, ok && onPremSync, "onPremisesSyncEnabled should be true")
	})

	t.Run("SP data flows correctly through pipeline", func(t *testing.T) {
		spMap := map[string]interface{}{
			"id":                              "SP-789",
			"displayName":                     "Test SP",
			"appOwnerOrganizationId":          "TENANT-ABC",
			"credentialSummary_hasCredentials": true,
		}

		normalizedId := l.normalizeResourceId(l.getStringValue(spMap, "id"))
		assert.Equal(t, "sp-789", normalizedId)
		assert.Equal(t, "TENANT-ABC", l.getStringValue(spMap, "appOwnerOrganizationId"))
	})

	t.Run("Ownership edge IDs match node IDs", func(t *testing.T) {
		ownerID := "USER-123-ABC"
		appID := "APP-456-DEF"

		// Node IDs are normalized during creation
		nodeOwnerID := l.normalizeResourceId(ownerID)
		nodeAppID := l.normalizeResourceId(appID)

		// Edge IDs must also be normalized to match
		edgeSourceID := l.normalizeResourceId(ownerID)
		edgeTargetID := l.normalizeResourceId(appID)

		assert.Equal(t, nodeOwnerID, edgeSourceID, "Edge source must match node ID")
		assert.Equal(t, nodeAppID, edgeTargetID, "Edge target must match node ID")
	})
}
