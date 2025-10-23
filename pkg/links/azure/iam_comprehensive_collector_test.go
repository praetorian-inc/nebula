package azure

import (
	"testing"
)

func TestShouldCollectRBACForResource(t *testing.T) {
	// Create a link instance for testing
	link := &IAMComprehensiveCollectorLink{}

	testCases := []struct {
		resourceType   string
		shouldCollect  bool
		description    string
	}{
		// Should collect - selected resource types
		{"microsoft.compute/virtualmachines", true, "Virtual machines should be collected"},
		{"microsoft.keyvault/vaults", true, "Key vaults should be collected"},
		{"microsoft.storage/storageaccounts", true, "Storage accounts should be collected"},
		{"microsoft.containerservice/managedclusters", true, "AKS clusters should be collected"},
		{"microsoft.web/sites", true, "App services should be collected"},

		// Should NOT collect - non-selected resource types
		{"microsoft.network/networkinterfaces", false, "Network interfaces should be skipped"},
		{"microsoft.compute/disks", false, "Disks should be skipped"},
		{"microsoft.insights/components", false, "Application insights should be skipped"},
		{"microsoft.network/publicipaddresses", false, "Public IP addresses should be skipped"},
		{"microsoft.portal/dashboards", false, "Portal dashboards should be skipped"},

		// Case insensitive matching
		{"Microsoft.Compute/VirtualMachines", true, "Should handle case insensitive matching"},
		{"MICROSOFT.KEYVAULT/VAULTS", true, "Should handle uppercase"},

		// Non-existent types
		{"unknown.resource/type", false, "Unknown resource types should be skipped"},
		{"", false, "Empty resource type should be skipped"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			result := link.shouldCollectRBACForResource(tc.resourceType)
			if result != tc.shouldCollect {
				t.Errorf("Expected shouldCollectRBACForResource(%q) = %v, got %v",
					tc.resourceType, tc.shouldCollect, result)
			}
		})
	}
}

func TestSelectedResourceTypesCoverage(t *testing.T) {
	// Verify we have a good selection of resource types
	expectedCategories := map[string]bool{
		"compute":     false,
		"storage":     false,
		"keyvault":    false,
		"web":         false,
		"network":     false,
	}

	for _, resourceType := range selectedResourceTypes {
		if contains(resourceType, "compute") {
			expectedCategories["compute"] = true
		}
		if contains(resourceType, "storage") {
			expectedCategories["storage"] = true
		}
		if contains(resourceType, "keyvault") {
			expectedCategories["keyvault"] = true
		}
		if contains(resourceType, "web") {
			expectedCategories["web"] = true
		}
		if contains(resourceType, "network") {
			expectedCategories["network"] = true
		}
	}

	for category, found := range expectedCategories {
		if !found {
			t.Errorf("Missing resource types for category: %s", category)
		}
	}

	// Verify we have a reasonable number of resource types (not too few, not too many)
	count := len(selectedResourceTypes)
	if count < 10 {
		t.Errorf("Too few selected resource types (%d). Expected at least 10 for good coverage", count)
	}
	if count > 50 {
		t.Errorf("Too many selected resource types (%d). This defeats the optimization purpose", count)
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		 indexInString(s, substr) >= 0)))
}

func indexInString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}