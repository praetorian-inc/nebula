package enricher

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
	"github.com/stretchr/testify/assert"
)

func TestDataExplorerEnricher_GetNetworkRulesCommand(t *testing.T) {
	enricher := &DataExplorerEnricher{}
	ctx := context.Background()

	// Create a minimal resource for testing
	resource := &model.AzureResource{}
	resource.Name = "testcluster"
	resource.AccountRef = "test-subscription-id"
	resource.ResourceGroup = "test-rg"

	cmd := enricher.getNetworkRulesCommand(ctx, resource)

	// Verify command structure
	assert.Contains(t, cmd.Command, "az kusto cluster show")
	assert.Contains(t, cmd.Command, "testcluster")
	assert.Contains(t, cmd.Command, "test-rg")
	
	// Description should contain "Retrieve Data Explorer cluster network rules"
	// (may have additional text if SDK failed)
	assert.Contains(t, cmd.Description, "Retrieve Data Explorer cluster network rules")
}

func TestDataExplorerEnricher_GetNetworkRulesCommand_MissingClusterName(t *testing.T) {
	enricher := &DataExplorerEnricher{}
	ctx := context.Background()

	resource := &model.AzureResource{}
	resource.Name = ""
	resource.AccountRef = "sub-123"
	resource.ResourceGroup = "rg-test"

	cmd := enricher.getNetworkRulesCommand(ctx, resource)

	assert.Equal(t, 1, cmd.ExitCode, "Should return error exit code")
	assert.True(t, strings.Contains(cmd.ActualOutput, "Error:") || strings.Contains(cmd.ActualOutput, "missing"),
		"Should contain error message about missing fields")
}

func TestDataExplorerEnricher_GetNetworkRulesCommand_MissingSubscriptionID(t *testing.T) {
	enricher := &DataExplorerEnricher{}
	ctx := context.Background()

	resource := &model.AzureResource{}
	resource.Name = "cluster1"
	resource.AccountRef = ""
	resource.ResourceGroup = "rg-test"

	cmd := enricher.getNetworkRulesCommand(ctx, resource)

	assert.Equal(t, 1, cmd.ExitCode, "Should return error exit code")
	assert.True(t, strings.Contains(cmd.ActualOutput, "Error:") || strings.Contains(cmd.ActualOutput, "missing"),
		"Should contain error message about missing fields")
}

func TestDataExplorerEnricher_GetNetworkRulesCommand_MissingResourceGroup(t *testing.T) {
	enricher := &DataExplorerEnricher{}
	ctx := context.Background()

	resource := &model.AzureResource{}
	resource.Name = "cluster1"
	resource.AccountRef = "sub-123"
	resource.ResourceGroup = ""

	cmd := enricher.getNetworkRulesCommand(ctx, resource)

	assert.Equal(t, 1, cmd.ExitCode, "Should return error exit code")
	assert.True(t, strings.Contains(cmd.ActualOutput, "Error:") || strings.Contains(cmd.ActualOutput, "missing"),
		"Should contain error message about missing fields")
}
