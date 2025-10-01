package collectors

import (
	"context"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZDeviceCollector collects Azure AD devices
type AZDeviceCollector struct{}

func (c *AZDeviceCollector) Name() string {
	return "devices"
}

func (c *AZDeviceCollector) Priority() int {
	return 6
}

func (c *AZDeviceCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// TODO: Implement device collection
	return nil
}