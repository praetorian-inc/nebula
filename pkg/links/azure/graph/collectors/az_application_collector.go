package collectors

import (
	"context"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZApplicationCollector collects Azure AD applications
type AZApplicationCollector struct{}

func (c *AZApplicationCollector) Name() string {
	return "applications"
}

func (c *AZApplicationCollector) Priority() int {
	return 5
}

func (c *AZApplicationCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// TODO: Implement application collection
	return nil
}