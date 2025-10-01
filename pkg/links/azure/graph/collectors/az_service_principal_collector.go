package collectors

import (
	"context"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/storage"
)

// AZServicePrincipalCollector collects Azure AD service principals
type AZServicePrincipalCollector struct{}

func (c *AZServicePrincipalCollector) Name() string {
	return "serviceprincipals"
}

func (c *AZServicePrincipalCollector) Priority() int {
	return 4
}

func (c *AZServicePrincipalCollector) Collect(ctx context.Context, client *msgraphsdk.GraphServiceClient, writer *storage.AZNeo4jWriter) error {
	// TODO: Implement service principal collection
	return nil
}