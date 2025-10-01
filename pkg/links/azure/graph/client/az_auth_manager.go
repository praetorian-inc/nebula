package client

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// AzureAuthManagerLink manages authentication for Microsoft Graph API
type AzureAuthManagerLink struct {
	*chain.Base
	graphClient *msgraphsdk.GraphServiceClient
	credential  *azidentity.DefaultAzureCredential
}

func NewAzureAuthManagerLink(configs ...cfg.Config) chain.Link {
	l := &AzureAuthManagerLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureAuthManagerLink) Process(data any) error {
	l.Logger.Info("Initializing Azure Graph authentication")

	// Get default Azure credentials (supports multiple auth methods)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.Logger.Error("Failed to get Azure credentials", "error", err)
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}
	l.credential = cred

	// Create Graph client
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		l.Logger.Error("Failed to create Graph client", "error", err)
		return fmt.Errorf("failed to create Graph client: %w", err)
	}
	l.graphClient = client

	// Test authentication by getting tenant info
	testCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	org, err := client.Organization().Get(testCtx, nil)
	if err != nil {
		l.Logger.Error("Failed to authenticate to Graph API", "error", err)
		return fmt.Errorf("failed to authenticate to Graph API: %w", err)
	}

	if org.GetValue() != nil && len(org.GetValue()) > 0 {
		l.Logger.Info("Successfully authenticated to Azure tenant",
			"tenant_id", *org.GetValue()[0].GetId(),
			"tenant_name", *org.GetValue()[0].GetDisplayName())
	}

	// Pass the client to next link
	l.Send(&GraphClientContext{
		Client:     l.graphClient,
		Credential: l.credential,
	})

	return nil
}

// GraphClientContext holds the authenticated Graph client
type GraphClientContext struct {
	Client     *msgraphsdk.GraphServiceClient
	Credential *azidentity.DefaultAzureCredential
}