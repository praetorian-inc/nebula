package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	serviceusagepb "cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

func CheckAssetAPIEnabled(projectID string, clientOptions ...option.ClientOption) error {
	ctx := context.Background()
	client, err := serviceusage.NewClient(ctx, clientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create service usage client: %w", err)
	}
	defer client.Close()

	serviceName := fmt.Sprintf("projects/%s/services/cloudasset.googleapis.com", projectID)
	req := &serviceusagepb.GetServiceRequest{
		Name: serviceName,
	}

	resp, err := client.GetService(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to check Cloud Asset API status: %w. Enable it with: gcloud services enable cloudasset.googleapis.com --project=%s", err, projectID)
	}

	if resp.State != serviceusagepb.State_ENABLED {
		return fmt.Errorf("Cloud Asset API is not enabled for project %s. Enable it with: gcloud services enable cloudasset.googleapis.com --project=%s", projectID, projectID)
	}

	slog.Debug("Cloud Asset API is enabled", "project", projectID)
	return nil
}

func GetProjectFromADC(ctx context.Context) (string, error) {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to find default credentials: %w", err)
	}

	if creds.ProjectID == "" {
		return "", fmt.Errorf("no project ID found in application default credentials")
	}

	return creds.ProjectID, nil
}
