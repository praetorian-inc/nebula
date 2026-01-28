package firebase

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	gcperrors "github.com/praetorian-inc/nebula/pkg/gcp/errors"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/firebasehosting/v1beta1"
)

// FILE INFO:
// GcpFirebaseHostingSiteListLink - list all Firebase Hosting sites in a project, Process(resource tab.GCPResource)

type GcpFirebaseHostingSiteListLink struct {
	*base.GcpBaseLink
	hostingService *firebasehosting.Service
}

func NewGcpFirebaseHostingSiteListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFirebaseHostingSiteListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFirebaseHostingSiteListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.hostingService, err = firebasehosting.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create firebase hosting service: %w", err)
	}
	return nil
}

func (g *GcpFirebaseHostingSiteListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	parent := fmt.Sprintf("projects/%s", projectId)

	listCall := g.hostingService.Projects.Sites.List(parent)
	resp, err := listCall.Do()
	if err != nil {
		if gcperrors.IsServiceDisabled(err) {
			slog.Debug("Firebase Hosting API disabled for project", "project", projectId)
			return nil
		}
		return common.HandleGcpError(err, "failed to list Firebase Hosting sites")
	}

	for _, site := range resp.Sites {
		properties := map[string]any{
			"name":   site.Name,
			"labels": site.Labels,
			"type":   site.Type,
			"appId":  site.AppId,
		}

		// Check for public URLs (Firebase Hosting sites are public by default)
		if site.DefaultUrl != "" {
			properties["defaultUrl"] = site.DefaultUrl
			properties["publicURL"] = site.DefaultUrl
			properties["isPublic"] = true
			properties["riskLevel"] = "informational" // Hosting sites are designed to be public
		}

		gcpSite, err := tab.NewGCPResource(
			site.Name,
			projectId,
			tab.GCPResourceFirebaseHostingSite,
			properties,
		)
		if err != nil {
			slog.Error("Failed to create Firebase Hosting site resource", "error", err, "site", site.Name)
			continue
		}
		g.Send(gcpSite)
	}
	return nil
}
