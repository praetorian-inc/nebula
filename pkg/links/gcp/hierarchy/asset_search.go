package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	serviceusagepb "cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/iterator"
)

// FILE INFO:
// GcpAssetSearchLink - search all resources using Cloud Asset Inventory API, Process(resource tab.GCPResource)
// GcpAssetSearchRouterLink - routes to asset search based on scope type (org/folder/project)

type GcpAssetSearchLink struct {
	*base.GcpBaseLink
	assetClient    *asset.Client
	resourceCounts map[string]int
}

// creates a link to search resources using Cloud Asset Inventory
func NewGcpAssetSearchLink(configs ...cfg.Config) chain.Link {
	g := &GcpAssetSearchLink{
		resourceCounts: make(map[string]int),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAssetSearchLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	ctx := context.Background()
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchLink) checkAssetAPIEnabled(projectID string) error {
	ctx := context.Background()
	client, err := serviceusage.NewClient(ctx, g.ClientOptions...)
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

func (g *GcpAssetSearchLink) Process(resource tab.GCPResource) error {
	var scope string
	var scopeName string
	var scopeType string
	switch resource.ResourceType {
	case tab.GCPResourceOrganization:
		scope = fmt.Sprintf("organizations/%s", resource.Name)
		scopeName = resource.DisplayName
		scopeType = "organization"
	case tab.GCPResourceFolder:
		scope = fmt.Sprintf("folders/%s", resource.Name)
		scopeName = resource.DisplayName
		scopeType = "folder"
	case tab.GCPResourceProject:
		scope = fmt.Sprintf("projects/%s", resource.Name)
		scopeName = resource.DisplayName
		scopeType = "project"
		// TODO: check for all cases, we need it enabled for all projects
		if err := g.checkAssetAPIEnabled(resource.Name); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported resource type for asset search: %s", resource.ResourceType)
	}
	slog.Info("Searching assets", "scope", scope, "scopeName", scopeName)

	req := &assetpb.SearchAllResourcesRequest{
		Scope: scope,
	}
	ctx := context.Background()
	it := g.assetClient.SearchAllResources(ctx, req)
	totalCount := 0
	for {
		assetResource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate assets: %w", err)
		}
		assetType := assetResource.AssetType
		g.resourceCounts[assetType]++
		totalCount++
	}
	slog.Info("Asset search completed", "scope", scope, "totalResources", totalCount, "uniqueTypes", len(g.resourceCounts))

	var resources []*helpers.ResourceCount
	for assetType, count := range g.resourceCounts {
		resources = append(resources, &helpers.ResourceCount{
			ResourceType: assetType,
			Count:        count,
		})
	}
	envDetails := &helpers.GCPEnvironmentDetails{
		ScopeType: scopeType,
		ScopeName: scopeName,
		ScopeID:   resource.Name,
		Location:  resource.Region,
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	g.Send(envDetails)
	return nil
}

type GcpAssetSearchRouterLink struct {
	*chain.Base
	scopeType  string
	scopeValue string
}

func NewGcpAssetSearchRouterLink(configs ...cfg.Config) chain.Link {
	r := &GcpAssetSearchRouterLink{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
	)
	return r
}

func (r *GcpAssetSearchRouterLink) Initialize() error {
	if err := r.Base.Initialize(); err != nil {
		return err
	}
	orgList, _ := cfg.As[[]string](r.Arg("org"))
	folderList, _ := cfg.As[[]string](r.Arg("folder"))
	projectList, _ := cfg.As[[]string](r.Arg("project"))
	scopeCount := 0
	if len(orgList) > 0 {
		scopeCount++
		r.scopeType = "org"
		r.scopeValue = orgList[0]
	}
	if len(folderList) > 0 {
		scopeCount++
		r.scopeType = "folder"
		r.scopeValue = folderList[0]
	}
	if len(projectList) > 0 {
		scopeCount++
		r.scopeType = "project"
		r.scopeValue = projectList[0]
	}
	if scopeCount == 0 {
		return fmt.Errorf("must provide exactly one of --org, --folder, or --project")
	}
	if scopeCount > 1 {
		return fmt.Errorf("must provide exactly one of --org, --folder, or --project (got %d)", scopeCount)
	}
	return nil
}

func (r *GcpAssetSearchRouterLink) Process(input string) error {
	var resourceChain chain.Chain
	switch r.scopeType {
	case "org":
		resourceChain = chain.NewChain(NewGcpOrgInfoLink())
		resourceChain.WithConfigs(cfg.WithArgs(r.Args()))
		resourceChain.Send(r.scopeValue)
	case "folder":
		resourceChain = chain.NewChain(NewGcpFolderInfoLink())
		resourceChain.WithConfigs(cfg.WithArgs(r.Args()))
		resourceChain.Send(r.scopeValue)
	case "project":
		resourceChain = chain.NewChain(NewGcpProjectInfoLink())
		resourceChain.WithConfigs(cfg.WithArgs(r.Args()))
		resourceChain.Send(r.scopeValue)
	default:
		return fmt.Errorf("invalid scope type: %s", r.scopeType)
	}
	resourceChain.Close()
	var scopeResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](resourceChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](resourceChain) {
		scopeResource = result
	}
	if err := resourceChain.Error(); err != nil {
		return fmt.Errorf("failed to get %s info: %w", r.scopeType, err)
	}
	if scopeResource == nil {
		return fmt.Errorf("%s not found: %s", r.scopeType, r.scopeValue)
	}
	assetSearchChain := chain.NewChain(NewGcpAssetSearchLink())
	assetSearchChain.WithConfigs(cfg.WithArgs(r.Args()))
	assetSearchChain.Send(*scopeResource)
	assetSearchChain.Close()
	for envDetails, ok := chain.RecvAs[*helpers.GCPEnvironmentDetails](assetSearchChain); ok; envDetails, ok = chain.RecvAs[*helpers.GCPEnvironmentDetails](assetSearchChain) {
		r.Send(envDetails)
	}
	return assetSearchChain.Error()
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func getLabelsFromResource(resource tab.GCPResource) map[string]string {
	labels := make(map[string]string)
	if resource.Properties == nil {
		return labels
	}
	if labelsRaw, ok := resource.Properties["labels"]; ok {
		if labelMap, ok := labelsRaw.(map[string]string); ok {
			return labelMap
		}
	}
	return labels
}
