package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/iterator"
)

type GcpAssetSearchOrgLink struct {
	*base.GcpBaseLink
	assetClient      *asset.Client
	resourceCounts   map[string]int
	assetAPIProject  string
}

func NewGcpAssetSearchOrgLink(configs ...cfg.Config) chain.Link {
	g := &GcpAssetSearchOrgLink{
		resourceCounts: make(map[string]int),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAssetSearchOrgLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to ADC project)"),
	}
}

func (g *GcpAssetSearchOrgLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}

	assetAPIProject, _ := cfg.As[string](g.Arg("asset-api-project"))
	if assetAPIProject == "" {
		ctx := context.Background()
		adcProject, err := GetProjectFromADC(ctx)
		if err != nil {
			return fmt.Errorf("--asset-api-project not provided and could not determine project from ADC: %w", err)
		}
		g.assetAPIProject = adcProject
		slog.Debug("Using project from ADC for Asset API", "project", adcProject)
	} else {
		g.assetAPIProject = assetAPIProject
	}

	var err error
	ctx := context.Background()
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchOrgLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		return fmt.Errorf("expected organization resource, got %s", resource.ResourceType)
	}

	if err := CheckAssetAPIEnabled(g.assetAPIProject, g.ClientOptions...); err != nil {
		return err
	}

	scope := fmt.Sprintf("organizations/%s", resource.Name)
	return g.performAssetSearch(scope, "organization", resource)
}

func (g *GcpAssetSearchOrgLink) performAssetSearch(scope, scopeType string, resource tab.GCPResource) error {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)

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
		ScopeName: resource.DisplayName,
		ScopeID:   resource.Name,
		Location:  resource.Region,
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	g.Send(envDetails)
	return nil
}

type GcpAssetSearchFolderLink struct {
	*base.GcpBaseLink
	assetClient      *asset.Client
	resourceCounts   map[string]int
	assetAPIProject  string
}

func NewGcpAssetSearchFolderLink(configs ...cfg.Config) chain.Link {
	g := &GcpAssetSearchFolderLink{
		resourceCounts: make(map[string]int),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAssetSearchFolderLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to ADC project)"),
	}
}

func (g *GcpAssetSearchFolderLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}

	assetAPIProject, _ := cfg.As[string](g.Arg("asset-api-project"))
	if assetAPIProject == "" {
		ctx := context.Background()
		adcProject, err := GetProjectFromADC(ctx)
		if err != nil {
			return fmt.Errorf("--asset-api-project not provided and could not determine project from ADC: %w", err)
		}
		g.assetAPIProject = adcProject
		slog.Debug("Using project from ADC for Asset API", "project", adcProject)
	} else {
		g.assetAPIProject = assetAPIProject
	}

	var err error
	ctx := context.Background()
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchFolderLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceFolder {
		return fmt.Errorf("expected folder resource, got %s", resource.ResourceType)
	}

	if err := CheckAssetAPIEnabled(g.assetAPIProject, g.ClientOptions...); err != nil {
		return err
	}

	scope := fmt.Sprintf("folders/%s", resource.Name)
	return g.performAssetSearch(scope, "folder", resource)
}

func (g *GcpAssetSearchFolderLink) performAssetSearch(scope, scopeType string, resource tab.GCPResource) error {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)

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
		ScopeName: resource.DisplayName,
		ScopeID:   resource.Name,
		Location:  resource.Region,
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	g.Send(envDetails)
	return nil
}

type GcpAssetSearchProjectLink struct {
	*base.GcpBaseLink
	assetClient      *asset.Client
	resourceCounts   map[string]int
	assetAPIProject  string
}

func NewGcpAssetSearchProjectLink(configs ...cfg.Config) chain.Link {
	g := &GcpAssetSearchProjectLink{
		resourceCounts: make(map[string]int),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAssetSearchProjectLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to scoped project)"),
	}
}

func (g *GcpAssetSearchProjectLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}

	assetAPIProject, _ := cfg.As[string](g.Arg("asset-api-project"))
	g.assetAPIProject = assetAPIProject

	var err error
	ctx := context.Background()
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchProjectLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return fmt.Errorf("expected project resource, got %s", resource.ResourceType)
	}

	projectID := resource.Name
	if g.assetAPIProject != "" {
		projectID = g.assetAPIProject
	}

	if err := CheckAssetAPIEnabled(projectID, g.ClientOptions...); err != nil {
		return err
	}

	scope := fmt.Sprintf("projects/%s", resource.Name)
	return g.performAssetSearch(scope, "project", resource)
}

func (g *GcpAssetSearchProjectLink) performAssetSearch(scope, scopeType string, resource tab.GCPResource) error {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)

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
		ScopeName: resource.DisplayName,
		ScopeID:   resource.Name,
		Location:  resource.Region,
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	g.Send(envDetails)
	return nil
}

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
