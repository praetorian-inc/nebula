package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/compute"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/containers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/storage"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("gcp", "recon", GcpListResources.Metadata().Properties()["id"].(string), *GcpListResources)
}

var GcpListResources = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Resources",
		"List GCP resources across organization, folder, or project scope with optional resource type filtering.",
	).WithProperties(map[string]any{
		"id":          "list-resources",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	NewGcpResourceListRouter,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
	options.GcpResourceTypes(),
	options.GcpIncludeSysProjects(),
).WithConfigs(
	cfg.WithArg("module-name", "list-resources"),
).WithAutoRun()

// routes to chains based on scope and resource types
type GcpResourceListRouter struct {
	*chain.Base
	resourceTypes []string
	scopeType     string
	scopeValue    string
}

func NewGcpResourceListRouter(configs ...cfg.Config) chain.Link {
	r := &GcpResourceListRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
		options.GcpResourceTypes(),
		options.GcpIncludeSysProjects(),
	)
	return r
}

func (r *GcpResourceListRouter) Initialize() error {
	if err := r.Base.Initialize(); err != nil {
		return err
	}
	resourceTypes, err := cfg.As[[]string](r.Arg("type"))
	if err != nil {
		return fmt.Errorf("failed to get resource types: %w", err)
	}
	r.resourceTypes = resourceTypes
	if len(r.resourceTypes) > 0 && r.resourceTypes[0] != "all" {
		for _, rt := range r.resourceTypes {
			if common.ResrouceIdentifier(rt) == tab.ResourceTypeUnknown {
				return fmt.Errorf("unsupported resource type: %s", rt)
			}
		}
	}
	// one of org/folder/project needed
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

func (r *GcpResourceListRouter) shouldSendResource(resourceType tab.CloudResourceType) bool {
	if len(r.resourceTypes) == 0 || r.resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range r.resourceTypes {
		if rt == resourceType.String() {
			return true
		}
		if common.ResrouceIdentifier(rt) == resourceType {
			return true
		}
	}
	return false
}

// check if we should fan out to resources in projects (skip if only hierarchy types requested)
func (r *GcpResourceListRouter) shouldFanOutToResources() bool {
	if len(r.resourceTypes) == 0 || r.resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range r.resourceTypes {
		resType := common.ResrouceIdentifier(rt)
		if resType != tab.GCPResourceOrganization &&
			resType != tab.GCPResourceFolder &&
			resType != tab.GCPResourceProject {
			return true // found a non-hierarchy type, so we should fan out
		}
	}
	return false
}

func (r *GcpResourceListRouter) Process(input string) error {
	switch r.scopeType {
	case "org":
		return r.processOrganization()
	case "folder":
		return r.processFolder()
	case "project":
		return r.processProject()
	default:
		return fmt.Errorf("invalid scope type: %s", r.scopeType)
	}
}

func (r *GcpResourceListRouter) processOrganization() error {
	orgChain := chain.NewChain(hierarchy.NewGcpOrgInfoLink())
	orgChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgChain.Send(r.scopeValue)
	orgChain.Close()
	var orgResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](orgChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](orgChain) {
		orgResource = result
		if r.shouldSendResource(tab.GCPResourceOrganization) {
			r.Send(orgResource)
		}
	}
	if err := orgChain.Error(); err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}
	if orgResource == nil {
		return fmt.Errorf("organization not found: %s", r.scopeValue)
	}

	// List folders if requested
	if r.shouldSendResource(tab.GCPResourceFolder) {
		folderChain := chain.NewChain(hierarchy.NewGcpOrgFolderListLink())
		folderChain.WithConfigs(cfg.WithArgs(r.Args()))
		folderChain.Send(*orgResource)
		folderChain.Close()
		for folder, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; folder, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
			r.Send(folder)
		}
		if err := folderChain.Error(); err != nil {
			return fmt.Errorf("failed to list folders in organization: %w", err)
		}
	}

	// Fan out to projects in org hierarchy
	projectChain := chain.NewChain(hierarchy.NewGcpOrgProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*orgResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(project)
		}
		if r.shouldFanOutToResources() {
			r.fanOutToResources(*project)
		}
	}
	return projectChain.Error()
}

func (r *GcpResourceListRouter) processFolder() error {
	folderChain := chain.NewChain(hierarchy.NewGcpFolderInfoLink())
	folderChain.WithConfigs(cfg.WithArgs(r.Args()))
	folderChain.Send(r.scopeValue)
	folderChain.Close()
	var folderResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
		folderResource = result
		if r.shouldSendResource(tab.GCPResourceFolder) {
			r.Send(folderResource)
		}
	}
	if err := folderChain.Error(); err != nil {
		return fmt.Errorf("failed to get folder info: %w", err)
	}
	if folderResource == nil {
		return fmt.Errorf("folder not found: %s", r.scopeValue)
	}

	// List subfolders if requested
	if r.shouldSendResource(tab.GCPResourceFolder) {
		subfolderChain := chain.NewChain(hierarchy.NewGcpFolderSubFolderListLink())
		subfolderChain.WithConfigs(cfg.WithArgs(r.Args()))
		subfolderChain.Send(*folderResource)
		subfolderChain.Close()
		for subfolder, ok := chain.RecvAs[*tab.GCPResource](subfolderChain); ok; subfolder, ok = chain.RecvAs[*tab.GCPResource](subfolderChain) {
			r.Send(subfolder)
		}
		if err := subfolderChain.Error(); err != nil {
			return fmt.Errorf("failed to list subfolders in folder: %w", err)
		}
	}

	// Fan out to projects in folder
	projectChain := chain.NewChain(hierarchy.NewGcpFolderProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*folderResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(project)
		}
		if r.shouldFanOutToResources() {
			r.fanOutToResources(*project)
		}
	}
	return projectChain.Error()
}

func (r *GcpResourceListRouter) processProject() error {
	projectChain := chain.NewChain(hierarchy.NewGcpProjectInfoLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(r.scopeValue)
	projectChain.Close()
	var projectResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		projectResource = result
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(projectResource)
		}
	}
	if err := projectChain.Error(); err != nil {
		return fmt.Errorf("failed to get project info: %w", err)
	}
	if projectResource == nil {
		return fmt.Errorf("project not found: %s", r.scopeValue)
	}
	// Fan out to resources in project
	if r.shouldFanOutToResources() {
		return r.fanOutToResources(*projectResource)
	}
	return nil
}

func (r *GcpResourceListRouter) fanOutToResources(project tab.GCPResource) error {
	if project.ResourceType != tab.GCPResourceProject {
		return fmt.Errorf("expected project resource, got %s", project.ResourceType)
	}
	chains := r.buildResourceChains()
	if len(chains) == 0 {
		slog.Debug("No resource types to scan", "project", project.Name)
		return nil
	}
	// multi-chain for given resource types
	multi := chain.NewMulti(chains...)
	multi.WithConfigs(cfg.WithArgs(r.Args()))
	multi.WithStrictness(chain.Lax)
	multi.Send(project)
	multi.Close()
	for result, ok := chain.RecvAs[*tab.GCPResource](multi); ok; result, ok = chain.RecvAs[*tab.GCPResource](multi) {
		r.Send(result)
	}
	if err := multi.Error(); err != nil {
		slog.Warn("Some resources failed for project (continuing with others)", "project", project.Name, "error", err)
		resourceErrors := common.ParseAggregatedListError(project.Name, err.Error())
		for _, resourceError := range resourceErrors {
			r.Send(resourceError)
		}
	}
	return nil
}

// build chains based on resource types
func (r *GcpResourceListRouter) buildResourceChains() []chain.Link {
	var chains []chain.Link
	includeAll := len(r.resourceTypes) == 0 || r.resourceTypes[0] == "all"
	shouldInclude := func(resourceType string) bool {
		if includeAll {
			return true
		}
		for _, rt := range r.resourceTypes {
			if rt == resourceType {
				return true
			}
			if common.ResrouceIdentifier(rt) == common.ResrouceIdentifier(resourceType) {
				return true
			}
		}
		return false
	}

	// Storage resources
	if shouldInclude("bucket") {
		chains = append(chains, chain.NewChain(storage.NewGcpStorageBucketListLink()))
	}
	if shouldInclude("sql") {
		chains = append(chains, chain.NewChain(storage.NewGcpSQLInstanceListLink()))
	}

	// Compute resources
	if shouldInclude("instance") || shouldInclude("vm") {
		chains = append(chains, chain.NewChain(compute.NewGcpInstanceListLink()))
	}

	// Networking resources (has its own fanout)
	if shouldInclude("forwardingrule") || shouldInclude("globalforwardingrule") ||
		shouldInclude("address") || shouldInclude("dnszone") || shouldInclude("managedzone") {
		chains = append(chains, chain.NewChain(compute.NewGCPNetworkingFanOut()))
	}

	// Application resources
	if shouldInclude("function") || shouldInclude("functionv2") || shouldInclude("functionv1") || shouldInclude("cloudfunction") {
		chains = append(chains, chain.NewChain(applications.NewGcpFunctionListLink()))
	}
	if shouldInclude("runservice") || shouldInclude("cloudrunservice") {
		chains = append(chains, chain.NewChain(applications.NewGcpCloudRunServiceListLink()))
	}
	if shouldInclude("appengineservice") {
		chains = append(chains, chain.NewChain(applications.NewGcpAppEngineApplicationListLink()))
	}

	// Container resources - chained together
	if shouldInclude("artifactrepo") || shouldInclude("containerimage") ||
		shouldInclude("dockerimage") || shouldInclude("artifactoryimage") {
		chains = append(chains, chain.NewChain(
			containers.NewGcpRepositoryListLink(),
			containers.NewGcpContainerImageListLink(),
		))
	}

	return chains
}
