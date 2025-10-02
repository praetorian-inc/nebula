package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
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
	registry.Register("gcp", "recon", GcpFindSecrets.Metadata().Properties()["id"].(string), *GcpFindSecrets)
}

var GcpFindSecrets = chain.NewModule(
	cfg.NewMetadata(
		"GCP Find Secrets",
		"Scan GCP resources for secrets using NoseyParker across organization, folder, or project scope with optional resource type filtering.",
	).WithProperties(map[string]any{
		"id":          "find-secrets",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	NewGcpSecretsRouter,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
	options.GcpResourceTypes(),
	options.GcpIncludeSysProjects(),
).WithConfigs(
	cfg.WithArg("module-name", "find-secrets"),
).WithStrictness(chain.Lax).WithAutoRun()

// routes to chains based on scope and resource types
type GcpSecretsRouter struct {
	*chain.Base
	resourceTypes []string
	scopeType     string
	scopeValue    string
}

func NewGcpSecretsRouter(configs ...cfg.Config) chain.Link {
	r := &GcpSecretsRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
		options.GcpResourceTypes(),
	)
	return r
}

func (r *GcpSecretsRouter) Initialize() error {
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
			if common.SecretsResourceIdentifier(rt) == tab.ResourceTypeUnknown {
				return fmt.Errorf("unsupported resource type for secrets scanning: %s", rt)
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

func (r *GcpSecretsRouter) Process(input string) error {
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

func (r *GcpSecretsRouter) processOrganization() error {
	orgChain := chain.NewChain(hierarchy.NewGcpOrgInfoLink())
	orgChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgChain.Send(r.scopeValue)
	orgChain.Close()
	var orgResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](orgChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](orgChain) {
		orgResource = result
	}
	if err := orgChain.Error(); err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}

	// Fan out to projects in org hierarchy
	projectChain := chain.NewChain(hierarchy.NewGcpOrgProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*orgResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		r.scanProjectSecrets(*project)
	}
	return projectChain.Error()
}

func (r *GcpSecretsRouter) processFolder() error {
	folderChain := chain.NewChain(hierarchy.NewGcpFolderInfoLink())
	folderChain.WithConfigs(cfg.WithArgs(r.Args()))
	folderChain.Send(r.scopeValue)
	folderChain.Close()
	var folderResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
		folderResource = result
	}
	if err := folderChain.Error(); err != nil {
		return fmt.Errorf("failed to get folder info: %w", err)
	}

	// Fan out to projects in folder
	projectChain := chain.NewChain(hierarchy.NewGcpFolderProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*folderResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		r.scanProjectSecrets(*project)
	}
	return projectChain.Error()
}

func (r *GcpSecretsRouter) processProject() error {
	projectChain := chain.NewChain(hierarchy.NewGcpProjectInfoLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(r.scopeValue)
	projectChain.Close()
	var projectResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		projectResource = result
	}
	if err := projectChain.Error(); err != nil {
		return fmt.Errorf("failed to get project info: %w", err)
	}
	return r.scanProjectSecrets(*projectResource)
}

func (r *GcpSecretsRouter) scanProjectSecrets(project tab.GCPResource) error {
	if project.ResourceType != tab.GCPResourceProject {
		return fmt.Errorf("expected project resource, got %s", project.ResourceType)
	}
	chains := r.buildSecretsChains()
	if len(chains) == 0 {
		slog.Debug("No resource types to scan for secrets", "project", project.Name)
		return nil
	}
	// multi-chain for all secrets scanning
	multi := chain.NewMulti(chains...)
	multi.WithConfigs(cfg.WithArgs(r.Args()))
	multi.WithStrictness(chain.Lax)
	multi.Send(project)
	multi.Close()
	for result, ok := chain.RecvAs[any](multi); ok; result, ok = chain.RecvAs[any](multi) {
		r.Send(result)
	}
	if err := multi.Error(); err != nil {
		slog.Warn("Some secrets scanning failed for project (continuing with others)", "project", project.Name, "error", err)
		resourceErrors := common.ParseAggregatedListError(project.Name, err.Error())
		for _, resourceError := range resourceErrors {
			r.Send(resourceError)
		}
	}
	return nil
}

// build chains based on resource types
func (r *GcpSecretsRouter) buildSecretsChains() []chain.Link {
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
			if common.SecretsResourceIdentifier(rt) == common.SecretsResourceIdentifier(resourceType) {
				return true
			}
		}
		return false
	}

	// Storage buckets - chain through list, list objects, scan objects
	if shouldInclude("bucket") {
		chains = append(chains, chain.NewChain(
			storage.NewGcpStorageBucketListLink(),
			storage.NewGcpStorageObjectListLink(),
			storage.NewGcpStorageObjectSecretsLink(),
		))
	}

	// Compute instances - scan instance metadata and user data
	if shouldInclude("instance") || shouldInclude("vm") {
		chains = append(chains, chain.NewChain(
			compute.NewGcpInstanceListLink(),
			compute.NewGcpInstanceSecretsLink(),
		))
	}

	// Cloud Functions - scan function source code and environment variables
	if shouldInclude("function") || shouldInclude("functionv2") || shouldInclude("functionv1") || shouldInclude("cloudfunction") {
		chains = append(chains, chain.NewChain(
			applications.NewGcpFunctionListLink(),
			applications.NewGcpFunctionSecretsLink(),
		))
	}

	// Cloud Run - scan service configuration and environment variables
	if shouldInclude("runservice") || shouldInclude("cloudrunservice") {
		chains = append(chains, chain.NewChain(
			applications.NewGcpCloudRunServiceListLink(),
			applications.NewGcpCloudRunSecretsLink(),
		))
	}

	// App Engine - scan application source code and configuration
	if shouldInclude("appengineservice") {
		chains = append(chains, chain.NewChain(
			applications.NewGcpAppEngineApplicationListLink(),
			applications.NewGcpAppEngineSecretsLink(),
		))
	}

	// Container images - chain through repository list, image list, scan images
	if shouldInclude("containerimage") || shouldInclude("dockerimage") || shouldInclude("artifactoryimage") {
		chains = append(chains, chain.NewChain(
			containers.NewGcpRepositoryListLink(),
			containers.NewGcpContainerImageListLink(),
			containers.NewGcpContainerImageSecretsLink(),
		))
	}

	return chains
}
