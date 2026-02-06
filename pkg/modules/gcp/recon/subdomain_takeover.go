package recon

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/dns"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("gcp", "recon", GcpSubdomainTakeover.Metadata().Properties()["id"].(string), *GcpSubdomainTakeover)
}

var GcpSubdomainTakeover = chain.NewModule(
	cfg.NewMetadata(
		"GCP Subdomain Takeover",
		"Scan for dangling DNS records that could enable subdomain takeover across organization, folder, or project scope.",
	).WithProperties(map[string]any{
		"id":          "subdomain-takeover",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	NewGcpSubdomainTakeoverRouter,
	dns.NewGcpSubdomainTakeoverLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
	options.GcpIncludeSysProjects(),
).WithConfigs(
	cfg.WithArg("module-name", "subdomain-takeover"),
).WithStrictness(chain.Lax).WithAutoRun()

type GcpSubdomainTakeoverRouter struct {
	*chain.Base
	scope *common.ScopeConfig
}

func NewGcpSubdomainTakeoverRouter(configs ...cfg.Config) chain.Link {
	r := &GcpSubdomainTakeoverRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
	)
	return r
}

func (r *GcpSubdomainTakeoverRouter) Initialize() error {
	if err := r.Base.Initialize(); err != nil {
		return err
	}
	scope, err := common.ParseScopeArgs(r.Args())
	if err != nil {
		return err
	}
	r.scope = scope
	return nil
}

func (r *GcpSubdomainTakeoverRouter) Process(input string) error {
	switch r.scope.Type {
	case "org":
		return r.processOrganization()
	case "folder":
		return r.processFolder()
	case "project":
		return r.processProject()
	default:
		return fmt.Errorf("invalid scope type: %s", r.scope.Type)
	}
}

func (r *GcpSubdomainTakeoverRouter) processOrganization() error {
	orgChain := chain.NewChain(hierarchy.NewGcpOrgInfoLink())
	orgChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgChain.Send(r.scope.Value)
	orgChain.Close()
	var orgResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](orgChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](orgChain) {
		orgResource = result
	}
	if err := orgChain.Error(); err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}

	r.Send(*orgResource)
	return nil
}

func (r *GcpSubdomainTakeoverRouter) processFolder() error {
	folderChain := chain.NewChain(hierarchy.NewGcpFolderInfoLink())
	folderChain.WithConfigs(cfg.WithArgs(r.Args()))
	folderChain.Send(r.scope.Value)
	folderChain.Close()
	var folderResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
		folderResource = result
	}
	if err := folderChain.Error(); err != nil {
		return fmt.Errorf("failed to get folder info: %w", err)
	}

	r.Send(*folderResource)
	return nil
}

func (r *GcpSubdomainTakeoverRouter) processProject() error {
	projectChain := chain.NewChain(hierarchy.NewGcpProjectInfoLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(r.scope.Value)
	projectChain.Close()
	var projectResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		projectResource = result
	}
	if err := projectChain.Error(); err != nil {
		return fmt.Errorf("failed to get project info: %w", err)
	}

	r.Send(*projectResource)
	return nil
}
