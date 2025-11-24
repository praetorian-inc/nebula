package recon

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/orgpolicy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("gcp", "recon", GcpOrgPolicyConstraints.Metadata().Properties()["id"].(string), *GcpOrgPolicyConstraints)
}

var GcpOrgPolicyConstraints = chain.NewModule(
	cfg.NewMetadata(
		"GCP Organizational Policy Constraints",
		"Analyze GCP organizational policy constraints across org, folder, and project hierarchy to identify security misconfigurations",
	).WithProperties(map[string]any{
		"id":          "org-policy-constraints",
		"platform":    "gcp",
		"category":    "recon",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://cloud.google.com/resource-manager/docs/organization-policy/overview",
			"https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
		},
		"description": `
This module evaluates GCP organizational policy constraints to identify security misconfigurations across the resource hierarchy.

**Checked Organizational Policy Constraints:**
1. **Disable Automatic IAM Grants for Default Service Accounts** (iam.automaticIamGrantsForDefaultServiceAccounts)
   - Prevents automatic Editor role assignment to default service accounts
   - Should be enforced (true) for security

2. **Skip Default Network Creation** (compute.skipDefaultNetworkCreation)
   - Prevents creation of default VPC with permissive firewall rules
   - Should be enforced (true) for security

3. **Restrict Public IP on Cloud SQL** (sql.restrictPublicIp)
   - Prevents Cloud SQL instances from having public IP addresses
   - Should be enforced (true) for security

4. **Disable Cloud Build Default Service Account** (cloudbuild.useBuildServiceAccount)
   - Prevents use of legacy high-privilege Cloud Build service account
   - Should be not enforced (false) for security

5. **Disable Compute Engine Service Account for Cloud Build** (cloudbuild.useComputeServiceAccount)
   - Prevents Cloud Build from using overprivileged Compute Engine default service account
   - Should be not enforced (false) for security

6. **Disable Service Account Key Creation** (iam.disableServiceAccountKeyCreation)
   - Prevents creation of long-lived service account keys
   - Should be enforced (true) for security

7. **Enforce Public Access Prevention** (storage.publicAccessPrevention)
   - Prevents Storage buckets from being made public
   - Should be enforced (true) for security

8. **Domain Restricted Sharing** (iam.allowedPolicyMemberDomains)
   - Restricts IAM policy members to approved domains
   - Should have allowedValues configured

**Detection Method:**
1. Discovers organization, folders, and projects in hierarchy
2. Collects effective policy for each constraint at each container (unless inherited from parent)
3. Compares against secure baseline configuration
4. Reports violations as table output

**Output:**
- Console: Shows only resources with explicit misconfigurations
- JSON: Contains the derived policies inventory
`,
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithStrictness(chain.Lax).WithLinks( // TODO: make moderate
	NewGcpOrgPolicyRouter,
).WithOutputters(
	outputters.NewMarkdownTableConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[bool]("include-sys-projects", "include system projects from analysis").WithDefault(false),
).WithConfigs(
	cfg.WithArg("module-name", "org-policy-constraints"),
	cfg.WithArg("include-sys-projects", false),
)

type GcpOrgPolicyRouter struct {
	*chain.Base
}

func NewGcpOrgPolicyRouter(configs ...cfg.Config) chain.Link {
	r := &GcpOrgPolicyRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpIncludeSysProjects(),
	)
	return r
}

func (r *GcpOrgPolicyRouter) Initialize() error {
	return r.Base.Initialize()
}

func (r *GcpOrgPolicyRouter) Process(orgID string) error {
	orgChain := chain.NewChain(hierarchy.NewGcpOrgInfoLink())
	orgChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgChain.Send(orgID)
	orgChain.Close()
	var orgResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](orgChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](orgChain) {
		orgResource = result
	}
	if err := orgChain.Error(); err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}
	if orgResource == nil {
		return fmt.Errorf("organization not found: %s", orgID)
	}

	folderChain := chain.NewChain(hierarchy.NewGcpOrgFolderListLink())
	folderChain.WithConfigs(cfg.WithArgs(r.Args()))
	folderChain.Send(*orgResource)
	folderChain.Close()
	folders := make([]tab.GCPResource, 0)
	for folder, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; folder, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
		folders = append(folders, *folder)
	}
	if err := folderChain.Error(); err != nil {
		return fmt.Errorf("failed to list folders: %w", err)
	}

	projectChain := chain.NewChain(hierarchy.NewGcpOrgProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*orgResource)
	projectChain.Close()
	projects := make([]tab.GCPResource, 0)
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		projects = append(projects, *project)
	}
	if err := projectChain.Error(); err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	orgPolicyChain := chain.NewChain(
		orgpolicy.NewGcpOrgConstraintCollectorLink(),
		orgpolicy.NewGcpConstraintAnalyzerLink(),
		orgpolicy.NewGcpConstraintConsoleFormatterLink(),
	)
	orgPolicyChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgPolicyChain.Send(*orgResource)
	orgPolicyChain.Close()

	for result, ok := chain.RecvAs[any](orgPolicyChain); ok; result, ok = chain.RecvAs[any](orgPolicyChain) {
		r.Send(result)
	}
	if err := orgPolicyChain.Error(); err != nil {
		return fmt.Errorf("failed to collect org constraints: %w", err)
	}

	if len(folders) > 0 {
		folderPolicyChain := chain.NewChain(
			orgpolicy.NewGcpFolderConstraintCollectorLink(),
			orgpolicy.NewGcpConstraintAnalyzerLink(),
			orgpolicy.NewGcpConstraintConsoleFormatterLink(),
		)
		folderPolicyChain.WithConfigs(cfg.WithArgs(r.Args()))
		for _, folder := range folders {
			folderPolicyChain.Send(folder)
		}
		folderPolicyChain.Close()
		for result, ok := chain.RecvAs[any](folderPolicyChain); ok; result, ok = chain.RecvAs[any](folderPolicyChain) {
			r.Send(result)
		}
		if err := folderPolicyChain.Error(); err != nil {
			return fmt.Errorf("failed to collect folder constraints: %w", err)
		}
	}

	if len(projects) > 0 {
		projectPolicyChain := chain.NewChain(
			orgpolicy.NewGcpProjectConstraintCollectorLink(),
			orgpolicy.NewGcpConstraintAnalyzerLink(),
			orgpolicy.NewGcpConstraintConsoleFormatterLink(),
		)
		projectPolicyChain.WithConfigs(cfg.WithArgs(r.Args()))
		for _, project := range projects {
			projectPolicyChain.Send(project)
		}
		projectPolicyChain.Close()
		for result, ok := chain.RecvAs[any](projectPolicyChain); ok; result, ok = chain.RecvAs[any](projectPolicyChain) {
			r.Send(result)
		}
		if err := projectPolicyChain.Error(); err != nil {
			return fmt.Errorf("failed to collect project constraints: %w", err)
		}
	}

	return nil
}
