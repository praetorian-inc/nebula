package orgpolicy

import (
	"context"
	"fmt"
	"log/slog"

	"cloud.google.com/go/orgpolicy/apiv2"
	"cloud.google.com/go/orgpolicy/apiv2/orgpolicypb"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

var securityConstraints = []string{
	"iam.automaticIamGrantsForDefaultServiceAccounts",
	"compute.skipDefaultNetworkCreation",
	"sql.restrictPublicIp",
	"cloudbuild.useBuildServiceAccount",
	"cloudbuild.useComputeServiceAccount",
	"iam.disableServiceAccountKeyCreation",
	"storage.publicAccessPrevention",
	"iam.allowedPolicyMemberDomains",
}

type GcpOrgConstraintCollectorLink struct {
	*base.GcpBaseLink
	orgPolicyClient *orgpolicy.Client
}

func NewGcpOrgConstraintCollectorLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgConstraintCollectorLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgConstraintCollectorLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.orgPolicyClient, err = orgpolicy.NewClient(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create org policy client: %w", err)
	}
	return nil
}

func (g *GcpOrgConstraintCollectorLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		return nil
	}

	orgName := "organizations/" + resource.Name
	for _, constraint := range securityConstraints {
		constraintID := "constraints/" + constraint
		policyResource, err := g.collectEffectivePolicy(orgName, constraint, constraintID, "organization", resource.Name)
		if err != nil {
			slog.Error("Failed to collect org constraint", "org", orgName, "constraint", constraintID, "error", err)
			continue
		}
		if policyResource != nil {
			g.Send(*policyResource)
		}
	}
	return nil
}

func (g *GcpOrgConstraintCollectorLink) collectEffectivePolicy(resourceName, constraint, constraintID, resourceTypeLabel, resourceID string) (*tab.GCPResource, error) {
	policyName := fmt.Sprintf("%s/policies/%s", resourceName, constraint)

	req := &orgpolicypb.GetEffectivePolicyRequest{
		Name: policyName,
	}

	policy, err := g.orgPolicyClient.GetEffectivePolicy(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to get effective policy: %w", err)
	}

	properties := extractPolicyProperties(policy, constraintID, resourceName)

	// Check if policy is explicitly set at this resource level
	isExplicitlySet := isPolicyExplicitlySet(g.orgPolicyClient, policyName)
	properties["isExplicitlySet"] = isExplicitlySet

	var resourceType tab.CloudResourceType
	switch resourceTypeLabel {
	case "organization":
		resourceType = tab.GCPResourceOrganizationPolicy
	case "folder":
		resourceType = tab.GCPResourceFolderPolicy
	case "project":
		resourceType = tab.GCPResourceProjectPolicy
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceTypeLabel)
	}

	policyResource, err := tab.NewGCPResource(
		policyName,
		resourceID,
		resourceType,
		properties,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP policy resource: %w", err)
	}

	return &policyResource, nil
}

type GcpFolderConstraintCollectorLink struct {
	*base.GcpBaseLink
	orgPolicyClient *orgpolicy.Client
}

func NewGcpFolderConstraintCollectorLink(configs ...cfg.Config) chain.Link {
	g := &GcpFolderConstraintCollectorLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFolderConstraintCollectorLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.orgPolicyClient, err = orgpolicy.NewClient(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create org policy client: %w", err)
	}
	return nil
}

func (g *GcpFolderConstraintCollectorLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceFolder {
		return nil
	}

	folderName := resource.Name
	for _, constraint := range securityConstraints {
		constraintID := "constraints/" + constraint
		policyResource, err := g.collectEffectivePolicy(folderName, constraint, constraintID, "folder", resource.Name)
		if err != nil {
			slog.Error("Failed to collect folder constraint", "folder", folderName, "constraint", constraintID, "error", err)
			continue
		}
		if policyResource != nil {
			g.Send(*policyResource)
		}
	}
	return nil
}

func (g *GcpFolderConstraintCollectorLink) collectEffectivePolicy(resourceName, constraint, constraintID, resourceTypeLabel, resourceID string) (*tab.GCPResource, error) {
	policyName := fmt.Sprintf("%s/policies/%s", resourceName, constraint)

	req := &orgpolicypb.GetEffectivePolicyRequest{
		Name: policyName,
	}

	policy, err := g.orgPolicyClient.GetEffectivePolicy(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to get effective policy: %w", err)
	}

	properties := extractPolicyProperties(policy, constraintID, resourceName)

	// Check if policy is explicitly set at this resource level
	isExplicitlySet := isPolicyExplicitlySet(g.orgPolicyClient, policyName)
	properties["isExplicitlySet"] = isExplicitlySet

	var resourceType tab.CloudResourceType
	switch resourceTypeLabel {
	case "organization":
		resourceType = tab.GCPResourceOrganizationPolicy
	case "folder":
		resourceType = tab.GCPResourceFolderPolicy
	case "project":
		resourceType = tab.GCPResourceProjectPolicy
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceTypeLabel)
	}

	policyResource, err := tab.NewGCPResource(
		policyName,
		resourceID,
		resourceType,
		properties,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP policy resource: %w", err)
	}

	return &policyResource, nil
}

type GcpProjectConstraintCollectorLink struct {
	*base.GcpBaseLink
	orgPolicyClient *orgpolicy.Client
}

func NewGcpProjectConstraintCollectorLink(configs ...cfg.Config) chain.Link {
	g := &GcpProjectConstraintCollectorLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpProjectConstraintCollectorLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.orgPolicyClient, err = orgpolicy.NewClient(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create org policy client: %w", err)
	}
	return nil
}

func (g *GcpProjectConstraintCollectorLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}

	projectName := "projects/" + resource.Name
	for _, constraint := range securityConstraints {
		constraintID := "constraints/" + constraint
		policyResource, err := g.collectEffectivePolicy(projectName, constraint, constraintID, "project", resource.Name)
		if err != nil {
			slog.Error("Failed to collect project constraint", "project", projectName, "constraint", constraintID, "error", err)
			continue
		}
		if policyResource != nil {
			g.Send(*policyResource)
		}
	}
	return nil
}

func (g *GcpProjectConstraintCollectorLink) collectEffectivePolicy(resourceName, constraint, constraintID, resourceTypeLabel, resourceID string) (*tab.GCPResource, error) {
	policyName := fmt.Sprintf("%s/policies/%s", resourceName, constraint)

	req := &orgpolicypb.GetEffectivePolicyRequest{
		Name: policyName,
	}

	policy, err := g.orgPolicyClient.GetEffectivePolicy(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to get effective policy: %w", err)
	}

	properties := extractPolicyProperties(policy, constraintID, resourceName)

	// Check if policy is explicitly set at this resource level
	isExplicitlySet := isPolicyExplicitlySet(g.orgPolicyClient, policyName)
	properties["isExplicitlySet"] = isExplicitlySet

	var resourceType tab.CloudResourceType
	switch resourceTypeLabel {
	case "organization":
		resourceType = tab.GCPResourceOrganizationPolicy
	case "folder":
		resourceType = tab.GCPResourceFolderPolicy
	case "project":
		resourceType = tab.GCPResourceProjectPolicy
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceTypeLabel)
	}

	policyResource, err := tab.NewGCPResource(
		policyName,
		resourceID,
		resourceType,
		properties,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP policy resource: %w", err)
	}

	return &policyResource, nil
}

func isPolicyExplicitlySet(client *orgpolicy.Client, policyName string) bool {
	req := &orgpolicypb.GetPolicyRequest{
		Name: policyName,
	}

	// GetPolicy returns a policy ONLY if it's explicitly set at this resource
	// If the policy is inherited, it returns an error (NOT_FOUND)
	_, err := client.GetPolicy(context.Background(), req)
	return err == nil
}

func extractPolicyProperties(policy *orgpolicypb.Policy, constraintID, resourceName string) map[string]any {
	properties := map[string]any{
		"constraintId": constraintID,
		"resourceName": resourceName,
		"policyName":   policy.GetName(),
	}

	spec := policy.GetSpec()
	if spec == nil {
		properties["inherit"] = true
		properties["enforced"] = false
		return properties
	}

	properties["inherit"] = spec.GetInheritFromParent()

	if booleanPolicy := spec.GetRules(); len(booleanPolicy) > 0 {
		firstRule := booleanPolicy[0]

		if firstRule.GetEnforce() {
			properties["enforced"] = true
		} else {
			properties["enforced"] = false
		}

		if allowAll := firstRule.GetAllowAll(); allowAll {
			properties["allowAll"] = true
		}

		if denyAll := firstRule.GetDenyAll(); denyAll {
			properties["denyAll"] = true
		}

		if values := firstRule.GetValues(); values != nil {
			if len(values.GetAllowedValues()) > 0 {
				properties["allowedValues"] = values.GetAllowedValues()
			}
			if len(values.GetDeniedValues()) > 0 {
				properties["deniedValues"] = values.GetDeniedValues()
			}
		}
	}

	return properties
}
