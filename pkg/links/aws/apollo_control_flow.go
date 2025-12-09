package aws

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsApolloControlFlow struct {
	*base.AwsReconLink
	OrgPolicies *orgpolicies.OrgPolicies
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSRole,
		model.AWSUser,
		model.AWSGroup,
		model.AWSLambdaFunction,
		model.AWSEC2Instance,
		model.AWSCloudFormationStack,
	}
}

func NewAwsApolloControlFlow(configs ...cfg.Config) chain.Link {
	a := &AwsApolloControlFlow{}
	a.AwsReconLink = base.NewAwsReconLink(a, configs...)
	return a
}

func (a *AwsApolloControlFlow) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsOrgPolicies())
	params = append(params, options.Neo4jOptions()...)
	return params
}

func (a *AwsApolloControlFlow) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	if err := a.loadOrgPolicies(); err != nil {
		return fmt.Errorf("failed to load org policies: %v", err)
	}

	return nil
}

func (a *AwsApolloControlFlow) loadOrgPolicies() error {
	orgPol, ok := a.Args()[options.AwsOrgPolicies().Name()]
	if !ok || orgPol == nil {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		a.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	orgPolFile := orgPol.(string)
	if orgPolFile == "" {
		slog.Warn("Empty organization policies file path provided, assuming p-FullAWSAccess.")
		a.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	fileBytes, err := os.ReadFile(orgPolFile)
	if err != nil {
		return fmt.Errorf("failed to read org policies file: %w", err)
	}

	// Try to unmarshal as slice first (current format)
	if orgPolicies, err := a.unmarshalAsSlice(fileBytes); err == nil {
		a.OrgPolicies = orgPolicies
	}

	// Fallback to single object format
	if orgPolicies, err := a.unmarshalAsSingle(fileBytes); err == nil {
		a.OrgPolicies = orgPolicies
	}

	return fmt.Errorf("failed to unmarshal org policies")
}

func (a *AwsApolloControlFlow) unmarshalAsSlice(orgPolicyBytes []byte) (*orgpolicies.OrgPolicies, error) {
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(orgPolicyBytes, &orgPoliciesArray); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org policies: %w", err)
	}

	if len(orgPoliciesArray) > 0 {
		return orgPoliciesArray[0], nil
	}

	slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
	return orgpolicies.NewDefaultOrgPolicies(), nil
}

func (a *AwsApolloControlFlow) unmarshalAsSingle(orgPolicyBytes []byte) (*orgpolicies.OrgPolicies, error) {
	var orgPolicies *orgpolicies.OrgPolicies
	if err := json.Unmarshal(orgPolicyBytes, &orgPolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org policies: %w", err)
	}
	return orgPolicies, nil
}

func (a *AwsApolloControlFlow) Process(resourceType string) error {
	policyData, err := a.gatherPolicyData(resourceType)
	if err != nil {
		return fmt.Errorf("failed to gather policy data: %w", err)
	}

	analyzer := iam.NewGaadAnalyzer(policyData)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return fmt.Errorf("failed to analyze policy data: %w", err)
	}

	// Transform and send IAM permission relationships
	a.processAnalyzedSummary(summary)

	// Create assume role relationships between resources and their IAM roles
	err = a.sendResourceRelationships(*policyData.Resources)
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	// Process GitHub Actions federated identity relationships
	err = a.processGitHubActionsFederation(policyData.Gaad)
	if err != nil {
		a.Logger.Error("Failed to process GitHub Actions federation: " + err.Error())
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherPolicyData(resourceType string) (*iam.PolicyData, error) {
	resources, err := a.gatherResources(resourceType)
	if err != nil {
		return nil, err
	}

	resourcePolicies, err := a.gatherResourcePolicies(resources)
	if err != nil {
		return nil, err
	}

	gaad, err := a.gatherGaadDetails()
	if err != nil {
		return nil, err
	}

	policyData := &iam.PolicyData{
		OrgPolicies:      a.OrgPolicies,
		Resources:        &resources,
		ResourcePolicies: resourcePolicies,
		Gaad:             gaad,
	}

	return policyData, err
}

func (a *AwsApolloControlFlow) gatherResources(resourceType string) ([]types.EnrichedResourceDescription, error) {
	resourceChain := chain.NewChain(
		general.NewResourceTypePreprocessor(a)(),
		cloudcontrol.NewAWSCloudControl(cfg.WithArgs(a.Args())),
	)

	resourceChain.WithConfigs(cfg.WithArgs(a.Args()))
	resourceChain.Send(resourceType)
	resourceChain.Close()

	// Collect resources from the resource chain
	resources := []types.EnrichedResourceDescription{}
	for {
		slog.Info("gathering resource")
		resource, ok := chain.RecvAs[*types.EnrichedResourceDescription](resourceChain)
		if !ok {
			break
		}
		if resource.Identifier == "PrivilegeEscalator" {
			fmt.Println("foo")
		}
		resources = append(resources, *resource)
	}

	return resources, nil
}

func (a *AwsApolloControlFlow) gatherResourcePolicies(resources []types.EnrichedResourceDescription) (map[string]*types.Policy, error) {
	// Create policy fetcher chain
	policyChain := chain.NewChain(
		NewAwsResourcePolicyFetcher(cfg.WithArgs(a.Args())),
	)
	policyChain.WithConfigs(cfg.WithArgs(a.Args()))

	// Send resources to policy fetcher
	for _, resource := range resources {
		policyChain.Send(resource)
	}

	policyChain.Close()

	// Collect policies
	resourcePolicies := map[string]*types.Policy{}
	for {
		slog.Info("gathering resource policy")
		policy, ok := chain.RecvAs[*types.Policy](policyChain)
		if !ok {
			break
		}
		resourcePolicies[policy.ResourceARN] = policy
	}

	return resourcePolicies, nil
}

func (a *AwsApolloControlFlow) gatherGaadDetails() (*types.Gaad, error) {
	gaadChain := chain.NewChain(
		NewJanusAWSAuthorizationDetails(cfg.WithArgs(a.Args())),
	)
	gaadChain.WithConfigs(cfg.WithArgs(a.Args()))
	gaadChain.Send("") // GAAD doesn't need a resource type
	gaadChain.Close()

	slog.Info("gathering gaad details")
	gaadOutput, ok := chain.RecvAs[outputters.NamedOutputData](gaadChain)
	if !ok {
		return nil, fmt.Errorf("did not receive GAAD output")
	}

	// Convert GAAD output to PolicyData.Gaad
	// First marshal the map to JSON bytes
	jsonBytes, err := json.Marshal(gaadOutput.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GAAD data: %w", err)
	}

	var gaad types.Gaad
	if err := json.Unmarshal(jsonBytes, &gaad); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GAAD data: %w", err)
	}

	return &gaad, nil
}

func (a *AwsApolloControlFlow) processAnalyzedSummary(summary *iam.PermissionsSummary) {
	fullResults := summary.FullResults()
	a.Logger.Info(fmt.Sprintf("DEBUG: Found %d full results to process", len(fullResults)))

	for i, result := range fullResults {
		a.Logger.Debug(fmt.Sprintf("DEBUG: Processing result %d - Principal: %T, Resource: %v, Action: %s",
			i, result.Principal, result.Resource, result.Action))

		rel, err := TransformResultToRelationship(result)
		if err != nil {
			a.Logger.Error("Failed to transform relationship: " + err.Error())
			continue
		}

		a.Logger.Debug(fmt.Sprintf("DEBUG: Successfully transformed result %d, sending to outputter", i))
		a.Send(rel)
	}
}

// sendResourceRelationships creates assume role relationships using the outputter chain
func (a *AwsApolloControlFlow) sendResourceRelationships(resources []types.EnrichedResourceDescription) error {
	for _, resource := range resources {
		roleArn, roleName, accountId, err := a.parseRoleARN(resource)
		if err != nil {
			a.Logger.Error("Failed to parse role ARN: %v", err)
			continue
		}

		// Create the resource node using Tabularium transformers
		resourceNode, err := TransformERDToAWSResource(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform resource %s: %v", resource.Arn.String(), err))
			continue
		}

		// Create the role node using Tabularium types
		roleNode, err := model.NewAWSResource(
			roleArn,
			accountId,
			model.AWSRole,
			map[string]any{
				"roleName": roleName,
			},
		)

		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to create role resource %s: %v", roleArn, err))
			continue
		}

		// Create the assume role relationship
		assumeRoleRel := model.NewIAMRelationship(resourceNode, &roleNode, "sts:AssumeRole")
		assumeRoleRel.Capability = "apollo-resource-role-mapping"

		// Send to outputter
		a.Send(assumeRoleRel)
	}

	return nil
}

// parseRoleARN accepts an ARN string of an IAM role and returns the arn, role name, account ID, and an error
func (a *AwsApolloControlFlow) parseRoleARN(resource types.EnrichedResourceDescription) (string, string, string, error) {
	roleArn := resource.GetRoleArn()
	if roleArn == "" {
		return "", "", "", fmt.Errorf("role arn is empty")
	}

	// Check if we have a full ARN or just a role name
	if !strings.HasPrefix(roleArn, "arn:") {
		accountId := resource.AccountId

		roleName := roleArn
		roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)

		return roleArn, roleName, accountId, nil
	}

	parsedArn, err := arn.Parse(roleArn)
	if err != nil {
		a.Logger.Error(fmt.Sprintf("Failed to parse role ARN %s: %s", roleArn, err.Error()))
		return "", "", "", err
	}

	roleName := parsedArn.Resource

	// Handle the case where the resource includes a path like "role/rolename"
	if strings.Contains(roleName, "/") {
		parts := strings.Split(roleName, "/")
		roleName = parts[len(parts)-1]
	}

	return roleArn, roleName, parsedArn.AccountID, nil
}

// processGitHubActionsFederation processes GitHub Actions federated identity relationships
func (a *AwsApolloControlFlow) processGitHubActionsFederation(gaadData *types.Gaad) error {
	relationships, err := ExtractGitHubActionsRelationships(gaadData)
	if err != nil {
		return fmt.Errorf("failed to extract GitHub Actions relationships: %w", err)
	}

	for _, rel := range relationships {
		a.Send(rel)
	}

	return nil
}
