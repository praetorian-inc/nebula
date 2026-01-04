package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
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
	pd *iam.PolicyData
}

func (a *AwsApolloControlFlow) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSRole,
		model.AWSUser,
		model.AWSGroup,
		model.AWSLambdaFunction,
		model.AWSEC2Instance,
		model.AWSCloudFormationStack,
		model.CloudResourceType("AWS::CodeBuild::Project"),
		model.CloudResourceType("AWS::SageMaker::NotebookInstance"),
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
	// Initialize PolicyData with an empty slice of resources
	resources := make([]types.EnrichedResourceDescription, 0)
	a.pd = &iam.PolicyData{
		Resources: &resources,
	}
	a.loadOrgPolicies()

	return nil
}

func (a *AwsApolloControlFlow) loadOrgPolicies() error {
	orgPol, ok := a.Args()[options.AwsOrgPolicies().Name()]
	if !ok || orgPol == nil {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
		return nil
	}

	orgPolFile := orgPol.(string)
	if orgPolFile != "" {
		fileBytes, err := os.ReadFile(orgPolFile)
		if err != nil {
			return fmt.Errorf("failed to read org policies file: %w", err)
		}

		// Try to unmarshal as array first (current format)
		var orgPoliciesArray []*orgpolicies.OrgPolicies
		if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
			if len(orgPoliciesArray) > 0 {
				a.pd.OrgPolicies = orgPoliciesArray[0]
			} else {
				slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
				a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
			}
		} else {
			// Fallback to single object format
			var orgPolicies *orgpolicies.OrgPolicies
			if err := json.Unmarshal(fileBytes, &orgPolicies); err != nil {
				return fmt.Errorf("failed to unmarshal org policies: %w", err)
			}
			a.pd.OrgPolicies = orgPolicies
		}
	} else {
		slog.Warn("Empty organization policies file path provided, assuming p-FullAWSAccess.")
		a.pd.OrgPolicies = orgpolicies.NewDefaultOrgPolicies()
	}

	return nil
}

func (a *AwsApolloControlFlow) Process(resourceType string) error {
	err := a.gatherResources(resourceType)
	if err != nil {
		return err
	}

	// Gather CodeBuild projects (not supported by CloudControl)
	err = a.gatherCodeBuildProjects()
	if err != nil {
		a.Logger.Error("Failed to gather CodeBuild projects: " + err.Error())
		// Don't return error - continue with other resources
	}

	// Gather SageMaker notebook instances (not supported by CloudControl)
	err = a.gatherSageMakerNotebookInstances()
	if err != nil {
		a.Logger.Error("Failed to gather SageMaker notebook instances: " + err.Error())
		// Don't return error - continue with other resources
	}

	err = a.gatherResourcePolicies()
	if err != nil {
		return err
	}

	err = a.gatherGaadDetails()
	if err != nil {
		return err
	}

	// Send all GAAD principals as nodes BEFORE sending relationships
	// This ensures all roles/users/groups have full properties from GAAD
	// even if they only appear as relationship targets
	err = a.sendGaadPrincipals()
	if err != nil {
		a.Logger.Error("Failed to send GAAD principals: " + err.Error())
	}

	analyzer := iam.NewGaadAnalyzer(a.pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return err
	}

	// Transform and send IAM permission relationships
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

	// Create assume role relationships between resources and their IAM roles
	err = a.sendResourceRoleRelationships()
	if err != nil {
		a.Logger.Error("Failed to create assume role relationships: " + err.Error())
	}

	// Process GitHub Actions federated identity relationships
	err = a.processGitHubActionsFederation()
	if err != nil {
		a.Logger.Error("Failed to process GitHub Actions federation: " + err.Error())
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherResources(resourceType string) error {
	resourceChain := chain.NewChain(
		general.NewResourceTypePreprocessor(a)(),
		cloudcontrol.NewAWSCloudControl(cfg.WithArgs(a.Args())),
	)

	resourceChain.WithConfigs(cfg.WithArgs(a.Args()))
	resourceChain.Send(resourceType)
	resourceChain.Close()

	// Collect resources from the resource chain
	var resource *types.EnrichedResourceDescription
	var ok bool

	for {
		resource, ok = chain.RecvAs[*types.EnrichedResourceDescription](resourceChain)
		if !ok {
			break
		}
		*a.pd.Resources = append(*a.pd.Resources, *resource)
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherResourcePolicies() error {
	// Create policy fetcher chain
	policyChain := chain.NewChain(
		NewAwsResourcePolicyFetcher(cfg.WithArgs(a.Args())),
	)
	policyChain.WithConfigs(cfg.WithArgs(a.Args()))

	// Initialize map if nil
	if a.pd.ResourcePolicies == nil {
		a.pd.ResourcePolicies = make(map[string]*types.Policy)
	}

	// Send resources to policy fetcher and collect policies
	for _, resource := range *a.pd.Resources {
		policyChain.Send(resource)
	}

	policyChain.Close()

	for {
		policy, ok := chain.RecvAs[*types.Policy](policyChain)
		if !ok {
			break
		}
		a.pd.ResourcePolicies[policy.ResourceARN] = policy
	}

	return nil
}

func (a *AwsApolloControlFlow) gatherGaadDetails() error {
	gaadChain := chain.NewChain(
		NewJanusAWSAuthorizationDetails(cfg.WithArgs(a.Args())),
	)
	gaadChain.WithConfigs(cfg.WithArgs(a.Args()))
	gaadChain.Send("") // GAAD doesn't need a resource type
	gaadChain.Close()

	// Collect GAAD output
	var gaadOutput outputters.NamedOutputData
	var ok bool
	for {
		gaadOutput, ok = chain.RecvAs[outputters.NamedOutputData](gaadChain)
		if !ok {
			break
		}
		// Convert GAAD output to PolicyData.Gaad
		// First marshal the map to JSON bytes
		jsonBytes, err := json.Marshal(gaadOutput.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal GAAD data: %w", err)
		}
		// Then unmarshal into the Gaad struct
		if err := json.Unmarshal(jsonBytes, &a.pd.Gaad); err != nil {
			return fmt.Errorf("failed to unmarshal GAAD data: %w", err)
		}
	}

	if a.pd.Gaad == nil {
		return fmt.Errorf("failed to collect GAAD (GetAccountAuthorizationDetails) data - the IAM authorization details chain did not produce output")
	}

	return nil
}

// gatherCodeBuildProjects fetches CodeBuild projects from all regions
// CodeBuild is not supported by CloudControl, so we use the CodeBuild API directly
func (a *AwsApolloControlFlow) gatherCodeBuildProjects() error {
	var totalProjects int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := codebuild.NewFromConfig(config)

		// List all project names
		var projectNames []string
		var nextToken *string

		for {
			listInput := &codebuild.ListProjectsInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListProjects(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list CodeBuild projects in region %s: %s", region, err.Error()))
				break
			}

			projectNames = append(projectNames, listOutput.Projects...)

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}

		if len(projectNames) == 0 {
			continue
		}

		// Batch get project details (max 100 per request)
		for i := 0; i < len(projectNames); i += 100 {
			end := i + 100
			if end > len(projectNames) {
				end = len(projectNames)
			}
			batch := projectNames[i:end]

			batchInput := &codebuild.BatchGetProjectsInput{
				Names: batch,
			}

			batchOutput, err := client.BatchGetProjects(context.TODO(), batchInput)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to get CodeBuild project details in region %s: %s", region, err.Error()))
				continue
			}

			for _, project := range batchOutput.Projects {
				if project.Name == nil || project.Arn == nil {
					continue
				}

				// Parse the ARN to get account ID
				parsedArn, err := arn.Parse(*project.Arn)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to parse CodeBuild project ARN %s: %s", *project.Arn, err.Error()))
					continue
				}

				// Build properties map
				properties := map[string]any{
					"Name": *project.Name,
					"Arn":  *project.Arn,
				}

				if project.ServiceRole != nil {
					properties["Role"] = *project.ServiceRole
				}

				if project.Description != nil {
					properties["Description"] = *project.Description
				}

				if project.Source != nil {
					sourceProps := map[string]any{}
					if project.Source.Type != "" {
						sourceProps["Type"] = string(project.Source.Type)
					}
					if project.Source.Location != nil {
						sourceProps["Location"] = *project.Source.Location
					}
					properties["Source"] = sourceProps
				}

				if project.Environment != nil {
					envProps := map[string]any{}
					if project.Environment.ComputeType != "" {
						envProps["ComputeType"] = string(project.Environment.ComputeType)
					}
					if project.Environment.Image != nil {
						envProps["Image"] = *project.Environment.Image
					}
					if project.Environment.PrivilegedMode != nil {
						envProps["PrivilegedMode"] = *project.Environment.PrivilegedMode
					}
					properties["Environment"] = envProps
				}

				// Convert properties to JSON string (to match CloudControl format)
				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal CodeBuild project properties: %s", err.Error()))
					continue
				}

				// Create EnrichedResourceDescription
				erd := types.NewEnrichedResourceDescription(
					*project.Arn, // Use ARN as identifier for CodeBuild
					"AWS::CodeBuild::Project",
					region,
					parsedArn.AccountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalProjects++
			}
		}
	}

	if totalProjects > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d CodeBuild projects", totalProjects))
	}

	return nil
}

// gatherSageMakerNotebookInstances fetches SageMaker notebook instances from all regions
// SageMaker notebook instances are not supported by CloudControl, so we use the SageMaker API directly
func (a *AwsApolloControlFlow) gatherSageMakerNotebookInstances() error {
	var totalInstances int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := sagemaker.NewFromConfig(config)

		// List all notebook instances with pagination
		var nextToken *string

		for {
			listInput := &sagemaker.ListNotebookInstancesInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListNotebookInstances(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list SageMaker notebook instances in region %s: %s", region, err.Error()))
				break
			}

			for _, instance := range listOutput.NotebookInstances {
				if instance.NotebookInstanceName == nil || instance.NotebookInstanceArn == nil {
					continue
				}

				// Parse the ARN to get account ID
				parsedArn, err := arn.Parse(*instance.NotebookInstanceArn)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to parse SageMaker notebook instance ARN %s: %s", *instance.NotebookInstanceArn, err.Error()))
					continue
				}

				// Build properties map
				properties := map[string]any{
					"NotebookInstanceName": *instance.NotebookInstanceName,
					"Arn":                  *instance.NotebookInstanceArn,
				}

				// Get the role ARN - need to call DescribeNotebookInstance for full details
				descInput := &sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: instance.NotebookInstanceName,
				}

				descOutput, err := client.DescribeNotebookInstance(context.TODO(), descInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to describe SageMaker notebook instance %s: %s", *instance.NotebookInstanceName, err.Error()))
				} else {
					if descOutput.RoleArn != nil {
						properties["Role"] = *descOutput.RoleArn
					}
					if descOutput.InstanceType != "" {
						properties["InstanceType"] = string(descOutput.InstanceType)
					}
					if descOutput.NotebookInstanceStatus != "" {
						properties["Status"] = string(descOutput.NotebookInstanceStatus)
					}
					if descOutput.Url != nil {
						properties["Url"] = *descOutput.Url
					}
					if descOutput.DirectInternetAccess != "" {
						properties["DirectInternetAccess"] = string(descOutput.DirectInternetAccess)
					}
					if descOutput.RootAccess != "" {
						properties["RootAccess"] = string(descOutput.RootAccess)
					}
				}

				// Convert properties to JSON string (to match CloudControl format)
				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal SageMaker notebook instance properties: %s", err.Error()))
					continue
				}

				// Create EnrichedResourceDescription
				erd := types.NewEnrichedResourceDescription(
					*instance.NotebookInstanceArn, // Use ARN as identifier
					"AWS::SageMaker::NotebookInstance",
					region,
					parsedArn.AccountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalInstances++
			}

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}
	}

	if totalInstances > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d SageMaker notebook instances", totalInstances))
	}

	return nil
}

// sendGaadPrincipals sends all GAAD principals (users, roles, groups) as graph nodes
// This ensures that all principals have full properties from GAAD, even if they
// only appear as relationship targets (e.g., roles that can be assumed but have no permissions)
func (a *AwsApolloControlFlow) sendGaadPrincipals() error {
	if a.pd == nil || a.pd.Gaad == nil {
		return nil
	}

	var nodeCount int

	// Send all roles from GAAD
	for i := range a.pd.Gaad.RoleDetailList {
		role := &a.pd.Gaad.RoleDetailList[i]
		roleNode, err := TransformRoleDLToAWSResource(role)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform role %s: %s", role.Arn, err.Error()))
			continue
		}
		a.Send(roleNode)
		nodeCount++
	}

	// Send all users from GAAD
	for i := range a.pd.Gaad.UserDetailList {
		user := &a.pd.Gaad.UserDetailList[i]
		userNode, err := TransformUserDLToAWSResource(user)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform user %s: %s", user.Arn, err.Error()))
			continue
		}
		a.Send(userNode)
		nodeCount++
	}

	// Send all groups from GAAD
	for i := range a.pd.Gaad.GroupDetailList {
		group := &a.pd.Gaad.GroupDetailList[i]
		groupNode, err := TransformGroupDLToAWSResource(group)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform group %s: %s", group.Arn, err.Error()))
			continue
		}
		a.Send(groupNode)
		nodeCount++
	}

	a.Logger.Info(fmt.Sprintf("Sent %d GAAD principal nodes (roles, users, groups)", nodeCount))
	return nil
}

// sendResourceRoleRelationships creates assume role relationships using the outputter chain
func (a *AwsApolloControlFlow) sendResourceRoleRelationships() error {
	if a.pd.Resources == nil || len(*a.pd.Resources) == 0 {
		return nil
	}

	for _, resource := range *a.pd.Resources {
		roleArn := resource.GetRoleArn()
		if roleArn == "" {
			continue
		}

		var roleName string
		var accountId string = resource.AccountId

		// Check if we have a full ARN or just a role name
		if strings.HasPrefix(roleArn, "arn:") {
			// Parse the ARN for proper role name
			parsedArn, err := arn.Parse(roleArn)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to parse role ARN %s: %s", roleArn, err.Error()))
				continue
			}

			// If we have a valid ARN, use the account ID from it
			accountId = parsedArn.AccountID

			// Extract role name from resource field
			roleName = parsedArn.Resource
			// Handle the case where the resource includes a path like "role/rolename"
			if strings.Contains(roleName, "/") {
				parts := strings.Split(roleName, "/")
				roleName = parts[len(parts)-1]
			}
		} else {
			// If no ARN format, assume it's a direct role name
			roleName = roleArn
			// Use the resource's account ID for constructing the role ARN
			roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
		}

		// Create the resource node using Tabularium transformers
		resourceNode, err := TransformERDToAWSResource(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform resource %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create the role node using Tabularium types
		roleProperties := map[string]any{
			"roleName": roleName,
		}
		roleNode, err := model.NewAWSResource(
			roleArn,
			accountId,
			model.AWSRole,
			roleProperties,
		)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to create role resource %s: %s", roleArn, err.Error()))
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

// processGitHubActionsFederation processes GitHub Actions federated identity relationships
func (a *AwsApolloControlFlow) processGitHubActionsFederation() error {
	if a.pd == nil || a.pd.Gaad == nil {
		return nil
	}

	// Extract all GitHub Actions Repository→Role relationships from GAAD data
	relationships, err := ExtractGitHubActionsRelationships(a.pd.Gaad)
	if err != nil {
		return fmt.Errorf("failed to extract GitHub Actions relationships: %w", err)
	}

	// Send all relationships to the outputter chain
	for _, rel := range relationships {
		a.Send(rel)
	}

	return nil
}

func (a *AwsApolloControlFlow) Close() {
	// No database connection to close - handled by outputter
}
