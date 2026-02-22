package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
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
		model.CloudResourceType("AWS::EC2::LaunchTemplate"),
		model.AWSCloudFormationStack,
		model.CloudResourceType("AWS::CodeBuild::Project"),
		model.CloudResourceType("AWS::SageMaker::NotebookInstance"),
		model.CloudResourceType("AWS::ECS::TaskDefinition"),
		model.CloudResourceType("AWS::ECS::Cluster"),
		model.CloudResourceType("AWS::ECS::ContainerInstance"),
		model.CloudResourceType("AWS::AppRunner::Service"),
		model.CloudResourceType("AWS::Bedrock::CodeInterpreter"),
		model.CloudResourceType("AWS::Glue::Job"),
		model.CloudResourceType("AWS::CloudFormation::StackSet"),
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
	// Initialize PolicyData with an empty slice of resources and ResourcePolicies map
	resources := make([]types.EnrichedResourceDescription, 0)
	a.pd = &iam.PolicyData{
		Resources:        &resources,
		ResourcePolicies: make(map[string]*types.Policy),
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

	// Gather Bedrock CodeInterpreter instances (not supported by CloudControl)
	err = a.gatherBedrockCodeInterpreters()
	if err != nil {
		a.Logger.Error("Failed to gather Bedrock CodeInterpreters: " + err.Error())
		// Don't return error - continue with other resources
	}

	// Gather EC2 Launch Templates (not fully supported by CloudControl - missing LaunchTemplateData)
	err = a.gatherEC2LaunchTemplates()
	if err != nil {
		a.Logger.Error("Failed to gather EC2 Launch Templates: " + err.Error())
		// Don't return error - continue with other resources
	}

	// Gather App Runner services (CloudControl doesn't return InstanceRoleArn)
	err = a.gatherAppRunnerServices()
	if err != nil {
		a.Logger.Error("Failed to gather App Runner services: " + err.Error())
		// Don't return error - continue with other resources
	}

	// Gather ECS clusters (needed for privesc methods 49/50 resource scoping)
	err = a.gatherECSClusters()
	if err != nil {
		a.Logger.Error("Failed to gather ECS clusters: " + err.Error())
	}

	// Gather ECS container instances (needed for method 50 StartTask scoping)
	err = a.gatherECSContainerInstances()
	if err != nil {
		a.Logger.Error("Failed to gather ECS container instances: " + err.Error())
	}

	// Gather Glue jobs (needed for Glue privesc methods)
	err = a.gatherGlueJobs()
	if err != nil {
		a.Logger.Error("Failed to gather Glue jobs: " + err.Error())
	}

	// Gather CloudFormation StackSets (needed for StackSet privesc methods)
	err = a.gatherCloudFormationStackSets()
	if err != nil {
		a.Logger.Error("Failed to gather CloudFormation StackSets: " + err.Error())
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

	// Add resource policies (trust policies) from GAAD roles
	// This must be called after GAAD is loaded to populate ResourcePolicies map
	a.pd.AddResourcePolicies()

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

// gatherBedrockCodeInterpreters fetches Bedrock AgentCore CodeInterpreters from all regions
// CodeInterpreters are not supported by CloudControl, so we use the bedrockagentcorecontrol API directly
func (a *AwsApolloControlFlow) gatherBedrockCodeInterpreters() error {
	var totalInterpreters int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := bedrockagentcorecontrol.NewFromConfig(config)

		// List all code interpreters with pagination
		var nextToken *string

		for {
			listInput := &bedrockagentcorecontrol.ListCodeInterpretersInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListCodeInterpreters(context.TODO(), listInput)
			if err != nil {
				// Some regions don't support AgentCore (ap-northeast-3, sa-east-1, us-west-1)
				a.Logger.Debug(fmt.Sprintf("Failed to list Bedrock CodeInterpreters in region %s: %s", region, err.Error()))
				break
			}

			for _, summary := range listOutput.CodeInterpreterSummaries {
				if summary.CodeInterpreterId == nil || summary.CodeInterpreterArn == nil {
					continue
				}

				// Parse the ARN to get account ID
				parsedArn, err := arn.Parse(*summary.CodeInterpreterArn)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to parse CodeInterpreter ARN %s: %s", *summary.CodeInterpreterArn, err.Error()))
					continue
				}

				// Get details for ExecutionRoleArn
				getInput := &bedrockagentcorecontrol.GetCodeInterpreterInput{
					CodeInterpreterId: summary.CodeInterpreterId,
				}

				getOutput, err := client.GetCodeInterpreter(context.TODO(), getInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to get CodeInterpreter %s: %s", *summary.CodeInterpreterId, err.Error()))
					continue
				}

				// Build properties map
				properties := map[string]any{
					"CodeInterpreterId": *summary.CodeInterpreterId,
					"Arn":               *summary.CodeInterpreterArn,
				}

				if getOutput.Name != nil {
					properties["Name"] = *getOutput.Name
				}
				if getOutput.ExecutionRoleArn != nil {
					properties["ExecutionRoleArn"] = *getOutput.ExecutionRoleArn
				}
				if getOutput.Status != "" {
					properties["Status"] = string(getOutput.Status)
				}
				if getOutput.Description != nil {
					properties["Description"] = *getOutput.Description
				}

				// Convert properties to JSON string (to match CloudControl format)
				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal CodeInterpreter properties: %s", err.Error()))
					continue
				}

				// Create EnrichedResourceDescription
				erd := types.NewEnrichedResourceDescription(
					*summary.CodeInterpreterArn, // Use ARN as identifier
					"AWS::Bedrock::CodeInterpreter",
					region,
					parsedArn.AccountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalInterpreters++
			}

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}
	}

	if totalInterpreters > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d Bedrock CodeInterpreters", totalInterpreters))
	}

	return nil
}

// gatherEC2LaunchTemplates fetches EC2 launch templates from all regions with their default
// version's LaunchTemplateData. CloudControl does not return LaunchTemplateData, so we use
// the EC2 API directly and resolve instance profile ARNs to actual IAM role ARNs.
func (a *AwsApolloControlFlow) gatherEC2LaunchTemplates() error {
	var totalTemplates int

	// Get account ID once (same across all regions)
	var accountID string
	if len(a.Regions) > 0 {
		cfg, err := a.GetConfigWithRuntimeArgs(a.Regions[0])
		if err == nil {
			accountID, err = helpers.GetAccountId(cfg)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to get account ID for launch templates: %s", err.Error()))
				return nil
			}
		} else {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for account ID: %s", err.Error()))
			return nil
		}
	}

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		ec2Client := ec2.NewFromConfig(config)
		iamClient := awsiam.NewFromConfig(config)

		// List all launch templates with pagination
		var nextToken *string

		for {
			listInput := &ec2.DescribeLaunchTemplatesInput{
				NextToken: nextToken,
			}

			listOutput, err := ec2Client.DescribeLaunchTemplates(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list EC2 launch templates in region %s: %s", region, err.Error()))
				break
			}

			for _, lt := range listOutput.LaunchTemplates {
				if lt.LaunchTemplateId == nil {
					continue
				}

				// Construct the launch template ARN
				ltArn := fmt.Sprintf("arn:aws:ec2:%s:%s:launch-template/%s",
					region, accountID, *lt.LaunchTemplateId)

				// Get the default version's LaunchTemplateData
				versionsInput := &ec2.DescribeLaunchTemplateVersionsInput{
					LaunchTemplateId: lt.LaunchTemplateId,
					Versions:         []string{"$Default"},
				}

				versionsOutput, err := ec2Client.DescribeLaunchTemplateVersions(context.TODO(), versionsInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to get default version for launch template %s: %s", *lt.LaunchTemplateId, err.Error()))
					continue
				}

				// Build LaunchTemplateData map from the default version
				var launchTemplateDataMap map[string]any
				if len(versionsOutput.LaunchTemplateVersions) > 0 {
					ltVersion := versionsOutput.LaunchTemplateVersions[0]
					if ltVersion.LaunchTemplateData != nil {
						// Marshal and unmarshal to get a generic map
						ltdJSON, err := json.Marshal(ltVersion.LaunchTemplateData)
						if err != nil {
							a.Logger.Debug(fmt.Sprintf("Failed to marshal LaunchTemplateData for %s: %s", *lt.LaunchTemplateId, err.Error()))
						} else {
							if err := json.Unmarshal(ltdJSON, &launchTemplateDataMap); err != nil {
								a.Logger.Debug(fmt.Sprintf("Failed to unmarshal LaunchTemplateData for %s: %s", *lt.LaunchTemplateId, err.Error()))
							}
						}

						// Resolve IamInstanceProfile to actual IAM role ARN
						if ltVersion.LaunchTemplateData.IamInstanceProfile != nil {
							iamProfile := ltVersion.LaunchTemplateData.IamInstanceProfile
							var instanceProfileName string

							if iamProfile.Arn != nil {
								// Parse instance profile name from ARN
								// Format: arn:aws:iam::ACCOUNT:instance-profile/PROFILE_NAME
								parsedArn, err := arn.Parse(*iamProfile.Arn)
								if err == nil {
									resource := parsedArn.Resource
									if strings.Contains(resource, "/") {
										parts := strings.Split(resource, "/")
										instanceProfileName = parts[len(parts)-1]
									}
								}
							} else if iamProfile.Name != nil {
								instanceProfileName = *iamProfile.Name
							}

							if instanceProfileName != "" {
								getProfileInput := &awsiam.GetInstanceProfileInput{
									InstanceProfileName: &instanceProfileName,
								}

								profileOutput, err := iamClient.GetInstanceProfile(context.TODO(), getProfileInput)
								if err != nil {
									a.Logger.Debug(fmt.Sprintf("Failed to get instance profile %s: %s", instanceProfileName, err.Error()))
								} else if profileOutput.InstanceProfile != nil && len(profileOutput.InstanceProfile.Roles) > 0 {
									roleArn := profileOutput.InstanceProfile.Roles[0].Arn
									if roleArn != nil {
										// Add ResolvedRoleArn to the IamInstanceProfile map
										if launchTemplateDataMap != nil {
											if iamProfileMap, ok := launchTemplateDataMap["IamInstanceProfile"].(map[string]any); ok {
												iamProfileMap["ResolvedRoleArn"] = *roleArn
											}
										}
									}
								}
							}
						}
					}
				}

				// Build properties map
				properties := map[string]any{
					"LaunchTemplateId": *lt.LaunchTemplateId,
				}

				if lt.LaunchTemplateName != nil {
					properties["LaunchTemplateName"] = *lt.LaunchTemplateName
				}

				if lt.DefaultVersionNumber != nil {
					properties["DefaultVersionNumber"] = *lt.DefaultVersionNumber
				}

				if launchTemplateDataMap != nil {
					properties["LaunchTemplateData"] = launchTemplateDataMap
				}

				// Convert properties to JSON string (to match CloudControl format)
				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal launch template properties: %s", err.Error()))
					continue
				}

				// Create EnrichedResourceDescription
				erd := types.NewEnrichedResourceDescription(
					ltArn, // Use ARN as identifier
					"AWS::EC2::LaunchTemplate",
					region,
					accountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalTemplates++
			}

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}
	}

	if totalTemplates > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d EC2 launch templates", totalTemplates))
	}

	return nil
}

// gatherAppRunnerServices fetches App Runner services from all regions.
// CloudControl doesn't return InstanceRoleArn, so we use the AppRunner API directly.
func (a *AwsApolloControlFlow) gatherAppRunnerServices() error {
	var totalServices int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := apprunner.NewFromConfig(config)

		var nextToken *string

		for {
			listInput := &apprunner.ListServicesInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListServices(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list App Runner services in region %s: %s", region, err.Error()))
				break
			}

			for _, summary := range listOutput.ServiceSummaryList {
				if summary.ServiceArn == nil {
					continue
				}

				// Parse the ARN to get account ID
				parsedArn, err := arn.Parse(*summary.ServiceArn)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to parse App Runner service ARN %s: %s", *summary.ServiceArn, err.Error()))
					continue
				}

				// Get full service details for InstanceConfiguration.InstanceRoleArn
				describeInput := &apprunner.DescribeServiceInput{
					ServiceArn: summary.ServiceArn,
				}

				describeOutput, err := client.DescribeService(context.TODO(), describeInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to describe App Runner service %s: %s", *summary.ServiceArn, err.Error()))
					continue
				}

				if describeOutput.Service == nil {
					continue
				}

				svc := describeOutput.Service

				// Build properties map
				properties := map[string]any{
					"ServiceArn": *summary.ServiceArn,
				}

				if svc.ServiceName != nil {
					properties["ServiceName"] = *svc.ServiceName
				}
				if svc.ServiceId != nil {
					properties["ServiceId"] = *svc.ServiceId
				}
				if svc.Status != "" {
					properties["Status"] = string(svc.Status)
				}

				if svc.InstanceConfiguration != nil {
					instanceConfig := map[string]any{}
					if svc.InstanceConfiguration.InstanceRoleArn != nil {
						instanceConfig["InstanceRoleArn"] = *svc.InstanceConfiguration.InstanceRoleArn
					}
					if svc.InstanceConfiguration.Cpu != nil {
						instanceConfig["Cpu"] = *svc.InstanceConfiguration.Cpu
					}
					if svc.InstanceConfiguration.Memory != nil {
						instanceConfig["Memory"] = *svc.InstanceConfiguration.Memory
					}
					properties["InstanceConfiguration"] = instanceConfig
				}

				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal App Runner service properties: %s", err.Error()))
					continue
				}

				erd := types.NewEnrichedResourceDescription(
					*summary.ServiceArn,
					"AWS::AppRunner::Service",
					region,
					parsedArn.AccountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalServices++
			}

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}
	}

	if totalServices > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d App Runner services", totalServices))
	}

	return nil
}

// gatherECSClusters fetches ECS clusters from all regions.
// Clusters are infrastructure targets for CreateService/RunTask/StartTask privesc methods.
func (a *AwsApolloControlFlow) gatherECSClusters() error {
	var totalClusters int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := ecs.NewFromConfig(config)

		// List all cluster ARNs with pagination
		var clusterArns []string
		var nextToken *string

		for {
			listInput := &ecs.ListClustersInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListClusters(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list ECS clusters in region %s: %s", region, err.Error()))
				break
			}

			clusterArns = append(clusterArns, listOutput.ClusterArns...)

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}

		if len(clusterArns) == 0 {
			continue
		}

		// DescribeClusters accepts up to 100 ARNs per call
		for i := 0; i < len(clusterArns); i += 100 {
			end := i + 100
			if end > len(clusterArns) {
				end = len(clusterArns)
			}
			batch := clusterArns[i:end]

			describeInput := &ecs.DescribeClustersInput{
				Clusters: batch,
			}

			describeOutput, err := client.DescribeClusters(context.TODO(), describeInput)
			if err != nil {
				a.Logger.Error(fmt.Sprintf("Failed to describe ECS clusters in region %s: %s", region, err.Error()))
				continue
			}

			for _, cluster := range describeOutput.Clusters {
				if cluster.ClusterArn == nil || cluster.ClusterName == nil {
					continue
				}

				parsedArn, err := arn.Parse(*cluster.ClusterArn)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to parse ECS cluster ARN %s: %s", *cluster.ClusterArn, err.Error()))
					continue
				}

				properties := map[string]any{
					"ClusterName": *cluster.ClusterName,
					"Arn":         *cluster.ClusterArn,
				}

				if cluster.Status != nil {
					properties["Status"] = *cluster.Status
				}

				if cluster.RegisteredContainerInstancesCount > 0 {
					properties["RegisteredContainerInstancesCount"] = cluster.RegisteredContainerInstancesCount
				}
				if cluster.RunningTasksCount > 0 {
					properties["RunningTasksCount"] = cluster.RunningTasksCount
				}
				if cluster.ActiveServicesCount > 0 {
					properties["ActiveServicesCount"] = cluster.ActiveServicesCount
				}

				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal ECS cluster properties: %s", err.Error()))
					continue
				}

				erd := types.NewEnrichedResourceDescription(
					*cluster.ClusterArn,
					"AWS::ECS::Cluster",
					region,
					parsedArn.AccountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalClusters++
			}
		}
	}

	if totalClusters > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d ECS clusters", totalClusters))
	}

	return nil
}

// gatherECSContainerInstances fetches ECS container instances from all clusters.
// Container instances are required for ecs:StartTask (Method 50) — StartTask only works
// on clusters with EC2 container instances, not Fargate.
func (a *AwsApolloControlFlow) gatherECSContainerInstances() error {
	var totalInstances int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		client := ecs.NewFromConfig(config)

		// Find clusters we already collected for this region
		for _, resource := range *a.pd.Resources {
			if resource.TypeName != "AWS::ECS::Cluster" || resource.Region != region {
				continue
			}

			clusterArn := resource.Arn.String()

			// List container instances in this cluster
			var instanceArns []string
			var nextToken *string

			for {
				listInput := &ecs.ListContainerInstancesInput{
					Cluster:   &clusterArn,
					NextToken: nextToken,
				}

				listOutput, err := client.ListContainerInstances(context.TODO(), listInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to list container instances for cluster %s: %s", clusterArn, err.Error()))
					break
				}

				instanceArns = append(instanceArns, listOutput.ContainerInstanceArns...)

				if listOutput.NextToken == nil {
					break
				}
				nextToken = listOutput.NextToken
			}

			if len(instanceArns) == 0 {
				continue
			}

			// DescribeContainerInstances accepts up to 100 ARNs per call
			for i := 0; i < len(instanceArns); i += 100 {
				end := i + 100
				if end > len(instanceArns) {
					end = len(instanceArns)
				}
				batch := instanceArns[i:end]

				describeInput := &ecs.DescribeContainerInstancesInput{
					Cluster:            &clusterArn,
					ContainerInstances: batch,
				}

				describeOutput, err := client.DescribeContainerInstances(context.TODO(), describeInput)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to describe container instances in cluster %s: %s", clusterArn, err.Error()))
					continue
				}

				for _, ci := range describeOutput.ContainerInstances {
					if ci.ContainerInstanceArn == nil {
						continue
					}

					parsedArn, err := arn.Parse(*ci.ContainerInstanceArn)
					if err != nil {
						a.Logger.Error(fmt.Sprintf("Failed to parse container instance ARN %s: %s", *ci.ContainerInstanceArn, err.Error()))
						continue
					}

					properties := map[string]any{
						"Arn":        *ci.ContainerInstanceArn,
						"ClusterArn": clusterArn,
					}

					if ci.Status != nil {
						properties["Status"] = *ci.Status
					}
					if ci.Ec2InstanceId != nil {
						properties["Ec2InstanceId"] = *ci.Ec2InstanceId
					}
					if ci.RunningTasksCount > 0 {
						properties["RunningTasksCount"] = ci.RunningTasksCount
					}

					propsJSON, err := json.Marshal(properties)
					if err != nil {
						a.Logger.Error(fmt.Sprintf("Failed to marshal container instance properties: %s", err.Error()))
						continue
					}

					erd := types.NewEnrichedResourceDescription(
						*ci.ContainerInstanceArn,
						"AWS::ECS::ContainerInstance",
						region,
						parsedArn.AccountID,
						string(propsJSON),
					)

					*a.pd.Resources = append(*a.pd.Resources, erd)
					totalInstances++
				}
			}
		}
	}

	if totalInstances > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d ECS container instances", totalInstances))
	}

	return nil
}

// gatherGlueJobs fetches Glue jobs from all regions.
// Glue jobs are not supported by CloudControl, so we use the Glue API directly.
func (a *AwsApolloControlFlow) gatherGlueJobs() error {
	var totalJobs int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		accountID, err := helpers.GetAccountId(config)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get account ID for region %s: %s", region, err.Error()))
			continue
		}

		client := glue.NewFromConfig(config)

		var nextToken *string

		for {
			input := &glue.GetJobsInput{
				NextToken: nextToken,
			}

			output, err := client.GetJobs(context.TODO(), input)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list Glue jobs in region %s: %s", region, err.Error()))
				break
			}

			for _, job := range output.Jobs {
				if job.Name == nil {
					continue
				}

				jobArn := fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, *job.Name)

				properties := map[string]any{
					"Name": *job.Name,
					"Arn":  jobArn,
				}

				if job.Role != nil {
					properties["Role"] = *job.Role
				}

				if job.Description != nil {
					properties["Description"] = *job.Description
				}

				if job.GlueVersion != nil {
					properties["GlueVersion"] = *job.GlueVersion
				}

				if job.WorkerType != "" {
					properties["WorkerType"] = string(job.WorkerType)
				}

				if job.NumberOfWorkers != nil {
					properties["NumberOfWorkers"] = *job.NumberOfWorkers
				}

				if job.MaxCapacity != nil {
					properties["MaxCapacity"] = *job.MaxCapacity
				}

				if job.Command != nil {
					cmdProps := map[string]any{}
					if job.Command.Name != nil {
						cmdProps["Name"] = *job.Command.Name
					}
					if job.Command.ScriptLocation != nil {
						cmdProps["ScriptLocation"] = *job.Command.ScriptLocation
					}
					if job.Command.PythonVersion != nil {
						cmdProps["PythonVersion"] = *job.Command.PythonVersion
					}
					properties["Command"] = cmdProps
				}

				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal Glue job properties: %s", err.Error()))
					continue
				}

				erd := types.NewEnrichedResourceDescription(
					jobArn,
					"AWS::Glue::Job",
					region,
					accountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalJobs++
			}

			if output.NextToken == nil {
				break
			}
			nextToken = output.NextToken
		}
	}

	if totalJobs > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d Glue jobs", totalJobs))
	}

	return nil
}

// gatherCloudFormationStackSets fetches CloudFormation StackSets from all regions.
// StackSets are not supported by CloudControl, so we use the CloudFormation API directly.
// We need AdministrationRoleARN and ExecutionRoleName from DescribeStackSet.
func (a *AwsApolloControlFlow) gatherCloudFormationStackSets() error {
	var totalStackSets int

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get AWS config for region %s: %s", region, err.Error()))
			continue
		}

		accountID, err := helpers.GetAccountId(config)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to get account ID for region %s: %s", region, err.Error()))
			continue
		}

		client := cloudformation.NewFromConfig(config)

		var nextToken *string

		for {
			listInput := &cloudformation.ListStackSetsInput{
				NextToken: nextToken,
			}

			listOutput, err := client.ListStackSets(context.TODO(), listInput)
			if err != nil {
				a.Logger.Debug(fmt.Sprintf("Failed to list CloudFormation StackSets in region %s: %s", region, err.Error()))
				break
			}

			for _, summary := range listOutput.Summaries {
				if summary.StackSetName == nil || summary.StackSetId == nil {
					continue
				}

				// Get full details for AdministrationRoleARN and ExecutionRoleName
				describeInput := &cloudformation.DescribeStackSetInput{
					StackSetName: summary.StackSetName,
				}

				describeOutput, err := client.DescribeStackSet(context.TODO(), describeInput)
				if err != nil {
					a.Logger.Debug(fmt.Sprintf("Failed to describe StackSet %s in region %s: %s", *summary.StackSetName, region, err.Error()))
					continue
				}

				if describeOutput.StackSet == nil {
					continue
				}

				stackSet := describeOutput.StackSet

				stackSetArn := fmt.Sprintf("arn:aws:cloudformation:%s:%s:stackset/%s:%s",
					region, accountID, *summary.StackSetName, *summary.StackSetId)

				properties := map[string]any{
					"StackSetName": *summary.StackSetName,
					"StackSetId":   *summary.StackSetId,
					"Arn":          stackSetArn,
				}

				if summary.Status != "" {
					properties["Status"] = string(summary.Status)
				}

				if summary.Description != nil {
					properties["Description"] = *summary.Description
				}

				if summary.PermissionModel != "" {
					properties["PermissionModel"] = string(summary.PermissionModel)
				}

				if stackSet.AdministrationRoleARN != nil {
					properties["AdministrationRoleARN"] = *stackSet.AdministrationRoleARN
				}

				if stackSet.ExecutionRoleName != nil {
					properties["ExecutionRoleName"] = *stackSet.ExecutionRoleName
				}

				propsJSON, err := json.Marshal(properties)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Failed to marshal StackSet properties: %s", err.Error()))
					continue
				}

				erd := types.NewEnrichedResourceDescription(
					stackSetArn,
					"AWS::CloudFormation::StackSet",
					region,
					accountID,
					string(propsJSON),
				)

				*a.pd.Resources = append(*a.pd.Resources, erd)
				totalStackSets++
			}

			if listOutput.NextToken == nil {
				break
			}
			nextToken = listOutput.NextToken
		}
	}

	if totalStackSets > 0 {
		a.Logger.Info(fmt.Sprintf("Gathered %d CloudFormation StackSets", totalStackSets))
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

	// Create BELONGS_TO relationships for container instances → clusters
	for _, resource := range *a.pd.Resources {
		if resource.TypeName != "AWS::ECS::ContainerInstance" {
			continue
		}

		props, err := resource.PropertiesAsMap()
		if err != nil {
			continue
		}

		clusterArn, ok := props["ClusterArn"].(string)
		if !ok || clusterArn == "" {
			continue
		}

		// Create the container instance node
		ciNode, err := TransformERDToAWSResource(&resource)
		if err != nil {
			a.Logger.Error(fmt.Sprintf("Failed to transform container instance %s: %s", resource.Arn.String(), err.Error()))
			continue
		}

		// Create the cluster node reference
		clusterParsedArn, err := arn.Parse(clusterArn)
		if err != nil {
			continue
		}
		clusterNode, err := model.NewAWSResource(
			clusterArn,
			clusterParsedArn.AccountID,
			model.CloudResourceType("AWS::ECS::Cluster"),
			map[string]any{},
		)
		if err != nil {
			continue
		}

		// Create BELONGS_TO relationship
		belongsToRel := model.NewIAMRelationship(ciNode, &clusterNode, "BELONGS_TO")
		belongsToRel.Capability = "apollo-container-instance-cluster-mapping"
		a.Send(belongsToRel)
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
