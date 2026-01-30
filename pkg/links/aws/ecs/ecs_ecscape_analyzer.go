package ecs

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type EcsEcscapeAnalyzer struct {
	*base.AwsReconLink
}

func NewEcsEcscapeAnalyzer(configs ...cfg.Config) chain.Link {
	link := &EcsEcscapeAnalyzer{}
	link.AwsReconLink = base.NewAwsReconLink(link, configs...)
	link.Base.SetName("ECS ECScape Vulnerability Analyzer")
	return link
}

func (l *EcsEcscapeAnalyzer) Process(input any) error {
	ctx := context.Background()

	for _, region := range l.Regions {
		l.Logger.Info("analyzing ECS clusters for ECScape vulnerability", "region", region)

		awsConfig, err := l.GetConfigWithRuntimeArgs(region)
		if err != nil {
			l.Logger.Error("failed to get AWS config", "region", region, "error", err)
			continue
		}

		ecsClient := ecs.NewFromConfig(awsConfig)

		clusters, err := l.listClusters(ctx, ecsClient)
		if err != nil {
			l.Logger.Error("failed to list clusters", "region", region, "error", err)
			continue
		}

		for _, clusterArn := range clusters {
			l.Logger.Debug("analyzing cluster", "cluster", clusterArn, "region", region)

			finding, err := l.analyzeCluster(ctx, ecsClient, clusterArn, region)
			if err != nil {
				l.Logger.Error("failed to analyze cluster", "cluster", clusterArn, "error", err)
				continue
			}

			if err := l.Send(finding); err != nil {
				l.Logger.Error("failed to send finding", "cluster", clusterArn, "error", err)
			}
		}
	}

	return nil
}

func (l *EcsEcscapeAnalyzer) listClusters(ctx context.Context, client *ecs.Client) ([]string, error) {
	var allClusters []string
	var nextToken *string

	for {
		output, err := client.ListClusters(ctx, &ecs.ListClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list clusters: %w", err)
		}

		allClusters = append(allClusters, output.ClusterArns...)

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allClusters, nil
}

func (l *EcsEcscapeAnalyzer) analyzeCluster(ctx context.Context, client *ecs.Client, clusterArn, region string) (types.EnrichedResourceDescription, error) {
	describeOutput, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: []string{clusterArn},
		Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldConfigurations, ecstypes.ClusterFieldSettings},
	})
	if err != nil {
		return types.EnrichedResourceDescription{}, fmt.Errorf("failed to describe cluster: %w", err)
	}

	if len(describeOutput.Clusters) == 0 {
		return types.EnrichedResourceDescription{}, fmt.Errorf("cluster not found: %s", clusterArn)
	}

	cluster := describeOutput.Clusters[0]

	services, err := l.listServices(ctx, client, clusterArn)
	if err != nil {
		l.Logger.Warn("failed to list services", "cluster", clusterArn, "error", err)
		services = []string{}
	}

	serviceDetails := []map[string]any{}
	taskDefinitions := make(map[string]bool)

	if len(services) > 0 {
		describeServicesOutput, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{
			Cluster:  &clusterArn,
			Services: services,
		})
		if err != nil {
			l.Logger.Warn("failed to describe services", "cluster", clusterArn, "error", err)
		} else {
			for _, svc := range describeServicesOutput.Services {
				serviceDetail := map[string]any{
					"serviceName":    *svc.ServiceName,
					"serviceArn":     *svc.ServiceArn,
					"launchType":     string(svc.LaunchType),
					"taskDefinition": *svc.TaskDefinition,
					"desiredCount":   svc.DesiredCount,
					"runningCount":   svc.RunningCount,
				}
				serviceDetails = append(serviceDetails, serviceDetail)
				taskDefinitions[*svc.TaskDefinition] = true
			}
		}
	}

	taskDefDetails := []map[string]any{}
	for taskDefArn := range taskDefinitions {
		taskDef, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: &taskDefArn,
		})
		if err != nil {
			l.Logger.Warn("failed to describe task definition", "taskDef", taskDefArn, "error", err)
			continue
		}

		td := taskDef.TaskDefinition
		taskDefDetail := map[string]any{
			"taskDefinitionArn": *td.TaskDefinitionArn,
			"family":            *td.Family,
			"networkMode":       string(td.NetworkMode),
		}

		if td.TaskRoleArn != nil {
			taskDefDetail["taskRoleArn"] = *td.TaskRoleArn
		}
		if td.ExecutionRoleArn != nil {
			taskDefDetail["executionRoleArn"] = *td.ExecutionRoleArn
		}

		hasSecrets := false
		for _, containerDef := range td.ContainerDefinitions {
			if len(containerDef.Secrets) > 0 {
				hasSecrets = true
				break
			}
		}
		taskDefDetail["hasSecrets"] = hasSecrets

		taskDefDetails = append(taskDefDetails, taskDefDetail)
	}

	vulnerability := l.assessVulnerability(cluster, serviceDetails, taskDefDetails)

	properties := map[string]any{
		"clusterName":                     *cluster.ClusterName,
		"clusterArn":                      *cluster.ClusterArn,
		"region":                          region,
		"status":                          aws.ToString(cluster.Status),
		"registeredContainerInstances":    cluster.RegisteredContainerInstancesCount,
		"runningTasksCount":               cluster.RunningTasksCount,
		"activeServicesCount":             cluster.ActiveServicesCount,
		"capacityProviders":               cluster.CapacityProviders,
		"defaultCapacityProviderStrategy": cluster.DefaultCapacityProviderStrategy,
		"services":                        serviceDetails,
		"taskDefinitions":                 taskDefDetails,
		"vulnerability":                   vulnerability,
		"reference":                       "https://github.com/naorhaziz/ecscape",
	}

	accountId := l.extractAccountId(*cluster.ClusterArn)

	erd := types.NewEnrichedResourceDescription(
		*cluster.ClusterName,
		"AWS::ECS::Cluster",
		region,
		accountId,
		properties,
	)

	return erd, nil
}

func (l *EcsEcscapeAnalyzer) listServices(ctx context.Context, client *ecs.Client, clusterArn string) ([]string, error) {
	var allServices []string
	var nextToken *string

	for {
		output, err := client.ListServices(ctx, &ecs.ListServicesInput{
			Cluster:   &clusterArn,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list services: %w", err)
		}

		allServices = append(allServices, output.ServiceArns...)

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return allServices, nil
}

func (l *EcsEcscapeAnalyzer) extractAccountId(arn string) string {
	parts := []rune(arn)
	arnParts := []string{}
	current := ""
	for _, ch := range parts {
		if ch == ':' || ch == '/' {
			if current != "" {
				arnParts = append(arnParts, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		arnParts = append(arnParts, current)
	}
	if len(arnParts) >= 5 {
		return arnParts[4]
	}
	return ""
}

func (l *EcsEcscapeAnalyzer) assessVulnerability(cluster ecstypes.Cluster, services []map[string]any, taskDefDetails []map[string]any) map[string]any {
	usesEC2 := cluster.RegisteredContainerInstancesCount > 0

	usesFargateOnly := true
	if len(cluster.CapacityProviders) > 0 {
		for _, cp := range cluster.CapacityProviders {
			if cp != "FARGATE" && cp != "FARGATE_SPOT" {
				usesFargateOnly = false
				break
			}
		}
	} else {
		usesFargateOnly = false
	}

	hasEC2Services := false
	for _, svc := range services {
		if launchType, ok := svc["launchType"].(string); ok {
			if launchType == "EC2" || launchType == "" {
				hasEC2Services = true
				break
			}
		}
	}

	isVulnerable := false
	riskLevel := "LOW"
	vulnerabilityReason := ""
	recommendation := ""

	if usesFargateOnly && !usesEC2 && !hasEC2Services {
		vulnerabilityReason = "Cluster uses only Fargate launch type - not vulnerable to ECScape"
		recommendation = "No action required. Fargate provides task-level isolation."
	} else if usesEC2 || hasEC2Services {
		isVulnerable = true
		multipleServices := len(services) > 1

		if multipleServices {
			riskLevel = "HIGH"
			vulnerabilityReason = fmt.Sprintf("Cluster uses EC2 launch type with %d services that could co-locate on shared container instances, enabling credential theft via ECScape", len(services))
			recommendation = "CRITICAL: Migrate to Fargate for task isolation, or implement strict IAM policies with conditions on task role ARNs. See https://github.com/naorhaziz/ecscape"
		} else {
			riskLevel = "MEDIUM"
			vulnerabilityReason = "Cluster uses EC2 launch type with single service - potential risk if multiple tasks run on same instance"
			recommendation = "Consider migrating to Fargate for task isolation. See https://github.com/naorhaziz/ecscape"
		}
	} else {
		vulnerabilityReason = "Unable to determine launch type configuration"
		recommendation = "Review cluster and service configurations manually"
	}

	return map[string]any{
		"isVulnerable":           isVulnerable,
		"riskLevel":              riskLevel,
		"vulnerabilityReason":    vulnerabilityReason,
		"recommendation":         recommendation,
		"usesEC2":                usesEC2 || hasEC2Services,
		"usesFargateOnly":        usesFargateOnly,
		"serviceCount":           len(services),
		"containerInstanceCount": cluster.RegisteredContainerInstancesCount,
	}
}
