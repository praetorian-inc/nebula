package aws

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type SecurityGroupAnalysis struct {
	*base.AwsReconBaseLink
	regions      []string
	processedSGs map[string]bool
	mu           sync.RWMutex
}

func NewSecurityGroupAnalysis(configs ...cfg.Config) chain.Link {
	link := &SecurityGroupAnalysis{
		processedSGs: make(map[string]bool),
	}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS Security Group Analysis")
	return link
}

func (l *SecurityGroupAnalysis) Params() []cfg.Param {
	return append(l.AwsReconBaseLink.Params(),
		options.AwsRegions(),
		options.AwsSecurityGroupIds())
}

func (l *SecurityGroupAnalysis) Initialize() error {
	if err := l.AwsReconBaseLink.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize base link: %w", err)
	}

	// Get regions parameter
	regions, err := cfg.As[[]string](l.Arg("regions"))
	if err != nil || len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		// If "all" is specified or no regions provided, get all enabled regions
		l.regions, err = helpers.EnabledRegions(l.Profile, options.JanusArgsAdapter(l.Params(), l.Args()))
		if err != nil {
			return fmt.Errorf("failed to get enabled regions: %w", err)
		}
	} else {
		l.regions = regions
	}

	l.Logger.Info("initialized with regions", "regions", l.regions)
	return nil
}

func (l *SecurityGroupAnalysis) Process(input any) error {
	// Debug: Log when Process is called and with what input
	l.Logger.Info("SecurityGroupAnalysis Process method called",
		"input", input,
		"input_type", fmt.Sprintf("%T", input),
		"timestamp", time.Now().UnixNano())

	// Debug: Log all available arguments
	l.Logger.Info("available arguments", "args", l.Args())

	// Get security group IDs parameter
	sgIds, err := cfg.As[[]string](l.Arg("security-group-ids"))

	l.Logger.Info("security group IDs", "security-group-ids", sgIds)

	if err != nil {
		l.Logger.Error("failed to get security group IDs parameter", "error", err)
		return fmt.Errorf("failed to get security group IDs parameter: %w", err)
	}

	// Deduplicate security group IDs and filter out already processed ones
	uniqueSgIds := make([]string, 0)
	seen := make(map[string]bool)
	for _, sgId := range sgIds {
		if !seen[sgId] && !l.processedSGs[sgId] {
			seen[sgId] = true
			uniqueSgIds = append(uniqueSgIds, sgId)
		}
	}

	if len(uniqueSgIds) != len(sgIds) {
		l.Logger.Info("deduplicated security group IDs", "original_count", len(sgIds), "unique_count", len(uniqueSgIds))
	}

	// If all security groups have already been processed, return empty results
	if len(uniqueSgIds) == 0 {
		l.Logger.Info("all security groups already processed, skipping analysis")
		return l.Send(map[string]interface{}{
			"security_groups_analyzed": 0,
			"regions_searched":         l.regions,
			"results":                  []map[string]interface{}{},
			"message":                  "All security groups have already been processed",
		})
	}

	ctx := context.Background()
	var allResults []map[string]interface{}
	var resultsMu sync.Mutex

	// Create worker pool for processing security groups in parallel
	const maxWorkers = 10
	sgChan := make(chan string, len(uniqueSgIds))
	resultsChan := make(chan map[string]interface{}, len(uniqueSgIds)*len(l.regions))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers && i < len(uniqueSgIds); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sgId := range sgChan {
				l.processSingleSecurityGroup(ctx, sgId, resultsChan)
			}
		}()
	}

	// Send security groups to workers
	for _, sgId := range uniqueSgIds {
		sgChan <- sgId
	}
	close(sgChan)

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect all results
	for result := range resultsChan {
		resultsMu.Lock()
		allResults = append(allResults, result)
		resultsMu.Unlock()
	}

	// Send combined results
	result := map[string]interface{}{
		"security_groups_analyzed": len(uniqueSgIds),
		"regions_searched":         l.regions,
		"results":                  allResults,
	}

	l.Logger.Info("SecurityGroupAnalysis sending results",
		"results_count", len(allResults),
		"timestamp", time.Now().UnixNano())

	return l.Send(result)
}

func (l *SecurityGroupAnalysis) processSingleSecurityGroup(ctx context.Context, sgId string, resultsChan chan<- map[string]interface{}) {
	l.Logger.Info("analyzing security group", "security-group-id", sgId)

	// Check if already processed with read lock
	l.mu.RLock()
	if l.processedSGs[sgId] {
		l.mu.RUnlock()
		return
	}
	l.mu.RUnlock()

	// Use channels and goroutines to search all regions in parallel
	regionChan := make(chan string, len(l.regions))
	regionResultsChan := make(chan map[string]interface{}, len(l.regions))

	// Start workers to search across regions
	const maxRegionWorkers = 5
	var regionWg sync.WaitGroup
	for i := 0; i < maxRegionWorkers && i < len(l.regions); i++ {
		regionWg.Add(1)
		go func() {
			defer regionWg.Done()
			for region := range regionChan {
				l.searchInRegion(ctx, sgId, region, regionResultsChan)
			}
		}()
	}

	// Send regions to workers
	for _, region := range l.regions {
		regionChan <- region
	}
	close(regionChan)

	// Collect results
	go func() {
		regionWg.Wait()
		close(regionResultsChan)
	}()

	// Process results - take the first successful result
	found := false
	for result := range regionResultsChan {
		if result["error"] == nil {
			found = true
			resultsChan <- result
			break
		}
	}

	// Mark as processed and handle not found case
	l.mu.Lock()
	l.processedSGs[sgId] = true
	l.mu.Unlock()

	if !found {
		l.Logger.Warn("security group not found in any region", "security-group-id", sgId)
		resultsChan <- map[string]interface{}{
			"security_group_id": sgId,
			"error":             "Security group not found in any of the specified regions",
			"regions_searched":  l.regions,
		}
	}
}

func (l *SecurityGroupAnalysis) searchInRegion(ctx context.Context, sgId, region string, resultsChan chan<- map[string]interface{}) {
	l.Logger.Debug("searching in region", "region", region, "security-group-id", sgId)

	// Get AWS config for this region
	awsConfig, err := l.GetConfigWithRuntimeArgs(region)
	if err != nil {
		l.Logger.Warn("failed to get AWS config for region", "region", region, "error", err)
		resultsChan <- map[string]interface{}{
			"error":  err,
			"region": region,
			"sg_id":  sgId,
		}
		return
	}

	result, err := l.analyzeSecurityGroup(ctx, awsConfig, sgId, region)
	if err != nil {
		l.Logger.Debug("security group not found in region", "region", region, "security-group-id", sgId, "error", err)
		resultsChan <- map[string]interface{}{
			"error":  err,
			"region": region,
			"sg_id":  sgId,
		}
		return
	}

	// Security group found in this region
	l.Logger.Info("security group found and analyzed", "region", region, "security-group-id", sgId)
	resultsChan <- result
}

func (l *SecurityGroupAnalysis) analyzeSecurityGroup(ctx context.Context, awsConfig aws.Config, sgId string, region string) (map[string]interface{}, error) {
	ec2Client := ec2.NewFromConfig(awsConfig)

	// Run API calls in parallel using goroutines
	type sgResult struct {
		sgDetails *types.SecurityGroup
		err       error
	}
	type eniResult struct {
		enis []types.NetworkInterface
		err  error
	}

	sgChan := make(chan sgResult, 1)
	eniChan := make(chan eniResult, 1)

	// Get security group details in parallel
	go func() {
		sgDetails, err := l.getSecurityGroupDetails(ctx, ec2Client, sgId)
		sgChan <- sgResult{sgDetails, err}
	}()

	// Get network interfaces in parallel
	go func() {
		enis, err := l.getNetworkInterfaces(ctx, ec2Client, sgId)
		eniChan <- eniResult{enis, err}
	}()

	// Collect results
	sgRes := <-sgChan
	eniRes := <-eniChan

	if sgRes.err != nil {
		return nil, fmt.Errorf("failed to get security group details: %w", sgRes.err)
	}
	if eniRes.err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", eniRes.err)
	}

	// Analyze ENIs in parallel
	eniAnalysisChan := make(chan map[string]interface{}, len(eniRes.enis))
	var eniWg sync.WaitGroup

	for _, eni := range eniRes.enis {
		eniWg.Add(1)
		go func(eni types.NetworkInterface) {
			defer eniWg.Done()
			analysis := l.analyzeNetworkInterface(eni)
			eniAnalysisChan <- analysis
		}(eni)
	}

	go func() {
		eniWg.Wait()
		close(eniAnalysisChan)
	}()

	var analyzedEnis []map[string]interface{}
	for analysis := range eniAnalysisChan {
		analyzedEnis = append(analyzedEnis, analysis)
	}

	// Get VPC info (async but not critical for main result)
	vpcInfoChan := make(chan map[string]interface{}, 1)
	go func() {
		vpcInfo, err := l.getVpcInfo(ctx, ec2Client, sgRes.sgDetails.VpcId)
		if err != nil {
			l.Logger.Warn("failed to get VPC info", "vpc-id", sgRes.sgDetails.VpcId, "error", err)
			vpcInfoChan <- nil
		} else {
			vpcInfoChan <- vpcInfo
		}
	}()

	vpcInfo := <-vpcInfoChan

	return map[string]interface{}{
		"security_group_id":          sgId,
		"security_group_name":        sgRes.sgDetails.GroupName,
		"security_group_description": sgRes.sgDetails.Description,
		"region":                     region,
		"vpc_id":                     sgRes.sgDetails.VpcId,
		"vpc_info":                   vpcInfo,
		"network_interfaces":         analyzedEnis,
		"total_enis":                 len(eniRes.enis),
	}, nil
}

func (l *SecurityGroupAnalysis) getSecurityGroupDetails(ctx context.Context, client *ec2.Client, sgId string) (*types.SecurityGroup, error) {
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgId},
	}

	result, err := client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}

	if len(result.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group not found: %s", sgId)
	}

	return &result.SecurityGroups[0], nil
}

func (l *SecurityGroupAnalysis) getNetworkInterfaces(ctx context.Context, client *ec2.Client, sgId string) ([]types.NetworkInterface, error) {
	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgId},
			},
		},
	}

	result, err := client.DescribeNetworkInterfaces(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.NetworkInterfaces, nil
}

func (l *SecurityGroupAnalysis) getVpcInfo(ctx context.Context, client *ec2.Client, vpcId *string) (map[string]interface{}, error) {
	if vpcId == nil {
		return nil, nil
	}

	input := &ec2.DescribeVpcsInput{
		VpcIds: []string{*vpcId},
	}

	result, err := client.DescribeVpcs(ctx, input)
	if err != nil {
		return nil, err
	}

	if len(result.Vpcs) == 0 {
		return nil, fmt.Errorf("VPC not found: %s", *vpcId)
	}

	vpc := result.Vpcs[0]
	return map[string]interface{}{
		"vpc_id":           *vpc.VpcId,
		"cidr_block":       vpc.CidrBlock,
		"state":            vpc.State,
		"is_default":       vpc.IsDefault,
		"instance_tenancy": vpc.InstanceTenancy,
	}, nil
}

func (l *SecurityGroupAnalysis) analyzeNetworkInterface(eni types.NetworkInterface) map[string]interface{} {
	analysis := map[string]interface{}{
		"eni_id":            *eni.NetworkInterfaceId,
		"interface_type":    eni.InterfaceType,
		"description":       eni.Description,
		"subnet_id":         *eni.SubnetId,
		"vpc_id":            *eni.VpcId,
		"availability_zone": eni.AvailabilityZone,
		"private_ip":        eni.PrivateIpAddress,
		"mac_address":       eni.MacAddress,
		"status":            eni.Status,
	}

	// Determine asset type and extract relevant information
	assetInfo := l.determineAssetType(eni)
	analysis["asset_type"] = assetInfo["type"]
	analysis["asset_details"] = assetInfo["details"]

	// Add attachment information if available
	if eni.Attachment != nil {
		analysis["attachment"] = map[string]interface{}{
			"attachment_id": eni.Attachment.AttachmentId,
			"instance_id":   eni.Attachment.InstanceId,
			"device_index":  eni.Attachment.DeviceIndex,
			"status":        eni.Attachment.Status,
		}
	}

	return analysis
}

func (l *SecurityGroupAnalysis) determineAssetType(eni types.NetworkInterface) map[string]interface{} {
	description := ""
	if eni.Description != nil {
		description = *eni.Description
	}

	// Check for Directory Service
	if strings.Contains(strings.ToLower(description), "directory") {
		dirId := l.extractDirectoryId(description)
		return map[string]interface{}{
			"type": "AWS Directory Service",
			"details": map[string]interface{}{
				"directory_id": dirId,
				"description":  description,
			},
		}
	}

	// Check for EC2 Instance
	if eni.Attachment != nil && eni.Attachment.InstanceId != nil {
		return map[string]interface{}{
			"type": "EC2 Instance",
			"details": map[string]interface{}{
				"instance_id": *eni.Attachment.InstanceId,
				"description": description,
			},
		}
	}

	// Check for RDS
	if eni.RequesterId != nil && *eni.RequesterId == "amazon-rds" {
		return map[string]interface{}{
			"type": "RDS Database",
			"details": map[string]interface{}{
				"description": description,
			},
		}
	}

	// Check for Load Balancer
	if eni.RequesterId != nil && *eni.RequesterId == "amazon-elb" {
		return map[string]interface{}{
			"type": "Load Balancer",
			"details": map[string]interface{}{
				"description": description,
			},
		}
	}

	// Check for Lambda
	if eni.RequesterId != nil && *eni.RequesterId == "amazon-lambda" {
		return map[string]interface{}{
			"type": "Lambda Function",
			"details": map[string]interface{}{
				"description": description,
			},
		}
	}

	// Check for ECS
	if eni.RequesterId != nil && *eni.RequesterId == "amazon-ecs" {
		return map[string]interface{}{
			"type": "ECS Task",
			"details": map[string]interface{}{
				"description": description,
			},
		}
	}

	// Check for VPC Endpoint
	if strings.Contains(strings.ToLower(description), "vpc endpoint") {
		return map[string]interface{}{
			"type": "VPC Endpoint",
			"details": map[string]interface{}{
				"description": description,
			},
		}
	}

	// Unknown/Other
	return map[string]interface{}{
		"type": "Unknown/Other",
		"details": map[string]interface{}{
			"description":       description,
			"requester_id":      eni.RequesterId,
			"requester_managed": eni.RequesterManaged,
		},
	}
}

func (l *SecurityGroupAnalysis) extractDirectoryId(description string) string {
	// Extract directory ID from description (format: d-xxxxxxxxx)
	dirRegex := regexp.MustCompile(`d-[a-z0-9]+`)
	matches := dirRegex.FindString(description)
	return matches
}
