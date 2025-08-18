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

type SecurityGroupLinks struct {
	*base.AwsReconBaseLink
	regions           []string
	processedSGs      map[string]bool
	prefixListDetails map[string]map[string]interface{}
	mu                sync.RWMutex
}

func NewSecurityGroupLinks(configs ...cfg.Config) chain.Link {
	link := &SecurityGroupLinks{
		processedSGs:      make(map[string]bool),
		prefixListDetails: make(map[string]map[string]interface{}),
	}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS Security Group Links")
	return link
}

func (l *SecurityGroupLinks) Params() []cfg.Param {
	return append(l.AwsReconBaseLink.Params(),
		options.AwsRegions(),
		options.AwsSecurityGroupIds())
}

func (l *SecurityGroupLinks) Initialize() error {
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

func (l *SecurityGroupLinks) Process(input any) error {
	// Debug: Log when Process is called and with what input
	l.Logger.Info("SecurityGroupLinks Process method called",
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

	l.Logger.Info("SecurityGroupLinks sending results",
		"results_count", len(allResults),
		"timestamp", time.Now().UnixNano())

	return l.Send(result)
}

func (l *SecurityGroupLinks) processSingleSecurityGroup(ctx context.Context, sgId string, resultsChan chan<- map[string]interface{}) {
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

func (l *SecurityGroupLinks) searchInRegion(ctx context.Context, sgId, region string, resultsChan chan<- map[string]interface{}) {
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

func (l *SecurityGroupLinks) analyzeSecurityGroup(ctx context.Context, awsConfig aws.Config, sgId string, region string) (map[string]interface{}, error) {
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

	// Get prefix list details for all prefix lists referenced in security group rules
	l.populatePrefixListDetails(ctx, ec2Client, sgRes.sgDetails)

	// Extract security group rules
	securityGroupRules := l.extractSecurityGroupRules(sgRes.sgDetails)

	return map[string]interface{}{
		"security_group_id":          sgId,
		"security_group_name":        sgRes.sgDetails.GroupName,
		"security_group_description": sgRes.sgDetails.Description,
		"region":                     region,
		"vpc_id":                     sgRes.sgDetails.VpcId,
		"vpc_info":                   vpcInfo,
		"network_interfaces":         analyzedEnis,
		"total_enis":                 len(eniRes.enis),
		"security_group_rules":       securityGroupRules,
	}, nil
}

// extractSecurityGroupRules extracts and formats the ingress and egress rules from a security group
func (l *SecurityGroupLinks) extractSecurityGroupRules(sg *types.SecurityGroup) map[string]interface{} {
	rules := map[string]interface{}{
		"ingress_rules": []map[string]interface{}{},
		"egress_rules":  []map[string]interface{}{},
	}

	// Process ingress rules
	if sg.IpPermissions != nil {
		for _, permission := range sg.IpPermissions {
			rule := l.extractPermissionRule(permission)
			rules["ingress_rules"] = append(rules["ingress_rules"].([]map[string]interface{}), rule)
		}
	}

	// Process egress rules
	if sg.IpPermissionsEgress != nil {
		for _, permission := range sg.IpPermissionsEgress {
			rule := l.extractPermissionRule(permission)
			rules["egress_rules"] = append(rules["egress_rules"].([]map[string]interface{}), rule)
		}
	}

	return rules
}

// extractPermissionRule extracts and formats a single permission rule with all reference types
func (l *SecurityGroupLinks) extractPermissionRule(permission types.IpPermission) map[string]interface{} {
	rule := map[string]interface{}{
		"protocol":  l.derefString(permission.IpProtocol),
		"from_port": l.derefInt32(permission.FromPort),
		"to_port":   l.derefInt32(permission.ToPort),
	}

	// Extract IP ranges
	if permission.IpRanges != nil {
		var ipRanges []string
		var descriptions []string

		for _, ipRange := range permission.IpRanges {
			if ipRange.CidrIp != nil {
				ipRanges = append(ipRanges, *ipRange.CidrIp)
			}
			// Extract description if available
			if ipRange.Description != nil {
				descriptions = append(descriptions, *ipRange.Description)
			}
		}

		// Only add fields if they have data
		if len(ipRanges) > 0 {
			rule["ip_ranges"] = ipRanges
		}
		if len(descriptions) > 0 {
			rule["ip_range_descriptions"] = descriptions
		}
	}

	// Extract IPv6 ranges
	if permission.Ipv6Ranges != nil {
		var ipv6Ranges []string
		var descriptions []string

		for _, ipv6Range := range permission.Ipv6Ranges {
			if ipv6Range.CidrIpv6 != nil {
				ipv6Ranges = append(ipv6Ranges, *ipv6Range.CidrIpv6)
			}
			// Extract description if available
			if ipv6Range.Description != nil {
				descriptions = append(descriptions, *ipv6Range.Description)
			}
		}

		// Only add fields if they have data
		if len(ipv6Ranges) > 0 {
			rule["ipv6_ranges"] = ipv6Ranges
		}
		if len(descriptions) > 0 {
			rule["ipv6_range_descriptions"] = descriptions
		}
	}

	// Extract user ID group pairs (security group references)
	if permission.UserIdGroupPairs != nil {
		var pairs []map[string]interface{}

		for _, pair := range permission.UserIdGroupPairs {
			groupPair := map[string]interface{}{
				"user_id":     l.derefString(pair.UserId),
				"group_id":    l.derefString(pair.GroupId),
				"group_name":  l.derefString(pair.GroupName),
				"description": l.derefString(pair.Description),
			}
			pairs = append(pairs, groupPair)
		}

		// Only add field if there are pairs
		if len(pairs) > 0 {
			rule["user_id_group_pairs"] = pairs
		}
	}

	// Extract prefix list references
	if permission.PrefixListIds != nil {
		var prefixLists []map[string]interface{}

		for _, prefixListId := range permission.PrefixListIds {
			if prefixListId.PrefixListId != nil {
				prefixList := map[string]interface{}{
					"prefix_list_id": l.derefString(prefixListId.PrefixListId),
					"description":    l.derefString(prefixListId.Description),
				}

				// Get detailed prefix list information if available
				if l.prefixListDetails != nil {
					if details, exists := l.prefixListDetails[*prefixListId.PrefixListId]; exists {
						// Add prefix list name
						if name, hasName := details["Name"]; hasName {
							prefixList["name"] = name
						}

						// Add CIDR entries
						if entries, hasEntries := details["Entries"]; hasEntries {
							prefixList["cidr_entries"] = entries
						}

						// Add entry count
						if entryCount, hasEntryCount := details["EntryCount"]; hasEntryCount {
							prefixList["EntryCount"] = entryCount
						}

						// Add other metadata
						if version, hasVersion := details["Version"]; hasVersion {
							prefixList["version"] = version
						}
						if maxEntries, hasMaxEntries := details["MaxEntries"]; hasMaxEntries {
							prefixList["max_entries"] = maxEntries
						}
						if state, hasState := details["State"]; hasState {
							prefixList["state"] = state
						}
						if addressFamily, hasAddressFamily := details["AddressFamily"]; hasAddressFamily {
							prefixList["address_family"] = addressFamily
						}
						if ownerId, hasOwnerId := details["OwnerId"]; hasOwnerId {
							prefixList["owner_id"] = ownerId
						}
						if tags, hasTags := details["Tags"]; hasTags {
							prefixList["tags"] = tags
						}
					}
				}

				prefixLists = append(prefixLists, prefixList)
			}
		}

		// Only add field if there are prefix lists
		if len(prefixLists) > 0 {
			rule["prefix_lists"] = prefixLists
		}
	}

	// Note: Additional reference types like ReferencedGroupIds may be available
	// in newer AWS SDK versions. This can be extended as needed.

	return rule
}

// populatePrefixListDetails populates the prefixListDetails map with comprehensive information about prefix lists
func (l *SecurityGroupLinks) populatePrefixListDetails(ctx context.Context, client *ec2.Client, sg *types.SecurityGroup) {
	// Collect all prefix list IDs from security group rules
	var allPrefixListIds []string

	// Collect from ingress rules
	if sg.IpPermissions != nil {
		for _, permission := range sg.IpPermissions {
			if permission.PrefixListIds != nil {
				for _, prefixList := range permission.PrefixListIds {
					if prefixList.PrefixListId != nil {
						allPrefixListIds = append(allPrefixListIds, *prefixList.PrefixListId)
					}
				}
			}
		}
	}

	// Collect from egress rules
	if sg.IpPermissionsEgress != nil {
		for _, permission := range sg.IpPermissionsEgress {
			if permission.PrefixListIds != nil {
				for _, prefixList := range permission.PrefixListIds {
					if prefixList.PrefixListId != nil {
						allPrefixListIds = append(allPrefixListIds, *prefixList.PrefixListId)
					}
				}
			}
		}
	}

	if len(allPrefixListIds) == 0 {
		return
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniquePrefixListIds []string
	for _, id := range allPrefixListIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniquePrefixListIds = append(uniquePrefixListIds, id)
		}
	}

	l.Logger.Info("Resolving prefix list details", "count", len(uniquePrefixListIds))

	// AWS API has a limit on the number of IDs per request, so we might need to batch
	const maxIdsPerRequest = 200

	for i := 0; i < len(uniquePrefixListIds); i += maxIdsPerRequest {
		end := i + maxIdsPerRequest
		if end > len(uniquePrefixListIds) {
			end = len(uniquePrefixListIds)
		}

		batch := uniquePrefixListIds[i:end]
		input := &ec2.DescribeManagedPrefixListsInput{
			PrefixListIds: batch,
		}

		output, err := client.DescribeManagedPrefixLists(ctx, input)
		if err != nil {
			l.Logger.Warn("Failed to describe prefix lists", "prefixListIds", batch, "error", err)
			continue
		}

		for _, prefixList := range output.PrefixLists {
			if prefixList.PrefixListId != nil && prefixList.PrefixListName != nil {
				// Store prefix list metadata
				details := map[string]interface{}{
					"Name": *prefixList.PrefixListName,
				}

				if prefixList.PrefixListArn != nil {
					details["PrefixListArn"] = *prefixList.PrefixListArn
				}
				if prefixList.Version != nil {
					details["Version"] = *prefixList.Version
				}
				if prefixList.MaxEntries != nil {
					details["MaxEntries"] = *prefixList.MaxEntries
				}
				details["State"] = prefixList.State
				if prefixList.StateMessage != nil {
					details["StateMessage"] = *prefixList.StateMessage
				}
				if prefixList.AddressFamily != nil {
					details["AddressFamily"] = *prefixList.AddressFamily
				}
				if prefixList.OwnerId != nil {
					details["OwnerId"] = *prefixList.OwnerId
				}
				if len(prefixList.Tags) > 0 {
					tags := make(map[string]string)
					for _, tag := range prefixList.Tags {
						if tag.Key != nil && tag.Value != nil {
							tags[*tag.Key] = *tag.Value
						}
					}
					if len(tags) > 0 {
						details["Tags"] = tags
					}
				}

				l.prefixListDetails[*prefixList.PrefixListId] = details
				l.Logger.Debug("Resolved prefix list metadata", "id", *prefixList.PrefixListId, "name", *prefixList.PrefixListName)
			}
		}
	}

	// Now get the actual entries for each prefix list
	for i := 0; i < len(uniquePrefixListIds); i += maxIdsPerRequest {
		end := i + maxIdsPerRequest
		if end > len(uniquePrefixListIds) {
			end = len(uniquePrefixListIds)
		}

		batch := uniquePrefixListIds[i:end]

		// Process each prefix list individually since GetManagedPrefixListEntries doesn't support batching
		for _, prefixListId := range batch {
			input := &ec2.GetManagedPrefixListEntriesInput{
				PrefixListId: &prefixListId,
			}

			entriesOutput, err := client.GetManagedPrefixListEntries(ctx, input)
			if err != nil {
				l.Logger.Warn("Failed to get prefix list entries", "prefixListId", prefixListId, "error", err)
				continue
			}

			var entries []map[string]interface{}
			for _, entry := range entriesOutput.Entries {
				entryInfo := map[string]interface{}{
					"Cidr": *entry.Cidr,
				}

				// Add description if available
				if entry.Description != nil {
					entryInfo["Description"] = *entry.Description
				}

				entries = append(entries, entryInfo)
			}

			if len(entries) > 0 {
				// Add entries to existing details
				if details, exists := l.prefixListDetails[prefixListId]; exists {
					details["Entries"] = entries
					details["EntryCount"] = len(entries)
				} else {
					// Create new details if none existed
					l.prefixListDetails[prefixListId] = map[string]interface{}{
						"Entries":    entries,
						"EntryCount": len(entries),
					}
				}
				l.Logger.Debug("Retrieved prefix list entries", "id", prefixListId, "entryCount", len(entries))
			}
		}
	}

	l.Logger.Info("Successfully resolved prefix list details",
		"resolvedCount", len(l.prefixListDetails),
		"total", len(uniquePrefixListIds))
}

// derefString safely dereferences a string pointer, returning empty string if nil
func (l *SecurityGroupLinks) derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// derefInt32 safely dereferences an int32 pointer, returning nil if nil
func (l *SecurityGroupLinks) derefInt32(i *int32) interface{} {
	if i == nil {
		return nil
	}
	return *i
}

func (l *SecurityGroupLinks) getSecurityGroupDetails(ctx context.Context, client *ec2.Client, sgId string) (*types.SecurityGroup, error) {
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

func (l *SecurityGroupLinks) getNetworkInterfaces(ctx context.Context, client *ec2.Client, sgId string) ([]types.NetworkInterface, error) {
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

func (l *SecurityGroupLinks) getVpcInfo(ctx context.Context, client *ec2.Client, vpcId *string) (map[string]interface{}, error) {
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

func (l *SecurityGroupLinks) analyzeNetworkInterface(eni types.NetworkInterface) map[string]interface{} {
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

func (l *SecurityGroupLinks) determineAssetType(eni types.NetworkInterface) map[string]interface{} {
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

func (l *SecurityGroupLinks) extractDirectoryId(description string) string {
	// Extract directory ID from description (format: d-xxxxxxxxx)
	dirRegex := regexp.MustCompile(`d-[a-z0-9]+`)
	matches := dirRegex.FindString(description)
	return matches
}
