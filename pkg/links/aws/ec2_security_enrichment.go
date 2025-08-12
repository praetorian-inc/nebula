package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// EC2SecurityEnrichmentLink enriches EC2 instances with security group and NACL details
type EC2SecurityEnrichmentLink struct {
	*base.AwsReconLink
}

func NewEC2SecurityEnrichmentLink(configs ...cfg.Config) chain.Link {
	e := &EC2SecurityEnrichmentLink{}
	e.AwsReconLink = base.NewAwsReconLink(e, configs...)
	return e
}

func (e *EC2SecurityEnrichmentLink) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::EC2::Instance" {
		// Pass through non-EC2 resources unchanged
		e.Send(resource)
		return nil
	}

	config, err := e.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		// Pass through the resource even if we can't enrich it
		e.Send(resource)
		return nil
	}

	ec2Client := ec2.NewFromConfig(config)

	// Get instance details including network interfaces
	instanceInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{resource.Identifier},
	}

	instanceOutput, err := ec2Client.DescribeInstances(context.TODO(), instanceInput)
	if err != nil {
		slog.Error("Failed to describe EC2 instance", "instance", resource.Identifier, "error", err)
		e.Send(resource)
		return nil
	}

	if len(instanceOutput.Reservations) == 0 || len(instanceOutput.Reservations[0].Instances) == 0 {
		slog.Error("No instance found", "instance", resource.Identifier)
		e.Send(resource)
		return nil
	}

	instance := instanceOutput.Reservations[0].Instances[0]

	// Extract security group IDs
	var securityGroupIds []string
	var networkInterfaceIds []string
	var subnetIds []string

	for _, networkInterface := range instance.NetworkInterfaces {
		networkInterfaceIds = append(networkInterfaceIds, *networkInterface.NetworkInterfaceId)
		if networkInterface.SubnetId != nil {
			subnetIds = append(subnetIds, *networkInterface.SubnetId)
		}
		for _, group := range networkInterface.Groups {
			securityGroupIds = append(securityGroupIds, *group.GroupId)
		}
	}

	// Get security group details
	securityGroups := e.getSecurityGroupDetails(ec2Client, securityGroupIds)

	// Get NACL details for associated subnets
	networkAcls := e.getNetworkAclDetails(ec2Client, subnetIds)

	// Enrich the resource properties
	if resource.Properties == nil {
		resource.Properties = make(map[string]interface{})
	}

	props := resource.Properties.(map[string]interface{})
	props["SecurityGroups"] = securityGroups
	props["NetworkAcls"] = networkAcls
	props["NetworkInterfaceIds"] = networkInterfaceIds
	props["SubnetIds"] = subnetIds

	e.Send(resource)
	return nil
}

func (e *EC2SecurityEnrichmentLink) getSecurityGroupDetails(client *ec2.Client, groupIds []string) []map[string]interface{} {
	if len(groupIds) == 0 {
		return nil
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniqueGroupIds []string
	for _, id := range groupIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniqueGroupIds = append(uniqueGroupIds, id)
		}
	}

	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: uniqueGroupIds,
	}

	output, err := client.DescribeSecurityGroups(context.TODO(), input)
	if err != nil {
		slog.Error("Failed to describe security groups", "groupIds", uniqueGroupIds, "error", err)
		return nil
	}

	var securityGroups []map[string]interface{}
	for _, sg := range output.SecurityGroups {
		sgInfo := map[string]interface{}{
			"GroupId":     *sg.GroupId,
			"GroupName":   *sg.GroupName,
			"VpcId":       *sg.VpcId,
			"Description": *sg.Description,
		}

		// Add ingress rules
		var ingressRules []map[string]interface{}
		for _, rule := range sg.IpPermissions {
			ingressRule := map[string]interface{}{
				"Protocol": rule.IpProtocol,
				"FromPort": rule.FromPort,
				"ToPort":   rule.ToPort,
			}

			// Add source IP ranges
			var sourceRanges []string
			for _, ipRange := range rule.IpRanges {
				if ipRange.Description != nil {
					sourceRanges = append(sourceRanges, fmt.Sprintf("%s (%s)", *ipRange.CidrIp, *ipRange.Description))
				} else {
					sourceRanges = append(sourceRanges, *ipRange.CidrIp)
				}
			}
			ingressRule["SourceRanges"] = sourceRanges

			// Add source security groups
			var sourceGroups []string
			for _, group := range rule.UserIdGroupPairs {
				sourceGroups = append(sourceGroups, *group.GroupId)
			}
			ingressRule["SourceGroups"] = sourceGroups

			ingressRules = append(ingressRules, ingressRule)
		}
		sgInfo["IngressRules"] = ingressRules

		// Add egress rules
		var egressRules []map[string]interface{}
		for _, rule := range sg.IpPermissionsEgress {
			egressRule := map[string]interface{}{
				"Protocol": rule.IpProtocol,
				"FromPort": rule.FromPort,
				"ToPort":   rule.ToPort,
			}

			// Add destination IP ranges
			var destRanges []string
			for _, ipRange := range rule.IpRanges {
				if ipRange.Description != nil {
					destRanges = append(destRanges, fmt.Sprintf("%s (%s)", *ipRange.CidrIp, *ipRange.Description))
				} else {
					destRanges = append(destRanges, *ipRange.CidrIp)
				}
			}
			egressRule["DestinationRanges"] = destRanges

			egressRules = append(egressRules, egressRule)
		}
		sgInfo["EgressRules"] = egressRules

		securityGroups = append(securityGroups, sgInfo)
	}

	return securityGroups
}

func (e *EC2SecurityEnrichmentLink) getNetworkAclDetails(client *ec2.Client, subnetIds []string) []map[string]interface{} {
	if len(subnetIds) == 0 {
		return nil
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniqueSubnetIds []string
	for _, id := range subnetIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniqueSubnetIds = append(uniqueSubnetIds, id)
		}
	}

	// Get subnet details to find associated NACLs
	// Note: We'll get NACL associations directly from the DescribeNetworkAcls API

	// For subnets, we need to use the DescribeNetworkAcls API with subnet filters
	// since subnets don't directly expose their NACL ID
	var naclIds []string
	if len(uniqueSubnetIds) > 0 {
		// Get all NACLs in the VPC and filter by subnet association
		naclInput := &ec2.DescribeNetworkAclsInput{}
		naclOutput, err := client.DescribeNetworkAcls(context.TODO(), naclInput)
		if err != nil {
			slog.Error("Failed to describe network ACLs", "error", err)
			return nil
		}

		// Find NACLs that are associated with our subnets
		for _, nacl := range naclOutput.NetworkAcls {
			for _, association := range nacl.Associations {
				if association.SubnetId != nil {
					for _, subnetId := range uniqueSubnetIds {
						if *association.SubnetId == subnetId {
							naclIds = append(naclIds, *nacl.NetworkAclId)
							break
						}
					}
				}
			}
		}
	}

	if len(naclIds) == 0 {
		return nil
	}

	// Get NACL details
	naclInput := &ec2.DescribeNetworkAclsInput{
		NetworkAclIds: naclIds,
	}

	naclOutput, err := client.DescribeNetworkAcls(context.TODO(), naclInput)
	if err != nil {
		slog.Error("Failed to describe network ACLs", "naclIds", naclIds, "error", err)
		return nil
	}

	var networkAcls []map[string]interface{}
	for _, nacl := range naclOutput.NetworkAcls {
		naclInfo := map[string]interface{}{
			"NetworkAclId": *nacl.NetworkAclId,
			"VpcId":        *nacl.VpcId,
			"IsDefault":    nacl.IsDefault,
		}

		// Add entries (rules)
		var entries []map[string]interface{}
		for _, entry := range nacl.Entries {
			entryInfo := map[string]interface{}{
				"RuleNumber": entry.RuleNumber,
				"Protocol":   entry.Protocol,
				"RuleAction": entry.RuleAction,
				"Egress":     entry.Egress,
			}

			if entry.CidrBlock != nil {
				entryInfo["CidrBlock"] = *entry.CidrBlock
			}
			if entry.IcmpTypeCode != nil {
				entryInfo["IcmpTypeCode"] = map[string]interface{}{
					"Type": entry.IcmpTypeCode.Type,
					"Code": entry.IcmpTypeCode.Code,
				}
			}
			if entry.PortRange != nil {
				entryInfo["PortRange"] = map[string]interface{}{
					"From": entry.PortRange.From,
					"To":   entry.PortRange.To,
				}
			}

			entries = append(entries, entryInfo)
		}
		naclInfo["Entries"] = entries

		networkAcls = append(networkAcls, naclInfo)
	}

	return networkAcls
}
