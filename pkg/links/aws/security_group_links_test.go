package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestExtractSecurityGroupRules(t *testing.T) {
	t.Parallel()
	// Create a test security group with sample rules
	testSG := &types.SecurityGroup{
		GroupId:     aws.String("sg-test123"),
		GroupName:   aws.String("test-sg"),
		Description: aws.String("Test security group"),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("10.0.0.0/8"),
					},
				},
				UserIdGroupPairs: []types.UserIdGroupPair{
					{
						UserId:    aws.String("123456789012"),
						GroupId:   aws.String("sg-allow443"),
						GroupName: aws.String("allow-443"),
					},
				},
			},
		},
		IpPermissionsEgress: []types.IpPermission{
			{
				IpProtocol: aws.String("-1"), // All traffic
				FromPort:   aws.Int32(-1),
				ToPort:     aws.Int32(-1),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
	}

	// Create an instance of SecurityGroupLinks to test the method
	sga := &SecurityGroupLinks{}

	// Extract rules
	rules := sga.extractSecurityGroupRules(testSG)

	// Test ingress rules
	if len(rules["ingress_rules"].([]map[string]interface{})) != 2 {
		t.Errorf("Expected 2 ingress rules, got %d", len(rules["ingress_rules"].([]map[string]interface{})))
	}

	// Test egress rules
	if len(rules["egress_rules"].([]map[string]interface{})) != 1 {
		t.Errorf("Expected 1 egress rule, got %d", len(rules["egress_rules"].([]map[string]interface{})))
	}

	// Test first ingress rule (port 80)
	ingressRules := rules["ingress_rules"].([]map[string]interface{})
	var firstRule map[string]interface{}
	for _, r := range ingressRules {
		if r["from_port"] == int32(80) && r["to_port"] == int32(80) {
			firstRule = r
			break
		}
	}
	if firstRule == nil {
		t.Fatalf("did not find ingress rule for port 80")
	}
	if firstRule["protocol"] != "tcp" {
		t.Errorf("Expected protocol 'tcp', got %v", firstRule["protocol"])
	}
	if firstRule["from_port"] != int32(80) {
		t.Errorf("Expected from_port 80, got %v", firstRule["from_port"])
	}
	if firstRule["to_port"] != int32(80) {
		t.Errorf("Expected to_port 80, got %v", firstRule["to_port"])
	}

	// Test IP ranges in first rule
	ipRanges := firstRule["ip_ranges"].([]string)
	if len(ipRanges) != 1 || ipRanges[0] != "0.0.0.0/0" {
		t.Errorf("Expected IP range '0.0.0.0/0', got %v", ipRanges)
	}

	// Test second ingress rule with security group reference
	var secondRule map[string]interface{}
	for _, r := range ingressRules {
		if r["from_port"] == int32(443) && r["to_port"] == int32(443) {
			secondRule = r
			break
		}
	}
	if secondRule == nil {
		t.Fatalf("did not find ingress rule for port 443")
	}
	userGroupPairs := secondRule["user_id_group_pairs"].([]map[string]interface{})
	if len(userGroupPairs) != 1 {
		t.Errorf("Expected 1 user group pair, got %d", len(userGroupPairs))
	}

	pair := userGroupPairs[0]
	if pair["user_id"] != "123456789012" {
		t.Errorf("Expected user_id '123456789012', got %v", pair["user_id"])
	}
	if pair["group_id"] != "sg-allow443" {
		t.Errorf("Expected group_id 'sg-allow443', got %v", pair["group_id"])
	}
	if pair["group_name"] != "allow-443" {
		t.Errorf("Expected group_name 'allow-443', got %v", pair["group_name"])
	}

	// Test egress rule
	egressRules := rules["egress_rules"].([]map[string]interface{})
	egressRule := egressRules[0]
	if egressRule["protocol"] != "-1" {
		t.Errorf("Expected protocol '-1', got %v", egressRule["protocol"])
	}
	if egressRule["from_port"] != int32(-1) {
		t.Errorf("Expected from_port -1, got %v", egressRule["from_port"])
	}
	if egressRule["to_port"] != int32(-1) {
		t.Errorf("Expected to_port -1, got %v", egressRule["to_port"])
	}
}

func TestExtractSecurityGroupRulesEmpty(t *testing.T) {
	t.Parallel()
	// Test with empty security group
	testSG := &types.SecurityGroup{
		GroupId:     aws.String("sg-empty"),
		GroupName:   aws.String("empty-sg"),
		Description: aws.String("Empty security group"),
	}

	sga := &SecurityGroupLinks{}
	rules := sga.extractSecurityGroupRules(testSG)

	// Should have empty arrays for rules
	if len(rules["ingress_rules"].([]map[string]interface{})) != 0 {
		t.Errorf("Expected 0 ingress rules, got %d", len(rules["ingress_rules"].([]map[string]interface{})))
	}
	if len(rules["egress_rules"].([]map[string]interface{})) != 0 {
		t.Errorf("Expected 0 egress rules, got %d", len(rules["egress_rules"].([]map[string]interface{})))
	}
}

func TestExtractSecurityGroupRulesWithPrefixLists(t *testing.T) {
	t.Parallel()
	// Create a test security group with prefix list references
	testSG := &types.SecurityGroup{
		GroupId:     aws.String("sg-prefix-test"),
		GroupName:   aws.String("prefix-test-sg"),
		Description: aws.String("Test security group with prefix lists"),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				PrefixListIds: []types.PrefixListId{
					{
						PrefixListId: aws.String("pl-12345678"),
						Description:  aws.String("SSH access from corporate network"),
					},
				},
			},
		},
		IpPermissionsEgress: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				PrefixListIds: []types.PrefixListId{
					{
						PrefixListId: aws.String("pl-87654321"),
						Description:  aws.String("HTTPS outbound to internet"),
					},
				},
			},
		},
	}

	sga := &SecurityGroupLinks{}

	// Populate prefix list details for testing
	sga.prefixListDetails = map[string]map[string]interface{}{
		"pl-12345678": {
			"Name":          "corporate-network",
			"Version":       int32(1),
			"MaxEntries":    int32(100),
			"State":         "create-complete",
			"AddressFamily": "IPv4",
			"OwnerId":       "123456789012",
			"Entries": []map[string]interface{}{
				{
					"Cidr":        "10.0.0.0/8",
					"Description": "Corporate HQ network",
				},
				{
					"Cidr":        "172.16.0.0/12",
					"Description": "Branch office network",
				},
			},
			"EntryCount": 2,
		},
		"pl-87654321": {
			"Name":          "internet-access",
			"Version":       int32(1),
			"MaxEntries":    int32(50),
			"State":         "create-complete",
			"AddressFamily": "IPv4",
			"OwnerId":       "123456789012",
			"Entries": []map[string]interface{}{
				{
					"Cidr":        "0.0.0.0/0",
					"Description": "All internet",
				},
			},
			"EntryCount": 1,
		},
	}

	rules := sga.extractSecurityGroupRules(testSG)

	// Test ingress rules with prefix lists
	if len(rules["ingress_rules"].([]map[string]interface{})) != 1 {
		t.Errorf("Expected 1 ingress rule, got %d", len(rules["ingress_rules"].([]map[string]interface{})))
	}

	ingressRule := rules["ingress_rules"].([]map[string]interface{})[0]
	prefixLists := ingressRule["prefix_lists"].([]map[string]interface{})
	if len(prefixLists) != 1 {
		t.Errorf("Expected 1 prefix list in ingress rule, got %d", len(prefixLists))
	}

	prefixList := prefixLists[0]
	if prefixList["prefix_list_id"] != "pl-12345678" {
		t.Errorf("Expected prefix list ID 'pl-12345678', got %v", prefixList["prefix_list_id"])
	}
	if prefixList["description"] != "SSH access from corporate network" {
		t.Errorf("Expected description 'SSH access from corporate network', got %v", prefixList["description"])
	}

	// Test enhanced prefix list details
	if prefixList["name"] != "corporate-network" {
		t.Errorf("Expected prefix list name 'corporate-network', got %v", prefixList["name"])
	}
	if prefixList["version"] != int32(1) {
		t.Errorf("Expected version 1, got %v", prefixList["version"])
	}
	if prefixList["max_entries"] != int32(100) {
		t.Errorf("Expected max_entries 100, got %v", prefixList["max_entries"])
	}
	if prefixList["state"] != "create-complete" {
		t.Errorf("Expected state 'create-complete', got %v", prefixList["state"])
	}
	if prefixList["address_family"] != "IPv4" {
		t.Errorf("Expected address_family 'IPv4', got %v", prefixList["address_family"])
	}
	if prefixList["owner_id"] != "123456789012" {
		t.Errorf("Expected owner_id '123456789012', got %v", prefixList["owner_id"])
	}

	// Test CIDR entries
	cidrEntries := prefixList["cidr_entries"].([]map[string]interface{})
	if len(cidrEntries) != 2 {
		t.Errorf("Expected 2 CIDR entries, got %d", len(cidrEntries))
	}

	// Test first CIDR entry
	firstEntry := cidrEntries[0]
	if firstEntry["Cidr"] != "10.0.0.0/8" {
		t.Errorf("Expected first CIDR '10.0.0.0/8', got %v", firstEntry["Cidr"])
	}
	if firstEntry["Description"] != "Corporate HQ network" {
		t.Errorf("Expected first entry description 'Corporate HQ network', got %v", firstEntry["Description"])
	}

	// Test egress rules with prefix lists
	if len(rules["egress_rules"].([]map[string]interface{})) != 1 {
		t.Errorf("Expected 1 egress rule, got %d", len(rules["egress_rules"].([]map[string]interface{})))
	}

	egressRule := rules["egress_rules"].([]map[string]interface{})[0]
	egressPrefixLists := egressRule["prefix_lists"].([]map[string]interface{})
	if len(egressPrefixLists) != 1 {
		t.Errorf("Expected 1 prefix list in egress rule, got %d", len(egressPrefixLists))
	}

	egressPrefixList := egressPrefixLists[0]
	if egressPrefixList["prefix_list_id"] != "pl-87654321" {
		t.Errorf("Expected prefix list ID 'pl-87654321', got %v", egressPrefixList["prefix_list_id"])
	}
	if egressPrefixList["description"] != "HTTPS outbound to internet" {
		t.Errorf("Expected description 'HTTPS outbound to internet', got %v", egressPrefixList["description"])
	}

	// Test enhanced egress prefix list details
	if egressPrefixList["name"] != "internet-access" {
		t.Errorf("Expected prefix list name 'internet-access', got %v", egressPrefixList["name"])
	}
	egressCidrEntries := egressPrefixList["cidr_entries"].([]map[string]interface{})
	if len(egressCidrEntries) != 1 {
		t.Errorf("Expected 1 CIDR entry, got %d", len(egressCidrEntries))
	}
}

func TestExtractSecurityGroupRulesCleanOutput(t *testing.T) {
	t.Parallel()
	// Create a test security group with minimal rules
	testSG := &types.SecurityGroup{
		GroupId:     aws.String("sg-clean-test"),
		GroupName:   aws.String("clean-test-sg"),
		Description: aws.String("Test security group with clean output"),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				// No IP ranges, no descriptions, no groups, no prefix lists
			},
		},
		IpPermissionsEgress: []types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				FromPort:   aws.Int32(-1),
				ToPort:     aws.Int32(-1),
				// No IP ranges, no descriptions, no groups, no prefix lists
			},
		},
	}

	sga := &SecurityGroupLinks{}
	rules := sga.extractSecurityGroupRules(testSG)

	// Test ingress rule - should only have basic fields
	if len(rules["ingress_rules"].([]map[string]interface{})) != 1 {
		t.Errorf("Expected 1 ingress rule, got %d", len(rules["ingress_rules"].([]map[string]interface{})))
	}

	ingressRule := rules["ingress_rules"].([]map[string]interface{})[0]

	// Should have these basic fields
	expectedFields := []string{"protocol", "from_port", "to_port"}
	for _, field := range expectedFields {
		if _, exists := ingressRule[field]; !exists {
			t.Errorf("Expected field '%s' to exist in ingress rule", field)
		}
	}

	// Should NOT have empty slice fields
	emptySliceFields := []string{"ip_ranges", "ipv6_ranges", "ip_range_descriptions", "ipv6_range_descriptions", "user_id_group_pairs", "prefix_lists"}
	for _, field := range emptySliceFields {
		if _, exists := ingressRule[field]; exists {
			t.Errorf("Expected field '%s' to NOT exist in ingress rule (should be omitted when empty)", field)
		}
	}

	// Test egress rule - should only have basic fields
	if len(rules["egress_rules"].([]map[string]interface{})) != 1 {
		t.Errorf("Expected 1 egress rule, got %d", len(rules["egress_rules"].([]map[string]interface{})))
	}

	egressRule := rules["egress_rules"].([]map[string]interface{})[0]

	// Should have these basic fields
	for _, field := range expectedFields {
		if _, exists := egressRule[field]; !exists {
			t.Errorf("Expected field '%s' to exist in egress rule", field)
		}
	}

	// Should NOT have empty slice fields
	for _, field := range emptySliceFields {
		if _, exists := egressRule[field]; exists {
			t.Errorf("Expected field '%s' to NOT exist in egress rule (should be omitted when empty)", field)
		}
	}
}
