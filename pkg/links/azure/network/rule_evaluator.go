package network

import (
	"bytes"
	"net"
	"sort"
	"strings"
)

// RuleEvaluator evaluates NSG rules for connectivity analysis
type RuleEvaluator struct {
	// Cache for evaluated rules
	cache map[string]bool
}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() *RuleEvaluator {
	return &RuleEvaluator{
		cache: make(map[string]bool),
	}
}

// CanConnect evaluates if traffic can flow from source to destination
func (e *RuleEvaluator) CanConnect(
	sourceIP string,
	destIP string,
	port int,
	protocol string,
	sourceNSGRules []ProcessedRule,
	destNSGRules []ProcessedRule,
) bool {
	// Create cache key
	cacheKey := strings.Join([]string{
		sourceIP, destIP,
		string(rune(port)), protocol,
	}, "|")

	// Check cache
	if result, ok := e.cache[cacheKey]; ok {
		return result
	}

	// Normalize protocol
	protocol = NormalizeProtocol(protocol)

	// 1. Check outbound rules from source
	outboundRules := e.filterRules(sourceNSGRules, "Outbound")
	if !e.evaluateRules(sourceIP, destIP, port, protocol, outboundRules) {
		e.cache[cacheKey] = false
		return false
	}

	// 2. Check inbound rules at destination
	inboundRules := e.filterRules(destNSGRules, "Inbound")
	result := e.evaluateRules(sourceIP, destIP, port, protocol, inboundRules)

	e.cache[cacheKey] = result
	return result
}

// filterRules filters rules by direction
func (e *RuleEvaluator) filterRules(rules []ProcessedRule, direction string) []ProcessedRule {
	var filtered []ProcessedRule
	for _, rule := range rules {
		if strings.EqualFold(rule.Direction, direction) {
			filtered = append(filtered, rule)
		}
	}

	// Sort by priority (lower number = higher priority)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Priority < filtered[j].Priority
	})

	return filtered
}

// evaluateRules evaluates a set of rules in priority order
func (e *RuleEvaluator) evaluateRules(
	sourceIP string,
	destIP string,
	port int,
	protocol string,
	rules []ProcessedRule,
) bool {
	// Process rules in priority order
	for _, rule := range rules {
		if e.matchesRule(sourceIP, destIP, port, protocol, rule) {
			// First matching rule determines outcome
			return strings.EqualFold(rule.Access, "Allow")
		}
	}

	// No matching rule found - default deny
	return false
}

// matchesRule checks if traffic matches a specific rule
func (e *RuleEvaluator) matchesRule(
	sourceIP string,
	destIP string,
	port int,
	protocol string,
	rule ProcessedRule,
) bool {
	// Check protocol
	if rule.Protocol != "*" && !strings.EqualFold(rule.Protocol, protocol) {
		return false
	}

	// Check source IP
	srcIP := net.ParseIP(sourceIP)
	if srcIP == nil {
		return false
	}

	sourceMatch := false
	for _, ipRange := range rule.SourceIPRanges {
		if e.ipInRange(srcIP, ipRange) {
			sourceMatch = true
			break
		}
	}
	if !sourceMatch {
		return false
	}

	// Check destination IP
	dstIP := net.ParseIP(destIP)
	if dstIP == nil {
		return false
	}

	destMatch := false
	for _, ipRange := range rule.DestIPRanges {
		if e.ipInRange(dstIP, ipRange) {
			destMatch = true
			break
		}
	}
	if !destMatch {
		return false
	}

	// Check port
	portMatch := false
	for _, portRange := range rule.PortRanges {
		if port >= portRange.Start && port <= portRange.End {
			portMatch = true
			break
		}
	}

	return portMatch
}

// ipInRange checks if an IP is within a range
func (e *RuleEvaluator) ipInRange(ip net.IP, ipRange IPRange) bool {
	// Normalize IPs to same format (v4 or v6)
	if ipRange.Start == nil || ipRange.End == nil {
		return false
	}

	// Convert to 4-byte representation if possible
	ipv4 := ip.To4()
	startv4 := ipRange.Start.To4()
	endv4 := ipRange.End.To4()

	if ipv4 != nil && startv4 != nil && endv4 != nil {
		return bytes.Compare(ipv4, startv4) >= 0 && bytes.Compare(ipv4, endv4) <= 0
	}

	// Fall back to full comparison
	return bytes.Compare(ip, ipRange.Start) >= 0 && bytes.Compare(ip, ipRange.End) <= 0
}

// EvaluatePathSecurity evaluates the security posture of a network path
func (e *RuleEvaluator) EvaluatePathSecurity(
	path []interface{}, // Array of nodes in the path
) map[string]interface{} {
	result := map[string]interface{}{
		"isSecure":     true,
		"exposures":    []string{},
		"protections":  []string{},
		"risks":        []string{},
		"pathLength":   len(path),
	}

	exposures := []string{}
	protections := []string{}
	risks := []string{}

	// Analyze each node in the path
	for i, node := range path {
		nodeMap, ok := node.(map[string]interface{})
		if !ok {
			continue
		}

		nodeType, _ := nodeMap["type"].(string)

		switch nodeType {
		case "PublicIP":
			exposures = append(exposures, "Internet-facing endpoint")
			if i == 0 {
				risks = append(risks, "Direct internet exposure")
			}

		case "NSG":
			if rules, ok := nodeMap["processedRules"].([]ProcessedRule); ok {
				// Check for overly permissive rules
				for _, rule := range rules {
					if e.isOverlyPermissive(rule) {
						risks = append(risks, "Overly permissive rule: "+rule.Name)
					}
				}
				protections = append(protections, "Protected by NSG")
			}

		case "NIC":
			if _, hasNSG := nodeMap["nsgId"]; !hasNSG {
				risks = append(risks, "NIC without NSG protection")
			}

		case "Subnet":
			if _, hasNSG := nodeMap["nsgId"]; !hasNSG {
				risks = append(risks, "Subnet without NSG protection")
			}
		}
	}

	result["exposures"] = exposures
	result["protections"] = protections
	result["risks"] = risks
	result["isSecure"] = len(risks) == 0

	return result
}

// isOverlyPermissive checks if a rule is too permissive
func (e *RuleEvaluator) isOverlyPermissive(rule ProcessedRule) bool {
	// Check for any-any rules
	if rule.Access != "Allow" {
		return false
	}

	// Check for Internet source on inbound
	if rule.Direction == "Inbound" {
		for _, ipRange := range rule.SourceIPRanges {
			// Check for 0.0.0.0/0
			if e.isInternetRange(ipRange) {
				// Check if it's for common sensitive ports
				for _, portRange := range rule.PortRanges {
					if e.containsSensitivePort(portRange) {
						return true
					}
				}
			}
		}
	}

	return false
}

// isInternetRange checks if an IP range represents the Internet
func (e *RuleEvaluator) isInternetRange(ipRange IPRange) bool {
	// Check for 0.0.0.0 - 255.255.255.255
	zeroIP := net.ParseIP("0.0.0.0")
	maxIP := net.ParseIP("255.255.255.255")

	return bytes.Equal(ipRange.Start.To4(), zeroIP.To4()) &&
		bytes.Equal(ipRange.End.To4(), maxIP.To4())
}

// containsSensitivePort checks if a port range contains sensitive ports
func (e *RuleEvaluator) containsSensitivePort(portRange PortRange) bool {
	sensitivePorts := []int{
		22,   // SSH
		23,   // Telnet
		135,  // RPC
		139,  // NetBIOS
		445,  // SMB
		1433, // SQL Server
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		5985, // WinRM HTTP
		5986, // WinRM HTTPS
	}

	for _, port := range sensitivePorts {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}

	return false
}

// AnalyzeExposure analyzes Internet exposure for a resource
func (e *RuleEvaluator) AnalyzeExposure(
	resourceType string,
	hasPublicIP bool,
	nsgRules []ProcessedRule,
) map[string]interface{} {
	analysis := map[string]interface{}{
		"resourceType":    resourceType,
		"hasPublicIP":     hasPublicIP,
		"exposureLevel":   "None",
		"openPorts":       []int{},
		"recommendations": []string{},
	}

	if !hasPublicIP {
		analysis["exposureLevel"] = "Private"
		return analysis
	}

	// Analyze inbound rules for Internet exposure
	openPorts := []int{}
	recommendations := []string{}
	exposureLevel := "Limited"

	inboundRules := e.filterRules(nsgRules, "Inbound")
	for _, rule := range inboundRules {
		if rule.Access != "Allow" {
			continue
		}

		// Check for Internet source
		for _, ipRange := range rule.SourceIPRanges {
			if e.isInternetRange(ipRange) {
				// Internet-accessible rule found
				for _, portRange := range rule.PortRanges {
					// Add exposed ports
					if portRange.Start == portRange.End {
						openPorts = append(openPorts, portRange.Start)
					} else if portRange.End-portRange.Start < 100 {
						// Add individual ports for small ranges
						for p := portRange.Start; p <= portRange.End && p < portRange.Start+100; p++ {
							openPorts = append(openPorts, p)
						}
					} else {
						// Large range - just note it
						openPorts = append(openPorts, -1) // Indicator for "many"
					}

					// Check for sensitive exposure
					if e.containsSensitivePort(portRange) {
						exposureLevel = "High"
						recommendations = append(recommendations,
							"Restrict access to sensitive ports from Internet")
					}
				}

				// Check for any-any rule
				if rule.Protocol == "*" && len(rule.PortRanges) > 0 {
					if rule.PortRanges[0].Start == 0 && rule.PortRanges[0].End == 65535 {
						exposureLevel = "Critical"
						recommendations = append(recommendations,
							"Remove any-any rule allowing all Internet traffic")
					}
				}
			}
		}
	}

	// Remove duplicates from openPorts
	portMap := make(map[int]bool)
	uniquePorts := []int{}
	for _, port := range openPorts {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	analysis["exposureLevel"] = exposureLevel
	analysis["openPorts"] = uniquePorts
	analysis["recommendations"] = recommendations

	return analysis
}