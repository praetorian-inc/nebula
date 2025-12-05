package network

import (
	"fmt"
	"net"
	"strings"
)

// ServiceTagResolver handles Azure service tag resolution
type ServiceTagResolver struct {
	cache      map[string][]IPRange
	vnetRanges []IPRange // Collected from actual environment
}

// IPRange represents an IP address range
type IPRange struct {
	Start net.IP `json:"start"`
	End   net.IP `json:"end"`
}

// PortRange represents a port range
type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ProcessedRule represents a normalized NSG rule with expanded tags
type ProcessedRule struct {
	Name           string     `json:"name"`
	Priority       int        `json:"priority"`
	Direction      string     `json:"direction"`
	Access         string     `json:"access"`
	Protocol       string     `json:"protocol"`
	SourceIPRanges []IPRange  `json:"sourceIPRanges"`
	DestIPRanges   []IPRange  `json:"destIPRanges"`
	PortRanges     []PortRange `json:"portRanges"`
}

// NewServiceTagResolver creates a new service tag resolver
func NewServiceTagResolver() *ServiceTagResolver {
	return &ServiceTagResolver{
		cache:      make(map[string][]IPRange),
		vnetRanges: []IPRange{},
	}
}

// UpdateServiceTags downloads and caches the latest Azure service tags
func (r *ServiceTagResolver) UpdateServiceTags() error {
	// Initialize with RFC1918 ranges for VirtualNetwork
	r.cache["VirtualNetwork"] = []IPRange{
		{Start: net.ParseIP("10.0.0.0"), End: net.ParseIP("10.255.255.255")},
		{Start: net.ParseIP("172.16.0.0"), End: net.ParseIP("172.31.255.255")},
		{Start: net.ParseIP("192.168.0.0"), End: net.ParseIP("192.168.255.255")},
	}

	// Internet is everything
	r.cache["Internet"] = []IPRange{
		{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
	}

	// Azure Load Balancer health probe IP
	r.cache["AzureLoadBalancer"] = []IPRange{
		{Start: net.ParseIP("168.63.129.16"), End: net.ParseIP("168.63.129.16")},
	}

	// Try to download latest service tags (optional)
	if err := r.downloadAzureIPRanges(); err != nil {
		// Non-fatal: continue with defaults
		fmt.Printf("Warning: Could not download Azure IP ranges: %v\n", err)
	}

	return nil
}

// AddVNetRange adds an actual VNet range from the environment
func (r *ServiceTagResolver) AddVNetRange(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ipRange := cidrToRange(ipnet)
	r.vnetRanges = append(r.vnetRanges, ipRange)

	// Add to VirtualNetwork cache
	if existing, ok := r.cache["VirtualNetwork"]; ok {
		r.cache["VirtualNetwork"] = append(existing, ipRange)
	}

	return nil
}

// Resolve resolves a service tag or CIDR to IP ranges
func (r *ServiceTagResolver) Resolve(tag string) []IPRange {
	// Check if it's a known service tag
	if ranges, ok := r.cache[tag]; ok {
		return ranges
	}

	// Handle wildcard
	if tag == "*" {
		return []IPRange{{
			Start: net.ParseIP("0.0.0.0"),
			End:   net.ParseIP("255.255.255.255"),
		}}
	}

	// Try to parse as CIDR
	if _, ipnet, err := net.ParseCIDR(tag); err == nil {
		return []IPRange{cidrToRange(ipnet)}
	}

	// Try as single IP
	if ip := net.ParseIP(tag); ip != nil {
		return []IPRange{{Start: ip, End: ip}}
	}

	// Handle comma-separated values
	if strings.Contains(tag, ",") {
		var ranges []IPRange
		for _, part := range strings.Split(tag, ",") {
			ranges = append(ranges, r.Resolve(strings.TrimSpace(part))...)
		}
		return ranges
	}

	// Unknown tag - return empty
	return []IPRange{}
}

// downloadAzureIPRanges downloads the Azure IP ranges JSON
func (r *ServiceTagResolver) downloadAzureIPRanges() error {
	// TODO: In production, download from https://www.microsoft.com/en-us/download/details.aspx?id=56519
	// For now, return empty ranges - the graph will create an "AzureCloud" node instead
	// This allows proper representation without pretending to have accurate IP ranges

	// Return empty slice to indicate we don't have actual ranges
	// The topology importer will handle this by creating service tag nodes
	r.cache["AzureCloud"] = []IPRange{}

	// Add other common Azure service tags as placeholders
	r.cache["AzureStorage"] = []IPRange{}
	r.cache["AzureSQL"] = []IPRange{}
	r.cache["AzureKeyVault"] = []IPRange{}

	return nil
}

// cidrToRange converts a CIDR to an IP range
func cidrToRange(ipnet *net.IPNet) IPRange {
	// Get the network address
	networkIP := ipnet.IP.Mask(ipnet.Mask)

	// Calculate broadcast address
	broadcast := make(net.IP, len(networkIP))
	copy(broadcast, networkIP)

	for i := range broadcast {
		broadcast[i] |= ^ipnet.Mask[i]
	}

	return IPRange{
		Start: networkIP,
		End:   broadcast,
	}
}

// ParsePortRanges parses a port specification into port ranges
func ParsePortRanges(portSpec string) []PortRange {
	if portSpec == "" || portSpec == "*" {
		return []PortRange{{Start: 0, End: 65535}}
	}

	var ranges []PortRange
	for _, part := range strings.Split(portSpec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range like "80-443"
			parts := strings.Split(part, "-")
			if len(parts) == 2 {
				var start, end int
				fmt.Sscanf(parts[0], "%d", &start)
				fmt.Sscanf(parts[1], "%d", &end)
				ranges = append(ranges, PortRange{Start: start, End: end})
			}
		} else {
			// Single port
			var port int
			fmt.Sscanf(part, "%d", &port)
			ranges = append(ranges, PortRange{Start: port, End: port})
		}
	}

	if len(ranges) == 0 {
		// Default to all ports if parsing failed
		return []PortRange{{Start: 0, End: 65535}}
	}

	return ranges
}

// NormalizeProtocol normalizes protocol strings
func NormalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "tcp", "6":
		return "TCP"
	case "udp", "17":
		return "UDP"
	case "icmp", "1":
		return "ICMP"
	case "*", "any", "":
		return "*"
	default:
		return strings.ToUpper(protocol)
	}
}

// GetDefaultInboundRules returns Azure's default inbound NSG rules
func GetDefaultInboundRules() []ProcessedRule {
	return []ProcessedRule{
		{
			Name:      "AllowVnetInBound",
			Priority:  65000,
			Direction: "Inbound",
			Access:    "Allow",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("10.0.0.0"), End: net.ParseIP("10.255.255.255")},
				{Start: net.ParseIP("172.16.0.0"), End: net.ParseIP("172.31.255.255")},
				{Start: net.ParseIP("192.168.0.0"), End: net.ParseIP("192.168.255.255")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("10.0.0.0"), End: net.ParseIP("10.255.255.255")},
				{Start: net.ParseIP("172.16.0.0"), End: net.ParseIP("172.31.255.255")},
				{Start: net.ParseIP("192.168.0.0"), End: net.ParseIP("192.168.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
		{
			Name:      "AllowAzureLoadBalancerInBound",
			Priority:  65001,
			Direction: "Inbound",
			Access:    "Allow",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("168.63.129.16"), End: net.ParseIP("168.63.129.16")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
		{
			Name:      "DenyAllInBound",
			Priority:  65500,
			Direction: "Inbound",
			Access:    "Deny",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
	}
}

// GetDefaultOutboundRules returns Azure's default outbound NSG rules
func GetDefaultOutboundRules() []ProcessedRule {
	return []ProcessedRule{
		{
			Name:      "AllowVnetOutBound",
			Priority:  65000,
			Direction: "Outbound",
			Access:    "Allow",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("10.0.0.0"), End: net.ParseIP("10.255.255.255")},
				{Start: net.ParseIP("172.16.0.0"), End: net.ParseIP("172.31.255.255")},
				{Start: net.ParseIP("192.168.0.0"), End: net.ParseIP("192.168.255.255")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("10.0.0.0"), End: net.ParseIP("10.255.255.255")},
				{Start: net.ParseIP("172.16.0.0"), End: net.ParseIP("172.31.255.255")},
				{Start: net.ParseIP("192.168.0.0"), End: net.ParseIP("192.168.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
		{
			Name:      "AllowInternetOutBound",
			Priority:  65001,
			Direction: "Outbound",
			Access:    "Allow",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
		{
			Name:      "DenyAllOutBound",
			Priority:  65500,
			Direction: "Outbound",
			Access:    "Deny",
			Protocol:  "*",
			SourceIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			DestIPRanges: []IPRange{
				{Start: net.ParseIP("0.0.0.0"), End: net.ParseIP("255.255.255.255")},
			},
			PortRanges: []PortRange{{Start: 0, End: 65535}},
		},
	}
}