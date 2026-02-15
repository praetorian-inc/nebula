package dns

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/storage/v1"
)

// GcpSubdomainTakeoverLink scans for dangling DNS records that could enable subdomain takeover
type GcpSubdomainTakeoverLink struct {
	*base.GcpBaseLink
	dnsService       *dns.Service
	storageService   *storage.Service
	runService       *run.Service
	appengineService *appengine.APIService
	computeService   *compute.Service
	crmService       *cloudresourcemanager.Service
}

// NewGcpSubdomainTakeoverLink creates a new subdomain takeover detection link
func NewGcpSubdomainTakeoverLink(configs ...cfg.Config) chain.Link {
	g := &GcpSubdomainTakeoverLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpSubdomainTakeoverLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.dnsService, err = dns.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create dns service: %w", err)
	}
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create run service: %w", err)
	}
	g.appengineService, err = appengine.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}
	g.crmService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud resource manager service: %w", err)
	}
	return nil
}

func (g *GcpSubdomainTakeoverLink) Process(resource tab.GCPResource) error {
	slog.Debug("Starting subdomain takeover scan", "resourceType", resource.ResourceType, "resourceName", resource.Name)

	var projectIds []string

	switch resource.ResourceType {
	case tab.GCPResourceProject:
		// Process single project directly
		projectIds = append(projectIds, resource.Name)

	case tab.GCPResourceOrganization:
		// List all projects in the organization
		orgProjects, err := g.listProjects("organizations", resource.Name)
		if err != nil {
			slog.Error("Failed to list projects in organization", "error", err, "org", resource.Name)
			return common.HandleGcpError(err, "failed to list projects in organization")
		}
		projectIds = append(projectIds, orgProjects...)

	case tab.GCPResourceFolder:
		// List all projects in the folder
		folderProjects, err := g.listProjects("folders", resource.Name)
		if err != nil {
			slog.Error("Failed to list projects in folder", "error", err, "folder", resource.Name)
			return common.HandleGcpError(err, "failed to list projects in folder")
		}
		projectIds = append(projectIds, folderProjects...)

	default:
		// Skip other resource types
		return nil
	}

	slog.Debug("Found projects to scan", "count", len(projectIds), "projects", projectIds)

	// Scan DNS zones in each discovered project
	for _, projectId := range projectIds {
		if err := g.scanProjectDNS(projectId); err != nil {
			slog.Error("Failed to scan project DNS", "error", err, "project", projectId)
			continue
		}
	}

	return nil
}

func (g *GcpSubdomainTakeoverLink) scanProjectDNS(projectId string) error {
	slog.Debug("Listing DNS managed zones", "project", projectId)

	// List all DNS managed zones in the project
	managedZones, err := g.dnsService.ManagedZones.List(projectId).Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to list DNS managed zones")
	}

	// Build zone names list for logging
	zoneNames := make([]string, 0, len(managedZones.ManagedZones))
	for _, zone := range managedZones.ManagedZones {
		zoneNames = append(zoneNames, zone.Name)
	}
	slog.Debug("Found DNS managed zones", "project", projectId, "count", len(managedZones.ManagedZones), "zones", zoneNames)

	for _, zone := range managedZones.ManagedZones {
		if err := g.scanZoneForTakeovers(projectId, zone); err != nil {
			slog.Error("Failed to scan DNS zone for subdomain takeovers", "error", err, "zone", zone.Name)
			continue
		}
	}

	return nil
}

func (g *GcpSubdomainTakeoverLink) scanZoneForTakeovers(projectId string, zone *dns.ManagedZone) error {
	slog.Debug("Scanning zone for takeover vulnerabilities", "project", projectId, "zone", zone.Name, "dnsName", zone.DnsName)

	// Get all resource record sets in this zone
	rrsets, err := g.dnsService.ResourceRecordSets.List(projectId, zone.Name).Do()
	if err != nil {
		return common.HandleGcpError(err, fmt.Sprintf("failed to list resource record sets for zone %s", zone.Name))
	}

	slog.Debug("Found resource record sets", "zone", zone.Name, "count", len(rrsets.Rrsets))

	for _, rrset := range rrsets.Rrsets {
		// Check CNAME records for vulnerable patterns
		if rrset.Type == "CNAME" {
			g.checkCNAMERecord(projectId, zone, rrset)
		}

		// Check A/AAAA records for orphaned IPs
		if rrset.Type == "A" || rrset.Type == "AAAA" {
			g.checkARecord(projectId, zone, rrset)
		}

		// Check NS records for orphaned delegations
		if rrset.Type == "NS" && rrset.Name != zone.DnsName {
			g.checkNSRecord(projectId, zone, rrset)
		}
	}

	return nil
}

// servicePattern defines a GCP service vulnerable to subdomain takeover
type servicePattern struct {
	patterns    []string
	service     string
	severity    string
	description func(rdata string) string
	remediation string
	checker     func(g *GcpSubdomainTakeoverLink, projectId, rdata string) bool
}

// cnameServicePatterns defines patterns for CNAME subdomain takeover detection
var cnameServicePatterns = []servicePattern{
	{
		patterns: []string{".storage.googleapis.com", "c.storage.googleapis.com"},
		service:  "Cloud Storage",
		severity: "critical",
		description: func(rdata string) string {
			bucketName := extractBucketName(rdata)
			return fmt.Sprintf("CNAME record points to non-existent Cloud Storage bucket: %s", bucketName)
		},
		remediation: "Delete the CNAME record or create the bucket with appropriate permissions",
		checker:     checkBucketExists,
	},
	{
		patterns: []string{".run.app", ".a.run.app"},
		service:  "Cloud Run",
		severity: "high",
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME record points to potentially deleted Cloud Run service: %s", rdata)
		},
		remediation: "Delete the CNAME record or verify the Cloud Run service exists",
		checker:     checkCloudRunExists,
	},
	{
		patterns: []string{".appspot.com", "ghs.googlehosted.com"},
		service:  "App Engine",
		severity: "high",
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME record points to potentially deleted App Engine application: %s", rdata)
		},
		remediation: "Delete the CNAME record or verify the App Engine application exists",
		checker:     checkAppEngineExists,
	},
	{
		patterns: []string{".firebaseapp.com", ".web.app"},
		service:  "Firebase Hosting",
		severity: "informational",
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME record points to Firebase hosting site: %s. Manual verification required - Firebase requires TXT record ownership verification.", rdata)
		},
		remediation: "Verify Firebase site ownership via TXT record validation or remove the CNAME if site is abandoned",
		checker:     nil, // Always report - no automatic verification
	},
	{
		patterns: []string{".cloudfunctions.net"},
		service:  "Cloud Functions",
		severity: "informational",
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME record points to Cloud Function: %s. Manual verification required - function existence cannot be automatically verified.", rdata)
		},
		remediation: "Delete the CNAME record or manually verify the Cloud Function exists",
		checker:     nil, // Always report - no automatic verification
	},
	{
		patterns: []string{".endpoints.", ".cloud.goog"},
		service:  "Cloud Endpoints",
		severity: "informational",
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME record points to Cloud Endpoints service: %s. Manual verification required - backend existence cannot be automatically verified.", rdata)
		},
		remediation: "Delete the CNAME record or manually verify the backend service exists",
		checker:     nil, // Always report - no automatic verification
	},
}

func (g *GcpSubdomainTakeoverLink) checkCNAMERecord(projectId string, zone *dns.ManagedZone, rrset *dns.ResourceRecordSet) {
	for _, rdata := range rrset.Rrdatas {
		rdata = strings.TrimSuffix(rdata, ".")
		slog.Debug("Checking CNAME record", "domain", rrset.Name, "target", rdata)

		for _, pattern := range cnameServicePatterns {
			if !matchesAnyPattern(rdata, pattern.patterns) {
				continue
			}

			// For Cloud Endpoints, require both patterns to match
			if pattern.service == "Cloud Endpoints" {
				if !strings.Contains(rdata, ".endpoints.") || !strings.Contains(rdata, ".cloud.goog") {
					continue
				}
			}

			slog.Debug("Matched service pattern", "domain", rrset.Name, "service", pattern.service, "severity", pattern.severity)

			// Skip if checker exists and resource exists (not vulnerable)
			if pattern.checker != nil && pattern.checker(g, projectId, rdata) {
				continue
			}

			// Emit finding
			g.emitFinding(projectId, zone, rrset, rdata,
				pattern.severity, pattern.service,
				pattern.description(rdata), pattern.remediation)
			break // Only emit one finding per rdata
		}
	}
}

// matchesAnyPattern checks if rdata contains any of the patterns
func matchesAnyPattern(rdata string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(rdata, pattern) {
			return true
		}
	}
	return false
}

// extractBucketName extracts bucket name from Cloud Storage URL
func extractBucketName(rdata string) string {
	bucketName := strings.TrimSuffix(rdata, ".storage.googleapis.com")
	bucketName = strings.TrimSuffix(bucketName, ".c.storage.googleapis.com")
	return bucketName
}

// checkBucketExists wraps bucketExists with signature matching servicePattern.checker
func checkBucketExists(g *GcpSubdomainTakeoverLink, projectId, rdata string) bool {
	bucketName := extractBucketName(rdata)
	return g.bucketExists(bucketName)
}

// checkCloudRunExists wraps cloudRunServiceExists with signature matching servicePattern.checker
func checkCloudRunExists(g *GcpSubdomainTakeoverLink, projectId, rdata string) bool {
	return g.cloudRunServiceExists(projectId, rdata)
}

// checkAppEngineExists wraps appEngineExists with signature matching servicePattern.checker
func checkAppEngineExists(g *GcpSubdomainTakeoverLink, projectId, rdata string) bool {
	return g.appEngineExists(projectId)
}

func (g *GcpSubdomainTakeoverLink) checkARecord(projectId string, zone *dns.ManagedZone, rrset *dns.ResourceRecordSet) {
	for _, rdata := range rrset.Rrdatas {
		slog.Debug("Checking A/AAAA record", "domain", rrset.Name, "type", rrset.Type, "ip", rdata)

		// Check if IP is orphaned (not associated with active compute resource)
		if !g.ipIsInUse(projectId, rdata) {
			severity := "low"
			service := "Compute Engine / Load Balancing"
			description := fmt.Sprintf("A/AAAA record points to potentially orphaned IP address: %s", rdata)
			remediation := "Delete the DNS record or verify the IP address is properly allocated"
			g.emitFinding(projectId, zone, rrset, rdata, severity, service, description, remediation)
		}
	}
}

func (g *GcpSubdomainTakeoverLink) checkNSRecord(projectId string, zone *dns.ManagedZone, rrset *dns.ResourceRecordSet) {
	for _, rdata := range rrset.Rrdatas {
		rdata = strings.TrimSuffix(rdata, ".")
		slog.Debug("Checking NS record for delegation", "domain", rrset.Name, "nameserver", rdata)

		// Check for ns-cloud-*.googledomains.com delegation
		if strings.Contains(rdata, "ns-cloud-") && strings.Contains(rdata, ".googledomains.com") {
			// Extract potential zone name from the subdomain
			subdomain := strings.TrimSuffix(rrset.Name, zone.DnsName)
			subdomain = strings.TrimSuffix(subdomain, ".")

			if !g.delegatedZoneExists(projectId, subdomain) {
				severity := "critical"
				service := "Cloud DNS"
				description := fmt.Sprintf("NS record delegates to Cloud DNS nameserver but delegated zone may not exist: %s", rdata)
				remediation := "Delete the NS delegation or create the corresponding Cloud DNS zone"
				g.emitFinding(projectId, zone, rrset, rdata, severity, service, description, remediation)
			}
		}
	}
}

// Helper functions to verify resource existence

func (g *GcpSubdomainTakeoverLink) bucketExists(bucketName string) bool {
	slog.Debug("Checking bucket existence", "bucket", bucketName)
	_, err := g.storageService.Buckets.Get(bucketName).Do()
	exists := err == nil
	slog.Debug("Bucket check result", "bucket", bucketName, "exists", exists)
	return exists
}

func (g *GcpSubdomainTakeoverLink) cloudRunServiceExists(projectId, domain string) bool {
	slog.Debug("Checking Cloud Run service existence", "project", projectId, "domain", domain)

	// Cloud Run domains are like: service-name-hash-region.a.run.app
	// Extract the service name (first part before first hyphen + hash pattern)
	parts := strings.Split(domain, ".")
	if len(parts) < 4 {
		return true // Can't parse, assume exists to avoid false positive
	}

	// The first part contains: servicename-hash-region
	// We'll try to extract the service name by looking for the pattern
	serviceAndRegion := parts[0]

	// Cloud Run service names are typically before the hash/region suffix
	// This is a heuristic - try to match against actual services
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	services, err := g.runService.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		return true // Assume exists if we can't check (avoid false positives)
	}

	// Check if any service name matches the beginning of our domain pattern
	for _, service := range services.Services {
		// Extract service name from the full resource name
		// Format: projects/PROJECT/locations/REGION/services/SERVICE
		nameParts := strings.Split(service.Name, "/")
		if len(nameParts) > 0 {
			serviceName := nameParts[len(nameParts)-1]
			// Check if the domain starts with this service name
			if strings.HasPrefix(serviceAndRegion, serviceName) {
				slog.Debug("Cloud Run check result", "project", projectId, "serviceCount", len(services.Services), "matchFound", true)
				return true
			}
		}
	}

	// No matching service found
	slog.Debug("Cloud Run check result", "project", projectId, "serviceCount", len(services.Services), "matchFound", false)
	return false
}

func (g *GcpSubdomainTakeoverLink) appEngineExists(projectId string) bool {
	slog.Debug("Checking App Engine existence", "project", projectId)
	appName := fmt.Sprintf("apps/%s", projectId)
	_, err := g.appengineService.Apps.Get(appName).Do()
	exists := err == nil
	slog.Debug("App Engine check result", "project", projectId, "exists", exists)
	return exists
}

func (g *GcpSubdomainTakeoverLink) ipIsInUse(projectId, ipAddress string) bool {
	slog.Debug("Checking IP address usage", "project", projectId, "ip", ipAddress)

	// Check if IP is allocated to any address resource
	addresses, err := g.computeService.Addresses.AggregatedList(projectId).Do()
	if err != nil {
		return true // Assume in use if we can't check
	}
	for _, addressList := range addresses.Items {
		for _, address := range addressList.Addresses {
			if address.Address == ipAddress {
				inUse := address.Status == "IN_USE"
				slog.Debug("IP check result", "project", projectId, "ip", ipAddress, "inUse", inUse)
				return inUse
			}
		}
	}
	slog.Debug("IP check result", "project", projectId, "ip", ipAddress, "inUse", false)
	return false
}

func (g *GcpSubdomainTakeoverLink) delegatedZoneExists(projectId, subdomain string) bool {
	slog.Debug("Checking delegated zone existence", "project", projectId, "subdomain", subdomain)

	// Check if a managed zone exists for the delegated subdomain
	zones, err := g.dnsService.ManagedZones.List(projectId).Do()
	if err != nil {
		return true // Assume exists if we can't check
	}

	// Normalize subdomain for comparison
	normalizedSubdomain := strings.TrimSuffix(subdomain, ".")

	for _, zone := range zones.ManagedZones {
		// Normalize zone DNS name for comparison
		normalizedZoneName := strings.TrimSuffix(zone.DnsName, ".")

		// Check for exact match or proper suffix match
		if normalizedZoneName == normalizedSubdomain {
			slog.Debug("Delegated zone check result", "project", projectId, "subdomain", subdomain, "exists", true)
			return true
		}
		if strings.HasSuffix(normalizedZoneName, "."+normalizedSubdomain) {
			slog.Debug("Delegated zone check result", "project", projectId, "subdomain", subdomain, "exists", true)
			return true
		}
	}
	slog.Debug("Delegated zone check result", "project", projectId, "subdomain", subdomain, "exists", false)
	return false
}

func (g *GcpSubdomainTakeoverLink) listProjects(parentType, parentId string) ([]string, error) {
	var projectIds []string
	parent := fmt.Sprintf("%s/%s", parentType, parentId)

	// Use Cloud Resource Manager API v3 to list projects
	req := g.crmService.Projects.List().Parent(parent)
	err := req.Pages(context.Background(), func(resp *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range resp.Projects {
			// Only include active projects
			if project.State == "ACTIVE" {
				projectIds = append(projectIds, project.ProjectId)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list projects in %s %s: %w", parentType, parentId, err)
	}

	return projectIds, nil
}

func (g *GcpSubdomainTakeoverLink) emitFinding(projectId string, zone *dns.ManagedZone, rrset *dns.ResourceRecordSet, recordValue, severity, service, description, remediation string) {
	slog.Debug("Emitting subdomain takeover finding", "domain", rrset.Name, "service", service, "severity", severity)

	properties := map[string]any{
		"zoneName":     zone.Name,
		"dnsName":      zone.DnsName,
		"domain":       rrset.Name,
		"recordType":   rrset.Type,
		"recordValue":  recordValue,
		"service":      service,
		"severity":     severity,
		"description":  description,
		"remediation":  remediation,
		"findingType":  "subdomain_takeover",
		"publicDomain": rrset.Name, // For asset creation
	}

	finding, err := tab.NewGCPResource(
		fmt.Sprintf("%s/%s", zone.Name, rrset.Name),
		projectId,
		tab.GCPResourceDNSManagedZone,
		properties,
	)
	if err != nil {
		slog.Error("Failed to create GCP subdomain takeover finding", "error", err, "domain", rrset.Name)
		return
	}

	g.Send(finding)
}
