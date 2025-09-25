package hierarchy

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/compute"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/containers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/storage"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

type GcpOrgAllResourcesFanOut struct {
	*base.GcpBaseLink
}

// creates a link to fan out to all resource discovery links for each project
func NewGcpOrgAllResourcesFanOut(configs ...cfg.Config) chain.Link {
	g := &GcpOrgAllResourcesFanOut{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgAllResourcesFanOut) Process(resource tab.GCPResource) error {
	// Only process projects - don't forward non-project resources to prevent infinite loop
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}

	// Forward the project itself
	g.Send(&resource)

	// Create multi-chain for all resource types
	multi := chain.NewMulti(
		// Storage resources
		chain.NewChain(storage.NewGcpStorageBucketListLink()),
		chain.NewChain(storage.NewGcpSQLInstanceListLink()),

		// Compute resources
		chain.NewChain(compute.NewGcpInstanceListLink()),

		// Networking resources (already has its own fanout)
		chain.NewChain(compute.NewGCPNetworkingFanOut()),

		// Application resources
		chain.NewChain(applications.NewGcpFunctionListLink()),
		chain.NewChain(applications.NewGcpCloudRunServiceListLink()),
		chain.NewChain(applications.NewGcpAppEngineApplicationListLink()),

		// Container resources - chained together
		chain.NewChain(
			containers.NewGcpRepositoryListLink(),
			containers.NewGcpContainerImageListLink(),
		),
	)

	// Configure and run
	multi.WithConfigs(cfg.WithArgs(g.Args()))
	multi.WithStrictness(chain.Lax)
	multi.Send(resource)
	multi.Close()

	// Collect and forward all results
	for result, ok := chain.RecvAs[*tab.GCPResource](multi); ok; result, ok = chain.RecvAs[*tab.GCPResource](multi) {
		g.Send(result)
	}

	// Log errors and capture them as structured error objects
	if err := multi.Error(); err != nil {
		slog.Warn("Some resources failed for project (continuing with others)", "project", resource.Name, "error", err)

		// Parse the error and create ResourceError objects for each failure
		g.captureResourceErrors(resource.Name, err.Error())
	}

	// Always return nil to keep processing other projects
	return nil
}

// captureResourceErrors parses multi-chain errors and creates ResourceError objects
func (g *GcpOrgAllResourcesFanOut) captureResourceErrors(projectName, errorText string) {
	// Common error patterns for different resource types
	errorMappings := map[string]string{
		"storage.buckets.list":             "storage.buckets",
		"cloudsql.instances.list":          "sql.instances",
		"compute.instances.list":           "compute.instances",
		"compute.zones.list":               "compute.zones",
		"compute.regions.list":             "compute.regions",
		"cloudfunctions.functions.list":    "cloudfunctions.functions",
		"run.services.list":                "run.services",
		"appengine.applications.get":       "appengine.applications",
		"artifactregistry.repositories.list": "artifactregistry.repositories",
		"compute.globalForwardingRules.list": "compute.globalForwardingRules",
		"compute.globalAddresses.list":     "compute.globalAddresses",
		"dns.managedZones.list":            "dns.managedZones",
	}

	// Parse error text for specific permission/resource type failures
	lines := strings.Split(errorText, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var resourceError *common.ResourceError

		// Check for specific error patterns and create appropriate ResourceError
		if strings.Contains(line, "does not have") && strings.Contains(line, "access") {
			// Permission denied pattern: "elgin.lee@praetorian.com does not have storage.buckets.list access"
			for permission, resourceType := range errorMappings {
				if strings.Contains(line, permission) {
					resourceError = common.NewResourceError(projectName, resourceType, "list", "Permission denied").
						WithErrorCode(403).
						WithDetails(line)
					break
				}
			}
		} else if strings.Contains(line, "API has not been used") || strings.Contains(line, "SERVICE_DISABLED") {
			// API disabled pattern
			for permission, resourceType := range errorMappings {
				if strings.Contains(line, strings.Split(permission, ".")[0]) {
					resourceError = common.NewResourceError(projectName, resourceType, "list", "API disabled").
						WithErrorCode(403).
						WithDetails(line)
					break
				}
			}
		} else if strings.Contains(line, "was not found") {
			// Resource not found pattern
			resourceError = common.NewResourceError(projectName, "unknown", "list", "Resource not found").
				WithErrorCode(404).
				WithDetails(line)
		} else if strings.Contains(line, "Error 403") || strings.Contains(line, "Error 404") {
			// Generic HTTP error pattern
			errorCodeStr := ""
			if strings.Contains(line, "Error 403") {
				errorCodeStr = "403"
			} else if strings.Contains(line, "Error 404") {
				errorCodeStr = "404"
			}

			if errorCodeStr != "" {
				if errorCode, err := strconv.Atoi(errorCodeStr); err == nil {
					// Try to extract resource type from context
					resourceType := "unknown"
					for permission, resType := range errorMappings {
						if strings.Contains(line, strings.Split(permission, ".")[0]) {
							resourceType = resType
							break
						}
					}

					message := "HTTP error"
					if errorCode == 403 {
						message = "Forbidden"
					} else if errorCode == 404 {
						message = "Not found"
					}

					resourceError = common.NewResourceError(projectName, resourceType, "list", message).
						WithErrorCode(errorCode).
						WithDetails(line)
				}
			}
		}

		// Send the error object if we created one
		if resourceError != nil {
			g.Send(resourceError)
		}
	}
}
