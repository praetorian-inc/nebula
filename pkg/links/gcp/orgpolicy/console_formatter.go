package orgpolicy

import (
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

type GcpConstraintConsoleFormatterLink struct {
	*chain.Base
	violations []violationRecord
}

type violationRecord struct {
	resourceType   string
	resourceName   string
	constraintName string
	expected       string
	actual         string
	severity       string
	description    string
}

func NewGcpConstraintConsoleFormatterLink(configs ...cfg.Config) chain.Link {
	g := &GcpConstraintConsoleFormatterLink{
		violations: make([]violationRecord, 0),
	}
	g.Base = chain.NewBase(g, configs...)
	return g
}

func (g *GcpConstraintConsoleFormatterLink) Initialize() error {
	return g.Base.Initialize()
}

func (g *GcpConstraintConsoleFormatterLink) Process(resource tab.GCPResource) error {
	if !isPolicyResource(resource.ResourceType) {
		return nil
	}

	g.Send(resource)

	if shouldSkipConsoleOutput(resource) {
		return nil
	}

	isCompliant, ok := resource.Properties["isCompliant"].(bool)
	if !ok || isCompliant {
		return nil
	}

	violation := extractViolationRecord(resource)
	g.violations = append(g.violations, violation)

	return nil
}

func (g *GcpConstraintConsoleFormatterLink) Complete() error {
	if len(g.violations) == 0 {
		return g.Base.Complete()
	}

	table := buildViolationsTable(g.violations)
	g.Send(table)
	g.Send("\n") // Add spacing after table

	return g.Base.Complete()
}

func shouldSkipConsoleOutput(resource tab.GCPResource) bool {
	// Always show organization-level policies
	isOrg := resource.ResourceType == tab.GCPResourceOrganizationPolicy
	if isOrg {
		return false
	}

	// For folders and projects, only show if the policy is explicitly set at that level
	isExplicitlySet, ok := resource.Properties["isExplicitlySet"].(bool)
	if !ok {
		// If property is missing, default to old behavior
		return shouldSkipConsoleOutputLegacy(resource)
	}

	// Skip if not explicitly set (i.e., inherited from parent)
	return !isExplicitlySet
}

func shouldSkipConsoleOutputLegacy(resource tab.GCPResource) bool {
	inherit, ok := resource.Properties["inherit"].(bool)
	if ok && inherit {
		return true
	}

	hasExplicitPolicy := hasExplicitPolicyConfiguration(resource.Properties)
	return !hasExplicitPolicy
}

func hasExplicitPolicyConfiguration(properties map[string]any) bool {
	if enforced, ok := properties["enforced"].(bool); ok && enforced {
		return true
	}

	if allowedValues, ok := properties["allowedValues"].([]string); ok && len(allowedValues) > 0 {
		return true
	}

	if deniedValues, ok := properties["deniedValues"].([]string); ok && len(deniedValues) > 0 {
		return true
	}

	if allowAll, ok := properties["allowAll"].(bool); ok && allowAll {
		return true
	}

	if denyAll, ok := properties["denyAll"].(bool); ok && denyAll {
		return true
	}

	return false
}

func extractViolationRecord(resource tab.GCPResource) violationRecord {
	resourceType := formatResourceType(resource.ResourceType)
	resourceName := extractResourceName(resource.Properties)
	constraintName := extractConstraintName(resource.Properties)
	expected := extractStringProperty(resource.Properties, "expectedConfig")
	actual := extractStringProperty(resource.Properties, "actualConfig")
	severity := extractStringProperty(resource.Properties, "severity")
	description := extractStringProperty(resource.Properties, "description")

	return violationRecord{
		resourceType:   resourceType,
		resourceName:   resourceName,
		constraintName: constraintName,
		expected:       expected,
		actual:         actual,
		severity:       severity,
		description:    description,
	}
}

func formatResourceType(resourceType tab.CloudResourceType) string {
	switch resourceType {
	case tab.GCPResourceOrganizationPolicy:
		return "Organization"
	case tab.GCPResourceFolderPolicy:
		return "Folder"
	case tab.GCPResourceProjectPolicy:
		return "Project"
	default:
		return string(resourceType)
	}
}

func extractResourceName(properties map[string]any) string {
	if resourceName, ok := properties["resourceName"].(string); ok {
		parts := strings.Split(resourceName, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-1]
		}
		return resourceName
	}
	return "unknown"
}

func extractConstraintName(properties map[string]any) string {
	if constraintID, ok := properties["constraintId"].(string); ok {
		return strings.TrimPrefix(constraintID, "constraints/")
	}
	return "unknown"
}

func extractStringProperty(properties map[string]any, key string) string {
	if value, ok := properties[key].(string); ok {
		return value
	}
	return ""
}

func buildViolationsTable(violations []violationRecord) types.MarkdownTable {
	table := types.MarkdownTable{
		TableHeading: "GCP Organizational Policy Constraint Violations",
		Headers:      []string{"Resource Type", "Resource Name", "Constraint", "Severity", "Expected", "Actual", "Description"},
		Rows:         make([][]string, 0, len(violations)),
	}

	for _, v := range violations {
		row := []string{
			v.resourceType,
			v.resourceName,
			v.constraintName,
			v.severity,
			v.expected,
			v.actual,
			v.description,
		}
		table.Rows = append(table.Rows, row)
	}

	return table
}
