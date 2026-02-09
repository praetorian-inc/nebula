package cognito

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Privilege escalation patterns to detect in custom attribute names
var privilegePatterns = []string{
	// Admin patterns
	"admin", "isadmin", "is_admin", "administrator",
	// Role patterns
	"role", "roles", "user_role", "userrole",
	// Group patterns
	"group", "groups", "user_group", "usergroup",
	// Tenant/org patterns
	"tenant", "tenantid", "tenant_id", "organization", "org", "orgid", "org_id",
	// Permission patterns
	"permission", "permissions", "access", "access_level", "accesslevel",
	// Tier/subscription patterns
	"tier", "plan", "subscription", "level", "userlevel", "user_level",
	// Additional aggressive patterns
	"privilege", "privileges", "scope", "scopes", "entitlement", "entitlements",
	"department", "team", "division", "unit", "company", "account_type",
}

// SchemaAttribute represents a Cognito user pool schema attribute
type SchemaAttribute struct {
	Name    string
	Mutable bool
}

// WritablePrivilegeAttribute contains details about a writable privilege attribute
type WritablePrivilegeAttribute struct {
	Name    string `json:"Name"`
	Mutable bool   `json:"Mutable"`
	Pattern string `json:"Pattern"`
}

// CognitoUserPoolSchemaAnalyzer analyzes Cognito user pool schema for privilege escalation risks
type CognitoUserPoolSchemaAnalyzer struct {
	*base.AwsReconBaseLink
}

func NewCognitoUserPoolSchemaAnalyzer(configs ...cfg.Config) chain.Link {
	l := &CognitoUserPoolSchemaAnalyzer{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *CognitoUserPoolSchemaAnalyzer) Params() []cfg.Param {
	return l.AwsReconBaseLink.Params()
}

func (l *CognitoUserPoolSchemaAnalyzer) Process(resource types.EnrichedResourceDescription) error {
	// Convert the properties to a map if it's not already one
	var propsMap map[string]any
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			propsMap = make(map[string]any)
		}
	case map[string]any:
		propsMap = props
	default:
		propsMap = make(map[string]any)
	}

	// Extract Schema from properties (CloudControl provides this)
	schemaInterface, hasSchema := propsMap["Schema"]
	if !hasSchema {
		// No schema present, pass through without modification
		return l.Send(resource)
	}

	// Parse schema array - handle both []any and []map[string]any
	var schemaArray []any
	switch s := schemaInterface.(type) {
	case []any:
		schemaArray = s
	case []map[string]any:
		// Convert to []any for uniform processing
		schemaArray = make([]any, len(s))
		for i, v := range s {
			schemaArray[i] = v
		}
	default:
		// Schema is not in expected format, pass through
		return l.Send(resource)
	}

	// Analyze schema for writable privilege attributes
	var writablePrivilegeAttrs []WritablePrivilegeAttribute
	var riskFactors []string

	for _, attrInterface := range schemaArray {
		attrMap, ok := attrInterface.(map[string]any)
		if !ok {
			continue
		}

		// Extract Name field
		nameInterface, hasName := attrMap["Name"]
		if !hasName {
			continue
		}
		name, ok := nameInterface.(string)
		if !ok {
			continue
		}

		// Only analyze custom attributes (those starting with "custom:")
		if !strings.HasPrefix(name, "custom:") {
			continue
		}

		// Extract Mutable field (defaults to false if not present)
		mutable := false
		if mutableInterface, hasMutable := attrMap["Mutable"]; hasMutable {
			if mutableBool, ok := mutableInterface.(bool); ok {
				mutable = mutableBool
			}
		}

		// Check if attribute is mutable
		if !mutable {
			continue
		}

		// Remove "custom:" prefix for pattern matching
		attrNameLower := strings.ToLower(strings.TrimPrefix(name, "custom:"))

		// Check if attribute name matches any privilege pattern
		for _, pattern := range privilegePatterns {
			if strings.Contains(attrNameLower, pattern) {
				writablePrivilegeAttrs = append(writablePrivilegeAttrs, WritablePrivilegeAttribute{
					Name:    name,
					Mutable: mutable,
					Pattern: pattern,
				})
				riskFactors = append(riskFactors, fmt.Sprintf("Writable %s", name))
				break // Only match first pattern to avoid duplicates
			}
		}
	}

	// Calculate privilege escalation risk
	risk := "NONE"
	attrCount := len(writablePrivilegeAttrs)

	if attrCount > 0 {
		// Check if self-signup is enabled (from previous link in chain)
		selfSignupEnabled := false
		if selfSignupInterface, hasSelfSignup := propsMap["SelfSignupEnabled"]; hasSelfSignup {
			if selfSignupBool, ok := selfSignupInterface.(bool); ok {
				selfSignupEnabled = selfSignupBool
			}
		}

		if selfSignupEnabled {
			risk = "CRITICAL"
			riskFactors = append(riskFactors, "Self-signup enabled")
		} else if attrCount >= 2 {
			risk = "HIGH"
		} else {
			risk = "MEDIUM"
		}
	}

	// Add analysis results to properties
	if attrCount > 0 {
		propsMap["WritablePrivilegeAttributes"] = writablePrivilegeAttrs
		propsMap["PrivilegeEscalationRisk"] = risk
		propsMap["RiskFactors"] = riskFactors

		// Set human-readable description in properties based on risk level
		switch risk {
		case "CRITICAL":
			// List the writable attributes for CRITICAL risk
			attrNames := make([]string, 0, len(writablePrivilegeAttrs))
			for _, attr := range writablePrivilegeAttrs {
				attrNames = append(attrNames, attr.Name)
			}
			propsMap["Description"] = fmt.Sprintf("CRITICAL: Writable privilege attributes (%s) with self-signup enabled", strings.Join(attrNames, ", "))
		case "HIGH":
			propsMap["Description"] = fmt.Sprintf("HIGH: Multiple writable privilege attributes detected (%d)", attrCount)
		case "MEDIUM":
			// List the writable attribute for MEDIUM risk
			attrNames := make([]string, 0, len(writablePrivilegeAttrs))
			for _, attr := range writablePrivilegeAttrs {
				attrNames = append(attrNames, attr.Name)
			}
			propsMap["Description"] = fmt.Sprintf("MEDIUM: Writable privilege attribute detected (%s)", strings.Join(attrNames, ", "))
		}
	}
	// If no privilege escalation risk, preserve any existing description from previous link

	// Create a new resource with the updated properties
	enrichedResource := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: propsMap,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	return l.Send(enrichedResource)
}
