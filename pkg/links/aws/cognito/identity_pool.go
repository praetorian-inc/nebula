package cognito

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// CognitoIdentityPoolDescribe is a Janus link that adds identity pool configuration
// details including unauthenticated access settings and role mappings.
type CognitoIdentityPoolDescribe struct {
	*base.AwsReconBaseLink
}

func NewCognitoIdentityPoolDescribe(configs ...cfg.Config) chain.Link {
	l := &CognitoIdentityPoolDescribe{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *CognitoIdentityPoolDescribe) Process(resource types.EnrichedResourceDescription) error {
	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Warn("Could not set up client config for identity pool describe", "error", err)
		l.Send(resource)
		return nil
	}

	client := cognitoidentity.NewFromConfig(config)

	// Describe the identity pool to get configuration
	describeOutput, err := client.DescribeIdentityPool(l.Context(), &cognitoidentity.DescribeIdentityPoolInput{
		IdentityPoolId: &resource.Identifier,
	})
	if err != nil {
		slog.Warn("Failed to describe identity pool", "id", resource.Identifier, "error", err)
		l.Send(resource)
		return nil
	}

	// Get role mappings for the identity pool
	rolesOutput, err := client.GetIdentityPoolRoles(l.Context(), &cognitoidentity.GetIdentityPoolRolesInput{
		IdentityPoolId: &resource.Identifier,
	})
	if err != nil {
		slog.Warn("Failed to get identity pool roles", "id", resource.Identifier, "error", err)
		// Continue with what we have from describe
		rolesOutput = nil
	}

	// Convert the properties to a map
	var propsMap map[string]interface{}
	switch props := resource.Properties.(type) {
	case string:
		if err := json.Unmarshal([]byte(props), &propsMap); err != nil {
			propsMap = make(map[string]interface{})
		}
	case map[string]interface{}:
		propsMap = props
	default:
		propsMap = make(map[string]interface{})
	}

	// Add identity pool name
	if describeOutput.IdentityPoolName != nil {
		propsMap["IdentityPoolName"] = *describeOutput.IdentityPoolName
	}

	// Add unauthenticated access flag
	propsMap["AllowUnauthenticatedIdentities"] = describeOutput.AllowUnauthenticatedIdentities

	// Add classic (basic) auth flow flag - when enabled, session policy restrictions
	// are bypassed, giving full role permissions to unauthenticated identities.
	allowClassicFlow := false
	if describeOutput.AllowClassicFlow != nil {
		allowClassicFlow = *describeOutput.AllowClassicFlow
	}
	propsMap["AllowClassicFlow"] = allowClassicFlow

	// Extract unauthenticated role ARN
	unauthRoleArn := "none"
	roleStatus := "no_role_attached"
	if rolesOutput != nil && rolesOutput.Roles != nil {
		if roleArn, ok := rolesOutput.Roles["unauthenticated"]; ok && roleArn != "" {
			unauthRoleArn = roleArn
			roleStatus = "role_attached"
		}
	}
	propsMap["UnauthRoleArn"] = unauthRoleArn
	propsMap["RoleStatus"] = roleStatus

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

// CognitoIdentityPoolRoleAnalyzer is a Janus link that analyzes the IAM role
// attached to unauthenticated identities and classifies the risk level.
type CognitoIdentityPoolRoleAnalyzer struct {
	*base.AwsReconBaseLink
}

func NewCognitoIdentityPoolRoleAnalyzer(configs ...cfg.Config) chain.Link {
	l := &CognitoIdentityPoolRoleAnalyzer{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *CognitoIdentityPoolRoleAnalyzer) Process(resource types.EnrichedResourceDescription) error {
	// Extract properties map
	propsMap, ok := resource.Properties.(map[string]interface{})
	if !ok {
		slog.Debug("Properties not a map, passing through", "id", resource.Identifier)
		return l.Send(resource)
	}

	// Skip pools where unauthenticated access is disabled — no finding to report
	allowUnauth, _ := propsMap["AllowUnauthenticatedIdentities"].(bool)
	if !allowUnauth {
		slog.Debug("Unauthenticated access not enabled, dropping from output", "id", resource.Identifier)
		return nil
	}

	unauthRoleArn, _ := propsMap["UnauthRoleArn"].(string)
	if unauthRoleArn == "" || unauthRoleArn == "none" {
		slog.Debug("No unauthenticated role attached, skipping role analysis", "id", resource.Identifier)
		propsMap["RiskLevel"] = "LOW"
		propsMap["PolicySummary"] = "Unauthenticated access enabled but no role attached"
		resource.Properties = propsMap
		return l.Send(resource)
	}

	// Parse the role name from the ARN (format: arn:aws:iam::ACCOUNT:role/ROLENAME)
	roleName := extractRoleNameFromArn(unauthRoleArn)
	if roleName == "" {
		slog.Warn("Could not parse role name from ARN", "arn", unauthRoleArn)
		propsMap["RiskLevel"] = "MEDIUM"
		propsMap["PolicySummary"] = "Unauthenticated access enabled with role but could not analyze permissions"
		resource.Properties = propsMap
		return l.Send(resource)
	}

	// Create IAM client (IAM is global, use us-east-1)
	iamConfig, err := l.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		slog.Warn("Could not set up IAM client config", "error", err)
		propsMap["RiskLevel"] = "MEDIUM"
		propsMap["PolicySummary"] = "Unauthenticated access enabled but could not create IAM client"
		resource.Properties = propsMap
		return l.Send(resource)
	}

	iamClient := iam.NewFromConfig(iamConfig)

	// Collect all actions from policies
	var allActions []string
	var inlinePolicyNames []string
	var attachedPolicyNames []string

	// Enumerate inline policies
	inlineActions, inlineNames := l.enumerateInlinePolicies(iamClient, roleName)
	allActions = append(allActions, inlineActions...)
	inlinePolicyNames = append(inlinePolicyNames, inlineNames...)

	// Enumerate managed policies
	managedActions, managedNames := l.enumerateManagedPolicies(iamClient, roleName)
	allActions = append(allActions, managedActions...)
	attachedPolicyNames = append(attachedPolicyNames, managedNames...)

	// Classify risk (classic flow bypasses session policies, escalating risk)
	allowClassicFlow, _ := propsMap["AllowClassicFlow"].(bool)
	riskLevel := classifyRisk(allActions, allowUnauth, allowClassicFlow)

	// Build sample credentials command (these APIs can be called without AWS credentials)
	sampleCmd := fmt.Sprintf("aws cognito-identity get-id --identity-pool-id %s --region %s --no-sign-request && aws cognito-identity get-credentials-for-identity --identity-id <identity-id> --region %s --no-sign-request",
		resource.Identifier, resource.Region, resource.Region)

	// Build structured policy summaries for UnauthRolePolicies
	var unauthRolePolicies []map[string]interface{}
	for _, name := range inlinePolicyNames {
		unauthRolePolicies = append(unauthRolePolicies, map[string]interface{}{
			"PolicyName": name,
			"PolicyType": "inline",
		})
	}
	for _, name := range attachedPolicyNames {
		unauthRolePolicies = append(unauthRolePolicies, map[string]interface{}{
			"PolicyName": name,
			"PolicyType": "managed",
		})
	}

	propsMap["PolicyActions"] = allActions
	propsMap["AttachedPolicies"] = attachedPolicyNames
	propsMap["InlinePolicies"] = inlinePolicyNames
	propsMap["UnauthRolePolicies"] = unauthRolePolicies
	propsMap["RiskLevel"] = riskLevel
	propsMap["PolicySummary"] = buildPolicySummary(riskLevel, allActions, roleName, allowClassicFlow)
	propsMap["SampleCommand"] = sampleCmd

	resource.Properties = propsMap
	return l.Send(resource)
}

// enumerateInlinePolicies lists and parses all inline policies for a role.
func (l *CognitoIdentityPoolRoleAnalyzer) enumerateInlinePolicies(client *iam.Client, roleName string) ([]string, []string) {
	var allActions []string
	var policyNames []string

	input := &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	}

	for {
		output, err := client.ListRolePolicies(l.Context(), input)
		if err != nil {
			slog.Warn("Failed to list inline policies", "role", roleName, "error", err)
			break
		}

		for _, policyName := range output.PolicyNames {
			policyNames = append(policyNames, policyName)

			getPolicyOutput, err := client.GetRolePolicy(l.Context(), &iam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &policyName,
			})
			if err != nil {
				slog.Warn("Failed to get inline policy", "role", roleName, "policy", policyName, "error", err)
				continue
			}

			if getPolicyOutput.PolicyDocument != nil {
				actions := parsePolicyDocument(*getPolicyOutput.PolicyDocument)
				allActions = append(allActions, actions...)
			}
		}

		if !output.IsTruncated {
			break
		}
		input.Marker = output.Marker
	}

	return allActions, policyNames
}

// enumerateManagedPolicies lists and parses all managed policies attached to a role.
func (l *CognitoIdentityPoolRoleAnalyzer) enumerateManagedPolicies(client *iam.Client, roleName string) ([]string, []string) {
	var allActions []string
	var policyNames []string

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	}

	for {
		output, err := client.ListAttachedRolePolicies(l.Context(), input)
		if err != nil {
			slog.Warn("Failed to list attached policies", "role", roleName, "error", err)
			break
		}

		for _, policy := range output.AttachedPolicies {
			if policy.PolicyArn == nil {
				continue
			}

			if policy.PolicyName != nil {
				policyNames = append(policyNames, *policy.PolicyName)
			}

			// Get the policy to find the default version
			getPolicyOutput, err := client.GetPolicy(l.Context(), &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			if err != nil {
				slog.Warn("Failed to get managed policy", "arn", *policy.PolicyArn, "error", err)
				continue
			}

			if getPolicyOutput.Policy == nil || getPolicyOutput.Policy.DefaultVersionId == nil {
				continue
			}

			// Get the policy version document
			versionOutput, err := client.GetPolicyVersion(l.Context(), &iam.GetPolicyVersionInput{
				PolicyArn: policy.PolicyArn,
				VersionId: getPolicyOutput.Policy.DefaultVersionId,
			})
			if err != nil {
				slog.Warn("Failed to get policy version", "arn", *policy.PolicyArn, "error", err)
				continue
			}

			if versionOutput.PolicyVersion != nil && versionOutput.PolicyVersion.Document != nil {
				actions := parsePolicyDocument(*versionOutput.PolicyVersion.Document)
				allActions = append(allActions, actions...)
			}
		}

		if !output.IsTruncated {
			break
		}
		input.Marker = output.Marker
	}

	return allActions, policyNames
}

// parsePolicyDocument extracts allowed actions from an IAM policy document.
// The document may be URL-encoded (from GetRolePolicy).
func parsePolicyDocument(document string) []string {
	// URL-decode the document (GetRolePolicy returns URL-encoded)
	decoded, err := url.QueryUnescape(document)
	if err != nil {
		slog.Warn("Failed to URL-decode policy document", "error", err)
		decoded = document
	}

	var policyDoc struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Action    interface{} `json:"Action"`
			NotAction interface{} `json:"NotAction"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(decoded), &policyDoc); err != nil {
		slog.Warn("Failed to parse policy document", "error", err)
		return nil
	}

	var actions []string
	for _, stmt := range policyDoc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// NotAction with Allow is a broad grant (everything except the listed actions)
		if stmt.NotAction != nil {
			switch na := stmt.NotAction.(type) {
			case string:
				slog.Warn("Policy uses Allow with NotAction, treating as broad grant", "NotAction", na)
			case []interface{}:
				slog.Warn("Policy uses Allow with NotAction, treating as broad grant", "NotAction", na)
			default:
				slog.Warn("Policy uses Allow with NotAction, treating as broad grant", "NotAction", na)
			}
			actions = append(actions, "*")
			continue
		}

		switch action := stmt.Action.(type) {
		case string:
			actions = append(actions, action)
		case []interface{}:
			for _, a := range action {
				if s, ok := a.(string); ok {
					actions = append(actions, s)
				}
			}
		}
	}

	return actions
}

// classifyRisk determines the risk level based on the actions granted to the unauthenticated role.
// When allowClassicFlow is true, the Basic (Classic) auth flow bypasses session policy
// restrictions, giving full role permissions -- this escalates any dangerous permission to CRITICAL.
func classifyRisk(actions []string, allowUnauth bool, allowClassicFlow bool) string {
	if !allowUnauth {
		return "NONE"
	}

	if len(actions) == 0 {
		return "LOW"
	}

	highRiskPrefixes := []string{"s3:*", "dynamodb:*", "ec2:*", "lambda:*", "secretsmanager:*", "kms:*"}

	for _, action := range actions {
		// CRITICAL: wildcard or IAM wildcard
		if action == "*" || strings.EqualFold(action, "iam:*") {
			return "CRITICAL"
		}
	}

	for _, action := range actions {
		for _, prefix := range highRiskPrefixes {
			if strings.EqualFold(action, prefix) {
				// Classic flow bypasses session policies, escalate to CRITICAL
				if allowClassicFlow {
					return "CRITICAL"
				}
				return "HIGH"
			}
		}
	}

	// Classic flow with any non-trivial actions escalates to at least HIGH
	// because session policy restrictions are bypassed.
	if allowClassicFlow {
		allReadOnly := true
		for _, action := range actions {
			if !isReadOnlyAction(strings.ToLower(action)) {
				allReadOnly = false
				break
			}
		}
		if !allReadOnly {
			return "HIGH"
		}
	}

	// Check if actions are only read-only/logging
	allReadOnly := true
	for _, action := range actions {
		lower := strings.ToLower(action)
		if !isReadOnlyAction(lower) {
			allReadOnly = false
			break
		}
	}

	if allReadOnly {
		return "LOW"
	}

	return "MEDIUM"
}

// isReadOnlyAction checks if an action is a read-only or logging action.
// The action parameter must already be lowercased.
func isReadOnlyAction(action string) bool {
	// Known safe full actions (logging and default Cognito SDK actions)
	knownSafeActions := []string{
		"logs:createloggroup", "logs:createlogstream", "logs:putlogevents",
		"mobileanalytics:putevents",
		"cognito-sync:listrecords", "cognito-sync:listdatasets",
		"cognito-sync:describeidentitypoolusage", "cognito-sync:describeidentityusage",
		"cognito-sync:describedataset", "cognito-sync:getbulkpublishdetails",
		"cognito-sync:getcognitoevents", "cognito-sync:getidentitypoolconfiguration",
		"cognito-identity:getid",
	}
	for _, safe := range knownSafeActions {
		if action == safe {
			return true
		}
	}

	// Read-only verb prefixes (checked against the action name part after "service:")
	readOnlyVerbPrefixes := []string{"get", "list", "describe", "head"}
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		actionName := parts[1]
		for _, prefix := range readOnlyVerbPrefixes {
			if strings.HasPrefix(actionName, prefix) {
				return true
			}
		}
	}

	return false
}

// extractRoleNameFromArn extracts the role name from an IAM role ARN.
func extractRoleNameFromArn(roleArn string) string {
	// ARN format: arn:aws:iam::ACCOUNT:role/ROLENAME or arn:aws:iam::ACCOUNT:role/path/ROLENAME
	parts := strings.Split(roleArn, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// buildPolicySummary creates a human-readable summary of the risk assessment.
func buildPolicySummary(riskLevel string, actions []string, roleName string, allowClassicFlow bool) string {
	classicFlowNote := ""
	if allowClassicFlow {
		classicFlowNote = " Classic (Basic) auth flow is enabled, bypassing session policy restrictions."
	}

	switch riskLevel {
	case "CRITICAL":
		return fmt.Sprintf("CRITICAL: Unauthenticated role '%s' has wildcard or dangerous permissions (%d actions).%s This allows any unauthenticated user to perform privileged operations.", roleName, len(actions), classicFlowNote)
	case "HIGH":
		return fmt.Sprintf("HIGH: Unauthenticated role '%s' has service-level wildcard permissions (%d actions).%s Unauthenticated users can access sensitive AWS services.", roleName, len(actions), classicFlowNote)
	case "MEDIUM":
		return fmt.Sprintf("MEDIUM: Unauthenticated role '%s' has non-trivial permissions (%d actions). Review actions for potential security impact.", roleName, len(actions))
	case "LOW":
		return fmt.Sprintf("LOW: Unauthenticated role '%s' has limited permissions (%d actions). Mostly read-only or logging actions.", roleName, len(actions))
	default:
		return "Unauthenticated access is disabled."
	}
}
