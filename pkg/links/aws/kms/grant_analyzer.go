package kms

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// KMSKeyLister is a Janus "Start" link that lists KMS keys using the native KMS API.
// This is used when CloudControl does not have permission to list KMS keys.
type KMSKeyLister struct {
	*base.AwsReconLink
	wg sync.WaitGroup
}

func NewKMSKeyLister(configs ...cfg.Config) chain.Link {
	l := &KMSKeyLister{}
	l.AwsReconLink = base.NewAwsReconLink(l, configs...)
	return l
}

func (l *KMSKeyLister) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "KMS Key Lister"}
}

func (l *KMSKeyLister) Params() []cfg.Param {
	params := l.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions())
	return params
}

func (l *KMSKeyLister) Initialize() error {
	return l.AwsReconLink.Initialize()
}

func (l *KMSKeyLister) Process(_ interface{}) error {
	for _, region := range l.Regions {
		l.wg.Add(1)
		go l.listKeysInRegion(region)
	}

	l.wg.Wait()
	slog.Debug("KMS key listing complete")
	return nil
}

func (l *KMSKeyLister) listKeysInRegion(region string) {
	defer l.wg.Done()

	config, err := l.GetConfigWithRuntimeArgs(region)
	if err != nil {
		slog.Warn("Could not create AWS config for KMS key lister", "region", region, "error", err)
		return
	}

	client := kms.NewFromConfig(config)
	message.Info("Listing AWS::KMS::Key resources in %s (profile: %s)", region, l.Profile)

	var keyCount int
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(l.Context())
		if err != nil {
			slog.Warn("Failed to list KMS keys", "region", region, "error", err)
			return
		}

		for _, key := range output.Keys {
			keyID := aws.ToString(key.KeyId)
			keyArnStr := aws.ToString(key.KeyArn)

			// Parse ARN
			parsedArn, err := arn.Parse(keyArnStr)
			if err != nil {
				slog.Warn("Failed to parse KMS key ARN", "arn", keyArnStr, "error", err)
				continue
			}

			resource := types.EnrichedResourceDescription{
				Identifier: keyID,
				TypeName:   "AWS::KMS::Key",
				Region:     region,
				Properties: map[string]interface{}{
					"KeyId":  keyID,
					"KeyArn": keyArnStr,
				},
				AccountId: parsedArn.AccountID,
				Arn:       parsedArn,
			}

			if err := l.Send(resource); err != nil {
				slog.Warn("Failed to send KMS key", "id", keyID, "error", err)
			}
			keyCount++
		}
	}

	slog.Debug("Listed KMS keys", "region", region, "count", keyCount)
}

// extractAccountFromArn extracts the AWS account ID from an ARN
func extractAccountFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// KMSKeyDescribe is a Janus link that adds KMS key configuration details
// including key policy and grant information.
type KMSKeyDescribe struct {
	*base.AwsReconBaseLink
}

func NewKMSKeyDescribe(configs ...cfg.Config) chain.Link {
	l := &KMSKeyDescribe{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *KMSKeyDescribe) Process(resource types.EnrichedResourceDescription) error {
	config, err := l.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Warn("Could not set up client config for KMS key describe", "error", err)
		l.Send(resource)
		return nil
	}

	client := kms.NewFromConfig(config)

	// Convert properties to map
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

	// Get the key ID from properties or identifier
	keyID := resource.Identifier
	if kid, ok := propsMap["KeyId"].(string); ok && kid != "" {
		keyID = kid
	}

	// Describe the key to get metadata
	describeOutput, err := client.DescribeKey(l.Context(), &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		slog.Warn("Failed to describe KMS key", "id", keyID, "error", err)
		l.Send(resource)
		return nil
	}

	// Skip AWS managed keys (they cannot have custom grants/policies)
	if describeOutput.KeyMetadata.KeyManager == kmstypes.KeyManagerTypeAws {
		slog.Debug("Skipping AWS managed key", "id", keyID)
		return nil
	}

	// Add key metadata
	propsMap["KeyId"] = aws.ToString(describeOutput.KeyMetadata.KeyId)
	propsMap["KeyArn"] = aws.ToString(describeOutput.KeyMetadata.Arn)
	propsMap["KeyState"] = string(describeOutput.KeyMetadata.KeyState)
	propsMap["KeyManager"] = string(describeOutput.KeyMetadata.KeyManager)
	propsMap["KeyUsage"] = string(describeOutput.KeyMetadata.KeyUsage)
	if describeOutput.KeyMetadata.Description != nil {
		propsMap["Description"] = aws.ToString(describeOutput.KeyMetadata.Description)
	}

	// Get the key policy
	keyPolicy, err := client.GetKeyPolicy(l.Context(), &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		slog.Warn("Failed to get KMS key policy", "id", keyID, "error", err)
	} else if keyPolicy.Policy != nil {
		propsMap["KeyPolicy"] = aws.ToString(keyPolicy.Policy)
	}

	// List grants on the key
	grants, err := l.listAllGrants(client, keyID)
	if err != nil {
		slog.Warn("Failed to list KMS grants", "id", keyID, "error", err)
	} else {
		propsMap["Grants"] = grants
		propsMap["GrantCount"] = len(grants)
	}

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

// listAllGrants retrieves all grants for a KMS key with pagination
func (l *KMSKeyDescribe) listAllGrants(client *kms.Client, keyID string) ([]map[string]interface{}, error) {
	var allGrants []map[string]interface{}

	paginator := kms.NewListGrantsPaginator(client, &kms.ListGrantsInput{
		KeyId: aws.String(keyID),
	})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(l.Context())
		if err != nil {
			return nil, err
		}

		for _, grant := range output.Grants {
			grantMap := map[string]interface{}{
				"GrantId":          aws.ToString(grant.GrantId),
				"GranteePrincipal": aws.ToString(grant.GranteePrincipal),
				"Operations":       convertOperations(grant.Operations),
			}
			if grant.RetiringPrincipal != nil {
				grantMap["RetiringPrincipal"] = aws.ToString(grant.RetiringPrincipal)
			}
			if grant.Name != nil {
				grantMap["Name"] = aws.ToString(grant.Name)
			}
			if grant.IssuingAccount != nil {
				grantMap["IssuingAccount"] = aws.ToString(grant.IssuingAccount)
			}
			if grant.Constraints != nil {
				grantMap["Constraints"] = convertConstraints(grant.Constraints)
			}
			allGrants = append(allGrants, grantMap)
		}
	}

	return allGrants, nil
}

// convertOperations converts KMS grant operations to string slice
func convertOperations(ops []kmstypes.GrantOperation) []string {
	var result []string
	for _, op := range ops {
		result = append(result, string(op))
	}
	return result
}

// convertConstraints converts grant constraints to a map
func convertConstraints(c *kmstypes.GrantConstraints) map[string]interface{} {
	result := make(map[string]interface{})
	if c.EncryptionContextEquals != nil {
		result["EncryptionContextEquals"] = c.EncryptionContextEquals
	}
	if c.EncryptionContextSubset != nil {
		result["EncryptionContextSubset"] = c.EncryptionContextSubset
	}
	return result
}

// KMSGrantPrivescAnalyzer analyzes KMS keys for grant-based privilege escalation risks
type KMSGrantPrivescAnalyzer struct {
	*base.AwsReconBaseLink
}

func NewKMSGrantPrivescAnalyzer(configs ...cfg.Config) chain.Link {
	l := &KMSGrantPrivescAnalyzer{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *KMSGrantPrivescAnalyzer) Process(resource types.EnrichedResourceDescription) error {
	propsMap, ok := resource.Properties.(map[string]interface{})
	if !ok {
		slog.Debug("Properties not a map, passing through", "id", resource.Identifier)
		return l.Send(resource)
	}

	accountID := resource.AccountId
	keyArn, _ := propsMap["KeyArn"].(string)

	// Analyze key policy for CreateGrant permissions
	var policyFindings []PolicyFinding
	if keyPolicy, ok := propsMap["KeyPolicy"].(string); ok && keyPolicy != "" {
		policyFindings = analyzeKeyPolicyForCreateGrant(keyPolicy, accountID)
	}

	// Analyze existing grants
	var grantFindings []GrantFinding
	if grants, ok := propsMap["Grants"].([]map[string]interface{}); ok {
		grantFindings = analyzeGrants(grants, accountID)
	}

	// Determine overall risk level
	riskLevel, riskReasons := classifyOverallRisk(policyFindings, grantFindings)

	// Skip if no findings (secure baseline)
	if riskLevel == "NONE" {
		slog.Debug("No KMS grant privesc risks found, dropping from output", "id", resource.Identifier)
		return nil
	}

	// Build findings summary
	propsMap["RiskLevel"] = riskLevel
	propsMap["RiskReasons"] = riskReasons
	propsMap["PolicyFindings"] = policyFindingsToMaps(policyFindings)
	propsMap["GrantFindings"] = grantFindingsToMaps(grantFindings)

	// Build exploitation guidance
	propsMap["ExploitationGuidance"] = buildExploitationGuidance(keyArn, policyFindings, grantFindings, resource.Region)

	resource.Properties = propsMap
	return l.Send(resource)
}

// PolicyFinding represents a finding from key policy analysis
type PolicyFinding struct {
	Severity       string
	Principal      string
	Actions        []string
	HasConstraints bool
	Description    string
}

// GrantFinding represents a finding from grant analysis
type GrantFinding struct {
	Severity         string
	GrantID          string
	GranteePrincipal string
	Operations       []string
	HasConstraints   bool
	IsCrossAccount   bool
	Description      string
}

// analyzeKeyPolicyForPrivesc parses key policy and finds privilege escalation patterns
func analyzeKeyPolicyForCreateGrant(policyJSON string, accountID string) []PolicyFinding {
	var findings []PolicyFinding

	var policy struct {
		Statement []struct {
			Sid       string      `json:"Sid"`
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Action    interface{} `json:"Action"`
			Resource  interface{} `json:"Resource"`
			Condition interface{} `json:"Condition"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		slog.Warn("Failed to parse key policy", "error", err)
		return findings
	}

	// Track statements for IAM delegation detection
	rootAccountArn := fmt.Sprintf("arn:aws:iam::%s:root", accountID)
	var hasRootWithKMSWildcard bool // tracks if root account has kms:* (enables IAM delegation)

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := normalizeToStringSlice(stmt.Action)
		hasCreateGrant := false
		hasKMSWildcard := false
		hasCryptoOps := false
		var relevantActions []string

		cryptoActions := map[string]bool{
			"kms:decrypt": true, "kms:encrypt": true, "kms:generatedatakey": true,
			"kms:generatedatakey*": true, "kms:generatedatakeywithoutplaintext": true,
			"kms:reencryptfrom": true, "kms:reencryptto": true, "kms:reencrypt*": true,
		}

		for _, action := range actions {
			actionLower := strings.ToLower(action)
			if actionLower == "kms:creategrant" {
				hasCreateGrant = true
				relevantActions = append(relevantActions, action)
			} else if actionLower == "kms:*" || actionLower == "*" {
				hasCreateGrant = true
				hasKMSWildcard = true
				hasCryptoOps = true
				relevantActions = append(relevantActions, action)
			} else if cryptoActions[actionLower] {
				hasCryptoOps = true
				relevantActions = append(relevantActions, action)
			}
		}

		principals := extractPrincipals(stmt.Principal)
		conditionInfo := parseConditions(stmt.Condition)

		// Check if root account has kms:* - this enables IAM delegation model
		for _, p := range principals {
			if p == rootAccountArn && hasKMSWildcard {
				hasRootWithKMSWildcard = true
			}
		}

		for _, principal := range principals {
			// Check for wildcard principal with crypto operations (even without CreateGrant)
			if principal == "*" && hasCryptoOps {
				severity, description := classifyWildcardPrincipalRisk(accountID, relevantActions, conditionInfo)
				if severity != "NONE" {
					findings = append(findings, PolicyFinding{
						Severity:       severity,
						Principal:      principal,
						Actions:        relevantActions,
						HasConstraints: conditionInfo.hasConditions,
						Description:    description,
					})
				}
				continue
			}

			// Check for CreateGrant permissions
			if hasCreateGrant {
				severity, description := classifyPolicyStatementRisk(
					principal, accountID, relevantActions, hasKMSWildcard, conditionInfo,
				)
				if severity != "NONE" {
					findings = append(findings, PolicyFinding{
						Severity:       severity,
						Principal:      principal,
						Actions:        relevantActions,
						HasConstraints: conditionInfo.hasConditions,
						Description:    description,
					})
				}
			}
		}
	}

	// Check for IAM delegation model: if root account has kms:*, IAM policies can grant access
	// This requires IAM policy evaluation to determine who can actually access the key
	if hasRootWithKMSWildcard {
		findings = append(findings, PolicyFinding{
			Severity:       "INFO",
			Principal:      rootAccountArn,
			Actions:        []string{"kms:*"},
			HasConstraints: false,
			Description:    "Key uses IAM delegation model (root account has kms:*) - requires IAM policy evaluation to determine actual access",
		})
	}

	return findings
}

// ConditionInfo holds parsed condition details for risk classification
type ConditionInfo struct {
	hasConditions            bool
	hasGrantIsForAWSResource bool
	grantIsForAWSResourceVal bool // true if GrantIsForAWSResource=true
	hasViaService            bool
	hasCalledVia             bool
	hasPrincipalOrgID        bool
	hasPrincipalAccount      bool
	hasPrincipalArn          bool
	hasPrincipalTag          bool
	principalArnPattern      string // for StringLike patterns
}

// parseConditions extracts relevant condition information
func parseConditions(condition interface{}) ConditionInfo {
	info := ConditionInfo{}
	if condition == nil {
		return info
	}

	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return info
	}

	info.hasConditions = true

	// Check for Bool conditions
	if boolCond, ok := condMap["Bool"].(map[string]interface{}); ok {
		if val, ok := boolCond["kms:GrantIsForAWSResource"]; ok {
			info.hasGrantIsForAWSResource = true
			// Value can be string "true"/"false" or bool
			switch v := val.(type) {
			case string:
				info.grantIsForAWSResourceVal = strings.ToLower(v) == "true"
			case bool:
				info.grantIsForAWSResourceVal = v
			}
		}
	}

	// Check for StringEquals conditions
	if strEquals, ok := condMap["StringEquals"].(map[string]interface{}); ok {
		if _, ok := strEquals["kms:ViaService"]; ok {
			info.hasViaService = true
		}
		if _, ok := strEquals["aws:PrincipalOrgID"]; ok {
			info.hasPrincipalOrgID = true
		}
		if _, ok := strEquals["aws:PrincipalAccount"]; ok {
			info.hasPrincipalAccount = true
		}
		if _, ok := strEquals["aws:PrincipalTag/KMSAccess"]; ok {
			info.hasPrincipalTag = true
		}
	}

	// Check for StringLike conditions (often used for role patterns)
	if strLike, ok := condMap["StringLike"].(map[string]interface{}); ok {
		if pattern, ok := strLike["aws:PrincipalArn"].(string); ok {
			info.hasPrincipalArn = true
			info.principalArnPattern = pattern
		}
	}

	// Check for ArnLike conditions
	if arnLike, ok := condMap["ArnLike"].(map[string]interface{}); ok {
		if pattern, ok := arnLike["aws:PrincipalArn"].(string); ok {
			info.hasPrincipalArn = true
			info.principalArnPattern = pattern
		}
	}

	// Check for ForAnyValue:StringEquals (CalledVia)
	if forAny, ok := condMap["ForAnyValue:StringEquals"].(map[string]interface{}); ok {
		if _, ok := forAny["aws:CalledVia"]; ok {
			info.hasCalledVia = true
		}
	}

	return info
}

// isAdminRole checks if a principal appears to be an administrative role
func isAdminRole(principal string) bool {
	principalLower := strings.ToLower(principal)
	adminPatterns := []string{
		"terraform",
		"admin",
		"administrator",
		"cloudformation",
		"cdk",
		"pulumi",
		"crossplane",
		"organizationaccountaccessrole",
		"awsreservedsso",
		"stacksets",
	}
	for _, pattern := range adminPatterns {
		if strings.Contains(principalLower, pattern) {
			return true
		}
	}
	return false
}

// classifyPolicyStatementRisk determines risk level with smarter logic
func classifyPolicyStatementRisk(principal, accountID string, actions []string, hasKMSWildcard bool, cond ConditionInfo) (string, string) {
	// Root account is expected to have full access - skip entirely
	if principal == fmt.Sprintf("arn:aws:iam::%s:root", accountID) {
		return "NONE", ""
	}

	// Check if this is an admin role with kms:*
	if hasKMSWildcard && isAdminRole(principal) {
		// Admin roles with kms:* are expected - skip
		return "NONE", ""
	}

	// Wildcard principal analysis
	if principal == "*" {
		return classifyWildcardPrincipalRisk(accountID, actions, cond)
	}

	// Specific principal analysis
	return classifySpecificPrincipalRisk(principal, accountID, actions, hasKMSWildcard, cond)
}

// classifyWildcardPrincipalRisk handles Principal: "*" cases
func classifyWildcardPrincipalRisk(accountID string, actions []string, cond ConditionInfo) (string, string) {
	// No conditions at all - CRITICAL
	if !cond.hasConditions {
		return "CRITICAL", "Wildcard principal (*) with unrestricted access"
	}

	// Check for organization-wide access
	if cond.hasPrincipalOrgID {
		return "HIGH", "Wildcard principal with PrincipalOrgID condition - organization-wide access"
	}

	// Check for account-wide access
	if cond.hasPrincipalAccount {
		// Check if CreateGrant is in actions
		hasCreateGrant := false
		for _, a := range actions {
			if strings.ToLower(a) == "kms:creategrant" {
				hasCreateGrant = true
				break
			}
		}
		if hasCreateGrant {
			return "CRITICAL", "Wildcard principal with PrincipalAccount condition AND CreateGrant - any principal in account can escalate"
		}
		return "HIGH", "Wildcard principal with PrincipalAccount condition - account-wide access"
	}

	// Check for role pattern (StringLike on PrincipalArn)
	if cond.hasPrincipalArn && strings.Contains(cond.principalArnPattern, "*") {
		return "HIGH", fmt.Sprintf("Wildcard principal with role pattern condition (%s) - new roles matching pattern can access", cond.principalArnPattern)
	}

	// Check for tag-based condition
	if cond.hasPrincipalTag {
		return "HIGH", "Wildcard principal with PrincipalTag condition - bypassable via iam:TagRole or sts:TagSession"
	}

	// Check for ViaService condition
	if cond.hasViaService {
		return "MEDIUM", "Wildcard principal with ViaService condition - any principal using the service can access"
	}

	// Check for CalledVia condition
	if cond.hasCalledVia {
		return "MEDIUM", "Wildcard principal with CalledVia condition - service chaining may allow access"
	}

	// Unknown condition type - flag as MEDIUM for review
	return "MEDIUM", "Wildcard principal with conditions - review required"
}

// classifySpecificPrincipalRisk handles specific IAM principal cases
func classifySpecificPrincipalRisk(principal, accountID string, actions []string, hasKMSWildcard bool, cond ConditionInfo) (string, string) {
	isRole := strings.Contains(principal, ":role/")
	isUser := strings.Contains(principal, ":user/")

	// Check if this is kms:* (full KMS access) for non-admin
	if hasKMSWildcard {
		if isRole || isUser {
			return "HIGH", fmt.Sprintf("Principal %s has kms:* (full KMS access including CreateGrant)", principal)
		}
	}

	// Check for CreateGrant specifically
	hasCreateGrant := false
	for _, a := range actions {
		if strings.ToLower(a) == "kms:creategrant" {
			hasCreateGrant = true
			break
		}
	}

	if !hasCreateGrant {
		return "NONE", ""
	}

	// CreateGrant with GrantIsForAWSResource=true is the SECURE pattern - INFO only
	if cond.hasGrantIsForAWSResource && cond.grantIsForAWSResourceVal {
		return "INFO", fmt.Sprintf("Principal %s has CreateGrant with GrantIsForAWSResource=true (secure pattern)", principal)
	}

	// CreateGrant with GrantIsForAWSResource=false is explicitly insecure
	if cond.hasGrantIsForAWSResource && !cond.grantIsForAWSResourceVal {
		return "CRITICAL", fmt.Sprintf("Principal %s has CreateGrant with GrantIsForAWSResource=false (explicitly allows arbitrary grants)", principal)
	}

	// CreateGrant without GrantIsForAWSResource condition
	if isRole || isUser {
		if !cond.hasConditions {
			return "CRITICAL", fmt.Sprintf("Principal %s has CreateGrant without conditions - can grant to arbitrary principals", principal)
		}
		return "HIGH", fmt.Sprintf("Principal %s has CreateGrant with conditions but missing GrantIsForAWSResource", principal)
	}

	// Service principals are generally lower risk
	if strings.HasSuffix(principal, ".amazonaws.com") {
		return "LOW", fmt.Sprintf("Service principal %s has CreateGrant", principal)
	}

	return "MEDIUM", fmt.Sprintf("Principal %s has CreateGrant", principal)
}

// analyzeGrants examines existing grants for overly permissive configurations
func analyzeGrants(grants []map[string]interface{}, accountID string) []GrantFinding {
	var findings []GrantFinding

	cryptoOps := map[string]bool{
		"Decrypt":                         true,
		"Encrypt":                         true,
		"GenerateDataKey":                 true,
		"GenerateDataKeyWithoutPlaintext": true,
		"ReEncryptFrom":                   true,
		"ReEncryptTo":                     true,
	}

	delegationOps := map[string]bool{
		"CreateGrant": true,
		"RetireGrant": true,
	}

	for _, grant := range grants {
		grantID, _ := grant["GrantId"].(string)
		granteePrincipal, _ := grant["GranteePrincipal"].(string)
		operations, _ := grant["Operations"].([]string)
		constraints := grant["Constraints"]

		if operations == nil {
			// Try to convert from []interface{}
			if opsInterface, ok := grant["Operations"].([]interface{}); ok {
				for _, op := range opsInterface {
					if opStr, ok := op.(string); ok {
						operations = append(operations, opStr)
					}
				}
			}
		}

		var hasConstraints bool
		if constraints != nil {
			if constraintMap, ok := constraints.(map[string]interface{}); ok {
				hasConstraints = len(constraintMap) > 0
			}
		}

		isCrossAccount := !strings.Contains(granteePrincipal, accountID) &&
			!strings.HasPrefix(granteePrincipal, "arn:aws:iam::"+accountID)

		// Categorize operations
		var cryptoOperations []string
		var delegationOperations []string
		for _, op := range operations {
			if cryptoOps[op] {
				cryptoOperations = append(cryptoOperations, op)
			}
			if delegationOps[op] {
				delegationOperations = append(delegationOperations, op)
			}
		}

		// Check for delegation operations (CreateGrant, RetireGrant)
		if len(delegationOperations) > 0 {
			severity := "HIGH"
			description := fmt.Sprintf("Grant includes delegation operations %v - enables cascading privilege escalation", delegationOperations)

			if isCrossAccount {
				severity = "CRITICAL"
				description = fmt.Sprintf("Cross-account grant with delegation operations %v", delegationOperations)
			}

			findings = append(findings, GrantFinding{
				Severity:         severity,
				GrantID:          grantID,
				GranteePrincipal: granteePrincipal,
				Operations:       delegationOperations,
				HasConstraints:   hasConstraints,
				IsCrossAccount:   isCrossAccount,
				Description:      description,
			})
		}

		// Check for crypto operations
		if len(cryptoOperations) > 0 {
			// Cross-account grants with crypto operations are HIGH/CRITICAL
			if isCrossAccount {
				findings = append(findings, GrantFinding{
					Severity:         "CRITICAL",
					GrantID:          grantID,
					GranteePrincipal: granteePrincipal,
					Operations:       cryptoOperations,
					HasConstraints:   hasConstraints,
					IsCrossAccount:   true,
					Description:      fmt.Sprintf("Cross-account grant allows crypto operations %v", cryptoOperations),
				})
				continue
			}

			// Same-account grants: only flag if unconstrained AND broad
			if !hasConstraints && len(cryptoOperations) >= 2 {
				findings = append(findings, GrantFinding{
					Severity:         "HIGH",
					GrantID:          grantID,
					GranteePrincipal: granteePrincipal,
					Operations:       cryptoOperations,
					HasConstraints:   false,
					IsCrossAccount:   false,
					Description:      fmt.Sprintf("Unconstrained grant allows broad crypto operations: %v", cryptoOperations),
				})
			}
			// Constrained same-account grants with crypto ops are INFO (expected pattern)
			// We don't add a finding for these - they're secure
		}
	}

	return findings
}

// classifyOverallRisk determines the overall risk level from all findings
func classifyOverallRisk(policyFindings []PolicyFinding, grantFindings []GrantFinding) (string, []string) {
	var reasons []string
	maxRisk := "NONE"

	riskPriority := map[string]int{
		"NONE":     0,
		"INFO":     1,
		"LOW":      2,
		"MEDIUM":   3,
		"HIGH":     4,
		"CRITICAL": 5,
	}

	for _, f := range policyFindings {
		if riskPriority[f.Severity] > riskPriority[maxRisk] {
			maxRisk = f.Severity
		}
		reasons = append(reasons, f.Description)
	}

	for _, f := range grantFindings {
		if riskPriority[f.Severity] > riskPriority[maxRisk] {
			maxRisk = f.Severity
		}
		reasons = append(reasons, f.Description)
	}

	return maxRisk, reasons
}

// buildPolicyFindingDescription creates a human-readable description
func buildPolicyFindingDescription(principal string, actions []string, hasConditions bool) string {
	constraint := "without constraints"
	if hasConditions {
		constraint = "with conditions"
	}
	return fmt.Sprintf("Principal %s has %v %s", principal, actions, constraint)
}

// buildExploitationGuidance generates exploitation commands
func buildExploitationGuidance(keyArn string, policyFindings []PolicyFinding, grantFindings []GrantFinding, region string) map[string]string {
	guidance := make(map[string]string)

	// If policy allows CreateGrant, show self-escalation command
	for _, f := range policyFindings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			guidance["create_grant_self_escalation"] = fmt.Sprintf(
				"# Create a grant giving yourself Decrypt permission\n"+
					"aws kms create-grant --key-id %s --grantee-principal <YOUR_ARN> "+
					"--operations Decrypt GenerateDataKey --region %s",
				keyArn, region)
			break
		}
	}

	// If there are existing grants with Decrypt, show usage
	for _, f := range grantFindings {
		for _, op := range f.Operations {
			if op == "Decrypt" {
				guidance["use_existing_grant"] = fmt.Sprintf(
					"# Use existing grant to decrypt data\n"+
						"# Assume the grantee principal: %s\n"+
						"aws kms decrypt --key-id %s --ciphertext-blob fileb://encrypted.bin --region %s",
					f.GranteePrincipal, keyArn, region)
				break
			}
		}
	}

	// List grants command
	guidance["list_grants"] = fmt.Sprintf(
		"# List all grants on this key\n"+
			"aws kms list-grants --key-id %s --region %s",
		keyArn, region)

	return guidance
}

// Helper functions

func normalizeToStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return val
	}
	return nil
}

func extractPrincipals(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case map[string]interface{}:
		var result []string
		if aws, ok := val["AWS"]; ok {
			result = append(result, normalizeToStringSlice(aws)...)
		}
		if service, ok := val["Service"]; ok {
			result = append(result, normalizeToStringSlice(service)...)
		}
		if federated, ok := val["Federated"]; ok {
			result = append(result, normalizeToStringSlice(federated)...)
		}
		return result
	}
	return nil
}

func policyFindingsToMaps(findings []PolicyFinding) []map[string]interface{} {
	var result []map[string]interface{}
	for _, f := range findings {
		result = append(result, map[string]interface{}{
			"Severity":       f.Severity,
			"Principal":      f.Principal,
			"Actions":        f.Actions,
			"HasConstraints": f.HasConstraints,
			"Description":    f.Description,
		})
	}
	return result
}

func grantFindingsToMaps(findings []GrantFinding) []map[string]interface{} {
	var result []map[string]interface{}
	for _, f := range findings {
		result = append(result, map[string]interface{}{
			"Severity":         f.Severity,
			"GrantID":          f.GrantID,
			"GranteePrincipal": f.GranteePrincipal,
			"Operations":       f.Operations,
			"HasConstraints":   f.HasConstraints,
			"IsCrossAccount":   f.IsCrossAccount,
			"Description":      f.Description,
		})
	}
	return result
}
