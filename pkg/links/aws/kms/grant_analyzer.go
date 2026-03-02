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

// analyzeKeyPolicyForCreateGrant parses key policy and finds CreateGrant permissions
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

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := normalizeToStringSlice(stmt.Action)
		hasCreateGrant := false
		var grantActions []string

		for _, action := range actions {
			actionLower := strings.ToLower(action)
			if actionLower == "kms:creategrant" || actionLower == "kms:*" || actionLower == "*" {
				hasCreateGrant = true
				grantActions = append(grantActions, action)
			}
		}

		if !hasCreateGrant {
			continue
		}

		principals := extractPrincipals(stmt.Principal)
		hasConditions := stmt.Condition != nil

		for _, principal := range principals {
			severity := classifyPrincipalRisk(principal, accountID, hasConditions, grantActions)
			if severity != "NONE" {
				findings = append(findings, PolicyFinding{
					Severity:       severity,
					Principal:      principal,
					Actions:        grantActions,
					HasConstraints: hasConditions,
					Description:    buildPolicyFindingDescription(principal, grantActions, hasConditions),
				})
			}
		}
	}

	return findings
}

// analyzeGrants examines existing grants for overly permissive configurations
func analyzeGrants(grants []map[string]interface{}, accountID string) []GrantFinding {
	var findings []GrantFinding

	highRiskOps := map[string]bool{
		"Decrypt":                         true,
		"Encrypt":                         true,
		"GenerateDataKey":                 true,
		"GenerateDataKeyWithoutPlaintext": true,
		"ReEncryptFrom":                   true,
		"ReEncryptTo":                     true,
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

		hasConstraints := constraints != nil && len(constraints.(map[string]interface{})) > 0
		isCrossAccount := !strings.Contains(granteePrincipal, accountID) && !strings.HasPrefix(granteePrincipal, "arn:aws:iam::"+accountID)

		// Check for high-risk operations
		var riskyOps []string
		for _, op := range operations {
			if highRiskOps[op] {
				riskyOps = append(riskyOps, op)
			}
		}

		if len(riskyOps) == 0 {
			continue
		}

		severity := "MEDIUM"
		description := fmt.Sprintf("Grant allows %v operations", riskyOps)

		if isCrossAccount {
			severity = "HIGH"
			description = fmt.Sprintf("Cross-account grant allows %v operations", riskyOps)
		}

		if !hasConstraints && len(riskyOps) >= 3 {
			if severity == "MEDIUM" {
				severity = "HIGH"
			}
			description = fmt.Sprintf("Unconstrained grant allows broad crypto operations: %v", riskyOps)
		}

		findings = append(findings, GrantFinding{
			Severity:         severity,
			GrantID:          grantID,
			GranteePrincipal: granteePrincipal,
			Operations:       riskyOps,
			HasConstraints:   hasConstraints,
			IsCrossAccount:   isCrossAccount,
			Description:      description,
		})
	}

	return findings
}

// classifyPrincipalRisk determines risk level based on principal configuration
func classifyPrincipalRisk(principal string, accountID string, hasConditions bool, actions []string) string {
	// Root account is expected to have full access
	if principal == fmt.Sprintf("arn:aws:iam::%s:root", accountID) {
		return "NONE"
	}

	// Wildcard principal with account condition is HIGH risk
	if principal == "*" {
		if hasConditions {
			return "HIGH" // Any principal in account can CreateGrant
		}
		return "CRITICAL" // Any principal anywhere can CreateGrant
	}

	// Check if actions include kms:* (full KMS access)
	for _, action := range actions {
		if action == "kms:*" || action == "*" {
			if !hasConditions {
				return "HIGH"
			}
			return "MEDIUM"
		}
	}

	// Regular IAM principal with CreateGrant
	if strings.Contains(principal, ":role/") || strings.Contains(principal, ":user/") {
		if !hasConditions {
			return "CRITICAL" // Can self-escalate
		}
		return "MEDIUM"
	}

	// Service principals are generally lower risk
	if strings.HasSuffix(principal, ".amazonaws.com") {
		return "LOW"
	}

	return "MEDIUM"
}

// classifyOverallRisk determines the overall risk level from all findings
func classifyOverallRisk(policyFindings []PolicyFinding, grantFindings []GrantFinding) (string, []string) {
	var reasons []string
	maxRisk := "NONE"

	riskPriority := map[string]int{
		"NONE":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
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
