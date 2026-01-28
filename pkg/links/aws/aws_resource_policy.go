package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePolicyChecker struct {
	*base.AwsReconLink
	orgPolicies *orgpolicies.OrgPolicies
}

func NewAwsResourcePolicyChecker(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyChecker{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyChecker) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsOrgPoliciesFile())
	return params
}

func (a *AwsResourcePolicyChecker) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Load org policies if file is provided
	orgPoliciesFile, _ := cfg.As[string](a.Arg("org-policies"))
	if orgPoliciesFile != "" {
		slog.Debug("Loading organization policies", "file", orgPoliciesFile)
		orgPolicies, err := loadOrgPoliciesFromFile(orgPoliciesFile)
		if err != nil {
			slog.Error("Failed to load org policies", "file", orgPoliciesFile, "error", err)
			return fmt.Errorf("failed to load org policies from %s: %w", orgPoliciesFile, err)
		}
		a.orgPolicies = orgPolicies
		slog.Info("Successfully loaded organization policies", "file", orgPoliciesFile, "scps", len(orgPolicies.SCPs), "rcps", len(orgPolicies.RCPs))
	}

	return nil
}

// loadOrgPoliciesFromFile loads organization policies from a JSON file
func loadOrgPoliciesFromFile(filePath string) (*orgpolicies.OrgPolicies, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var orgPolicies orgpolicies.OrgPolicies
	if err := json.Unmarshal(data, &orgPolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &orgPolicies, nil
}

func (a *AwsResourcePolicyChecker) Process(resource *types.EnrichedResourceDescription) error {
	// Check if we have a configuration for this resource type
	serviceConfig, ok := ServiceMap[resource.TypeName]
	if !ok {
		// Skip this resource type
		return nil
	}

	// Parse resource properties
	var props map[string]any
	switch p := resource.Properties.(type) {
	case string:
		err := json.Unmarshal([]byte(p), &props)
		if err != nil {
			return fmt.Errorf("failed to unmarshal resource properties: %w", err)
		}
	case map[string]any:
		props = p
	default:
		return fmt.Errorf("unexpected properties type: %T", resource.Properties)
	}

	// Extract the identifier
	identifier, ok := props[serviceConfig.IdentifierField]
	if !ok {
		return fmt.Errorf("resource does not have identifier field '%s'", serviceConfig.IdentifierField)
	}

	identifierStr, ok := identifier.(string)
	if !ok {
		return fmt.Errorf("identifier is not a string: %v", identifier)
	}

	// Get AWS config
	awsCfg, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config", "region", resource.Region, "error", err)
		return nil // Continue with other resources
	}

	// Delegate to S3-specific handler (has additional checks: BPA, object-level policies, ACLs)
	if resource.TypeName == "AWS::S3::Bucket" {
		return a.processS3Bucket(resource, awsCfg, props, identifierStr, serviceConfig)
	}

	// Standard flow for non-S3 resources
	return a.processStandardResource(resource, awsCfg, props, identifierStr, serviceConfig)
}

// processStandardResource handles policy analysis for non-S3 resources
func (a *AwsResourcePolicyChecker) processStandardResource(
	resource *types.EnrichedResourceDescription,
	awsCfg aws.Config,
	props map[string]any,
	identifierStr string,
	serviceConfig ServicePolicyConfig,
) error {
	// Get the policy
	policy, err := ServiceMap[resource.TypeName].GetPolicy(context.TODO(), awsCfg, identifierStr, a.Regions)
	if err != nil {
		slog.Debug("Failed to get policy", "resource", identifierStr, "type", resource.TypeName, "error", err)
		return nil // Continue with other resources
	}

	// Skip if no policy
	if policy == nil {
		return nil
	}

	policyJson, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		slog.Debug(fmt.Sprintf("policy for %s (failed to marshal): %v", resource.Arn.String(), err))
	} else {
		slog.Debug(fmt.Sprintf("policy for %s", resource.Arn.String()), "policy", string(policyJson))
	}

	// Check if the policy allows public access
	res, err := a.analyzePolicy(resource.Arn.String(), policy, resource.AccountId, resource.TypeName)
	if err != nil {
		slog.Error("Failed to analyze policy", "resource", identifierStr, "error", err)
		return err
	}

	// Skip if not public
	if !isPublic(res) {
		return nil
	}

	// Flag public resource
	a.flagPublicResource(resource, props, policy, res, serviceConfig, "Policy")
	return nil
}

// processS3Bucket handles S3-specific public access detection
// S3 requires additional checks: Block Public Access settings, object-level policies, and ACLs
func (a *AwsResourcePolicyChecker) processS3Bucket(
	resource *types.EnrichedResourceDescription,
	awsCfg aws.Config,
	props map[string]any,
	bucketName string,
	serviceConfig ServicePolicyConfig,
) error {
	ctx := context.TODO()

	// Step 0: Get bucket location and create region-specific client
	// This avoids PermanentRedirect errors when bucket is in a different region
	client := s3.NewFromConfig(awsCfg)
	locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		slog.Debug("Failed to get bucket location", "bucket", bucketName, "error", err)
		return nil
	}

	// Handle empty LocationConstraint (means us-east-1)
	bucketRegion := "us-east-1"
	if locationResp.LocationConstraint != "" {
		bucketRegion = string(locationResp.LocationConstraint)
	}

	// Check if the bucket's region is in the allowed regions list
	if !slices.Contains(a.Regions, bucketRegion) {
		slog.Debug("Bucket region not in allowed regions list", "bucket", bucketName, "bucketRegion", bucketRegion, "allowedRegions", a.Regions)
		return nil
	}

	// Create region-specific client if bucket is in a different region
	if bucketRegion != awsCfg.Region {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = bucketRegion
		client = s3.NewFromConfig(regionCfg)
		slog.Debug("Created region-specific S3 client", "bucket", bucketName, "region", bucketRegion)
	}

	// Step 1: Fetch BPA, policy, and ACL data in parallel for better performance
	var (
		bpa       *S3BPAStatus
		policy    *types.Policy
		policyErr error
		aclResult S3ACLResult
		wg        sync.WaitGroup
	)

	wg.Add(3)

	// Fetch BPA settings
	go func() {
		defer wg.Done()
		bpa = a.checkS3BlockPublicAccess(ctx, client, bucketName)
		if bpa != nil {
			slog.Debug("Retrieved BPA settings", "bucket", bucketName, "reason", bpa.Reason)
		}
	}()

	// Fetch bucket policy
	go func() {
		defer wg.Done()
		policy, policyErr = getS3BucketPolicy(ctx, client, bucketName)
		if policyErr != nil {
			slog.Debug("Failed to get policy", "resource", bucketName, "error", policyErr)
		}
	}()

	// Fetch ACL data
	go func() {
		defer wg.Done()
		aclResult = a.checkS3PublicACLs(ctx, client, bucketName)
	}()

	// Wait for all parallel fetches to complete
	wg.Wait()

	// Step 2: Apply BPA logic to determine what to process
	// Skip entire bucket only if BOTH flags are true (fully protected)
	if bpa != nil && bpa.IgnorePublicAcls && bpa.RestrictPublicBuckets {
		slog.Debug("Skipping bucket - fully protected by BPA", "bucket", bucketName, "reason", bpa.Reason)
		return nil
	}

	var policyResults []*iam.EvaluationResult
	policyIsPublic := false

	// Step 3: Analyze bucket policy (skip if RestrictPublicBuckets blocks policy-based access)
	if bpa == nil || !bpa.RestrictPublicBuckets {
		if policyErr == nil && policy != nil {
			// Log policy for debugging
			if policyJson, err := json.MarshalIndent(policy, "", "  "); err == nil {
				slog.Debug(fmt.Sprintf("policy for %s", resource.Arn.String()), "policy", string(policyJson))
			}

			// Analyze bucket-level policy
			policyResults, err = a.analyzePolicy(resource.Arn.String(), policy, resource.AccountId, resource.TypeName)
			if err != nil {
				slog.Error("Failed to analyze policy", "resource", bucketName, "error", err)
				return err
			}

			// Also check object-level permissions (e.g., s3:GetObject on bucket/*)
			// Policies often grant access to objects, not the bucket itself
			if !isPublic(policyResults) {
				objectRes, err := a.analyzeS3ObjectPolicy(resource.Arn.String(), policy, resource.AccountId)
				if err != nil {
					slog.Debug("Failed to analyze S3 object policy", "resource", bucketName, "error", err)
				} else if isPublic(objectRes) {
					slog.Debug("S3 bucket has public object-level access", "bucket", bucketName)
					policyResults = append(policyResults, objectRes...)
				}
			}

			policyIsPublic = isPublic(policyResults)
			if policyIsPublic {
				a.flagPublicResource(resource, props, policy, policyResults, serviceConfig, "Policy")
			}
		} else if policy == nil && policyErr == nil {
			slog.Debug("S3 bucket has no policy, checking ACLs", "bucket", bucketName)
		}
	} else {
		slog.Debug("Skipping policy check - RestrictPublicBuckets is enabled", "bucket", bucketName)
	}

	// Step 4: Process ACL results (skip if IgnorePublicAcls blocks ACL-based access)
	// ACLs are additive (can't deny), so skip if already public via policy
	if !policyIsPublic && (bpa == nil || !bpa.IgnorePublicAcls) {
		if len(aclResult.ACLGrants) > 0 {
			slog.Debug("Bucket has public ACL grants", "bucket", bucketName, "grants", aclResult.ACLGrants, "granteeType", aclResult.GranteeType)
			a.flagS3PublicACL(resource, props, aclResult)
		}
	} else if bpa != nil && bpa.IgnorePublicAcls {
		slog.Debug("Skipping ACL check - IgnorePublicAcls is enabled", "bucket", bucketName)
	}

	return nil
}

// flagPublicResource sends an enriched resource for a public policy finding
func (a *AwsResourcePolicyChecker) flagPublicResource(
	resource *types.EnrichedResourceDescription,
	props map[string]any,
	policy *types.Policy,
	results []*iam.EvaluationResult,
	serviceConfig ServicePolicyConfig,
	source string,
) {
	props[serviceConfig.PolicyField] = policy
	props["PublicAccessSource"] = source
	props["EvaluationReasons"] = getUnqiueDetails(results)
	props["NeedsManualTriage"] = hasInconclusiveConditions(results)
	props["Actions"] = getAllowedActions(results)

	enriched := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: props,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}
	a.Send(enriched)
}

// flagS3PublicACL sends an enriched resource for an S3 ACL-based public access finding
func (a *AwsResourcePolicyChecker) flagS3PublicACL(
	resource *types.EnrichedResourceDescription,
	props map[string]any,
	aclResult S3ACLResult,
) {
	props["PublicAccessSource"] = "ACL"
	props["ACLGrants"] = aclResult.ACLGrants
	props["GranteeType"] = aclResult.GranteeType
	props["EvaluationReasons"] = []string{fmt.Sprintf("Bucket ACL grants %v to %s", aclResult.ACLGrants, aclResult.GranteeType)}
	props["NeedsManualTriage"] = false
	props["Actions"] = aclResult.ACLGrants // ACL permissions map to actions

	enriched := types.EnrichedResourceDescription{
		Identifier: resource.Identifier,
		TypeName:   resource.TypeName,
		Region:     resource.Region,
		Properties: props,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}
	a.Send(enriched)
}

// ConditionPermutation represents a condition key and its possible values
type ConditionPermutation struct {
	Key    string
	Values []string // Include "" for missing/absent
}

// ContextGenerator generates comprehensive context permutations for testing
type ContextGenerator struct {
	BasePrincipals []string
	Conditions     []ConditionPermutation
}

// Bool helper function for creating *bool values
func Bool(b bool) *bool {
	return &b
}

// GenerateAllPermutations creates all combinations of contexts with condition permutations
func (cg *ContextGenerator) GenerateAllPermutations() []*iam.RequestContext {
	contexts := []*iam.RequestContext{}

	// Add base principal contexts first (existing behavior)
	for _, principal := range cg.BasePrincipals {
		ctx := &iam.RequestContext{
			PrincipalArn:      principal,
			RequestParameters: make(map[string]string),
		}
		contexts = append(contexts, ctx)
	}

	// Generate all condition combinations for wildcard principal
	permutations := cg.generateConditionPermutations()

	for _, perm := range permutations {
		ctx := &iam.RequestContext{
			PrincipalArn:      "*", // Wildcard for public access testing
			RequestParameters: make(map[string]string),
		}

		cg.applyPermutation(ctx, perm)
		contexts = append(contexts, ctx)
	}

	return contexts
}

// generateConditionPermutations creates all combinations of condition values
func (cg *ContextGenerator) generateConditionPermutations() []map[string]string {
	if len(cg.Conditions) == 0 {
		return []map[string]string{{}}
	}

	// Calculate total permutations
	totalPerms := 1
	for _, condition := range cg.Conditions {
		totalPerms *= len(condition.Values)
	}

	permutations := make([]map[string]string, totalPerms)

	// Generate all combinations
	for i := 0; i < totalPerms; i++ {
		perm := make(map[string]string)
		temp := i

		for _, condition := range cg.Conditions {
			valueIndex := temp % len(condition.Values)
			value := condition.Values[valueIndex]
			if value != "" { // Only include non-empty values
				perm[condition.Key] = value
			}
			temp /= len(condition.Values)
		}

		permutations[i] = perm
	}

	return permutations
}

// applyPermutation applies condition values to a RequestContext
func (cg *ContextGenerator) applyPermutation(ctx *iam.RequestContext, perm map[string]string) {
	for key, value := range perm {
		switch key {
		// Direct RequestContext fields
		case "aws:SecureTransport":
			if value == "true" {
				ctx.SecureTransport = Bool(true)
			} else if value == "false" {
				ctx.SecureTransport = Bool(false)
			}
		case "aws:PrincipalType":
			ctx.PrincipalType = value
		case "aws:SourceAccount":
			ctx.SourceAccount = value
		case "aws:SourceVpc":
			ctx.SourceVPC = value
		case "aws:SourceArn":
			ctx.SourceArn = value
		case "aws:PrincipalOrgID":
			ctx.PrincipalOrgID = value

		// RequestParameters (service-specific keys)
		default:
			ctx.RequestParameters[key] = value
		}
	}
}

// GetEvaluationContexts returns comprehensive RequestContexts for testing different access scenarios
func GetEvaluationContexts(resourceType string) []*iam.RequestContext {
	switch resourceType {
	case "AWS::Lambda::Function":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"apigateway.amazonaws.com",                  // API Gateway service
				"lambda.amazonaws.com",                      // Lambda service
			},
			Conditions: []ConditionPermutation{
				{"lambda:FunctionUrlAuthType", []string{"NONE", "AWS_IAM", ""}},
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", "Service", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::S3::Bucket":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"cloudfront.amazonaws.com",                  // CloudFront service
				"s3.amazonaws.com",                          // S3 service
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"s3:x-amz-server-side-encryption", []string{"AES256", "aws:kms", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceVpc", []string{"vpc-12345678", ""}},
				{"aws:SourceVpce", []string{"vpce-0123abcd4ef567890", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::SNS::Topic":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian",
				"sns.amazonaws.com",
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::SQS::Queue":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian",
				"sqs.amazonaws.com",
				"sns.amazonaws.com", // SNS can send to SQS
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceArn", []string{"arn:aws:sns:*:111122223333:*", ""}},
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"es.amazonaws.com",                          // ElasticSearch service
				"opensearch.amazonaws.com",                  // OpenSearch service
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", "Service", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceIp", []string{"0.0.0.0/0", "10.0.0.0/8", ""}},
				{"es:source", []string{"*", ""}}, // ElasticSearch specific
			},
		}
		return generator.GenerateAllPermutations()

	case "AWS::OpenSearchServerless::Collection":
		generator := ContextGenerator{
			BasePrincipals: []string{
				"arn:aws:iam::111122223333:role/praetorian", // Generic cross-account
				"aoss.amazonaws.com",                        // OpenSearch Serverless service
				"opensearch.amazonaws.com",                  // OpenSearch service
			},
			Conditions: []ConditionPermutation{
				{"aws:SecureTransport", []string{"true", "false", ""}},
				{"aws:PrincipalType", []string{"Anonymous", "AssumedRole", "User", "Service", ""}},
				{"aws:SourceAccount", []string{"111122223333", ""}},
				{"aws:SourceIp", []string{"0.0.0.0/0", "10.0.0.0/8", ""}},
				{"aoss:collection", []string{"*", ""}}, // OpenSearch Serverless specific
			},
		}
		return generator.GenerateAllPermutations()

	default:
		// Default fallback for unknown resource types
		return []*iam.RequestContext{
			{PrincipalArn: "arn:aws:iam::111122223333:role/praetorian"},
		}
	}
}

// evaluatePolicyWithContext evaluates a policy with a specific RequestContext (DRY helper)
func (a *AwsResourcePolicyChecker) evaluatePolicyWithContext(reqCtx *iam.RequestContext, policy *types.Policy, resource string) ([]*iam.EvaluationResult, error) {
	pd := iam.NewPolicyData(
		nil,           // GAAD - not needed for resource policy analysis
		a.orgPolicies, // Organization policies from loaded file
		map[string]*types.Policy{
			resource: policy,
		},
		nil, // Resources - not needed for this analysis
	)

	evaluator := iam.NewPolicyEvaluator(pd)

	if policy.Statement == nil {
		return nil, errors.New("policy statement is nil")
	}

	results := []*iam.EvaluationResult{}
	actions := iam.ExtractActions(policy.Statement)

	for _, action := range actions {
		er := &iam.EvaluationRequest{
			Action:             action,
			Resource:           resource,
			Context:            reqCtx,
			IdentityStatements: &types.PolicyStatementList{}, // purposely empty
		}

		res, err := evaluator.Evaluate(er)
		if err != nil {
			return nil, err
		}

		slog.Debug("Policy evaluation result", "principal", reqCtx.PrincipalArn, "resource", resource, "action", action, "allowed", res.Allowed, "EvaluationResult", res)
		results = append(results, res)
	}

	return results, nil
}

// analyzePolicy analyzes a policy to determine if it grants public access
func (a *AwsResourcePolicyChecker) analyzePolicy(resource string, policy *types.Policy, accountId string, resourceType string) ([]*iam.EvaluationResult, error) {
	allResults := []*iam.EvaluationResult{}

	contexts := GetEvaluationContexts(resourceType)

	for _, reqCtx := range contexts {
		// Apply org policies context if available
		if a.orgPolicies != nil && accountId != "" {
			reqCtx.ResourceAccount = accountId
			slog.Debug("Enhanced policy analysis with org policies", "resource", resource, "account", accountId, "principal", reqCtx.PrincipalArn, "org_policies_available", true)
		}
		reqCtx.PopulateDefaultRequestConditionKeys(resource)

		// Evaluate policy with this context
		results, err := a.evaluatePolicyWithContext(reqCtx, policy, resource)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// s3ObjectLevelActions contains S3 actions that operate on objects (not buckets)
// These actions typically require bucket/* resource ARNs in policies
var s3ObjectLevelActions = map[string]bool{
	"s3:GetObject":                  true,
	"s3:GetObjectAcl":               true,
	"s3:GetObjectAttributes":        true,
	"s3:GetObjectLegalHold":         true,
	"s3:GetObjectRetention":         true,
	"s3:GetObjectTagging":           true,
	"s3:GetObjectTorrent":           true,
	"s3:GetObjectVersion":           true,
	"s3:GetObjectVersionAcl":        true,
	"s3:GetObjectVersionTagging":    true,
	"s3:GetObjectVersionTorrent":    true,
	"s3:PutObject":                  true,
	"s3:PutObjectAcl":               true,
	"s3:PutObjectLegalHold":         true,
	"s3:PutObjectRetention":         true,
	"s3:PutObjectTagging":           true,
	"s3:PutObjectVersionAcl":        true,
	"s3:PutObjectVersionTagging":    true,
	"s3:DeleteObject":               true,
	"s3:DeleteObjectTagging":        true,
	"s3:DeleteObjectVersion":        true,
	"s3:DeleteObjectVersionTagging": true,
	"s3:AbortMultipartUpload":       true,
	"s3:ListMultipartUploadParts":   true,
	"s3:RestoreObject":              true,
	"s3:ReplicateObject":            true,
	"s3:ReplicateDelete":            true,
	"s3:ReplicateTags":              true,
}

// analyzeS3ObjectPolicy analyzes S3 bucket policy for object-level public access
// This handles the case where policy grants s3:GetObject on bucket/* but not the bucket itself
func (a *AwsResourcePolicyChecker) analyzeS3ObjectPolicy(bucketArn string, policy *types.Policy, accountId string) ([]*iam.EvaluationResult, error) {
	// Use the object-level resource ARN (bucket/*) instead of bucket ARN
	objectResource := bucketArn + "/*"

	slog.Debug("Analyzing S3 object-level policy", "bucketArn", bucketArn, "objectResource", objectResource)

	// Filter actions to only check object-level actions
	if policy.Statement == nil {
		return nil, nil
	}

	allResults := []*iam.EvaluationResult{}
	contexts := GetEvaluationContexts("AWS::S3::Bucket")

	for _, reqCtx := range contexts {
		if a.orgPolicies != nil && accountId != "" {
			reqCtx.ResourceAccount = accountId
		}
		reqCtx.PopulateDefaultRequestConditionKeys(objectResource)

		// Evaluate policy with object-level resource
		results, err := a.evaluatePolicyWithContext(reqCtx, policy, objectResource)
		if err != nil {
			return nil, err
		}

		// Only include results for object-level actions
		for _, res := range results {
			if s3ObjectLevelActions[string(res.Action)] {
				allResults = append(allResults, res)
			}
		}
	}

	return allResults, nil
}

func getAllowedResults(results []*iam.EvaluationResult) []*iam.EvaluationResult {
	allowed := []*iam.EvaluationResult{}
	for _, res := range results {
		if res.Allowed {
			allowed = append(allowed, res)
		}
	}
	return allowed
}

func isPublic(results []*iam.EvaluationResult) bool {
	allowed := getAllowedResults(results)
	return len(allowed) > 0
}

func getAllowedActions(results []*iam.EvaluationResult) []string {
	allowed := getAllowedResults(results)
	actionSet := make(map[string]struct{})
	actions := []string{}
	for _, res := range allowed {
		actionStr := string(res.Action)
		if _, exists := actionSet[actionStr]; !exists {
			actionSet[actionStr] = struct{}{}
			actions = append(actions, actionStr)
		}
	}
	return actions
}

func getUnqiueDetails(results []*iam.EvaluationResult) []string {
	details := []string{}
	for _, res := range results {
		if !slices.Contains(details, res.EvaluationDetails) {
			details = append(details, res.EvaluationDetails)
		}
	}
	return details
}

func hasInconclusiveConditions(results []*iam.EvaluationResult) bool {
	for _, res := range results {
		if res.HasInconclusiveCondition() {
			return true
		}
	}
	return false
}

func strToPolicy(s string) (*types.Policy, error) {
	var p types.Policy
	err := json.Unmarshal([]byte(s), &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type PolicyGetter func(ctx context.Context, cfg aws.Config, identifier string, allowedRegions []string) (*types.Policy, error)

type ServicePolicyConfig struct {
	// GetPolicy retrieves the policy for the given identifier
	GetPolicy PolicyGetter

	// IdentifierField is the name of the field in ResourceDescription.Properties to use as identifier
	IdentifierField string

	// PolicyField is the name of the field to store the policy in the output
	PolicyField string
}

// ServiceMap maps AWS resource types to their policy checking configurations
var ServiceMap = map[string]ServicePolicyConfig{
	"AWS::S3::Bucket": {
		GetPolicy:       ServicePolicyFuncMap["AWS::S3::Bucket"],
		IdentifierField: "BucketName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SNS::Topic": {
		GetPolicy:       ServicePolicyFuncMap["AWS::SNS::Topic"],
		IdentifierField: "TopicArn",
		PolicyField:     "AccessPolicy",
	},
	"AWS::SQS::Queue": {
		GetPolicy:       ServicePolicyFuncMap["AWS::SQS::Queue"],
		IdentifierField: "QueueUrl",
		PolicyField:     "AccessPolicy",
	},
	"AWS::Lambda::Function": {
		GetPolicy:       ServicePolicyFuncMap["AWS::Lambda::Function"],
		IdentifierField: "FunctionName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::EFS::FileSystem": {
		GetPolicy:       ServicePolicyFuncMap["AWS::EFS::FileSystem"],
		IdentifierField: "FileSystemId",
		PolicyField:     "AccessPolicy",
	},
	"AWS::ElasticSearch::Domain": {
		GetPolicy:       ServicePolicyFuncMap["AWS::ElasticSearch::Domain"],
		IdentifierField: "DomainName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::OpenSearchService::Domain": {
		GetPolicy:       ServicePolicyFuncMap["AWS::OpenSearchService::Domain"],
		IdentifierField: "DomainName",
		PolicyField:     "AccessPolicy",
	},
	"AWS::OpenSearchServerless::Collection": {
		GetPolicy:       ServicePolicyFuncMap["AWS::OpenSearchServerless::Collection"],
		IdentifierField: "Name",
		PolicyField:     "AccessPolicy",
	},
}

var ServicePolicyFuncMap = map[string]PolicyGetter{
	"AWS::Lambda::Function": func(ctx context.Context, cfg aws.Config, functionName string, allowedRegions []string) (*types.Policy, error) {
		client := lambda.NewFromConfig(cfg)
		resp, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
			FunctionName: aws.String(functionName),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "ResourceNotFoundException") || strings.Contains(err.Error(), "failed to get policy") {
				return nil, nil
			}
			return nil, err
		}
		if resp.Policy == nil {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(*resp.Policy)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::S3::Bucket": func(ctx context.Context, cfg aws.Config, bucketName string, allowedRegions []string) (*types.Policy, error) {
		client := s3.NewFromConfig(cfg)

		// 0. Check bucket location first to ensure we're using the correct region
		locationResp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			slog.Error("Failed to get bucket location", "bucket", bucketName, "error", err)
			return nil, err
		}

		// Handle empty LocationConstraint (means us-east-1)
		bucketRegion := "us-east-1"
		if locationResp.LocationConstraint != "" {
			bucketRegion = string(locationResp.LocationConstraint)
		}

		// Check if the bucket's region is in the user's allowed regions list
		if !slices.Contains(allowedRegions, bucketRegion) {
			slog.Debug("Bucket region not in allowed regions list", "bucket", bucketName, "bucketRegion", bucketRegion, "allowedRegions", allowedRegions)
			return nil, nil // Skip this bucket
		}

		// Only create a new client if the bucket is in a different region
		if bucketRegion != cfg.Region {
			newCfg := cfg.Copy()
			newCfg.Region = bucketRegion
			client = s3.NewFromConfig(newCfg)
			slog.Debug("Created region-specific S3 client", "bucket", bucketName, "region", bucketRegion)
		}

		// Get bucket policy (pure policy getter - no virtual policies)
		resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
				slog.Debug("Bucket has no policy", "bucket", bucketName)
				return nil, nil
			}
			slog.Debug("Failed to get bucket policy", "bucket", bucketName, "error", err)
			return nil, err
		}

		if resp == nil || resp.Policy == nil {
			return nil, nil
		}

		policy, err := strToPolicy(*resp.Policy)
		if err != nil {
			slog.Debug("Failed to parse bucket policy", "bucket", bucketName, "error", err)
			return nil, err
		}

		return policy, nil
	},
	"AWS::EFS::FileSystem": func(ctx context.Context, cfg aws.Config, fileSystemId string, allowedRegions []string) (*types.Policy, error) {
		client := efs.NewFromConfig(cfg)
		resp, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{
			FileSystemId: aws.String(fileSystemId),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "PolicyNotFound") ||
				strings.Contains(err.Error(), "FileSystemNotFound") {
				return nil, err
			}
			return nil, err
		}
		if resp.Policy == nil {
			return nil, nil
		}
		policy, err := strToPolicy(*resp.Policy)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::SQS::Queue": func(ctx context.Context, cfg aws.Config, queueUrl string, allowedRegions []string) (*types.Policy, error) {
		client := sqs.NewFromConfig(cfg)
		resp, err := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       aws.String(queueUrl),
			AttributeNames: []sqstypes.QueueAttributeName{"Policy"},
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "NoSuchEntityException") {
				return &types.Policy{}, nil
			}
			return nil, err
		}
		pol, ok := resp.Attributes["Policy"]
		if !ok {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(pol)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::ElasticSearch::Domain": func(ctx context.Context, cfg aws.Config, domainName string, allowedRegions []string) (*types.Policy, error) {
		client := elasticsearchservice.NewFromConfig(cfg)
		resp, err := client.DescribeElasticsearchDomainConfig(ctx, &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
			DomainName: aws.String(domainName),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return nil, err
			}
			return nil, err
		}
		if resp.DomainConfig.AccessPolicies == nil || resp.DomainConfig.AccessPolicies.Options == nil {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(*resp.DomainConfig.AccessPolicies.Options)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::SNS::Topic": func(ctx context.Context, cfg aws.Config, topicArn string, allowedRegions []string) (*types.Policy, error) {
		client := sns.NewFromConfig(cfg)
		resp, err := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
			TopicArn: aws.String(topicArn),
		})
		if err != nil {
			// Handle "no policy" errors gracefully
			if strings.Contains(err.Error(), "NoSuchEntityException") {
				return &types.Policy{}, nil
			}
			return &types.Policy{}, err
		}
		pol, ok := resp.Attributes["Policy"]
		if !ok {
			return &types.Policy{}, errors.New("no policy found")
		}

		policy, err := strToPolicy(pol)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::OpenSearchService::Domain": func(ctx context.Context, cfg aws.Config, domainName string, allowedRegions []string) (*types.Policy, error) {
		client := opensearch.NewFromConfig(cfg)
		resp, err := client.DescribeDomainConfig(ctx, &opensearch.DescribeDomainConfigInput{
			DomainName: aws.String(domainName),
		})
		if err != nil {
			// Handle "no domain" errors gracefully
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return nil, err
			}
			return nil, err
		}
		if resp.DomainConfig.AccessPolicies == nil || resp.DomainConfig.AccessPolicies.Options == nil {
			return nil, errors.New("no policy found")
		}

		policy, err := strToPolicy(*resp.DomainConfig.AccessPolicies.Options)
		if err != nil {
			return nil, err
		}

		return policy, nil
	},
	"AWS::OpenSearchServerless::Collection": func(ctx context.Context, cfg aws.Config, collectionName string, allowedRegions []string) (*types.Policy, error) {
		client := opensearchserverless.NewFromConfig(cfg)

		// List access policies to find the one for this collection
		listResp, err := client.ListAccessPolicies(ctx, &opensearchserverless.ListAccessPoliciesInput{
			Type: "data",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list access policies: %w", err)
		}

		// Find policy that matches our collection
		for _, policySummary := range listResp.AccessPolicySummaries {
			if policySummary.Name == nil {
				continue
			}

			// Get the full policy details
			getResp, err := client.GetAccessPolicy(ctx, &opensearchserverless.GetAccessPolicyInput{
				Name: policySummary.Name,
				Type: "data",
			})
			if err != nil {
				slog.Debug("Failed to get access policy details", "policy", *policySummary.Name, "error", err)
				continue
			}

			if getResp.AccessPolicyDetail == nil || getResp.AccessPolicyDetail.Policy == nil {
				continue
			}

			// Parse the policy to check if it applies to our collection
			var policyDoc map[string]any
			policyBytes, err := json.Marshal(getResp.AccessPolicyDetail.Policy)
			if err != nil {
				slog.Debug("Failed to marshal policy document", "policy", *policySummary.Name, "error", err)
				continue
			}
			if err := json.Unmarshal(policyBytes, &policyDoc); err != nil {
				slog.Debug("Failed to parse policy document", "policy", *policySummary.Name, "error", err)
				continue
			}

			// Check if this policy applies to our collection
			if rules, ok := policyDoc["Rules"].([]any); ok {
				for _, rule := range rules {
					if ruleMap, ok := rule.(map[string]any); ok {
						if resourceTypes, ok := ruleMap["ResourceType"].([]any); ok {
							for _, resourceType := range resourceTypes {
								if rt, ok := resourceType.(string); ok && strings.Contains(rt, collectionName) {
									// Convert the policy document to our Policy type
									policy, err := strToPolicy(string(policyBytes))
									if err != nil {
										return nil, fmt.Errorf("failed to parse policy: %w", err)
									}
									return policy, nil
								}
							}
						}
					}
				}
			}
		}

		// No specific access policy found for this collection
		return nil, nil
	},
}

// getS3BucketPolicy retrieves the bucket policy using a pre-configured S3 client
// This is used when we already have a region-specific client from GetBucketLocation
func getS3BucketPolicy(ctx context.Context, client *s3.Client, bucketName string) (*types.Policy, error) {
	resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			slog.Debug("Bucket has no policy", "bucket", bucketName)
			return nil, nil
		}
		return nil, err
	}

	if resp == nil || resp.Policy == nil {
		return nil, nil
	}

	policy, err := strToPolicy(*resp.Policy)
	if err != nil {
		slog.Debug("Failed to parse bucket policy", "bucket", bucketName, "error", err)
		return nil, err
	}

	return policy, nil
}

// S3BPAStatus contains the Block Public Access settings for an S3 bucket
type S3BPAStatus struct {
	IgnorePublicAcls      bool   // When true, ACL-based public access is blocked
	RestrictPublicBuckets bool   // When true, policy-based public access is blocked
	Reason                string // Human-readable description for logging
}

// S3ACLResult contains the results of checking S3 ACLs
type S3ACLResult struct {
	ACLGrants   []string // ACL permissions granted (e.g., ["READ", "WRITE"])
	GranteeType string   // Type of grantee (e.g., "AllUsers", "AuthenticatedUsers")
}

// checkS3BlockPublicAccess checks S3 Block Public Access settings
// Returns nil if BPA settings couldn't be retrieved, otherwise returns the BPA status
func (a *AwsResourcePolicyChecker) checkS3BlockPublicAccess(
	ctx context.Context,
	client *s3.Client,
	bucketName string,
) *S3BPAStatus {
	// Check Block Public Access settings
	blockPublicAccessResp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		slog.Debug("Failed to get public access block settings", "bucket", bucketName, "error", err)
		return nil // No BPA settings, continue evaluation
	}

	if blockPublicAccessResp.PublicAccessBlockConfiguration != nil {
		config := blockPublicAccessResp.PublicAccessBlockConfiguration
		ignoreAcls := config.IgnorePublicAcls != nil && *config.IgnorePublicAcls
		restrictBuckets := config.RestrictPublicBuckets != nil && *config.RestrictPublicBuckets

		return &S3BPAStatus{
			IgnorePublicAcls:      ignoreAcls,
			RestrictPublicBuckets: restrictBuckets,
			Reason: fmt.Sprintf("Block Public Access settings (IgnorePublicAcls=%v, RestrictPublicBuckets=%v)",
				ignoreAcls, restrictBuckets),
		}
	}

	return nil // No BPA configuration found
}

// checkS3PublicACLs checks S3 bucket ACLs for public access grants
// Returns ACL grants and grantee type if public access found
func (a *AwsResourcePolicyChecker) checkS3PublicACLs(
	ctx context.Context,
	client *s3.Client,
	bucketName string,
) S3ACLResult {
	result := S3ACLResult{}

	// Check Bucket Ownership Controls - if BucketOwnerEnforced, ACLs are disabled
	ownershipResp, err := client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		slog.Debug("Failed to get bucket ownership controls", "bucket", bucketName, "error", err)
	} else if ownershipResp.OwnershipControls != nil {
		for _, rule := range ownershipResp.OwnershipControls.Rules {
			if rule.ObjectOwnership == s3types.ObjectOwnershipBucketOwnerEnforced {
				slog.Debug("Bucket ownership enforced - ACLs disabled", "bucket", bucketName)
				return result // ACLs disabled, return empty result
			}
		}
	}

	// Check ACLs directly for public grantees
	aclResp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		slog.Debug("Failed to get bucket ACL", "bucket", bucketName, "error", err)
		return result
	}

	granteeTypes := make(map[string]bool)

	if aclResp.Grants != nil {
		for _, grant := range aclResp.Grants {
			if grant.Grantee == nil || grant.Grantee.URI == nil {
				continue
			}

			// Check for public grantees
			switch *grant.Grantee.URI {
			case "http://acs.amazonaws.com/groups/global/AllUsers":
				granteeTypes["AllUsers"] = true
				result.ACLGrants = append(result.ACLGrants, string(grant.Permission))
			case "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
				granteeTypes["AuthenticatedUsers"] = true
				result.ACLGrants = append(result.ACLGrants, string(grant.Permission))
			}
		}
	}

	// Prioritize AllUsers (more permissive) over AuthenticatedUsers
	if granteeTypes["AllUsers"] {
		result.GranteeType = "AllUsers"
	} else if granteeTypes["AuthenticatedUsers"] {
		result.GranteeType = "AuthenticatedUsers"
	}

	return result
}

type AwsResourcePolicyFetcher struct {
	*base.AwsReconLink
}

func NewAwsResourcePolicyFetcher(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyFetcher{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyFetcher) Process(resource *types.EnrichedResourceDescription) error {
	// Get the policy getter function for this resource type
	policyGetter, ok := ServicePolicyFuncMap[resource.TypeName]
	if !ok {
		// Silently skip resources that don't have resource policies
		slog.Debug("Skipping resource type without resource policy", "type", resource.TypeName)
		return nil
	}

	// Get AWS config from the link parameters
	awsCfg, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get the policy
	policy, err := policyGetter(a.ContextHolder.Context(), awsCfg, resource.Identifier, a.Regions)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	if policy == nil {
		return nil
	}

	// Send the policy downstream
	policy.ResourceARN = resource.Arn.String()
	a.Send(policy)
	return nil
}
