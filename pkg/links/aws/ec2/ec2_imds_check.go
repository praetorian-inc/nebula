package ec2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AWSEC2IMDSCheck struct {
	*base.AwsReconLink
}

func NewAWSEC2IMDSCheck(configs ...cfg.Config) chain.Link {
	link := &AWSEC2IMDSCheck{}
	link.AwsReconLink = base.NewAwsReconLink(link, configs...)
	return link
}

func (a *AWSEC2IMDSCheck) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::EC2::Instance" {
		slog.Debug("Skipping non-EC2 instance", "resource_type", resource.TypeName)
		return nil
	}

	config, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return nil
	}

	ec2Client := ec2.NewFromConfig(config)

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{resource.Identifier},
	}

	output, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && strings.HasPrefix(apiErr.ErrorCode(), "InvalidInstanceID") {
			slog.Warn("Instance not found", "instance_id", resource.Identifier)
			return nil
		}
		slog.Error("Failed to describe instance", "instance_id", resource.Identifier, "error", err)
		return nil
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances — they can't be exploited
			if instance.State != nil && instance.State.Name == ec2types.InstanceStateNameTerminated {
				slog.Debug("Skipping terminated instance", "instance_id", resource.Identifier)
				continue
			}

			// Nil MetadataOptions means default settings, which allow IMDSv1
			if instance.MetadataOptions == nil {
				slog.Debug("No metadata options found (defaults allow IMDSv1)", "instance_id", resource.Identifier)
				a.reportNonCompliantInstance(resource, instance)
				continue
			}

			// IMDS completely disabled — no credential theft risk
			if instance.MetadataOptions.HttpEndpoint == ec2types.InstanceMetadataEndpointStateDisabled {
				slog.Debug("IMDS disabled on instance", "instance_id", resource.Identifier)
				continue
			}

			if instance.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired {
				slog.Debug("Instance enforces IMDSv2", "instance_id", resource.Identifier)
				continue
			}

			a.reportNonCompliantInstance(resource, instance)
		}
	}

	return nil
}

func (a *AWSEC2IMDSCheck) reportNonCompliantInstance(resource *types.EnrichedResourceDescription, instance ec2types.Instance) {
	httpTokens := "unknown"
	httpEndpoint := "unknown"
	hopLimit := int32(0)
	if instance.MetadataOptions != nil {
		httpTokens = string(instance.MetadataOptions.HttpTokens)
		httpEndpoint = string(instance.MetadataOptions.HttpEndpoint)
		if instance.MetadataOptions.HttpPutResponseHopLimit != nil {
			hopLimit = *instance.MetadataOptions.HttpPutResponseHopLimit
		}
	}
	instanceState := ""
	if instance.State != nil {
		instanceState = string(instance.State.Name)
	}

	properties := map[string]any{
		"InstanceId":              resource.Identifier,
		"Region":                  resource.Region,
		"State":                   instanceState,
		"HttpTokens":              httpTokens,
		"HttpEndpoint":            httpEndpoint,
		"HttpPutResponseHopLimit": hopLimit,
	}

	target, err := model.NewAWSResource(
		resource.Arn.String(),
		resource.AccountId,
		model.AWSEC2Instance,
		properties,
	)
	if err != nil {
		slog.Error("Failed to create AWS resource target", "error", err)
		return
	}

	risk := model.NewRiskWithDNS(
		&target,
		"ec2-imdsv1-enabled",
		resource.Arn.String(),
		model.TriageMedium,
	)
	risk.Source = "nebula-ec2-imds-scanner"
	risk.Comment = fmt.Sprintf(
		"Instance: %s, Region: %s, State: %s, HttpTokens: %s, HttpEndpoint: %s, HopLimit: %d",
		resource.Identifier, resource.Region, instanceState, httpTokens, httpEndpoint, hopLimit,
	)

	riskDef := model.RiskDefinition{
		Description:    "EC2 instance does not enforce IMDSv2, allowing IMDSv1 which is vulnerable to SSRF attacks.",
		Impact:         "Attackers with SSRF can steal IAM role credentials from the instance metadata service.",
		Recommendation: "Enable IMDSv2 by setting HttpTokens to \"required\" via `aws ec2 modify-instance-metadata-options --instance-id " + resource.Identifier + " --http-tokens required`.",
		References:     "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
	}
	risk.Definition(riskDef)

	if err := a.Send(risk); err != nil {
		slog.Error("Failed to send risk", "error", err, "instance_id", resource.Identifier)
	}

	proofContent := fmt.Sprintf(`#### Vulnerability Description
EC2 instance %s does not enforce IMDSv2. The HttpTokens setting is "%s" instead of "required", which means IMDSv1 is still accessible. IMDSv1 is vulnerable to SSRF-based credential theft.

#### Impact
Attackers who can exploit an SSRF vulnerability on this instance can steal IAM role credentials from the instance metadata service at http://169.254.169.254/latest/meta-data/iam/security-credentials/.

#### Remediation
Enable IMDSv2 by setting HttpTokens to "required":
%s

#### References
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

#### Evidence
- Instance ID: %s
- Region: %s
- Account ID: %s
- State: %s
- HttpTokens: %s
- HttpEndpoint: %s
- HttpPutResponseHopLimit: %d
`,
		resource.Identifier, httpTokens,
		"aws ec2 modify-instance-metadata-options --instance-id "+resource.Identifier+" --http-tokens required --http-endpoint enabled",
		resource.Identifier, resource.Region, resource.AccountId, instanceState,
		httpTokens, httpEndpoint, hopLimit,
	)

	proofFile := model.NewFile(fmt.Sprintf("proofs/%s/ec2-imdsv1-enabled-%s-%s", resource.AccountId, resource.Identifier, resource.Region))
	proofFile.Bytes = []byte(proofContent)
	if err := a.Send(proofFile); err != nil {
		slog.Error("Failed to send proof file", "error", err, "instance_id", resource.Identifier)
	}
}

func (a *AWSEC2IMDSCheck) Permissions() []cfg.Permission {
	return []cfg.Permission{
		{
			Platform:   "aws",
			Permission: "ec2:DescribeInstances",
		},
	}
}
