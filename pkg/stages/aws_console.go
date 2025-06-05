package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Constants
const (
	awsFedEndpoint = "https://signin.aws.amazon.com/federation"
	consoleBase    = "https://console.aws.amazon.com/"
	defaultIssuer  = "aws-console-tool"
)

// Policy represents the IAM policy for federation token
var policy = map[string]interface{}{
	"Version": "2012-10-17",
	"Statement": []map[string]interface{}{
		{
			"Effect":   "Allow",
			"Action":   []string{"*"},
			"Resource": []string{"*"},
		},
	},
}

// AwsGetConsoleURL generates a federated sign-in URL for the AWS Console
func AwsGetConsoleURL(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "AWSGetConsoleURL")
	out := make(chan string)

	go func() {
		defer close(out)
		// Get configuration options
		profile := options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value
		roleArn := options.GetOptionByName(options.AwsRoleArnOpt.Name, opts).Value
		durationStr := options.GetOptionByName(options.AwsDurationOpt.Name, opts).Value
		region := options.GetOptionByName(options.AwsRegionOpt.Name, opts).Value

		// Parse duration
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			logger.Warn("Failed to parse duration, using default 3600 seconds")
			duration = 3600
		}

		// Get AWS config
		cfg, err := helpers.GetAWSCfg(region, profile, opts)
		if err != nil {
			logger.Error("Failed to get AWS config: " + err.Error())
			return
		}

		// Create STS client
		stsClient := sts.NewFromConfig(cfg)

		// Get temporary credentials
		var credentials *ststypes.Credentials
		if roleArn != "" {
			// Assume role
			result, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleArn),
				RoleSessionName: aws.String("aws-console-tool"),
				DurationSeconds: aws.Int32(int32(duration)),
			})
			if err != nil {
				logger.Error("Failed to assume role: " + err.Error())
				return
			}
			credentials = result.Credentials
		} else {
			// Get federation token
			policyBytes, err := json.Marshal(policy)
			if err != nil {
				logger.Error("Failed to marshal policy: " + err.Error())
				return
			}

			result, err := stsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
				Name:            aws.String("aws-console-tool"),
				Policy:          aws.String(string(policyBytes)),
				DurationSeconds: aws.Int32(int32(duration)),
			})
			if err != nil {
				logger.Error("Failed to get federation token: " + err.Error())
				return
			}
			credentials = result.Credentials
		}

		// Construct session data
		sessionData := map[string]string{
			"sessionId":    *credentials.AccessKeyId,
			"sessionKey":   *credentials.SecretAccessKey,
			"sessionToken": *credentials.SessionToken,
		}

		sessionDataBytes, err := json.Marshal(sessionData)
		if err != nil {
			logger.Error("Failed to marshal session data: " + err.Error())
			return
		}

		// Get sign-in token
		federationURL := fmt.Sprintf("%s?Action=getSigninToken&Session=%s",
			awsFedEndpoint,
			url.QueryEscape(string(sessionDataBytes)))

		resp, err := http.Get(federationURL)
		if err != nil {
			logger.Error("Failed to get sign-in token: " + err.Error())
			return
		}
		defer resp.Body.Close()

		var tokenResponse struct {
			SigninToken string `json:"SigninToken"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			logger.Error("Failed to decode sign-in token response: " + err.Error())
			return
		}

		// Build console URL
		consoleURL := fmt.Sprintf("%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
			awsFedEndpoint,
			defaultIssuer,
			consoleBase,
			url.QueryEscape(tokenResponse.SigninToken))

		out <- consoleURL
	}()

	return out
}
