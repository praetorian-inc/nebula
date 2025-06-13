package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	minDuration    = 900
	maxDuration    = 3600
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
		mfaToken := options.GetOptionByName(options.AwsMfaTokenOpt.Name, opts).Value
		roleSessionName := options.GetOptionByName(options.AwsRoleSessionNameOpt.Name, opts).Value
		federationName := options.GetOptionByName(options.AwsFederationNameOpt.Name, opts).Value

		// Parse duration
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			logger.Warn("Failed to parse duration, using default 3600 seconds")
			duration = maxDuration
		}
		if duration < minDuration || duration > maxDuration {
			logger.Error("Duration must be between " + strconv.Itoa(minDuration) + " and " + strconv.Itoa(maxDuration) + " seconds")
			return
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

		// Check if we're already using temporary credentials
		identity, err := helpers.GetCallerIdentity(cfg)
		if err != nil {
			logger.Error("Failed to get caller identity: " + err.Error())
			return
		}

		// If the identity ARN contains "assumed-role", we're already using temporary credentials
		if strings.Contains(*identity.Arn, ":assumed-role/") {
			// Extract the temporary credentials from the current config
			creds, err := cfg.Credentials.Retrieve(ctx)
			if err != nil {
				logger.Error("Failed to retrieve credentials: " + err.Error())
				return
			}
			credentials = &ststypes.Credentials{
				AccessKeyId:     aws.String(creds.AccessKeyID),
				SecretAccessKey: aws.String(creds.SecretAccessKey),
				SessionToken:    aws.String(creds.SessionToken),
				Expiration:      aws.Time(time.Now().Add(time.Duration(duration) * time.Second)),
			}
		} else if roleArn != "" {
			// Assume role
			assumeRoleConfig := &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleArn),
				RoleSessionName: aws.String(roleSessionName),
				DurationSeconds: aws.Int32(int32(duration)),
			}

			// Add MFA if token is provided
			if mfaToken != "" {
				// Extract account ID from ARN
				arnParts := strings.Split(*identity.Arn, ":")
				if len(arnParts) < 6 {
					logger.Error("Invalid ARN format: " + *identity.Arn)
					return
				}
				accountId := arnParts[4]
				userName := strings.Split(arnParts[5], "/")[1]

				// Construct MFA device ARN
				mfaDeviceArn := fmt.Sprintf("arn:aws:iam::%s:mfa/%s", accountId, userName)

				assumeRoleConfig.SerialNumber = aws.String(mfaDeviceArn)
				assumeRoleConfig.TokenCode = aws.String(mfaToken)
			}

			result, err := stsClient.AssumeRole(ctx, assumeRoleConfig)
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
				Name:            aws.String(federationName),
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
