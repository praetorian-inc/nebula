package awslogin

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AwsSSOIamICMetadata = modules.Metadata{
	Id:          "sso-iamic",
	Name:        "AWS SSO IAM Identity Center Login",
	Description: "Configure AWS SSO with IAM Identity Center for CLI access",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.None,
	References: []string{
		"https://github.com/aws/aws-sdk-go-v2/issues/2241",
		"https://aws.amazon.com/blogs/developer/aws-sso-support-in-the-aws-sdk-for-go/",
		"https://github.com/awslabs/amazon-ecr-credential-helper/issues/771",
		"https://github.com/aws/aws-sdk-go/issues/5184",
		"https://github.com/benkehoe/aws-sso-credential-process",
	},
}

var AwsSSOIamICOptions = []*types.Option{
	{
		Name:        "start-url",
		Short:       "u",
		Description: "AWS SSO start URL (e.g. https://my-sso.awsapps.com/start)",
		Required:    true,
		Type:        types.String,
		Value:       "",
	},
	{
		Name:        "sso-region",
		Short:       "r",
		Description: "AWS SSO profile region (default: us-east-1)",
		Required:    false,
		Type:        types.String,
		Value:       "us-east-1",
	},
	{
		Name:        "cli-region",
		Short:       "e",
		Description: "AWS CLI region for the new profiles (default: us-east-1)",
		Required:    false,
		Type:        types.String,
		Value:       "us-east-1",
	},
	{
		Name:        "session-name",
		Short:       "n",
		Description: "SSO session name to use in the config file (default: my-sso)",
		Required:    false,
		Type:        types.String,
		Value:       "my-sso",
	},
	&options.OutputOpt,
	&options.FileNameOpt,
}

// Local structs to aid in configuration
type localSSOConfig struct {
	StartURL    string
	SSORegion   string
	CLIRegion   string
	SessionName string
}

type localProfileConfig struct {
	Name        string
	AccountID   string
	RoleName    string
	Region      string
	SessionName string
	Output      string
}

// JSON type to store in the SSO cache (otherwise cannot reuse in CLI)
type localSSOCache struct {
	AccessToken           string `json:"accessToken"`
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ExpiresAt             string `json:"expiresAt"`
	RefreshToken          string `json:"refreshToken"`
	Region                string `json:"region"`
	RegistrationExpiresAt string `json:"registrationExpiresAt"`
	StartUrl              string `json:"startUrl"`
}

type localConfigData struct {
	Profiles []localProfileConfig
	Config   localSSOConfig
}

// Template for the AWS config file
const localConfigTemplate = `{{ range .Profiles }}[profile {{ .Name }}]
sso_session = {{ .SessionName }}
sso_account_id = {{ .AccountID }}
sso_role_name = {{ .RoleName }}
region = {{ .Region }}
output = {{ .Output }}

{{ end }}
[sso-session {{ .Config.SessionName }}]
sso_start_url = {{ .Config.StartURL }}
sso_region = {{ .Config.SSORegion }}
sso_registration_scopes = sso:account:access
`

var AwsSSOIamICOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
}

func NewAwsSSOIamIC(opts []*types.Option) (<-chan string, stages.Stage[string, string], error) {
	pipeline, err := stages.ChainStages[string, string](
		localAwsSSOLoginStage,
	)
	if err != nil {
		return nil, nil, err
	}
	return stages.Generator([]string{"sso-login"}), pipeline, nil
}

// Local stage for AWS SSO login with IAM Identity Center
func localAwsSSOLoginStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "AwsSSOLoginStage")
	out := make(chan string)

	go func() {
		defer close(out)
		for range in {
			ssoConfig := localSSOConfig{
				StartURL:    options.GetOptionByName("start-url", opts).Value,
				SSORegion:   options.GetOptionByName("sso-region", opts).Value,
				CLIRegion:   options.GetOptionByName("cli-region", opts).Value,
				SessionName: options.GetOptionByName("session-name", opts).Value,
			}

			// INFO: Using custom cfg; not sure if helpers.GetAWSConfig() will pose issues
			cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(ssoConfig.SSORegion))
			if err != nil {
				logger.Error(fmt.Sprintf("failed to load AWS config: %v", err))
				return
			}
			// Create OIDC client and start device auth for creating new SSO session
			oidcClient := ssooidc.NewFromConfig(cfg)
			regResp, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
				ClientName: aws.String("nebula-aws-sso-client"),
				ClientType: aws.String("public"),
				Scopes:     []string{"sso:account:access"},
			})
			if err != nil {
				logger.Error(fmt.Sprintf("failed to register OIDC client: %v", err))
				return
			}
			deviceAuth, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
				ClientId:     regResp.ClientId,
				ClientSecret: regResp.ClientSecret,
				StartUrl:     aws.String(ssoConfig.StartURL),
			})
			if err != nil {
				logger.Error(fmt.Sprintf("failed to start device authorization: %v", err))
				return
			}

			// INFO: this shows a red triangle on the UI because code is a GET param; not a security issue and adds usability
			message.Info(fmt.Sprintf("\nOpen this URL in your browser to sign in:\n%s\n", aws.ToString(deviceAuth.VerificationUriComplete)))
			message.Info("Press Enter after you have signed in...")
			bufio.NewReader(os.Stdin).ReadString('\n')

			// Create access token with SSO session to search for accounts and roles made available to us
			tokenResp, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
				ClientId:     regResp.ClientId,
				ClientSecret: regResp.ClientSecret,
				DeviceCode:   deviceAuth.DeviceCode,
				GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			})
			if err != nil {
				logger.Error(fmt.Sprintf("failed to create token: %v", err))
				return
			}

			ssoClient := sso.NewFromConfig(cfg)
			accounts, err := listAccounts(ctx, ssoClient, tokenResp.AccessToken)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to list accounts: %v", err))
				return
			}
			message.Info(fmt.Sprintf("Found %d accounts", len(accounts.AccountList)))
			home, err := os.UserHomeDir()
			if err != nil {
				logger.Error(fmt.Sprintf("failed to get home directory: %v", err))
				return
			}
			awsConfigDir := filepath.Join(home, ".aws")
			if err := os.MkdirAll(awsConfigDir, 0700); err != nil {
				logger.Error(fmt.Sprintf("failed to create .aws directory: %v", err))
				return
			}

			// processAccounts will create the AWS config file and also store the profile list ina txt file
			// the config file will be re-written to ~/.aws/config on every run
			configData, err := processAccounts(ctx, ssoClient, tokenResp.AccessToken, accounts, ssoConfig, opts)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to process accounts: %v", err))
				return
			}
			configPath := filepath.Join(awsConfigDir, "config")
			if err := writeAWSConfig(configPath, configData); err != nil {
				logger.Error(fmt.Sprintf("failed to write AWS config: %v", err))
				return
			}

			// Create SSO cache - required for CLI so that we don't have to re-auth
			if err := createSSOCache(home, ssoConfig.SessionName, ssoConfig.StartURL, ssoConfig.SSORegion, regResp, tokenResp); err != nil {
				logger.Error(fmt.Sprintf("failed to create SSO cache: %v", err))
				return
			}
			message.Success("AWS SSO configuration completed successfully")
			message.Info(fmt.Sprintf("Config file written to: %s", configPath))
			out <- "SSO configuration completed"
		}
	}()
	return out
}

// Helper functions
func listAccounts(ctx context.Context, client *sso.Client, accessToken *string) (*sso.ListAccountsOutput, error) {
	var accounts sso.ListAccountsOutput
	var nextToken *string
	for {
		resp, err := client.ListAccounts(ctx, &sso.ListAccountsInput{
			AccessToken: accessToken,
			MaxResults:  aws.Int32(100),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list accounts: %w", err)
		}
		accounts.AccountList = append(accounts.AccountList, resp.AccountList...)
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}
	return &accounts, nil
}

func processAccounts(ctx context.Context, client *sso.Client, accessToken *string, accounts *sso.ListAccountsOutput, config localSSOConfig, opts []*types.Option) (*localConfigData, error) {
	configData := &localConfigData{
		Config: config,
	}
	addedAccountNames := make(map[string]struct{}) // to keep track of added account names
	profileList := []string{}                      // to store the profile list on disk
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	for _, account := range accounts.AccountList {
		accountID := aws.ToString(account.AccountId)
		accountName := strings.ToLower(re.ReplaceAllString(aws.ToString(account.AccountName), "-")) // solve for spaces mainly; rest is safety
		// Get all assigned roles for the given account
		roles, err := listAccountRoles(ctx, client, accessToken, accountID)
		if err != nil {
			return nil, err
		}
		for _, role := range roles.RoleList {
			roleName := aws.ToString(role.RoleName)
			profileName := accountName
			// INFO: this step is needed as there can be multiple roles assigned to same account
			// if differentiation is not made, profile name repeats and CLI fails
			if _, ok := addedAccountNames[accountName]; ok {
				profileName = fmt.Sprintf("%s-%s-%s", accountName, accountID, roleName)
			}
			profileList = append(profileList, fmt.Sprintf("%s:%s", profileName, accountID))
			configData.Profiles = append(configData.Profiles, localProfileConfig{
				Name:        profileName,
				AccountID:   accountID,
				RoleName:    roleName,
				Region:      config.CLIRegion,
				SessionName: config.SessionName,
				Output:      "json",
			})
			addedAccountNames[accountName] = struct{}{}
		}
	}

	// Using this for conformity; meant to generally used in default case
	outputDir := options.GetOptionByName(options.OutputOpt.Name, opts).Value
	fileName := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
	if fileName == "" {
		fileName = "aws-sso-profile-list.txt"
	}
	profileListPath := filepath.Join(outputDir, fileName)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	profileFile, err := os.Create(profileListPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile list file: %w", err)
	}
	defer profileFile.Close()
	// TODO: can probably use the plauntext file output provider but at the same time, don't want a stage to fail because of this
	// although, maybe it's atomic enough to not fail in a generic sense
	writer := bufio.NewWriter(profileFile)
	for _, profile := range profileList {
		writer.WriteString(fmt.Sprintf("%s\n", profile))
	}
	if err := writer.Flush(); err != nil {
		message.Warning("failed to write profile list: %v", err)
	}
	message.Success("Profile list written to %s", profileListPath)
	return configData, nil
}

func listAccountRoles(ctx context.Context, client *sso.Client, accessToken *string, accountID string) (*sso.ListAccountRolesOutput, error) {
	var roles sso.ListAccountRolesOutput
	var nextToken *string
	for {
		resp, err := client.ListAccountRoles(ctx, &sso.ListAccountRolesInput{
			AccessToken: accessToken,
			AccountId:   aws.String(accountID),
			MaxResults:  aws.Int32(100),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list roles for account %s: %w", accountID, err)
		}
		roles.RoleList = append(roles.RoleList, resp.RoleList...)

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}
	return &roles, nil
}

// This needed to be a separate function as the template stucture is a bit complex and easiest to manage by rendering
func writeAWSConfig(path string, data *localConfigData) error {
	tmpl, err := template.New("config").Parse(localConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	return nil
}

func createSSOCache(home, sessionName, startURL, region string, regResp *ssooidc.RegisterClientOutput, tokenResp *ssooidc.CreateTokenOutput) error {
	cacheDir := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	// INFO: this is a bit of a fluke; I couldn't find a standardized way to name the cache, but session name is easily picked up by CLI
	// I've seen CLI ops create different files for different sessions, but couldn't find conclusive information on how to name it
	h := sha1.New()
	h.Write([]byte(sessionName))
	filename := hex.EncodeToString(h.Sum(nil)) + ".json"
	now := time.Now().UTC()
	cache := localSSOCache{
		AccessToken:           *tokenResp.AccessToken,
		ClientID:              *regResp.ClientId,
		ClientSecret:          *regResp.ClientSecret,
		ExpiresAt:             now.Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          *tokenResp.RefreshToken,
		Region:                region,
		RegistrationExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		StartUrl:              startURL,
	}
	cacheData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, filename), cacheData, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	return nil
}
