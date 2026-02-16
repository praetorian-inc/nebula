package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/graph"
	"github.com/praetorian-inc/nebula/pkg/graph/adapters"
	"github.com/praetorian-inc/nebula/pkg/graph/queries"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// ApolloReport generates analysis reports from Apollo graph queries
type ApolloReport struct {
	*chain.Base
	db graph.GraphDatabase
}

func NewApolloReport(configs ...cfg.Config) chain.Link {
	a := &ApolloReport{}
	a.Base = chain.NewBase(a, configs...)
	return a
}

func (a *ApolloReport) Params() []cfg.Param {
	params := a.Base.Params()
	params = append(params, options.Neo4jOptions()...)
	params = append(params,
		cfg.NewParam[string]("report-type", "Type of report to generate: all, privesc, external-trust").
			WithDefault("all").
			WithShortcode("t"),
	)
	return params
}

func (a *ApolloReport) Initialize() error {
	graphConfig := &graph.Config{
		URI:      a.Args()[options.Neo4jURI().Name()].(string),
		Username: a.Args()[options.Neo4jUsername().Name()].(string),
		Password: a.Args()[options.Neo4jPassword().Name()].(string),
	}

	db, err := adapters.NewNeo4jDatabase(graphConfig)
	if err != nil {
		return err
	}
	a.db = db

	err = a.db.VerifyConnectivity(context.Background())
	if err != nil {
		return err
	}

	return nil
}

func (a *ApolloReport) Process(input any) error {
	reportType, _ := cfg.As[string](a.Arg("report-type"))

	report := &types.ApolloReportData{
		Generated: time.Now().UTC().Format(time.RFC3339),
	}

	// Generate privilege escalation report
	if reportType == "all" || reportType == "privesc" {
		privescReport, err := a.generatePrivescReport()
		if err != nil {
			a.Logger.Error("Failed to generate privesc report", "error", err)
		} else {
			report.Privesc = privescReport
		}
	}

	// Generate external trust report
	if reportType == "all" || reportType == "external-trust" {
		externalTrustReport, err := a.generateExternalTrustReport()
		if err != nil {
			a.Logger.Error("Failed to generate external trust report", "error", err)
		} else {
			report.ExternalTrust = externalTrustReport
		}
	}

	return a.Send(report)
}

func (a *ApolloReport) generatePrivescReport() (*types.PrivescReport, error) {
	res, err := queries.RunPlatformQuery(a.db, "aws/analysis/privesc_paths", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to run privesc_paths query: %w", err)
	}

	report := &types.PrivescReport{
		ByHops: make(map[int]int),
		Paths:  make(map[int][]types.PrivescPath),
	}

	for _, record := range res.Records {
		path := types.PrivescPath{}

		// Extract source (vulnerable)
		if vulnerable, ok := record["vulnerable"].(string); ok {
			path.Source = vulnerable
		}

		// Extract intermediate targets
		if intermediates, ok := record["intermediateTargets"].([]any); ok {
			for _, i := range intermediates {
				if s, ok := i.(string); ok {
					path.Intermediate = append(path.Intermediate, s)
				}
			}
		}

		// Extract final targets
		if targets, ok := record["finalTargets"].([]any); ok {
			for _, t := range targets {
				if s, ok := t.(string); ok {
					path.Target = append(path.Target, s)
				}
			}
		}

		// Extract hops
		if hops, ok := record["hops"].(int64); ok {
			path.Hops = int(hops)
		}

		// Extract methods
		if methods, ok := record["methods"].([]any); ok {
			for _, m := range methods {
				if s, ok := m.(string); ok {
					path.Methods = append(path.Methods, s)
				}
			}
		}

		report.Total++
		report.ByHops[path.Hops]++
		report.Paths[path.Hops] = append(report.Paths[path.Hops], path)
	}

	// Sort paths within each hop count by source
	for hops := range report.Paths {
		sort.Slice(report.Paths[hops], func(i, j int) bool {
			return report.Paths[hops][i].Source < report.Paths[hops][j].Source
		})
	}

	return report, nil
}

func (a *ApolloReport) generateExternalTrustReport() (*types.ExternalTrustReport, error) {
	res, err := queries.RunPlatformQuery(a.db, "aws/analysis/external_role_trust", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to run external_role_trust query: %w", err)
	}

	report := &types.ExternalTrustReport{}

	for _, record := range res.Records {
		role := types.ExternalTrustRole{}

		// Extract ARN
		if arn, ok := record["vulnerable"].(string); ok {
			role.ARN = arn
		}

		// Extract role name
		if roleName, ok := record["roleName"].(string); ok {
			role.RoleName = roleName
		}

		// Extract account ID
		if accountID, ok := record["accountId"].(string); ok {
			role.AccountID = accountID
		}

		// Extract isPrivileged
		if isPrivileged, ok := record["isPrivileged"].(bool); ok {
			role.IsPrivileged = isPrivileged
		}

		// Extract trustsPublic
		if trustsPublic, ok := record["trustsPublic"].(bool); ok {
			role.TrustsPublic = trustsPublic
		}

		// Extract trustsAccountRoot
		if trustsRoot, ok := record["trustsAccountRoot"].(bool); ok {
			role.TrustsAccountRoot = trustsRoot
		}

		// Extract external principals
		if principals, ok := record["trustedExternalPrincipals"].([]any); ok {
			for _, p := range principals {
				if s, ok := p.(string); ok {
					role.ExternalPrincipals = append(role.ExternalPrincipals, s)
				}
			}
		}

		report.Total++

		// Categorize the role
		if role.IsPrivileged {
			report.PrivilegedWithExternal++
			report.PrivilegedRoles = append(report.PrivilegedRoles, role)
		} else if role.TrustsPublic {
			report.TrustsPublic++
			report.PublicTrustRoles = append(report.PublicTrustRoles, role)
		} else if role.TrustsAccountRoot {
			report.TrustsRoot++
			report.RootTrustRoles = append(report.RootTrustRoles, role)
		} else {
			report.OtherExternalTrustRoles = append(report.OtherExternalTrustRoles, role)
		}
	}

	// Sort each category by role name
	sortRoles := func(roles []types.ExternalTrustRole) {
		sort.Slice(roles, func(i, j int) bool {
			return roles[i].RoleName < roles[j].RoleName
		})
	}
	sortRoles(report.PrivilegedRoles)
	sortRoles(report.PublicTrustRoles)
	sortRoles(report.RootTrustRoles)
	sortRoles(report.OtherExternalTrustRoles)

	return report, nil
}

func (a *ApolloReport) Close() {
	if a.db != nil {
		a.db.Close()
	}
}

// Helper function to extract short name from ARN
func extractShortName(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	// Try extracting after last colon
	parts = strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}
