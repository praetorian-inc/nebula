package outputters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// ApolloReportOutputter outputs Apollo report data as markdown and JSON files
type ApolloReportOutputter struct {
	*chain.BaseOutputter
	outputDir string
	reports   []*types.ApolloReportData
}

func NewApolloReportOutputter(configs ...cfg.Config) chain.Outputter {
	o := &ApolloReportOutputter{
		reports: make([]*types.ApolloReportData, 0),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

func (o *ApolloReportOutputter) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
	}
}

func (o *ApolloReportOutputter) Initialize() error {
	outputDir, err := cfg.As[string](o.Arg("output"))
	if err != nil {
		outputDir = "nebula-output"
	}
	o.outputDir = outputDir

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(o.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return nil
}

func (o *ApolloReportOutputter) Output(val any) error {
	report, ok := val.(*types.ApolloReportData)
	if !ok {
		return nil
	}

	o.reports = append(o.reports, report)
	return nil
}

func (o *ApolloReportOutputter) Complete() error {
	for _, report := range o.reports {
		// Write JSON report
		if err := o.writeJSONReport(report); err != nil {
			return err
		}

		// Write Markdown reports
		if report.Privesc != nil {
			if err := o.writePrivescMarkdown(report); err != nil {
				return err
			}
		}

		if report.ExternalTrust != nil {
			if err := o.writeExternalTrustMarkdown(report); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *ApolloReportOutputter) writeJSONReport(report *types.ApolloReportData) error {
	jsonPath := filepath.Join(o.outputDir, "apollo-report.json")

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	fmt.Printf("Written: %s\n", jsonPath)
	return nil
}

func (o *ApolloReportOutputter) writePrivescMarkdown(report *types.ApolloReportData) error {
	mdPath := filepath.Join(o.outputDir, "privesc-report.md")

	var sb strings.Builder

	sb.WriteString("# Privilege Escalation Paths Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.Generated))
	sb.WriteString(fmt.Sprintf("**Total Principals with Escalation Paths:** %d\n\n", report.Privesc.Total))

	// Summary table
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Hop Distance | Count |\n")
	sb.WriteString("|--------------|-------|\n")

	// Sort hop counts for consistent output
	hopCounts := make([]int, 0, len(report.Privesc.ByHops))
	for hops := range report.Privesc.ByHops {
		hopCounts = append(hopCounts, hops)
	}
	sortInts(hopCounts)

	for _, hops := range hopCounts {
		count := report.Privesc.ByHops[hops]
		label := getHopLabel(hops)
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", label, count))
	}
	sb.WriteString("\n---\n\n")

	// Detailed tables by hop count
	for _, hops := range hopCounts {
		paths := report.Privesc.Paths[hops]
		if len(paths) == 0 {
			continue
		}

		label := getHopLabel(hops)
		sb.WriteString(fmt.Sprintf("## %s\n\n", label))

		if hops == 1 {
			// Simple table for direct escalation
			sb.WriteString("| Source Principal | Target (Admin) | Methods |\n")
			sb.WriteString("|-----------------|----------------|----------|\n")
			for _, path := range paths {
				source := formatARNForTable(path.Source)
				targets := formatARNListForTable(path.Target)
				methods := strings.Join(path.Methods, ", ")
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", source, targets, methods))
			}
		} else {
			// Table with intermediate nodes for multi-hop
			sb.WriteString("| Source Principal | Intermediate | Target (Admin) | Methods |\n")
			sb.WriteString("|-----------------|--------------|----------------|----------|\n")
			for _, path := range paths {
				source := formatARNForTable(path.Source)
				intermediate := formatARNListForTable(path.Intermediate)
				if intermediate == "" {
					intermediate = "-"
				}
				targets := formatARNListForTable(path.Target)
				methods := strings.Join(path.Methods, " -> ")
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", source, intermediate, targets, methods))
			}
		}
		sb.WriteString("\n---\n\n")
	}

	if err := os.WriteFile(mdPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write privesc markdown report: %w", err)
	}

	fmt.Printf("Written: %s\n", mdPath)
	return nil
}

func (o *ApolloReportOutputter) writeExternalTrustMarkdown(report *types.ApolloReportData) error {
	mdPath := filepath.Join(o.outputDir, "external-trust-report.md")

	var sb strings.Builder

	sb.WriteString("# External Role Trust Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.Generated))
	sb.WriteString(fmt.Sprintf("**Total Externally-Trusted Roles:** %d\n\n", report.ExternalTrust.Total))

	// Summary table
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Category | Count | Risk |\n")
	sb.WriteString("|----------|-------|------|\n")
	sb.WriteString(fmt.Sprintf("| Privileged + External Trust | %d | Critical |\n", report.ExternalTrust.PrivilegedWithExternal))
	sb.WriteString(fmt.Sprintf("| Trusts Public Principal | %d | Critical |\n", report.ExternalTrust.TrustsPublic))
	sb.WriteString(fmt.Sprintf("| Trusts Account Root | %d | High |\n", report.ExternalTrust.TrustsRoot))
	sb.WriteString(fmt.Sprintf("| Other External Trust | %d | Medium |\n", len(report.ExternalTrust.OtherExternalTrustRoles)))
	sb.WriteString("\n---\n\n")

	// Privileged roles with external trust
	if len(report.ExternalTrust.PrivilegedRoles) > 0 {
		sb.WriteString("## Critical: Privileged Roles with External Trust\n\n")
		sb.WriteString("These roles can escalate to admin AND are trusted by external accounts.\n\n")
		sb.WriteString("| Role | Account | External Principals | Trusts Public | Trusts Root |\n")
		sb.WriteString("|------|---------|---------------------|---------------|-------------|\n")
		for _, role := range report.ExternalTrust.PrivilegedRoles {
			principals := formatPrincipalsForTable(role.ExternalPrincipals)
			trustsPublic := boolToEmoji(role.TrustsPublic)
			trustsRoot := boolToEmoji(role.TrustsAccountRoot)
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s | %s |\n",
				role.RoleName, role.AccountID, principals, trustsPublic, trustsRoot))
		}
		sb.WriteString("\n---\n\n")
	}

	// Roles trusting public principals
	if len(report.ExternalTrust.PublicTrustRoles) > 0 {
		sb.WriteString("## Critical: Roles Trusting Public Principals\n\n")
		sb.WriteString("| Role | Account | Is Privileged | External Principals |\n")
		sb.WriteString("|------|---------|---------------|---------------------|\n")
		for _, role := range report.ExternalTrust.PublicTrustRoles {
			privileged := boolToEmoji(role.IsPrivileged)
			principals := formatPrincipalsForTable(role.ExternalPrincipals)
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n",
				role.RoleName, role.AccountID, privileged, principals))
		}
		sb.WriteString("\n---\n\n")
	}

	// Roles trusting account root
	if len(report.ExternalTrust.RootTrustRoles) > 0 {
		sb.WriteString("## High: Roles Trusting External Account Root\n\n")
		sb.WriteString("| Role | Account | External Principals | Is Privileged |\n")
		sb.WriteString("|------|---------|---------------------|---------------|\n")
		for _, role := range report.ExternalTrust.RootTrustRoles {
			principals := formatPrincipalsForTable(role.ExternalPrincipals)
			privileged := boolToEmoji(role.IsPrivileged)
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n",
				role.RoleName, role.AccountID, principals, privileged))
		}
		sb.WriteString("\n---\n\n")
	}

	// Other external trust roles
	if len(report.ExternalTrust.OtherExternalTrustRoles) > 0 {
		sb.WriteString("## Medium: Other Roles with External Trust\n\n")
		sb.WriteString("| Role | Account | External Principals | Trusts Root |\n")
		sb.WriteString("|------|---------|---------------------|-------------|\n")
		for _, role := range report.ExternalTrust.OtherExternalTrustRoles {
			principals := formatPrincipalsForTable(role.ExternalPrincipals)
			trustsRoot := boolToEmoji(role.TrustsAccountRoot)
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | %s |\n",
				role.RoleName, role.AccountID, principals, trustsRoot))
		}
		sb.WriteString("\n---\n\n")
	}

	if err := os.WriteFile(mdPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write external trust markdown report: %w", err)
	}

	fmt.Printf("Written: %s\n", mdPath)
	return nil
}

// Helper functions

func sortInts(ints []int) {
	for i := 0; i < len(ints)-1; i++ {
		for j := i + 1; j < len(ints); j++ {
			if ints[i] > ints[j] {
				ints[i], ints[j] = ints[j], ints[i]
			}
		}
	}
}

func getHopLabel(hops int) string {
	switch hops {
	case 1:
		return "First-Order Escalation Paths (Direct)"
	case 2:
		return "Second-Order Escalation Paths (2 Hops)"
	case 3:
		return "Third-Order Escalation Paths (3 Hops)"
	default:
		return fmt.Sprintf("%d-Hop Escalation Paths", hops)
	}
}

func formatARNForTable(arn string) string {
	// Extract the resource part after the last /
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		// Return role/name or user/name format
		resourceParts := strings.Split(arn, ":")
		if len(resourceParts) >= 6 {
			return fmt.Sprintf("`%s`", resourceParts[5])
		}
		return fmt.Sprintf("`%s`", parts[len(parts)-1])
	}
	return fmt.Sprintf("`%s`", arn)
}

func formatARNListForTable(arns []string) string {
	if len(arns) == 0 {
		return ""
	}
	formatted := make([]string, len(arns))
	for i, arn := range arns {
		formatted[i] = formatARNForTable(arn)
	}
	return strings.Join(formatted, ", ")
}

func formatPrincipalsForTable(principals []string) string {
	if len(principals) == 0 {
		return "-"
	}
	if len(principals) > 3 {
		// Truncate long lists
		short := make([]string, 3)
		for i := 0; i < 3; i++ {
			short[i] = truncateARN(principals[i])
		}
		return strings.Join(short, ", ") + fmt.Sprintf(" (+%d more)", len(principals)-3)
	}
	truncated := make([]string, len(principals))
	for i, p := range principals {
		truncated[i] = truncateARN(p)
	}
	return strings.Join(truncated, ", ")
}

func truncateARN(arn string) string {
	// Show just the resource portion for readability
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		accountID := parts[4]
		resource := ""
		if len(parts) >= 6 {
			resource = parts[5]
		}
		// Show account:resource
		if resource != "" {
			return fmt.Sprintf("`%s:%s`", accountID, resource)
		}
		return fmt.Sprintf("`%s`", accountID)
	}
	return fmt.Sprintf("`%s`", arn)
}

func boolToEmoji(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
