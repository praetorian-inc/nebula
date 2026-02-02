package types

import (
	"fmt"
	"strings"
)

type OutputProvider interface {
	Write(result Result) error
}

type OutputProviders []func(options []*Option) OutputProvider

type MarkdownTable struct {
	TableHeading string
	Headers      []string
	Rows         [][]string
}

// ToString converts the MarkdownTable to a markdown string
func (t MarkdownTable) ToString() string {
	var result strings.Builder
	
	// Write table heading if exists
	if t.TableHeading != "" {
		result.WriteString("# " + t.TableHeading + "\n\n")
	}
	
	if len(t.Headers) == 0 {
		return result.String()
	}

	// Dynamically determine column width
	colWidths := make([]int, len(t.Headers))
	for i, header := range t.Headers {
		colWidths[i] = len(header)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Write header
	headerRow := "|"
	dividerRow := "|"
	for i, header := range t.Headers {
		formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
		headerRow += fmt.Sprintf(formatter, header)
		dividerRow += fmt.Sprintf(" %s |", strings.Repeat("-", colWidths[i]))
	}
	headerRow += "\n"
	dividerRow += "\n"
	result.WriteString(headerRow)
	result.WriteString(dividerRow)

	// Write rows
	for _, row := range t.Rows {
		rowText := "|"
		for i, cell := range row {
			if i < len(colWidths) {
				formatter := fmt.Sprintf(" %%-%ds |", colWidths[i])
				rowText += fmt.Sprintf(formatter, cell)
			}
		}
		rowText += "\n"
		result.WriteString(rowText)
	}
	
	return result.String()
}

// Implement Markdownable interface for compatibility with janus-framework output
func (t MarkdownTable) Columns() []string {
	return t.Headers
}

func (t MarkdownTable) RowIndices() []int {
	rows := make([]int, len(t.Rows))
	for i := range t.Rows {
		rows[i] = i
	}
	return rows
}

func (t MarkdownTable) Values() []any {
	var values []any
	// Add headers first
	for _, header := range t.Headers {
		values = append(values, header)
	}
	// Add all row values
	for _, row := range t.Rows {
		for _, cell := range row {
			values = append(values, cell)
		}
	}
	return values
}

// PrivescPath represents a single privilege escalation path
type PrivescPath struct {
	Source       string   `json:"source"`
	Intermediate []string `json:"intermediate"`
	Target       []string `json:"target"`
	Hops         int      `json:"hops"`
	Methods      []string `json:"methods"`
}

// ExternalTrustRole represents a role with external trust
type ExternalTrustRole struct {
	ARN                string   `json:"arn"`
	RoleName           string   `json:"role_name"`
	AccountID          string   `json:"account_id"`
	IsPrivileged       bool     `json:"is_privileged"`
	TrustsPublic       bool     `json:"trusts_public"`
	TrustsAccountRoot  bool     `json:"trusts_root"`
	ExternalPrincipals []string `json:"external_principals"`
}

// PrivescReport contains aggregated privilege escalation data
type PrivescReport struct {
	Total  int                   `json:"total"`
	ByHops map[int]int           `json:"by_hops"`
	Paths  map[int][]PrivescPath `json:"paths_by_hops"` // grouped by hop count
}

// ExternalTrustReport contains aggregated external trust data
type ExternalTrustReport struct {
	Total                   int                 `json:"total"`
	PrivilegedWithExternal  int                 `json:"privileged_with_external"`
	TrustsPublic            int                 `json:"trusts_public"`
	TrustsRoot              int                 `json:"trusts_root"`
	PrivilegedRoles         []ExternalTrustRole `json:"privileged_roles"`
	PublicTrustRoles        []ExternalTrustRole `json:"public_trust_roles"`
	RootTrustRoles          []ExternalTrustRole `json:"root_trust_roles"`
	OtherExternalTrustRoles []ExternalTrustRole `json:"other_external_trust_roles"`
}

// ApolloReportData is the complete report structure sent to outputters
type ApolloReportData struct {
	Generated     string               `json:"generated"`
	Privesc       *PrivescReport       `json:"privesc,omitempty"`
	ExternalTrust *ExternalTrustReport `json:"external_trust,omitempty"`
}
