package outputters

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type RiskCSVOutputter struct {
	*chain.BaseOutputter
	risks        []model.Risk           // List to store all risks
	apolloResults []types.ApolloQueryResult // List to store Apollo query results
	outputFile   string
}

// NewRiskCSVOutputter creates a new CSV outputter for Risk types
func NewRiskCSVOutputter(configs ...cfg.Config) chain.Outputter {
	o := &RiskCSVOutputter{
		risks:         []model.Risk{},
		apolloResults: []types.ApolloQueryResult{},
		outputFile:    "risks.csv",
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects risk items for CSV output
func (o *RiskCSVOutputter) Output(v any) error {
	// Try to get an ApolloQueryResult first
	if apolloResult, ok := v.(types.ApolloQueryResult); ok {
		o.apolloResults = append(o.apolloResults, apolloResult)
		return nil
	}
	if apolloResultPtr, ok := v.(*types.ApolloQueryResult); ok {
		o.apolloResults = append(o.apolloResults, *apolloResultPtr)
		return nil
	}

	// Try to get a Janus Risk type
	janusRisk, ok := v.(model.Risk)
	if !ok {
		// Try as pointer
		janusRiskPtr, ok := v.(*model.Risk)
		if !ok {
			return nil // Not a supported type, silently ignore
		}
		janusRisk = *janusRiskPtr
	}

	// Store the risk
	o.risks = append(o.risks, janusRisk)

	return nil
}

// Initialize is called when the outputter is initialized
func (o *RiskCSVOutputter) Initialize() error {
	// Get output file from parameters
	outputFile, err := cfg.As[string](o.Arg("csvoutfile"))
	if err == nil && outputFile != "" {
		o.outputFile = outputFile
	}
	return nil
}

// Complete is called when the chain is complete - write all collected risks to CSV
func (o *RiskCSVOutputter) Complete() error {
	// Handle Apollo query results
	if len(o.apolloResults) > 0 {
		return o.writeApolloResults()
	}

	// Handle standard risks
	if len(o.risks) == 0 {
		slog.Info("No risks to write to CSV")
		return nil
	}

	return o.writeRisks()
}

// writeApolloResults writes Apollo query results to CSV
func (o *RiskCSVOutputter) writeApolloResults() error {
	file, err := os.Create(o.outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header for Apollo results
	header := []string{
		"Name",
		"Severity",
		"Vulnerable",
		"Description",
		"Impacted Services",
		"Proof",
	}

	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// Write each Apollo result as a CSV row
	for _, result := range o.apolloResults {
		// Convert impacted services to string
		impactedServices, _ := formatAny(result.ImpactedServices)

		// Convert proof to string
		proofStr, err := formatMap(result.Proof)
		if err != nil {
			proofStr = fmt.Sprintf("Error formatting proof: %v", err)
		}

		row := []string{
			result.Name,
			result.Severity,
			result.Vulnerable,
			result.Description,
			impactedServices,
			proofStr,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row: %w", err)
		}
	}

	message.Success("CSV output written to %s (%d results)", o.outputFile, len(o.apolloResults))
	return nil
}

// writeRisks writes standard Risk objects to CSV
func (o *RiskCSVOutputter) writeRisks() error {
	file, err := os.Create(o.outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	header := []string{
		"Name",
		"Severity",
		"DNS",
		"IP",
		"Description",
		"Impacted Services",
		"Proof",
		"Metadata",
	}

	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %w", err)
	}

	// Write each risk as a CSV row
	for _, risk := range o.risks {
		row := []string{
			risk.Name,
			fmt.Sprintf("%d", risk.Priority),
			risk.DNS,
			"", // IP (not used)
			"", // Description
			"", // Impacted Services
			"", // Proof
			"", // Metadata
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row: %w", err)
		}
	}

	message.Success("CSV output written to %s (%d risks)", o.outputFile, len(o.risks))
	return nil
}

// formatMap formats a map as a string (used for Proof and Metadata)
func formatMap(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	// Make the JSON string safe for CSV (replace commas, quotes, etc.)
	return strings.ReplaceAll(string(jsonBytes), "\"", "'"), nil
}

// formatAny formats any value as a string
func formatAny(v any) (string, error) {
	if v == nil {
		return "", nil
	}

	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// Make the JSON string safe for CSV (replace commas, quotes, etc.)
	return strings.ReplaceAll(string(jsonBytes), "\"", "'"), nil
}

// Params returns the parameters for this outputter
func (o *RiskCSVOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("csvoutfile", "file to write the CSV output to").WithDefault("risks.csv"),
	}
}
