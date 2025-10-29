package outputters

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// Command represents the input and output of a command that requires manual triage
// This is a local copy of enricher.Command to avoid import cycles
type Command struct {
	Command                   string `json:"command"`
	Description               string `json:"description"`
	ExpectedOutputDescription string `json:"expected_output_description"`
	ActualOutput              string `json:"actual_output"`
	ExitCode                  int    `json:"exit_code"`
	Error                     string `json:"error,omitempty"`
}

// ARGScanOutput represents the complete output structure with template metadata
type ARGScanOutput struct {
	Metadata ARGScanMetadata `json:"metadata"`
	Findings []any           `json:"findings"`
}

// ARGScanMetadata contains information about the scan and template details
type ARGScanMetadata struct {
	ScanDate    time.Time                                `json:"scanDate"`
	TotalCount  int                                      `json:"totalFindings"`
	Templates   map[string]*templates.ARGQueryTemplate   `json:"templates"`
}

// ARGScanJSONOutputter is specialized for ARG scan results with template metadata
type ARGScanJSONOutputter struct {
	*BaseFileOutputter
	indent     int
	findings   []any
	templates  map[string]*templates.ARGQueryTemplate
	outfile    string
	scanDate   time.Time
}

// NewARGScanJSONOutputter creates a new ARGScanJSONOutputter
func NewARGScanJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &ARGScanJSONOutputter{
		templates: make(map[string]*templates.ARGQueryTemplate),
		scanDate:  time.Now(),
	}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter
func (j *ARGScanJSONOutputter) Initialize() error {
	// Get output directory and filename (reuse logic from RuntimeJSONOutputter)
	outputDir, err := cfg.As[string](j.Arg("output"))
	if err != nil {
		outputDir = "nebula-output"
	}

	// Generate contextual filename
	moduleName, err := cfg.As[string](j.Arg("module-name"))
	if err != nil {
		moduleName = "arg-scan"
	}

	// Generate Azure-specific filename
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 {
		subscription := subscriptions[0]
		if subscription == "all" {
			j.outfile = fmt.Sprintf("%s/%s-all-subscriptions.json", outputDir, moduleName)
		} else {
			j.outfile = fmt.Sprintf("%s/%s-%s.json", outputDir, moduleName, subscription)
		}
	} else {
		j.outfile = fmt.Sprintf("%s/%s.json", outputDir, moduleName)
	}

	// Ensure directory exists
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Get indentation setting
	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 2 // Default to 2 for readability
	}
	j.indent = indent

	return nil
}

// Output processes findings and collects template metadata
func (j *ARGScanJSONOutputter) Output(val any) error {
	// Handle NamedOutputData wrapper
	if outputData, ok := val.(NamedOutputData); ok {
		return j.processFinding(outputData.Data)
	}
	return j.processFinding(val)
}

// processFinding extracts template information and stores the finding
func (j *ARGScanJSONOutputter) processFinding(finding any) error {
	j.findings = append(j.findings, finding)

	// Try to extract template information from different types
	var templateID string

	// Check if it's an AzureResource from the model package (value or pointer)
	if azureResource, ok := finding.(model.AzureResource); ok {
		if azureResource.Properties != nil {
			if id, exists := azureResource.Properties["templateID"]; exists {
				if templateIDStr, ok := id.(string); ok {
					templateID = templateIDStr
				}
			}
		}
	} else if azureResource, ok := finding.(*model.AzureResource); ok {
		if azureResource.Properties != nil {
			if id, exists := azureResource.Properties["templateID"]; exists {
				if templateIDStr, ok := id.(string); ok {
					templateID = templateIDStr
				}
			}
		}
	} else if findingMap, ok := finding.(map[string]any); ok {
		if properties, ok := findingMap["properties"].(map[string]any); ok {
			if id, ok := properties["templateID"].(string); ok {
				templateID = id
			}
		}
	}

	if templateID != "" {
		// Load template details if we haven't seen this template ID before
		if _, exists := j.templates[templateID]; !exists {
			j.loadTemplateDetails(templateID)
		}
	}

	return nil
}

// loadTemplateDetails loads template metadata for a given template ID
func (j *ARGScanJSONOutputter) loadTemplateDetails(templateID string) {
	// Initialize template loader
	var loader *templates.TemplateLoader
	var err error

	// Check if user specified a template directory
	if templateDir, dirErr := cfg.As[string](j.Arg("template-dir")); dirErr == nil && templateDir != "" {
		// User specified directory - use ONLY user templates
		loader, err = templates.NewTemplateLoader(templates.UserTemplatesOnly)
		if err != nil {
			message.Error("Failed to initialize template loader: %v", err)
			j.templates[templateID] = nil
			return
		}

		if err := loader.LoadUserTemplates(templateDir); err != nil {
			message.Error("Failed to load templates from %s: %v", templateDir, err)
			j.templates[templateID] = nil
			return
		}
	} else {
		// No template directory specified - use embedded templates
		loader, err = templates.NewTemplateLoader(templates.LoadEmbedded)
		if err != nil {
			message.Error("Failed to initialize template loader: %v", err)
			j.templates[templateID] = nil
			return
		}
	}

	// Find the template by ID
	templatesList := loader.GetTemplates()
	for _, template := range templatesList {
		if template.ID == templateID {
			j.templates[templateID] = template
			return
		}
	}

	// Template not found - this shouldn't happen for valid templateIDs
	message.Warning("Template with ID '%s' not found among %d available templates", templateID, len(templatesList))
	j.templates[templateID] = nil
}

// SetTemplateDetails allows the ARG scan module to provide template metadata
func (j *ARGScanJSONOutputter) SetTemplateDetails(templates map[string]*templates.ARGQueryTemplate) {
	j.templates = templates
}

// Complete writes the structured output with template metadata
func (j *ARGScanJSONOutputter) Complete() error {
	// Create the complete output structure
	output := ARGScanOutput{
		Metadata: ARGScanMetadata{
			ScanDate:   j.scanDate,
			TotalCount: len(j.findings),
			Templates:  j.templates,
		},
		Findings: j.findings,
	}

	// Write to file
	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating JSON file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	// Go's JSON encoder handles all special character escaping automatically
	err = encoder.Encode(output)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %w", err)
	}

	message.Success("ARG scan JSON output written to: %s", j.outfile)

	// Generate markdown report
	if err := j.writeMarkdownReport(); err != nil {
		message.Warning("Failed to generate markdown report: %v", err)
		// Don't fail the entire operation for markdown generation issues
	}

	return nil
}

// writeMarkdownReport generates a markdown report alongside the JSON output
func (j *ARGScanJSONOutputter) writeMarkdownReport() error {
	// Generate markdown filename from JSON filename
	markdownFile := strings.Replace(j.outfile, ".json", ".md", 1)

	writer, err := os.Create(markdownFile)
	if err != nil {
		return fmt.Errorf("error creating markdown file %s: %w", markdownFile, err)
	}
	defer writer.Close()

	// Write the report sections
	j.writeSummarySection(writer)
	j.writeTemplateDetails(writer)

	message.Success("ARG scan markdown report written to: %s", markdownFile)
	return nil
}

// extractTemplateIDAndResource extracts template ID and normalizes finding to AzureResource
// Handles model.AzureResource (value), *model.AzureResource (pointer), and map[string]any (generic maps)
func (j *ARGScanJSONOutputter) extractTemplateIDAndResource(finding any) (string, *model.AzureResource) {
	switch f := finding.(type) {
	case model.AzureResource:
		// Handle value type
		if f.Properties != nil {
			if id, exists := f.Properties["templateID"]; exists {
				if templateID, ok := id.(string); ok {
					return templateID, &f
				}
			}
		}
	case *model.AzureResource:
		// Handle pointer type
		if f != nil && f.Properties != nil {
			if id, exists := f.Properties["templateID"]; exists {
				if templateID, ok := id.(string); ok {
					return templateID, f
				}
			}
		}
	case map[string]any:
		// Handle generic map - convert to AzureResource
		templateID := ""
		if properties, ok := f["properties"].(map[string]any); ok {
			if id, ok := properties["templateID"].(string); ok {
				templateID = id
			}
		}
		if templateID != "" {
			// Convert map to AzureResource struct
			azureResource := &model.AzureResource{}
			if name, ok := f["name"].(string); ok {
				azureResource.Name = name
			}
			if resourceType, ok := f["type"].(string); ok {
				azureResource.ResourceType = model.CloudResourceType(resourceType)
			}
			if location, ok := f["location"].(string); ok {
				azureResource.Region = location
			}
			if subscriptionId, ok := f["subscriptionId"].(string); ok {
				azureResource.AccountRef = subscriptionId
			}
			if properties, ok := f["properties"].(map[string]any); ok {
				azureResource.Properties = properties
			}
			return templateID, azureResource
		}
	}
	return "", nil
}

// writeSummarySection writes the summary table showing all templates and their finding counts
func (j *ARGScanJSONOutputter) writeSummarySection(writer *os.File) {
	fmt.Fprintf(writer, "# Azure Resource Graph Scan Results\n\n")
	fmt.Fprintf(writer, "**Scan Date:** %s\n", j.scanDate.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(writer, "**Total Findings:** %d\n\n", len(j.findings))

	// Count findings by template
	findingCounts := make(map[string]int)
	for _, finding := range j.findings {
		if templateID, _ := j.extractTemplateIDAndResource(finding); templateID != "" {
			findingCounts[templateID]++
		}
	}

	fmt.Fprintf(writer, "## Summary\n\n")
	fmt.Fprintf(writer, "| Template Name | Findings Count |\n")
	fmt.Fprintf(writer, "|---------------|----------------|\n")

	// Include all templates, even those with 0 findings
	for templateID, template := range j.templates {
		if template != nil {
			count := findingCounts[templateID]
			fmt.Fprintf(writer, "| %s | %d |\n", template.Name, count)
		}
	}
	fmt.Fprintf(writer, "\n---\n\n")
}

// writeTemplateDetails writes detailed sections for each template that has findings
func (j *ARGScanJSONOutputter) writeTemplateDetails(writer *os.File) {
	// Group findings by template
	findingsByTemplate := make(map[string][]*model.AzureResource)
	for _, finding := range j.findings {
		if templateID, azureResource := j.extractTemplateIDAndResource(finding); templateID != "" && azureResource != nil {
			findingsByTemplate[templateID] = append(findingsByTemplate[templateID], azureResource)
		}
	}

	// Write section for each template with findings
	for templateID, findings := range findingsByTemplate {
		if template, exists := j.templates[templateID]; exists && template != nil {
			j.writeTemplateSectionDetail(writer, template, findings)
		}
	}
}

// writeTemplateSectionDetail writes the detailed section for a specific template
func (j *ARGScanJSONOutputter) writeTemplateSectionDetail(writer *os.File, template *templates.ARGQueryTemplate, findings []*model.AzureResource) {
	fmt.Fprintf(writer, "## %s\n\n", template.Name)
	fmt.Fprintf(writer, "**Description:** %s\n\n", template.Description)
	fmt.Fprintf(writer, "**Severity:** %s\n\n", template.Severity)
	fmt.Fprintf(writer, "**Template ID:** %s\n\n", template.ID)

	// Check if any findings have enricher commands
	hasEnricherCommands := j.findingsHaveEnricherCommands(findings)

	// Findings table
	fmt.Fprintf(writer, "### Findings\n\n")

	if hasEnricherCommands {
		j.writeEnrichedFindingsTable(writer, findings)
	} else {
		j.writeStandardFindingsTable(writer, findings)
	}


	// Triage guide
	if template.TriageNotes != "" {
		fmt.Fprintf(writer, "\n### Triage Guide\n\n")
		fmt.Fprintf(writer, "```\n%s\n```\n\n", template.TriageNotes)
	}

	// References
	if len(template.References) > 0 {
		fmt.Fprintf(writer, "### References\n\n")
		for _, ref := range template.References {
			fmt.Fprintf(writer, "- %s\n", ref)
		}
		fmt.Fprintf(writer, "\n")
	}

	fmt.Fprintf(writer, "---\n\n")
}

// buildDetailsString creates a concise details string from resource properties
func (j *ARGScanJSONOutputter) buildDetailsString(properties map[string]any) string {
	var details []string

	// Common interesting properties to include
	interestingProps := []string{
		"publicNetworkAccess", "publicAccess", "sku", "kind",
		"minimumTlsVersion", "enableNonSslPort", "hostname",
		"defaultAction", "bypass", "tags",
		"publicNetworkAccessForIngestion", "publicNetworkAccessForQuery",
		"accessType", "authorizedIPs", "publicIPs", "privateIPs",
	}

	for _, prop := range interestingProps {
		// Skip enricher commands as they are handled in the enriched table
		if prop == "commands" {
			continue
		}

		if value, exists := properties[prop]; exists {
			// Format the value appropriately
			switch v := value.(type) {
			case string:
				if v != "" {
					details = append(details, fmt.Sprintf("%s: %s", prop, v))
				}
			case bool:
				details = append(details, fmt.Sprintf("%s: %t", prop, v))
			case map[string]any:
				// For complex objects, just indicate presence
				details = append(details, fmt.Sprintf("%s: [object]", prop))
			case []any:
				if len(v) > 0 {
					details = append(details, fmt.Sprintf("%s: [%d items]", prop, len(v)))
				}
			default:
				details = append(details, fmt.Sprintf("%s: %v", prop, v))
			}
		}
	}

	// Also skip the commands property if it exists in properties but not in interestingProps
	for prop, value := range properties {
		if prop == "commands" || prop == "templateID" {
			continue // Skip enricher-specific properties
		}

		// Only add if not already in interestingProps to avoid duplication
		alreadyIncluded := false
		for _, intProp := range interestingProps {
			if prop == intProp {
				alreadyIncluded = true
				break
			}
		}

		if !alreadyIncluded && len(details) < 10 { // Limit additional properties
			switch v := value.(type) {
			case string:
				if v != "" && len(v) < 50 { // Keep short strings only
					details = append(details, fmt.Sprintf("%s: %s", prop, v))
				}
			case bool:
				details = append(details, fmt.Sprintf("%s: %t", prop, v))
			case int, int64, float64:
				details = append(details, fmt.Sprintf("%s: %v", prop, v))
			}
		}
	}

	// Limit to reasonable length for table cell
	result := strings.Join(details, "; ")
	if len(result) > 200 {
		result = result[:197] + "..."
	}

	return result
}

// findingsHaveEnricherCommands checks if any findings contain enricher commands
func (j *ARGScanJSONOutputter) findingsHaveEnricherCommands(findings []*model.AzureResource) bool {
	for _, finding := range findings {
		if finding != nil && finding.Properties != nil {
			if commands, exists := finding.Properties["commands"]; exists {
				if commandSlice, ok := commands.([]any); ok && len(commandSlice) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// writeStandardFindingsTable writes the traditional findings table format
func (j *ARGScanJSONOutputter) writeStandardFindingsTable(writer *os.File, findings []*model.AzureResource) {
	fmt.Fprintf(writer, "| Resource Name | Resource Type | Location | Subscription | Details |\n")
	fmt.Fprintf(writer, "|---------------|---------------|----------|--------------|----------|\n")

	for _, finding := range findings {
		if finding == nil {
			continue
		}
		resourceName := finding.Name
		resourceType := string(finding.ResourceType)
		location := finding.Region
		subscription := finding.AccountRef

		// Build details string from relevant properties (excluding commands)
		details := j.buildDetailsString(finding.Properties)

		fmt.Fprintf(writer, "| %s | %s | %s | %s | %s |\n",
			resourceName, resourceType, location, subscription, details)
	}
}

// writeEnrichedFindingsTable writes the enhanced findings table with enricher commands
func (j *ARGScanJSONOutputter) writeEnrichedFindingsTable(writer *os.File, findings []*model.AzureResource) {
	fmt.Fprintf(writer, "| Resource Name | Type | Location | Test Command | Expected Result | Actual Result | Status |\n")
	fmt.Fprintf(writer, "|---------------|------|----------|--------------|-----------------|---------------|--------|\n")

	var additionalCommands []struct {
		resourceName string
		commands     []any
	}

	for _, finding := range findings {
		if finding == nil {
			continue
		}

		resourceName := finding.Name
		resourceType := string(finding.ResourceType)
		location := finding.Region

		// Check for enricher commands
		if commands, exists := finding.Properties["commands"]; exists {
			if commandSlice, ok := commands.([]any); ok && len(commandSlice) > 0 {
				// Use the first command for the main table
				firstCommand := j.extractCommandInfo(commandSlice[0])
				status := j.interpretTestStatus(firstCommand)

				fmt.Fprintf(writer, "| %s | %s | %s | `%s` | %s | %s | %s |\n",
					resourceName, resourceType, location,
					j.truncateCommand(firstCommand.Command),
					firstCommand.ExpectedOutputDescription,
					j.summarizeActualOutput(firstCommand.ActualOutput),
					status)

				// Store additional commands if there are more than one
				if len(commandSlice) > 1 {
					additionalCommands = append(additionalCommands, struct {
						resourceName string
						commands     []any
					}{resourceName, commandSlice[1:]})
				}
			}
		} else {
			// No enricher commands, use basic info with standard details
			details := j.buildDetailsString(finding.Properties)
			fmt.Fprintf(writer, "| %s | %s | %s | No test available | Manual review required | %s | ⚠ |\n",
				resourceName, resourceType, location, details)
		}
	}

	// Write additional commands section if any exist
	if len(additionalCommands) > 0 {
		fmt.Fprintf(writer, "\n### Additional Test Commands\n\n")
		for _, resource := range additionalCommands {
			fmt.Fprintf(writer, "#### %s\n\n", resource.resourceName)
			for i, cmd := range resource.commands {
				commandInfo := j.extractCommandInfo(cmd)
				fmt.Fprintf(writer, "```bash\n# Command %d: %s\n%s\n# Expected: %s\n```\n\n",
					i+2, commandInfo.Description, commandInfo.Command, commandInfo.ExpectedOutputDescription)
			}
		}
	}
}

// extractCommandInfo converts command interface{} to Command struct
func (j *ARGScanJSONOutputter) extractCommandInfo(cmdInterface any) Command {
	var cmd Command

	if cmdMap, ok := cmdInterface.(map[string]any); ok {
		if command, exists := cmdMap["command"]; exists {
			if commandStr, ok := command.(string); ok {
				cmd.Command = commandStr
			}
		}
		if description, exists := cmdMap["description"]; exists {
			if descStr, ok := description.(string); ok {
				cmd.Description = descStr
			}
		}
		if expected, exists := cmdMap["expected_output_description"]; exists {
			if expectedStr, ok := expected.(string); ok {
				cmd.ExpectedOutputDescription = expectedStr
			}
		}
		if actualOutput, exists := cmdMap["actual_output"]; exists {
			if actualStr, ok := actualOutput.(string); ok {
				cmd.ActualOutput = actualStr
			}
		}
		if exitCode, exists := cmdMap["exit_code"]; exists {
			if exitCodeInt, ok := exitCode.(int); ok {
				cmd.ExitCode = exitCodeInt
			} else if exitCodeFloat, ok := exitCode.(float64); ok {
				cmd.ExitCode = int(exitCodeFloat)
			}
		}
		if errorMsg, exists := cmdMap["error"]; exists {
			if errorStr, ok := errorMsg.(string); ok {
				cmd.Error = errorStr
			}
		}
	}

	return cmd
}

// interpretTestStatus determines the status symbol based on command results
func (j *ARGScanJSONOutputter) interpretTestStatus(cmd Command) string {
	if cmd.Error != "" {
		return "⚠" // Warning - error occurred
	}

	if cmd.ActualOutput == "Manual execution required" || cmd.Command == "" {
		return "⚠" // Warning - manual verification needed
	}

	// HTTP status code interpretation for web services
	if cmd.ExitCode > 0 {
		switch cmd.ExitCode {
		case 401, 403: // Unauthorized/Forbidden - good for security
			return "✓"
		case 200: // OK - potentially bad if anonymous access expected to be blocked
			if strings.Contains(strings.ToLower(cmd.ExpectedOutputDescription), "anonymous access") {
				return "✗" // Fail - anonymous access is working
			}
			return "✓"
		case 404: // Not found - could be good or bad depending on context
			if strings.Contains(strings.ToLower(cmd.ExpectedOutputDescription), "404") {
				return "✓" // Expected 404
			}
			return "⚠"
		case 409: // Conflict - often means public access disabled
			if strings.Contains(strings.ToLower(cmd.ActualOutput), "public access") {
				return "✓" // Public access is disabled
			}
			return "⚠"
		default:
			return "⚠" // Unknown status
		}
	}

	return "⚠" // Default to warning for unknown cases
}

// truncateCommand shortens long commands for table display
func (j *ARGScanJSONOutputter) truncateCommand(command string) string {
	if len(command) <= 60 {
		return command
	}
	return command[:57] + "..."
}

// summarizeActualOutput creates a brief summary of the actual output
func (j *ARGScanJSONOutputter) summarizeActualOutput(actualOutput string) string {
	if actualOutput == "" {
		return "No output"
	}

	if actualOutput == "Manual execution required" {
		return "Manual execution required"
	}

	// Extract key information from output
	if strings.Contains(actualOutput, "Body:") {
		// For HTTP responses, extract status-like information
		if strings.Contains(actualOutput, "Unauthorized") {
			return "Unauthorized (401)"
		}
		if strings.Contains(actualOutput, "Forbidden") {
			return "Forbidden (403)"
		}
		if strings.Contains(actualOutput, "Not Found") {
			return "Not Found (404)"
		}
		if strings.Contains(actualOutput, "public access") {
			if strings.Contains(strings.ToLower(actualOutput), "not permitted") ||
			   strings.Contains(strings.ToLower(actualOutput), "disabled") {
				return "Public access disabled"
			}
			return "Public access enabled"
		}
	}

	// Truncate long outputs
	if len(actualOutput) > 80 {
		return actualOutput[:77] + "..."
	}

	return actualOutput
}

// Params defines the parameters accepted by this outputter
func (j *ARGScanJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(2),
		cfg.NewParam[string]("module-name", "the name of the module for dynamic file naming"),
		cfg.NewParam[string]("output", "output directory"),
	}
}