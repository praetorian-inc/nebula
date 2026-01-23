package outputters

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ProofFileOnly is a wrapper type that only ProofFileOutputter recognizes.
// Other outputters (like RuntimeJSONOutputter) will ignore this type,
// preventing proof files from appearing in JSON output.
type ProofFileOnly struct {
	File model.File
}

// NewProofFileOnly creates a wrapped proof file that only ProofFileOutputter will handle
func NewProofFileOnly(file model.File) ProofFileOnly {
	return ProofFileOnly{File: file}
}

// ProofFileOutputter handles model.File objects (proofs and definitions) by writing them to disk
type ProofFileOutputter struct {
	*BaseFileOutputter
	outputDirectory string
	filesWritten    int
}

// NewProofFileOutputter creates a new proof file outputter
func NewProofFileOutputter(configs ...cfg.Config) chain.Outputter {
	o := &ProofFileOutputter{}
	o.BaseFileOutputter = NewBaseFileOutputter(o, configs...)
	return o
}

// Initialize sets up the outputter and determines the output directory
func (o *ProofFileOutputter) Initialize() error {
	// Get base output directory
	outputDir, err := cfg.As[string](o.Arg("output"))
	if err != nil {
		outputDir = "nebula-output"
	}
	o.outputDirectory = outputDir

	return nil
}

// Output handles model.File objects and writes them to disk
func (o *ProofFileOutputter) Output(v any) error {
	// Handle ProofFileOnly wrapper (preferred - excludes from JSON output)
	if wrapper, ok := v.(ProofFileOnly); ok {
		return o.writeFile(wrapper.File)
	}

	// Handle raw model.File objects (legacy support)
	if file, ok := v.(model.File); ok {
		return o.writeFile(file)
	}

	// Silently ignore other types
	return nil
}

// writeFile writes a model.File to disk
func (o *ProofFileOutputter) writeFile(file model.File) error {
	// Construct full path - file.Name contains path like "proofs/{dns}/{name}"
	fullPath := filepath.Join(o.outputDirectory, file.Name)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create proof directory: %w", err)
	}

	// Write the file content
	if err := os.WriteFile(fullPath, file.Bytes, 0644); err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}

	o.filesWritten++
	slog.Debug("wrote proof file", "path", fullPath, "size", len(file.Bytes))
	return nil
}

// Complete is called when processing is done
func (o *ProofFileOutputter) Complete() error {
	if o.filesWritten > 0 {
		slog.Debug("proof file outputter complete", "files_written", o.filesWritten)
	}
	return nil
}

// Params defines the parameters accepted by this outputter
func (o *ProofFileOutputter) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
	}
}
