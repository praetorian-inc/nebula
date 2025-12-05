package network

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// JSONLReaderLink reads a JSONL file and sends each batch as output
type JSONLReaderLink struct {
	*chain.Base
	filePath string
}

// NewJSONLReaderLink creates a new JSONL file reader
func NewJSONLReaderLink(configs ...cfg.Config) chain.Link {
	l := &JSONLReaderLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

// Params defines the parameters this link accepts
func (l *JSONLReaderLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("data-file", "Input data file path").WithDefault("./nebula-output/network-topology-all-subscriptions.json"),
	}
}

// Initialize sets up the file path from configuration
func (l *JSONLReaderLink) Initialize() error {
	// Get file path from config - this will now include command-line override
	l.filePath, _ = cfg.As[string](l.Arg("data-file"))

	// Check if file path is set
	if l.filePath == "" {
		return fmt.Errorf("data-file parameter is required")
	}

	l.Logger.Debug("JSONL reader configuration", "filePath", l.filePath)
	return nil
}

// Process reads the JSONL file and sends resources to the next link
func (l *JSONLReaderLink) Process(input interface{}) error {
	l.Logger.Info("Reading network topology from file", "path", l.filePath)
	l.Logger.Debug("File reader configuration", "filePath", l.filePath)

	// Read entire file since it's a single large JSON array
	data, err := os.ReadFile(l.filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", l.filePath, err)
	}

	// Parse as JSON
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	var resources []interface{}

	// Check if it's the all-subscriptions format
	if arr, ok := jsonData.([]interface{}); ok && len(arr) > 0 {
		// Check if first element has network_topology structure
		if obj, ok := arr[0].(map[string]interface{}); ok {
			if networkTopology, ok := obj["network_topology"].(map[string]interface{}); ok {
				// Extract all network resources from all subscriptions
				for subID, subData := range networkTopology {
					l.Logger.Debug("Processing subscription", "id", subID)
					if subMap, ok := subData.(map[string]interface{}); ok {
						if networkResources, ok := subMap["network_resources"].([]interface{}); ok {
							resources = append(resources, networkResources...)
							l.Logger.Debug("Found network resources", "subscription", subID, "count", len(networkResources))
						}
					}
				}
			} else {
				// Standard array format - might be resources directly
				resources = arr
			}
		} else {
			// Array of resources directly
			resources = arr
		}
	} else if arr, ok := jsonData.([]interface{}); ok {
		// Standard JSON array
		resources = arr
	} else {
		return fmt.Errorf("unexpected JSON format")
	}

	l.Logger.Info("Loaded resources from file", "count", len(resources))

	// Send all resources to next link
	if err := l.Send(resources); err != nil {
		return fmt.Errorf("failed to send resources: %w", err)
	}

	l.Logger.Info("Finished reading network topology", "totalResources", len(resources))
	return nil
}