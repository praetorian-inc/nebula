package common

import (
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"google.golang.org/api/googleapi"
)

// logs skips and returns nil if the error is a 403 and the reason is API disabled
// NOTE: for use ONLY in GCP link Process() functions; DO NOT use in Initialize() functions
func HandleGcpError(err error, msg string) error {
	if err == nil {
		return nil
	}
	if reflect.TypeOf(err) == reflect.TypeOf(&googleapi.Error{}) {
		trueErr := err.(*googleapi.Error)
		if trueErr.Code == 403 {
			for _, detail := range trueErr.Details {
				if detailMap, ok := detail.(map[string]any); ok {
					if reason, ok := detailMap["reason"]; ok && reason == "SERVICE_DISABLED" {
						slog.Info("Skipping", "message", "API disabled for project")
						return nil
					}
					if reason, ok := detailMap["reason"]; ok && reason == "BILLING_DISABLED" {
						slog.Info("Skipping", "message", "Billing disabled for project")
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// ResourceError represents a failed resource discovery attempt
type ResourceError struct {
	Timestamp    string `json:"timestamp"`
	Project      string `json:"project"`
	ResourceType string `json:"resourceType"`
	Operation    string `json:"operation"`
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage"`
	Details      string `json:"details,omitempty"`
}

// NewResourceError creates a new ResourceError instance
func NewResourceError(project, resourceType, operation, errorMessage string) *ResourceError {
	return &ResourceError{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Project:      project,
		ResourceType: resourceType,
		Operation:    operation,
		ErrorMessage: errorMessage,
	}
}

// WithErrorCode adds an HTTP error code to the ResourceError
func (re *ResourceError) WithErrorCode(code int) *ResourceError {
	re.ErrorCode = code
	return re
}

// WithDetails adds additional error details to the ResourceError
func (re *ResourceError) WithDetails(details string) *ResourceError {
	re.Details = details
	return re
}
