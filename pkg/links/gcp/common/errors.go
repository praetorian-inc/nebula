package common

import "time"

// ResourceError represents a failed resource discovery attempt
type ResourceError struct {
	Timestamp     string `json:"timestamp"`
	Project       string `json:"project"`
	ResourceType  string `json:"resourceType"`
	Operation     string `json:"operation"`
	ErrorCode     int    `json:"errorCode,omitempty"`
	ErrorMessage  string `json:"errorMessage"`
	Details       string `json:"details,omitempty"`
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