package kms

import (
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// ConvertGrantOperations converts KMS grant operations to string slice
func ConvertGrantOperations(ops []kmstypes.GrantOperation) []string {
	var result []string
	for _, op := range ops {
		result = append(result, string(op))
	}
	return result
}

// ConvertGrantConstraints converts grant constraints to a map
func ConvertGrantConstraints(c *kmstypes.GrantConstraints) map[string]interface{} {
	result := make(map[string]interface{})
	if c == nil {
		return result
	}
	if c.EncryptionContextEquals != nil {
		result["EncryptionContextEquals"] = c.EncryptionContextEquals
	}
	if c.EncryptionContextSubset != nil {
		result["EncryptionContextSubset"] = c.EncryptionContextSubset
	}
	return result
}
