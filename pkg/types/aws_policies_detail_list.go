package types

type PoliciesDL struct {
	Arn                           string       `json:"Arn"`
	AttachmentCount               int          `json:"AttachmentCount"`
	CreateDate                    string       `json:"CreateDate"`
	DefaultVersionId              string       `json:"DefaultVersionId"`
	IsAttachable                  bool         `json:"IsAttachable"`
	Path                          string       `json:"Path"`
	PermissionsBoundaryUsageCount int          `json:"PermissionsBoundaryUsageCount"`
	PolicyId                      string       `json:"PolicyId"`
	PolicyName                    string       `json:"PolicyName"`
	PolicyVersionList             []PoliciesVL `json:"PolicyVersionList"`
	UpdateDate                    string       `json:"UpdateDate"`
}

// getDefaultPolicyDocument retrieves the default policy version document
func (policy *PoliciesDL) DefaultPolicyDocument() *Policy {
	for _, version := range policy.PolicyVersionList {
		if version.IsDefaultVersion {
			return &version.Document
		}
	}
	return nil
}
