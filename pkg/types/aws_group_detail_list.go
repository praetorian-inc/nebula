package types

type GroupDL struct {
	Arn                     string        `json:"Arn"`
	AttachedManagedPolicies []ManagedPL   `json:"AttachedManagedPolicies"`
	CreateDate              string        `json:"CreateDate"`
	GroupId                 string        `json:"GroupId"`
	GroupName               string        `json:"GroupName"`
	GroupPolicyList         []PrincipalPL `json:"GroupPolicyList"`
	Path                    string        `json:"Path"`
}
