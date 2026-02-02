package types

type Gaad struct {
	UserDetailList  []UserDL     `json:"UserDetailList"`
	RoleDetailList  []RoleDL     `json:"RoleDetailList"`
	GroupDetailList []GroupDL    `json:"GroupDetailList"`
	Policies        []PoliciesDL `json:"Policies"`
}

type PrincipalPL struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument Policy `json:"PolicyDocument"`
}

type ManagedPL struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type UserDL struct {
	Arn                     string        `json:"Arn"`
	UserName                string        `json:"UserName"`
	UserId                  string        `json:"UserId"`
	Path                    string        `json:"Path"`
	CreateDate              string        `json:"CreateDate"`
	GroupList               []string      `json:"GroupList"`
	Tags                    []Tag         `json:"Tags"`
	UserPolicyList          []PrincipalPL `json:"UserPolicyList"`
	PermissionsBoundary     ManagedPL     `json:"PermissionsBoundary"`
	AttachedManagedPolicies []ManagedPL   `json:"AttachedManagedPolicies"`
}

type InstanceProfile struct {
	Path                string                `json:"Path"`
	InstanceProfileName string                `json:"InstanceProfileName"`
	InstanceProfileId   string                `json:"InstanceProfileId"`
	Arn                 string                `json:"Arn"`
	CreateDate          string                `json:"CreateDate"`
	Roles               []InstanceProfileRole `json:"Roles"`
}

type InstanceProfileRole struct {
	Path                     string `json:"Path"`
	RoleName                 string `json:"RoleName"`
	RoleId                   string `json:"RoleId"`
	Arn                      string `json:"Arn"`
	CreateDate               string `json:"CreateDate"`
	AssumeRolePolicyDocument Policy `json:"AssumeRolePolicyDocument"`
}

type PoliciesVL struct {
	VersionId        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
	CreateDate       string `json:"CreateDate"`
	Document         Policy `json:"Document"`
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}
