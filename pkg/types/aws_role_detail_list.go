package types

type RoleDL struct {
	Arn                      string            `json:"Arn"`
	AssumeRolePolicyDocument Policy            `json:"AssumeRolePolicyDocument"`
	AttachedManagedPolicies  []ManagedPL       `json:"AttachedManagedPolicies"`
	CreateDate               string            `json:"CreateDate"`
	InstanceProfileList      []InstanceProfile `json:"InstanceProfileList"`
	Path                     string            `json:"Path"`
	PermissionsBoundary      ManagedPL         `json:"PermissionsBoundary"`
	RoleId                   string            `json:"RoleId"`
	RoleLastUsed             map[string]string `json:"RoleLastUsed"`
	RoleName                 string            `json:"RoleName"`
	RolePolicyList           []PrincipalPL     `json:"RolePolicyList"`
	Tags                     []Tag             `json:"Tags"`
}
