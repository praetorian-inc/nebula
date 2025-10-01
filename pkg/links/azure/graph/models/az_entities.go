package models

// AZUser represents an Azure AD user
type AZUser struct {
	ID                     string            `json:"id"`
	UserPrincipalName      string            `json:"userPrincipalName"`
	DisplayName            string            `json:"displayName"`
	Mail                   string            `json:"mail"`
	AccountEnabled         bool              `json:"accountEnabled"`
	UserType               string            `json:"userType"` // Member or Guest
	Department             string            `json:"department"`
	JobTitle               string            `json:"jobTitle"`
	IsBuiltIn              bool              `json:"isBuiltIn"` // Always false for users
	InvitedFrom            string            `json:"invitedFrom,omitempty"`
	MemberOfGroups         []string          `json:"memberOfGroups"`
	AssignedRoles          []string          `json:"assignedRoles"`
	EligibleRoles          []string          `json:"eligibleRoles"`
	OwnedApplications      []string          `json:"ownedApplications"`
	AppRoleAssignments     map[string]any    `json:"appRoleAssignments"`
	OAuth2PermissionGrants map[string]any    `json:"oauth2PermissionGrants"`
}

// AZGroup represents an Azure AD group
type AZGroup struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	Description     string   `json:"description"`
	SecurityEnabled bool     `json:"securityEnabled"`
	MailEnabled     bool     `json:"mailEnabled"`
	GroupTypes      []string `json:"groupTypes"` // Unified, DynamicMembership
	IsBuiltIn       bool     `json:"isBuiltIn"`
	AssignedRoles   []string `json:"assignedRoles"`
	Owners          []string `json:"owners"`
	Members         []string `json:"members"`
}

// AZServicePrincipal represents an Azure AD service principal
type AZServicePrincipal struct {
	ID                     string         `json:"id"`
	AppID                  string         `json:"appId"`
	DisplayName            string         `json:"displayName"`
	ServicePrincipalType   string         `json:"servicePrincipalType"` // Application, ManagedIdentity, Legacy
	IsBuiltIn              bool           `json:"isBuiltIn"`
	AppRoles               []string       `json:"appRoles"`
	OAuth2PermissionScopes map[string]any `json:"oauth2PermissionScopes"`
	AssignedRoles          []string       `json:"assignedRoles"`
	Owners                 []string       `json:"owners"`
}

// AZApplication represents an Azure AD application registration
type AZApplication struct {
	ID                     string         `json:"id"`
	AppID                  string         `json:"appId"`
	DisplayName            string         `json:"displayName"`
	SignInAudience         string         `json:"signInAudience"`
	IsBuiltIn              bool           `json:"isBuiltIn"`
	RequiredResourceAccess map[string]any `json:"requiredResourceAccess"`
	AppRoles               map[string]any `json:"appRoles"`
	Owners                 []string       `json:"owners"`
	PasswordCredentials    int            `json:"passwordCredentials"`
	KeyCredentials         int            `json:"keyCredentials"`
}

// AZRole represents an Azure AD directory role
type AZRole struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"displayName"`
	Description    string   `json:"description"`
	RoleTemplateID string   `json:"roleTemplateId"`
	IsBuiltIn      bool     `json:"isBuiltIn"`
	Permissions    []string `json:"permissions"`
	Members        []string `json:"members"`
}

// AZDevice represents an Azure AD device
type AZDevice struct {
	ID                      string   `json:"id"`
	DisplayName             string   `json:"displayName"`
	AccountEnabled          bool     `json:"accountEnabled"`
	OperatingSystem         string   `json:"operatingSystem"`
	OperatingSystemVersion  string   `json:"operatingSystemVersion"`
	TrustType               string   `json:"trustType"` // AzureAd, ServerAd, Workplace
	IsCompliant             bool     `json:"isCompliant"`
	IsManaged               bool     `json:"isManaged"`
	MemberOfGroups          []string `json:"memberOfGroups"`
	RegisteredOwners        []string `json:"registeredOwners"`
	RegisteredUsers         []string `json:"registeredUsers"`
}

// AZTenant represents an Azure AD tenant
type AZTenant struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	VerifiedDomains []string `json:"verifiedDomains"`
	TenantType      string   `json:"tenantType"` // AAD, B2C, B2B
}