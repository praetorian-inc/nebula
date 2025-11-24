package gcptypes

type Hierarchy struct {
	Organizations []*Organization     `json:"organizations,omitempty"`
	Ancestors     map[string][]string `json:"ancestors,omitempty"` // maps child container URIs (folder or project) to ordered ancestor URIs, closest-first, ending at org
}

type Organization struct {
	URI         string            `json:"uri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	OrganizationNumber string      `json:"organizationNumber"`
	DirectoryCustomer  string      `json:"directoryCustomer,omitempty"`
	Folders            []*Folder   `json:"folders,omitempty"`
	Projects           []*Project  `json:"projects,omitempty"`
	Policies           Policies    `json:"policies"`
	PABPolicies        []PABPolicy `json:"pabPolicies,omitempty"`
}

type Folder struct {
	URI         string            `json:"uri"`
	ParentURI   string            `json:"parentUri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	FolderNumber string     `json:"folderNumber"`
	Folders      []*Folder  `json:"folders,omitempty"`
	Projects     []*Project `json:"projects,omitempty"`
	Policies     Policies   `json:"policies"`
}

type Project struct {
	URI         string            `json:"uri"`
	ParentURI   string            `json:"parentUri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	ProjectNumber  string   `json:"projectNumber"`
	ProjectID      string   `json:"projectId"`
	BillingAccount string   `json:"billingAccount,omitempty"`
	Policies       Policies `json:"policies"`
	Services       []string `json:"services,omitempty"` // enabled services
}
