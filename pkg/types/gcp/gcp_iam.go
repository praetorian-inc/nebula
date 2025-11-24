package gcptypes

type PrincipalKind string

const (
	PrincipalUser   PrincipalKind = "USER"   // user:alice@example.com
	PrincipalGroup  PrincipalKind = "GROUP"  // group:devs@example.com
	PrincipalDomain PrincipalKind = "DOMAIN" // domain:example.com

	PrincipalServiceAccount PrincipalKind = "SERVICE_ACCOUNT" // serviceAccount:sa@project.iam.gserviceaccount.com
	PrincipalServiceAgent   PrincipalKind = "SERVICE_AGENT"   // google-managed service agents

	// special cases
	PrincipalAllUsers              PrincipalKind = "ALL_USERS"               // allUsers
	PrincipalAllAuthenticatedUsers PrincipalKind = "ALL_AUTHENTICATED_USERS" // allAuthenticatedUsers

	// federated principals (principal://)
	PrincipalWorkforceIdentity PrincipalKind = "WORKFORCE_IDENTITY"
	PrincipalWorkloadIdentity  PrincipalKind = "WORKLOAD_IDENTITY"

	// principal sets (principalSet://)
	PrincipalSet PrincipalKind = "PRINCIPAL_SET"
)

// entity that can act on a resource
type Principal struct {
	Kind PrincipalKind `json:"kind"`

	// ParentURI is the closest owning container or directory context for this principal, when applicable:
	//   - organizations/{ORG} for Workspace directory & workforce pools
	//   - projects/{PROJECT_NUMBER} for workload identity pools
	//   - may be empty for global principals (allUsers/allAuthenticatedUsers, consumer Google Accounts)
	ParentURI string `json:"parentUri,omitempty"`

	// Email-style identities (USER/GROUP/SERVICE_ACCOUNT/SERVICE_AGENT)
	Email         string `json:"email,omitempty"`
	OriginalEmail string `json:"originalEmail,omitempty"` // raw member if it had "deleted:" prefix
	Domain        string `json:"domain,omitempty"`
	Deleted       bool   `json:"deleted,omitempty"` // true if source member had "deleted:" prefix

	// Service Account flavor hints
	IsGoogleManaged bool `json:"isGoogleManaged,omitempty"` // true for service agents

	// Kubernetes Service Account (GKE Workload Identity) pattern - serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/NAME]
	KSAProjectID         string `json:"ksaProjectId,omitempty"`
	KubernetesNamespace  string `json:"kubernetesNamespace,omitempty"`
	KubernetesServiceAcc string `json:"kubernetesServiceAccount,omitempty"`

	// Federated identities (principal://…)
	WorkforcePoolName string `json:"workforcePoolName,omitempty"` // organizations/{ORG}/locations/global/workforcePools/{POOL}
	WorkforceSubject  string `json:"workforceSubject,omitempty"`  // subject/…

	WorkloadPoolName string `json:"workloadPoolName,omitempty"` // projects/{NUM}/locations/global/workloadIdentityPools/{POOL}
	WorkloadSubject  string `json:"workloadSubject,omitempty"`  // subject/…

	PrincipalURI string `json:"principalUri,omitempty"` // principal://iam.googleapis.com/...

	// Principal sets (deny/allow/PAB): e.g., “all service accounts in project X”, pools, directory sets
	PrincipalSetURI string            `json:"principalSetUri,omitempty"` // principalSet://iam.googleapis.com/...
	SetAttributes   map[string]string `json:"setAttributes,omitempty"`   // optional key→value for attribute-qualified sets
}

// Policies or resource policies are attached to a resource (if resource can host policies)
type Policies struct {
	Allow *AllowPolicy `json:"allow,omitempty"` // only one per resource, make nil if not fetching or resource doesn't host
	Deny  []DenyPolicy `json:"deny,omitempty"`  // can be multiple and only hosted by org/folder/project
}

// resource is acted on (TODO: only care about ones that host policies? or all?); all are CAI types, will translate to tabularium (TODO: direct import?)
type Resource struct {
	AssetType    string            `json:"assetType"`
	URI          string            `json:"uri"`
	ParentURI    string            `json:"parentUri,omitempty"` // where is it defined (and translate to accountRef in tabularium)
	DisplayName  string            `json:"displayName,omitempty"`
	Location     string            `json:"location,omitempty"`     // region zone
	Service      string            `json:"service,omitempty"`      // storage.googleapis.com, resourcemanager.googleapis.com, etc. (TODO: check if needed)
	ResourceKind string            `json:"resourceKind,omitempty"` // like bucket, vm, etc. (can be used for the resource map in cli modules, maybe)
	Tags         map[string]string `json:"tags,omitempty"`
	Policies     Policies          `json:"policies"`
}

type AllowBinding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
}

type AllowPolicy struct {
	Version     int            `json:"version,omitempty"` // 1 or 3, only 3 has conditions
	Etag        string         `json:"etag,omitempty"`
	Bindings    []AllowBinding `json:"bindings,omitempty"`
	ResourceURI string         `json:"resourceUri"`
}

type DenyRule struct {
	DeniedPrincipals    []string   `json:"deniedPrincipals,omitempty"`
	DeniedPermissions   []string   `json:"deniedPermissions,omitempty"`
	ExceptionPrincipals []string   `json:"exceptionPrincipals,omitempty"`
	Condition           *Condition `json:"condition,omitempty"`
	Description         string     `json:"description,omitempty"`
}

type DenyPolicy struct {
	Name      string     `json:"name"`
	Etag      string     `json:"etag,omitempty"`
	Rules     []DenyRule `json:"rules,omitempty"`
	ParentURI string     `json:"parentUri"` // container that hosts deny (org/folder/project)
}

type Condition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// always CEL; allow uses full CEL; deny uses only resource tag funcs; PAB uses CEL on principal set
	Expression string `json:"expression,omitempty"`
}

// effective boundary applicable and inherited from containers
type PABRule struct {
	Description string   `json:"description,omitempty"`
	Resources   []string `json:"resources"`
}

type PABPolicy struct {
	// defined at org like: organizations/ORG/locations/global/principalAccessBoundaryPolicies/POLICY_ID
	Name               string    `json:"name"`
	DisplayName        string    `json:"displayName,omitempty"`
	EnforcementVersion string    `json:"enforcementVersion,omitempty"` // TODO: check if needed
	Rules              []PABRule `json:"rules"`
	Etag               string    `json:"etag,omitempty"`
}

// applied to a principal set
type PABBinding struct {
	Name            string     `json:"name,omitempty"`
	PolicyName      string     `json:"policyName"` // PABPolicy.Name - the primary reference
	PrincipalSetURI string     `json:"principalSetUri"`
	Condition       *Condition `json:"condition,omitempty"`
	// this is the container that has the principal set which hosts this binding
	ParentURI string `json:"parentUri"`
}

type Permission string

type Role struct {
	Name                string       `json:"name"` // roles/viewer OR organizations/{ORG}/roles/{ID} OR projects/{PROJECT}/roles/{ID}
	Title               string       `json:"title,omitempty"`
	Description         string       `json:"description,omitempty"`
	Stage               string       `json:"stage,omitempty"`
	IncludedPermissions []Permission `json:"includedPermissions,omitempty"` // expanded for evaluation
	ParentURI           string       `json:"parentUri,omitempty"`           // org/project for custom role (empty for predefined)
	Etag                string       `json:"etag,omitempty"`
}
